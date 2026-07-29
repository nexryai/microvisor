use std::env;
use std::error::Error as StdError;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type Result<T> = std::result::Result<T, CiError>;

#[derive(Debug)]
enum CiError {
    Configuration(String),
    Io {
        context: String,
        source: io::Error,
    },
    Command {
        context: String,
        command: String,
        code: Option<i32>,
        stderr: String,
    },
    Unexpected(String),
}

impl fmt::Display for CiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) | Self::Unexpected(message) => {
                formatter.write_str(message)
            }
            Self::Io { context, source } => write!(formatter, "{context}: {source}"),
            Self::Command {
                context,
                command,
                code,
                stderr,
            } => {
                write!(
                    formatter,
                    "{context}: {command} exited with {}",
                    code.map_or_else(|| "a signal".to_string(), |code| format!("code {code}"))
                )?;
                if !stderr.trim().is_empty() {
                    write!(formatter, ": {}", stderr.trim())?;
                }
                Ok(())
            }
        }
    }
}

impl StdError for CiError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

trait IoContext<T> {
    fn context(self, context: impl Into<String>) -> Result<T>;
}

impl<T> IoContext<T> for io::Result<T> {
    fn context(self, context: impl Into<String>) -> Result<T> {
        self.map_err(|source| CiError::Io {
            context: context.into(),
            source,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloudInitOutcome {
    Success,
    RecoverableError,
    Fatal,
}

fn classify_cloud_init_exit(code: Option<i32>) -> CloudInitOutcome {
    match code {
        Some(0) => CloudInitOutcome::Success,
        Some(2) => CloudInitOutcome::RecoverableError,
        _ => CloudInitOutcome::Fatal,
    }
}

struct Config {
    repository_root: PathBuf,
    helper_path: PathBuf,
    image_name: String,
    image_url: OsString,
    image_sha256: String,
    image_cache_directory: PathBuf,
    console_log: PathBuf,
}

impl Config {
    fn from_environment() -> Result<Self> {
        let repository_root = find_repository_root()?;
        let image_name = required_utf8_environment("FEDORA_IMAGE_NAME")?;
        if Path::new(&image_name)
            .file_name()
            .and_then(|name| name.to_str())
            != Some(image_name.as_str())
        {
            return Err(CiError::Configuration(
                "FEDORA_IMAGE_NAME must be a file name, not a path".to_string(),
            ));
        }

        let image_sha256 = required_utf8_environment("FEDORA_IMAGE_SHA256")?;
        if image_sha256.len() != 64 || !image_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CiError::Configuration(
                "FEDORA_IMAGE_SHA256 must be a 64-character hexadecimal digest".to_string(),
            ));
        }

        let helper_path = env::var_os("INTEGRATION_HELPER_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                repository_root
                    .join("target")
                    .join("debug")
                    .join("microvisor-helper")
            });
        let image_cache_directory = env::var_os("FEDORA_IMAGE_CACHE_DIRECTORY")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env::var_os("HOME").unwrap_or_else(|| OsString::from("/tmp")))
                    .join(".cache")
                    .join("microvisor")
            });
        let console_log = env::var_os("VM_CONSOLE_LOG")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(env::var_os("RUNNER_TEMP").unwrap_or_else(|| OsString::from("/tmp")))
                    .join("microvisor-fedora-vm-console.log")
            });

        Ok(Self {
            repository_root,
            helper_path,
            image_name,
            image_url: required_environment("FEDORA_IMAGE_URL")?,
            image_sha256: image_sha256.to_ascii_lowercase(),
            image_cache_directory,
            console_log,
        })
    }
}

struct VmGuard {
    temporary_directory: PathBuf,
    pid_file: PathBuf,
    console_log: PathBuf,
    succeeded: bool,
}

impl VmGuard {
    fn new(console_log: PathBuf) -> Result<Self> {
        let temporary_directory = create_temporary_directory()?;
        let pid_file = temporary_directory.join("qemu.pid");
        Ok(Self {
            temporary_directory,
            pid_file,
            console_log,
            succeeded: false,
        })
    }

    fn qemu_pid(&self) -> Option<String> {
        let pid = fs::read_to_string(&self.pid_file).ok()?;
        let pid = pid.trim();
        (!pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit())).then(|| pid.to_string())
    }

    fn qemu_is_running(&self) -> bool {
        let Some(pid) = self.qemu_pid() else {
            return false;
        };
        Command::new("kill")
            .args(["-0", &pid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn wait_for_qemu_exit(&self, attempts: usize, delay: Duration) -> bool {
        for _ in 0..attempts {
            if !self.qemu_is_running() {
                return true;
            }
            thread::sleep(delay);
        }
        !self.qemu_is_running()
    }

    fn stop_qemu(&self) {
        let Some(pid) = self.qemu_pid() else {
            return;
        };
        if !self.qemu_is_running() {
            return;
        }

        let _ = Command::new("kill")
            .arg(&pid)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.wait_for_qemu_exit(30, Duration::from_millis(100));
    }

    fn print_console_tail(&self) {
        let Ok(contents) = fs::read(&self.console_log) else {
            return;
        };
        eprintln!("Last 200 lines from the Fedora VM console:");
        let lines: Vec<_> = contents.split(|byte| *byte == b'\n').collect();
        for line in lines.iter().skip(lines.len().saturating_sub(200)) {
            eprintln!("{}", String::from_utf8_lossy(line));
        }
    }
}

impl Drop for VmGuard {
    fn drop(&mut self) {
        self.stop_qemu();
        if !self.succeeded {
            self.print_console_tail();
        }
        if let Err(error) = fs::remove_dir_all(&self.temporary_directory) {
            eprintln!(
                "Failed to remove temporary directory {}: {error}",
                self.temporary_directory.display()
            );
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Fedora QEMU SELinux integration job failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let config = Config::from_environment()?;
    let mut vm = VmGuard::new(config.console_log.clone())?;
    let image_path = prepare_image(&config)?;

    println!("Fedora image: {}", config.image_name);
    println!("Fedora image SHA-256: {}", config.image_sha256);
    print_qemu_version()?;

    let ssh_key = vm.temporary_directory.join("id_ed25519");
    run_checked(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&ssh_key),
        "generate the VM SSH key",
    )?;
    let public_key = fs::read_to_string(ssh_key.with_extension("pub"))
        .context("read the generated SSH public key")?;
    write_cloud_init_seed(&vm.temporary_directory, public_key.trim())?;

    run_checked(
        Command::new("cloud-localds")
            .arg(vm.temporary_directory.join("seed.img"))
            .arg(vm.temporary_directory.join("user-data"))
            .arg(vm.temporary_directory.join("meta-data")),
        "create the cloud-init seed image",
    )?;
    run_checked(
        Command::new("qemu-img")
            .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
            .arg(
                image_path
                    .canonicalize()
                    .context("resolve the Fedora image path")?,
            )
            .arg(vm.temporary_directory.join("fedora-overlay.qcow2"))
            .arg("20G"),
        "create the disposable Fedora overlay",
    )?;

    let (acceleration, cpu) = select_qemu_acceleration()?;
    println!("Starting Fedora with QEMU acceleration: {acceleration}");
    if let Some(parent) = config.console_log.parent() {
        fs::create_dir_all(parent).context(format!(
            "create the console log directory {}",
            parent.display()
        ))?;
    }
    File::create(&config.console_log).context(format!(
        "truncate the console log {}",
        config.console_log.display()
    ))?;

    start_qemu(&vm, &config.console_log, acceleration, cpu)?;
    wait_for_ssh(&vm, &ssh_key)?;
    wait_for_cloud_init(&ssh_key)?;
    verify_selinux_enforcing(&ssh_key)?;

    let source_archive = vm.temporary_directory.join("microvisor-source.tar.gz");
    run_checked(
        Command::new("tar")
            .args(["--exclude=.git", "--exclude=build", "--exclude=target"])
            .arg("-C")
            .arg(&config.repository_root)
            .arg("-czf")
            .arg(&source_archive)
            .arg("."),
        "archive the Microvisor source",
    )?;
    if !config.helper_path.is_file() {
        return Err(CiError::Configuration(format!(
            "the Fedora-built integration helper was not found: {}",
            config.helper_path.display()
        )));
    }

    // Both files remain untrusted on the host. Privilege is granted only inside the disposable
    // guest, whose overlay is removed when this process exits.
    copy_to_guest(
        &ssh_key,
        &source_archive,
        "/home/runner/microvisor-source.tar.gz",
    )?;
    copy_to_guest(
        &ssh_key,
        &config.helper_path,
        "/home/runner/microvisor-helper",
    )?;
    run_ssh_checked(
        &ssh_key,
        "mkdir -p /home/runner/microvisor && \
         tar -xzf /home/runner/microvisor-source.tar.gz -C /home/runner/microvisor && \
         chmod 0755 /home/runner/microvisor-helper",
        "extract the source and prepare the helper in the guest",
    )?;

    run_ssh_checked(
        &ssh_key,
        "sudo dnf install -y \
         checkpolicy \
         libselinux-utils \
         make \
         policycoreutils \
         policycoreutils-python-utils \
         selinux-policy-devel \
         setools-console",
        "install the Fedora SELinux test dependencies",
    )?;

    run_ssh_checked(
        &ssh_key,
        "set -euo pipefail
         echo \"Fedora: $(cat /etc/fedora-release)\"
         echo \"Kernel: $(uname -r)\"
         echo \"SELinux userspace: $(rpm -q --qf '%{VERSION}\\n' libsepol)\"
         echo \"SELinux policy packages:\"
         rpm -q selinux-policy selinux-policy-targeted
         echo \"SELinux context: $(id -Z)\"
         sestatus
         cd /home/runner/microvisor
         sudo bash tests/selinux-integration.sh /home/runner/microvisor-helper",
        "run the SELinux integration test",
    )?;

    let mut poweroff = ssh_command(&ssh_key);
    poweroff.arg("sudo poweroff");
    let _ = run_status(&mut poweroff, "power off the Fedora guest");
    let _ = vm.wait_for_qemu_exit(30, Duration::from_secs(1));

    vm.succeeded = true;
    println!("Fedora QEMU SELinux integration job passed.");
    Ok(())
}

fn required_environment(name: &'static str) -> Result<OsString> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CiError::Configuration(format!("required environment variable {name} is not set"))
        })
}

fn required_utf8_environment(name: &'static str) -> Result<String> {
    required_environment(name)?
        .into_string()
        .map_err(|_| CiError::Configuration(format!("{name} must contain valid UTF-8")))
}

fn find_repository_root() -> Result<PathBuf> {
    let mut directory = env::current_dir().context("read the current working directory")?;
    loop {
        if directory.join("Cargo.toml").is_file() && directory.join(".github").is_dir() {
            return Ok(directory);
        }
        if !directory.pop() {
            return Err(CiError::Configuration(
                "run the Fedora VM driver from inside the Microvisor repository".to_string(),
            ));
        }
    }
}

fn create_temporary_directory() -> Result<PathBuf> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            CiError::Unexpected(format!("system clock is before Unix epoch: {error}"))
        })?
        .as_nanos();
    for attempt in 0..100_u8 {
        let path = env::temp_dir().join(format!(
            "microvisor-fedora-vm-{}-{timestamp}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).context(format!(
                    "set permissions on temporary directory {}",
                    path.display()
                ))?;
                return Ok(path);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(source) => {
                return Err(CiError::Io {
                    context: format!("create temporary directory {}", path.display()),
                    source,
                });
            }
        }
    }
    Err(CiError::Unexpected(
        "could not allocate a unique temporary directory".to_string(),
    ))
}

fn command_failure(context: impl Into<String>, command: &Command, output: &Output) -> CiError {
    CiError::Command {
        context: context.into(),
        command: format!("{command:?}"),
        code: output.status.code(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn status_failure(context: impl Into<String>, command: &Command, status: ExitStatus) -> CiError {
    CiError::Command {
        context: context.into(),
        command: format!("{command:?}"),
        code: status.code(),
        stderr: String::new(),
    }
}

fn run_status(command: &mut Command, context: &str) -> Result<ExitStatus> {
    println!("Running {context}: {command:?}");
    command
        .status()
        .context(format!("start command for {context}: {command:?}"))
}

fn run_checked(command: &mut Command, context: &str) -> Result<()> {
    let status = run_status(command, context)?;
    if status.success() {
        Ok(())
    } else {
        Err(status_failure(context, command, status))
    }
}

fn output_checked(command: &mut Command, context: &str) -> Result<Output> {
    println!("Running {context}: {command:?}");
    let output = command
        .output()
        .context(format!("start command for {context}: {command:?}"))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(command_failure(context, command, &output))
    }
}

fn verify_image(path: &Path, expected_sha256: &str) -> Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    let output = output_checked(
        Command::new("sha256sum").arg(path),
        "calculate the Fedora image checksum",
    )?;
    let stdout = String::from_utf8(output.stdout).map_err(|error| {
        CiError::Unexpected(format!("sha256sum returned invalid UTF-8: {error}"))
    })?;
    Ok(stdout
        .split_whitespace()
        .next()
        .is_some_and(|digest| digest.eq_ignore_ascii_case(expected_sha256)))
}

fn prepare_image(config: &Config) -> Result<PathBuf> {
    fs::create_dir_all(&config.image_cache_directory).context(format!(
        "create the Fedora image cache {}",
        config.image_cache_directory.display()
    ))?;
    let image_path = config.image_cache_directory.join(&config.image_name);
    // QEMU always uses a disposable overlay, but verifying the immutable backing image remains
    // essential because GitHub's cache may contain a partial or stale download.
    if verify_image(&image_path, &config.image_sha256)? {
        return Ok(image_path);
    }
    if image_path.exists() {
        fs::remove_file(&image_path).context(format!(
            "remove invalid cached Fedora image {}",
            image_path.display()
        ))?;
    }

    // Keep the temporary download in the cache directory so the final rename is atomic.
    let download_path = config.image_cache_directory.join(format!(
        ".{}.{}.download",
        config.image_name,
        std::process::id()
    ));
    if download_path.exists() {
        fs::remove_file(&download_path).context(format!(
            "remove stale Fedora image download {}",
            download_path.display()
        ))?;
    }
    run_checked(
        Command::new("curl")
            .args([
                "--fail",
                "--location",
                "--retry",
                "5",
                "--retry-all-errors",
                "--remove-on-error",
                "--output",
            ])
            .arg(&download_path)
            .arg("--")
            .arg(&config.image_url),
        "download the pinned Fedora Cloud image",
    )?;
    if !verify_image(&download_path, &config.image_sha256)? {
        let _ = fs::remove_file(&download_path);
        return Err(CiError::Unexpected(format!(
            "downloaded Fedora image checksum did not match {}",
            config.image_sha256
        )));
    }
    fs::rename(&download_path, &image_path).context(format!(
        "move the verified Fedora image into {}",
        image_path.display()
    ))?;

    Ok(image_path)
}

fn print_qemu_version() -> Result<()> {
    let output = output_checked(
        Command::new("qemu-system-x86_64").arg("--version"),
        "read the QEMU version",
    )?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!(
        "{}",
        stdout.lines().next().unwrap_or("QEMU version unavailable")
    );
    Ok(())
}

fn write_cloud_init_seed(directory: &Path, public_key: &str) -> Result<()> {
    let user_data = format!(
        "#cloud-config
users:
  - name: runner
    gecos: GitHub Actions
    groups: [wheel]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - {public_key}
ssh_pwauth: false
disable_root: true
growpart:
  mode: auto
  devices: [/]
resize_rootfs: true
"
    );
    write_file(&directory.join("user-data"), user_data.as_bytes())?;
    write_file(
        &directory.join("meta-data"),
        b"instance-id: microvisor-fedora-44-ci\nlocal-hostname: microvisor-fedora-ci\n",
    )
}

fn write_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = File::create(path).context(format!("create {}", path.display()))?;
    file.write_all(contents)
        .context(format!("write {}", path.display()))
}

fn select_qemu_acceleration() -> Result<(&'static str, &'static str)> {
    let kvm_path = Path::new("/dev/kvm");
    let kvm_available = fs::metadata(kvm_path)
        .map(|metadata| metadata.file_type().is_char_device())
        .unwrap_or(false);
    // Nested virtualization is opportunistic on GitHub-hosted runners. TCG keeps the workflow
    // usable when /dev/kvm is absent without requiring a self-hosted runner.
    if !kvm_available {
        return Ok(("tcg,thread=multi", "max"));
    }

    run_checked(
        Command::new("sudo").args(["chmod", "0666", "/dev/kvm"]),
        "make the hosted runner KVM device accessible",
    )?;
    if OpenOptions::new()
        .read(true)
        .write(true)
        .open(kvm_path)
        .is_ok()
    {
        Ok(("kvm", "host"))
    } else {
        Ok(("tcg,thread=multi", "max"))
    }
}

fn start_qemu(vm: &VmGuard, console_log: &Path, acceleration: &str, cpu: &str) -> Result<()> {
    run_checked(
        Command::new("qemu-system-x86_64")
            .args([
                "-name",
                "microvisor-fedora-ci",
                "-machine",
                "q35",
                "-accel",
                acceleration,
                "-cpu",
                cpu,
                "-smp",
                "2",
                "-m",
                "4096",
                "-drive",
            ])
            .arg(format!(
                "file={},if=virtio,format=qcow2",
                vm.temporary_directory
                    .join("fedora-overlay.qcow2")
                    .display()
            ))
            .arg("-drive")
            .arg(format!(
                "file={},if=virtio,format=raw,readonly=on",
                vm.temporary_directory.join("seed.img").display()
            ))
            .args([
                "-device",
                "virtio-rng-pci",
                "-netdev",
                "user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22",
                "-device",
                "virtio-net-pci,netdev=net0",
                "-display",
                "none",
                "-serial",
            ])
            .arg(format!("file:{}", console_log.display()))
            .args(["-monitor", "none", "-pidfile"])
            .arg(&vm.pid_file)
            .arg("-daemonize"),
        "start the Fedora VM",
    )
}

fn add_ssh_options(command: &mut Command, ssh_key: &Path, port_flag: &str) {
    command.arg("-i").arg(ssh_key).args([
        port_flag,
        "2222",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
    ]);
}

fn ssh_command(ssh_key: &Path) -> Command {
    let mut command = Command::new("ssh");
    add_ssh_options(&mut command, ssh_key, "-p");
    command.arg("runner@127.0.0.1");
    command
}

fn wait_for_ssh(vm: &VmGuard, ssh_key: &Path) -> Result<()> {
    for _ in 0..120 {
        let status = ssh_command(ssh_key)
            .arg("true")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("probe SSH readiness in the Fedora VM")?;
        if status.success() {
            return Ok(());
        }
        if !vm.qemu_is_running() {
            return Err(CiError::Unexpected(
                "QEMU exited before SSH became available".to_string(),
            ));
        }
        thread::sleep(Duration::from_secs(5));
    }
    Err(CiError::Unexpected(
        "timed out waiting for SSH in the Fedora VM".to_string(),
    ))
}

fn wait_for_cloud_init(ssh_key: &Path) -> Result<()> {
    let mut command = ssh_command(ssh_key);
    command.arg("sudo cloud-init status --wait");
    let status = run_status(&mut command, "wait for cloud-init")?;
    match classify_cloud_init_exit(status.code()) {
        CloudInitOutcome::Success => Ok(()),
        CloudInitOutcome::RecoverableError => {
            // Exit code 2 means cloud-init completed with recoverable errors. Emit the details, then
            // rely on the explicit security and provisioning checks that follow this step.
            eprintln!(
                "cloud-init completed with recoverable errors; continuing with explicit guest checks."
            );
            let mut diagnostics = ssh_command(ssh_key);
            diagnostics.arg("sudo cloud-init status --long");
            if let Err(error) = run_status(&mut diagnostics, "print cloud-init diagnostics") {
                eprintln!("Could not print cloud-init diagnostics: {error}");
            }
            Ok(())
        }
        CloudInitOutcome::Fatal => Err(status_failure("wait for cloud-init", &command, status)),
    }
}

fn verify_selinux_enforcing(ssh_key: &Path) -> Result<()> {
    run_ssh_checked(
        ssh_key,
        "set -eu
         mode=$(getenforce)
         echo \"SELinux mode: $mode\"
         test \"$mode\" = Enforcing
         test -d /sys/fs/selinux",
        "verify SELinux Enforcing mode in the guest",
    )
}

fn run_ssh_checked(ssh_key: &Path, remote_command: &str, context: &str) -> Result<()> {
    let mut command = ssh_command(ssh_key);
    command.arg(remote_command);
    run_checked(&mut command, context)
}

fn copy_to_guest(ssh_key: &Path, source: &Path, destination: &str) -> Result<()> {
    let mut command = Command::new("scp");
    add_ssh_options(&mut command, ssh_key, "-P");
    command
        .arg(source)
        .arg(format!("runner@127.0.0.1:{destination}"));
    run_checked(
        &mut command,
        &format!("copy {} into the Fedora guest", source.display()),
    )
}

#[cfg(test)]
mod tests {
    use super::{CloudInitOutcome, classify_cloud_init_exit};

    #[test]
    fn cloud_init_success_is_accepted() {
        assert_eq!(classify_cloud_init_exit(Some(0)), CloudInitOutcome::Success);
    }

    #[test]
    fn cloud_init_recoverable_errors_are_accepted() {
        assert_eq!(
            classify_cloud_init_exit(Some(2)),
            CloudInitOutcome::RecoverableError
        );
    }

    #[test]
    fn cloud_init_crashes_and_signals_are_fatal() {
        assert_eq!(classify_cloud_init_exit(Some(1)), CloudInitOutcome::Fatal);
        assert_eq!(classify_cloud_init_exit(Some(42)), CloudInitOutcome::Fatal);
        assert_eq!(classify_cloud_init_exit(None), CloudInitOutcome::Fatal);
    }
}
