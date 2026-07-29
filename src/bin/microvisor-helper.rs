use anyhow::{Context, Result, bail};
use microvisor::{
    diagnostics,
    model::{HelperRequest, HelperResponse, ProtectionProfile},
    policy,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read},
    os::fd::AsRawFd,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;
use uuid::Uuid;

const STATE_DIR: &str = "/var/lib/microvisor/profiles";
const RUNTIME_DIR: &str = "/run/microvisor";
const LOCK_FILE: &str = "/run/microvisor/helper.lock";
const POLICY_MAKEFILE: &str = "/usr/share/selinux/devel/Makefile";
const MAX_REQUEST_SIZE: usize = 1024 * 1024;
const TRUSTED_COMMAND_DIRS: &[&str] = &["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

fn main() {
    diagnostics::info("helper", format_args!("privileged helper started"));
    let result = run();
    let response = match result {
        Ok(message) => {
            diagnostics::info("helper", format_args!("request completed successfully"));
            HelperResponse { ok: true, message }
        }
        Err(error) => {
            diagnostics::error("helper", format_args!("request failed: {error:#}"));
            HelperResponse {
                ok: false,
                message: format!("{error:#}"),
            }
        }
    };

    // Keep stdout exclusively for the serialized protocol response. All diagnostics use stderr.
    match serde_json::to_string(&response) {
        Ok(json) => println!("{json}"),
        Err(error) => {
            diagnostics::error(
                "helper",
                format_args!("could not serialize helper response: {error}"),
            );
            std::process::exit(1);
        }
    }

    if !response.ok {
        std::process::exit(1);
    }
}

fn run() -> Result<String> {
    // geteuid is the only unsafe call needed here; checking it before parsing input ensures this
    // binary cannot silently perform a partial unprivileged transaction.
    if unsafe { libc::geteuid() } != 0 {
        diagnostics::warn(
            "helper",
            format_args!("refusing to run without root privileges"),
        );
        bail!("microvisor-helper must run as root through pkexec");
    }
    diagnostics::debug("helper", format_args!("effective UID check passed"));
    // The File guard holds the exclusive lock for the complete request, including rollback.
    let _transaction_lock = acquire_transaction_lock()?;
    ensure_environment()?;

    let mut input = Vec::new();
    // Read one byte beyond the limit so an oversized request is detected without buffering
    // attacker-controlled input indefinitely in the root process.
    io::stdin()
        .take((MAX_REQUEST_SIZE + 1) as u64)
        .read_to_end(&mut input)?;
    diagnostics::debug(
        "helper",
        format_args!("received a {} byte request", input.len()),
    );
    if input.len() > MAX_REQUEST_SIZE {
        bail!("Request exceeds the 1 MiB limit");
    }
    let request: HelperRequest =
        serde_json::from_slice(&input).context("Invalid helper request")?;

    match request {
        HelperRequest::Apply { profile } => {
            diagnostics::info(
                "helper",
                format_args!(
                    "processing apply for profile {} with {} protected directories",
                    profile.id,
                    profile.data_directories.len()
                ),
            );
            let name = profile.name.clone();
            apply_transaction(&profile)?;
            Ok(format!("Protection applied to {name}"))
        }
        HelperRequest::Remove { id } => {
            diagnostics::info("helper", format_args!("processing remove for profile {id}"));
            // Removal trusts only the root-owned profile snapshot. The user's configuration may
            // have changed since the policy and file-context rules were installed.
            match load_state_optional(id)? {
                Some(profile) => {
                    teardown(&profile)?;
                    remove_state(id)?;
                    Ok(format!("Protection removed from {}", profile.name))
                }
                None => {
                    diagnostics::info(
                        "helper",
                        format_args!("profile {id} had no installed root-side state"),
                    );
                    Ok("No installed protection profile was found".into())
                }
            }
        }
    }
}

fn acquire_transaction_lock() -> Result<File> {
    diagnostics::debug("helper", format_args!("acquiring the transaction lock"));
    fs::create_dir_all(RUNTIME_DIR)?;
    fs::set_permissions(RUNTIME_DIR, fs::Permissions::from_mode(0o700))?;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .open(LOCK_FILE)
        .context("Could not open the Microvisor transaction lock")?;
    fs::set_permissions(LOCK_FILE, fs::Permissions::from_mode(0o600))?;
    // flock serializes module, fcontext, relabel, state-save, and rollback operations across every
    // helper process. Releasing the File at function exit releases the lock.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if result != 0 {
        return Err(io::Error::last_os_error())
            .context("Could not lock Microvisor policy transactions");
    }
    diagnostics::debug("helper", format_args!("transaction lock acquired"));
    Ok(file)
}

fn ensure_environment() -> Result<()> {
    diagnostics::debug("helper", format_args!("checking the SELinux environment"));
    for command in ["getenforce", "make", "restorecon", "semanage", "semodule"] {
        find_command(command)
            .with_context(|| format!("Required command '{command}' is not installed"))?;
    }
    if !Path::new(POLICY_MAKEFILE).is_file() {
        bail!("SELinux policy development files are missing: {POLICY_MAKEFILE}");
    }

    ensure_selinux_userspace_version()?;

    let mut command = trusted_command("getenforce")?;
    let enforcement = checked(&mut command)?;
    let enforcement = String::from_utf8_lossy(&enforcement.stdout);
    diagnostics::info(
        "helper",
        format_args!("SELinux enforcement state is {:?}", enforcement.trim()),
    );
    if enforcement.trim() == "Disabled" {
        bail!("SELinux is disabled");
    }

    fs::create_dir_all(STATE_DIR)?;
    fs::set_permissions(STATE_DIR, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn ensure_selinux_userspace_version() -> Result<()> {
    let mut command = trusted_command("semodule")?;
    let output = checked(command.arg("--version"))?;
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let version = text
        .split_whitespace()
        .find_map(parse_major_minor)
        .context("Could not determine the SELinux userspace version")?;
    diagnostics::info(
        "helper",
        format_args!("detected SELinux userspace {}.{}", version.0, version.1),
    );
    if version < (3, 6) {
        bail!(
            "SELinux userspace {}.{} is too old; Microvisor requires 3.6 or newer",
            version.0,
            version.1
        );
    }
    Ok(())
}

fn parse_major_minor(token: &str) -> Option<(u32, u32)> {
    let cleaned =
        token.trim_matches(|character: char| !character.is_ascii_digit() && character != '.');
    let mut parts = cleaned.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn apply_transaction(input: &ProtectionProfile) -> Result<()> {
    diagnostics::info(
        "helper.transaction",
        format_args!("normalizing profile {}", input.id),
    );
    let profile = normalize_profile(input.clone())?;
    // The root-side snapshot is the rollback source. Never reconstruct the previous transaction
    // from mutable user configuration.
    let previous = load_state_optional(profile.id)?;

    if let Some(old) = &previous {
        diagnostics::info(
            "helper.transaction",
            format_args!("removing previous installation for profile {}", profile.id),
        );
        teardown(old).context("Could not remove the previous policy before updating")?;
    }

    diagnostics::debug(
        "helper.transaction",
        format_args!("running preflight checks for profile {}", profile.id),
    );
    if let Err(error) = preflight_install(&profile) {
        diagnostics::error(
            "helper.transaction",
            format_args!("preflight failed for profile {}: {error:#}", profile.id),
        );
        if let Some(old) = previous {
            diagnostics::warn(
                "helper.transaction",
                format_args!("attempting preflight rollback for profile {}", profile.id),
            );
            let rollback = apply(&old).and_then(|_| save_state(&old));
            if let Err(rollback_error) = rollback {
                diagnostics::error(
                    "helper.transaction",
                    format_args!(
                        "preflight rollback failed for profile {}: {rollback_error:#}",
                        profile.id
                    ),
                );
                return Err(error.context(format!(
                    "The previous profile could not be restored: {rollback_error:#}"
                )));
            }
        }
        return Err(error);
    }

    diagnostics::info(
        "helper.transaction",
        format_args!("applying SELinux changes for profile {}", profile.id),
    );
    match apply(&profile).and_then(|_| save_state(&profile)) {
        Ok(()) => {
            diagnostics::info(
                "helper.transaction",
                format_args!("committed profile {}", profile.id),
            );
            Ok(())
        }
        Err(error) => {
            diagnostics::error(
                "helper.transaction",
                format_args!(
                    "apply failed for profile {}; starting cleanup and rollback: {error:#}",
                    profile.id
                ),
            );
            let _ = remove_temporary_state(profile.id);
            let cleanup_error = teardown(&profile).err();
            let rollback_error = previous
                .as_ref()
                .and_then(|old| apply(old).and_then(|_| save_state(old)).err());

            let mut detail = format!("{error:#}");
            if let Some(cleanup_error) = cleanup_error {
                detail.push_str(&format!("; cleanup also failed: {cleanup_error:#}"));
            }
            if let Some(rollback_error) = rollback_error {
                detail.push_str(&format!(
                    "; restoring the previous profile also failed: {rollback_error:#}"
                ));
            }
            bail!(detail)
        }
    }
}

fn normalize_profile(mut profile: ProtectionProfile) -> Result<ProtectionProfile> {
    policy::validate_profile(&profile)?;

    // Resolve symlinks before overlap checks and before generating file-context expressions.
    // All later commands receive these canonical paths as individual argv entries.
    let executable = fs::canonicalize(&profile.executable)
        .with_context(|| format!("Could not resolve {}", profile.executable.display()))?;
    if !executable.is_file() {
        bail!("{} is not a regular file", executable.display());
    }
    if executable.metadata()?.permissions().mode() & 0o111 == 0 {
        bail!("{} is not executable", executable.display());
    }

    let mut directories = Vec::with_capacity(profile.data_directories.len());
    for directory in &profile.data_directories {
        let resolved = fs::canonicalize(directory)
            .with_context(|| format!("Could not resolve {}", directory.display()))?;
        if !resolved.is_dir() {
            bail!("{} is not a directory", resolved.display());
        }
        if normal_component_count(&resolved) < 3 {
            bail!(
                "{} is too broad to protect safely; select an application-specific subdirectory",
                resolved.display()
            );
        }
        directories.push(resolved);
    }

    directories.sort();
    directories.dedup();

    for (index, directory) in directories.iter().enumerate() {
        if executable.starts_with(directory) {
            bail!(
                "The protected directory {} contains the selected executable",
                directory.display()
            );
        }
        for other in directories.iter().skip(index + 1) {
            if other.starts_with(directory) {
                bail!(
                    "Protected directories must not overlap: {} contains {}",
                    directory.display(),
                    other.display()
                );
            }
        }
    }

    profile.executable = executable;
    profile.data_directories = directories;
    policy::validate_profile(&profile)?;
    Ok(profile)
}

fn normal_component_count(path: &Path) -> usize {
    path.components()
        .filter(|component| matches!(component, Component::Normal(_)))
        .count()
}

fn preflight_install(profile: &ProtectionProfile) -> Result<()> {
    ensure_no_profile_conflicts(profile)?;
    let ids = profile.identifiers();
    ensure_module_absent(&ids.module)?;
    ensure_module_absent(&ids.deny_module)?;

    let executable_regex = policy::selinux_path_regex(&profile.executable)?;
    ensure_fcontext_absent(&executable_regex)?;
    for directory in &profile.data_directories {
        ensure_fcontext_absent(&policy::recursive_directory_regex(directory)?)?;
    }
    diagnostics::debug(
        "helper.transaction",
        format_args!("preflight checks passed for profile {}", profile.id),
    );
    Ok(())
}

fn ensure_no_profile_conflicts(profile: &ProtectionProfile) -> Result<()> {
    for entry in fs::read_dir(STATE_DIR)? {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let data = fs::read(entry.path())?;
        let existing: ProtectionProfile = serde_json::from_slice(&data)
            .with_context(|| format!("Stored profile {} is invalid", entry.path().display()))?;
        if existing.id == profile.id {
            continue;
        }

        if existing.executable == profile.executable {
            bail!(
                "{} is already managed by the Microvisor profile '{}'",
                profile.executable.display(),
                existing.name
            );
        }

        for directory in &profile.data_directories {
            for existing_directory in &existing.data_directories {
                if paths_overlap(directory, existing_directory) {
                    bail!(
                        "{} overlaps a directory managed by the Microvisor profile '{}'",
                        directory.display(),
                        existing.name
                    );
                }
            }
            if existing.executable.starts_with(directory) {
                bail!(
                    "{} contains an executable managed by the Microvisor profile '{}'",
                    directory.display(),
                    existing.name
                );
            }
        }

        for existing_directory in &existing.data_directories {
            if profile.executable.starts_with(existing_directory) {
                bail!(
                    "{} is inside a directory managed by the Microvisor profile '{}'",
                    profile.executable.display(),
                    existing.name
                );
            }
        }
    }
    Ok(())
}

fn paths_overlap(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

fn ensure_module_absent(module: &str) -> Result<()> {
    if module_exists(module)? {
        bail!(
            "SELinux module '{module}' already exists but is not owned by the active \
             Microvisor transaction"
        );
    }
    Ok(())
}

fn module_exists(module: &str) -> Result<bool> {
    let mut command = trusted_command("semodule")?;
    let output = checked(command.arg("-l"))?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .any(|name| name == module))
}

fn ensure_fcontext_absent(regex: &str) -> Result<()> {
    if fcontext_rule_exists(regex)? {
        bail!(
            "A local SELinux file-context rule already exists for '{regex}'. \
             Microvisor will not overwrite it"
        );
    }
    Ok(())
}

fn fcontext_rule_exists(regex: &str) -> Result<bool> {
    let mut command = trusted_command("semanage")?;
    let output = checked(command.args(["fcontext", "-l", "-C"]))?;
    Ok(String::from_utf8_lossy(&output.stdout).lines().any(|line| {
        let line = line.trim_start();
        line.strip_prefix(regex)
            .and_then(|rest| rest.chars().next())
            .is_some_and(char::is_whitespace)
    }))
}

fn apply(profile: &ProtectionProfile) -> Result<()> {
    let ids = profile.identifiers();
    diagnostics::debug(
        "helper.apply",
        format_args!("building module {}", ids.module),
    );
    let work = TempDir::new().context("Could not create a policy build directory")?;
    let te_path = work.path().join(format!("{}.te", ids.module));
    fs::write(&te_path, policy::render_type_enforcement(profile)?)?;

    let mut make = trusted_command("make")?;
    checked(
        make.current_dir(work.path())
            .arg("-f")
            .arg(POLICY_MAKEFILE)
            .arg(format!("{}.pp", ids.module)),
    )
    .context("Could not compile the SELinux type-enforcement module")?;
    diagnostics::debug(
        "helper.apply",
        format_args!("compiled module {}", ids.module),
    );

    // Install the base types before assigning them to files. The deny module is deliberately
    // installed only after every requested path has been relabeled successfully.
    let mut semodule = trusted_command("semodule")?;
    checked(
        semodule
            .arg("-i")
            .arg(work.path().join(format!("{}.pp", ids.module))),
    )
    .context("Could not install the SELinux type-enforcement module")?;
    diagnostics::info(
        "helper.apply",
        format_args!("installed module {}", ids.module),
    );

    add_file_context(&profile.executable, &ids.exec_type, true)?;
    let mut restorecon = trusted_command("restorecon")?;
    checked(restorecon.arg("-v").arg(&profile.executable))
        .context("Could not label the application executable")?;
    diagnostics::debug(
        "helper.apply",
        format_args!("labeled the executable for profile {}", profile.id),
    );

    for (index, directory) in profile.data_directories.iter().enumerate() {
        add_file_context(directory, &ids.data_type, false)?;
        let mut restorecon = trusted_command("restorecon")?;
        checked(restorecon.arg("-RFv").arg(directory))
            .with_context(|| format!("Could not label {}", directory.display()))?;
        diagnostics::debug(
            "helper.apply",
            format_args!(
                "labeled protected directory {}/{} for profile {}",
                index + 1,
                profile.data_directories.len(),
                profile.id
            ),
        );
    }

    // This must remain the final mutation: installing the deny complement earlier could block
    // recovery while only part of the selected data has its new label.
    let cil_path = work.path().join(format!("{}.cil", ids.deny_module));
    fs::write(&cil_path, policy::render_deny_cil(profile)?)?;
    let mut semodule = trusted_command("semodule")?;
    checked(semodule.arg("-i").arg(&cil_path)).context(
        "Could not install the SELinux deny module. SELinux userspace 3.6 or newer is required",
    )?;
    diagnostics::info(
        "helper.apply",
        format_args!("installed deny module {}", ids.deny_module),
    );

    Ok(())
}

fn teardown(profile: &ProtectionProfile) -> Result<()> {
    let ids = profile.identifiers();
    diagnostics::info(
        "helper.teardown",
        format_args!("tearing down profile {}", profile.id),
    );
    // Remove the deny complement first so recovery and relabeling are not themselves denied.
    remove_module_if_present(&ids.deny_module)?;
    diagnostics::debug(
        "helper.teardown",
        format_args!("deny module is absent for profile {}", profile.id),
    );

    delete_file_context(&profile.executable, true)?;
    if profile.executable.exists() {
        let mut restorecon = trusted_command("restorecon")?;
        checked(restorecon.arg("-v").arg(&profile.executable))
            .context("Could not restore the executable label")?;
    }

    for directory in &profile.data_directories {
        delete_file_context(directory, false)?;
        if directory.exists() {
            let mut restorecon = trusted_command("restorecon")?;
            checked(restorecon.arg("-RFv").arg(directory)).with_context(|| {
                format!("Could not restore labels below {}", directory.display())
            })?;
        }
    }

    remove_module_if_present(&ids.module)?;
    diagnostics::info(
        "helper.teardown",
        format_args!("teardown completed for profile {}", profile.id),
    );
    Ok(())
}

fn add_file_context(path: &Path, selinux_type: &str, executable: bool) -> Result<()> {
    let regex = if executable {
        policy::selinux_path_regex(path)?
    } else {
        policy::recursive_directory_regex(path)?
    };

    let mut command = trusted_command("semanage")?;
    command.args(["fcontext", "-a"]);
    if executable {
        command.args(["-f", "f"]);
    }
    command.args(["-t", selinux_type, &regex]);
    checked(&mut command)
        .with_context(|| format!("Could not add file-context rule for {}", path.display()))?;
    Ok(())
}

fn delete_file_context(path: &Path, executable: bool) -> Result<()> {
    let regex = if executable {
        policy::selinux_path_regex(path)?
    } else {
        policy::recursive_directory_regex(path)?
    };

    if !fcontext_rule_exists(&regex)? {
        return Ok(());
    }

    let mut command = trusted_command("semanage")?;
    command.args(["fcontext", "-d"]);
    if executable {
        command.args(["-f", "f"]);
    }
    checked(command.arg(&regex))
        .with_context(|| format!("Could not delete file-context rule for {}", path.display()))?;
    Ok(())
}

fn remove_module_if_present(module: &str) -> Result<()> {
    if !module_exists(module)? {
        return Ok(());
    }
    let mut command = trusted_command("semodule")?;
    checked(command.args(["-r", module]))
        .with_context(|| format!("Could not remove policy module {module}"))?;
    Ok(())
}

fn state_path(id: Uuid) -> PathBuf {
    Path::new(STATE_DIR).join(format!("{id}.json"))
}

fn save_state(profile: &ProtectionProfile) -> Result<()> {
    diagnostics::debug(
        "helper.state",
        format_args!("saving root-side state for profile {}", profile.id),
    );
    let path = state_path(profile.id);
    let temporary = path.with_extension("json.tmp");
    // Write, secure, and atomically rename the snapshot only after policy application succeeds.
    // A future removal or rollback must never trust a partially written root-side profile.
    fs::write(&temporary, serde_json::to_vec_pretty(profile)?)?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn remove_temporary_state(id: Uuid) -> Result<()> {
    let temporary = state_path(id).with_extension("json.tmp");
    if temporary.exists() {
        fs::remove_file(temporary)?;
    }
    Ok(())
}

fn load_state_optional(id: Uuid) -> Result<Option<ProtectionProfile>> {
    let path = state_path(id);
    match fs::read(&path) {
        Ok(data) => serde_json::from_slice(&data)
            .map(Some)
            .context("Stored Microvisor profile is invalid"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("Could not read stored profile {}", path.display()))
        }
    }
}

fn load_state(id: Uuid) -> Result<ProtectionProfile> {
    let path = state_path(id);
    let data = fs::read(&path)
        .with_context(|| format!("No installed Microvisor profile exists for {id}"))?;
    serde_json::from_slice(&data).context("Stored Microvisor profile is invalid")
}

fn remove_state(id: Uuid) -> Result<()> {
    let path = state_path(id);
    if path.exists() {
        fs::remove_file(path)?;
        diagnostics::debug(
            "helper.state",
            format_args!("removed root-side state for profile {id}"),
        );
    }
    Ok(())
}

fn checked(command: &mut Command) -> Result<Output> {
    let program = command.get_program().to_string_lossy().into_owned();
    diagnostics::debug("helper.command", format_args!("executing {program}"));
    let output = command.output()?;
    if !output.status.success() {
        diagnostics::error(
            "helper.command",
            format_args!("{program} exited with {}", output.status),
        );
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        bail!(if stderr.is_empty() { stdout } else { stderr });
    }
    diagnostics::debug(
        "helper.command",
        format_args!("{program} exited successfully"),
    );
    Ok(output)
}

fn trusted_command(command: &str) -> Result<Command> {
    // Resolve the executable from root-owned system directories and discard the caller's
    // environment. Profile values are appended later as argv entries, never as shell text.
    let mut process = Command::new(find_command(command)?);
    process.env_clear().envs([
        ("HOME", "/root"),
        ("LANG", "C"),
        ("LC_ALL", "C"),
        ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
    ]);
    Ok(process)
}

fn find_command(command: &str) -> Result<PathBuf> {
    if command.contains('/') {
        bail!("Command names must not contain '/'");
    }

    for directory in TRUSTED_COMMAND_DIRS {
        let candidate = Path::new(directory).join(command);
        if candidate.is_file()
            && candidate
                .metadata()
                .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        {
            return Ok(candidate);
        }
    }
    bail!("Command not found")
}
