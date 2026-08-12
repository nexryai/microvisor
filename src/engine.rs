use crate::{diagnostics, model::ProtectionProfile, policy};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
};
use tempfile::TempDir;
use uuid::Uuid;

pub const STATE_DIR: &str = "/var/lib/microvisor/profiles";
const STATE_ROOT: &str = "/var/lib/microvisor";
const RUNTIME_DIR: &str = "/run/microvisor";
const LOCK_FILE: &str = "/run/microvisor/transaction.lock";
const POLICY_INCLUDE_DIR: &str = "/usr/share/selinux/devel/include";
const MAX_POLICY_SOURCE_FILES: usize = 4096;
const MAX_POLICY_SOURCE_SIZE: u64 = 4 * 1024 * 1024;
const MAX_GENERATED_POLICY_SIZE: u64 = 64 * 1024 * 1024;
const MAX_STATE_SIZE: usize = 1024 * 1024;
const STATE_SCHEMA_VERSION: u32 = 1;
const TRUSTED_COMMAND_DIRS: &[&str] = &["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

pub fn require_root() -> Result<()> {
    // Root is required before any configuration is parsed, so an unprivileged invocation cannot
    // probe protected paths or accidentally run only part of a privileged transaction.
    if unsafe { libc::geteuid() } != 0 {
        bail!("Microvisor must run as root");
    }
    Ok(())
}

pub fn validate_profiles(profiles: Vec<ProtectionProfile>) -> Result<Vec<ProtectionProfile>> {
    validate_profiles_with_applied(profiles, &[])
}

pub fn validate_desired_profiles(
    profiles: Vec<ProtectionProfile>,
) -> Result<Vec<ProtectionProfile>> {
    let _transaction_lock = acquire_transaction_lock()?;
    let applied = if Path::new(STATE_DIR).try_exists()? {
        ensure_state_directory()?;
        load_all_states()?
    } else {
        Vec::new()
    };
    validate_profiles_with_applied(profiles, &applied)
}

fn validate_profiles_with_applied(
    profiles: Vec<ProtectionProfile>,
    applied: &[ProtectionProfile],
) -> Result<Vec<ProtectionProfile>> {
    let mut normalized = profiles
        .into_iter()
        .map(|profile| {
            let previous = applied.iter().find(|item| item.id == profile.id);
            normalize_profile_with_applied(profile, previous)
        })
        .collect::<Result<Vec<_>>>()?;
    normalized.sort_by_key(|profile| profile.id);

    for (index, profile) in normalized.iter().enumerate() {
        for other in normalized.iter().skip(index + 1) {
            ensure_profiles_do_not_overlap(profile, other)?;
        }
    }
    Ok(normalized)
}

pub fn apply_profiles(profiles: Vec<ProtectionProfile>) -> Result<usize> {
    let _transaction_lock = acquire_transaction_lock()?;
    ensure_environment()?;
    let applied = load_all_states()?;
    let profiles = validate_profiles_with_applied(profiles, &applied)?;

    // Build every base module and render every deny module before the first host mutation. This
    // catches configuration and compiler failures without leaving a partially reconciled set.
    let prepared = profiles
        .into_iter()
        .map(PreparedProfile::new)
        .collect::<Result<Vec<_>>>()?;

    for item in &prepared {
        let previous = load_state_optional(item.profile.id)?;
        preflight_install(&item.profile, previous.as_ref())?;
    }

    let mut completed: Vec<(ProtectionProfile, Option<ProtectionProfile>)> = Vec::new();
    let mut changed = 0;
    for item in &prepared {
        let previous = load_state_optional(item.profile.id)?;
        if previous.as_ref() == Some(&item.profile) && profile_is_observed(&item.profile)? {
            diagnostics::info(
                "cli.apply",
                format_args!("profile {} is already applied", item.profile.id),
            );
            continue;
        }

        if let Err(error) = apply_prepared_transaction(item, previous.as_ref()) {
            let rollback_error = rollback_completed(&completed).err();
            if let Some(rollback_error) = rollback_error {
                return Err(error.context(format!(
                    "Rolling back earlier profiles also failed: {rollback_error:#}"
                )));
            }
            return Err(error);
        }
        completed.push((item.profile.clone(), previous));
        changed += 1;
    }

    Ok(changed)
}

pub fn remove_profile(id: Uuid) -> Result<bool> {
    let _transaction_lock = acquire_transaction_lock()?;
    ensure_recovery_environment()?;
    let Some(profile) = load_state_optional(id)? else {
        return Ok(false);
    };
    teardown(&profile)?;
    remove_state(id)?;
    Ok(true)
}

pub struct ProfileStatus {
    pub id: Uuid,
    pub name: String,
    pub state: &'static str,
}

#[derive(Debug, Clone)]
pub struct SupervisionProfile {
    pub profile: ProtectionProfile,
    pub applied: bool,
    pub desired: bool,
}

pub fn supervision_profiles(desired: Vec<ProtectionProfile>) -> Result<Vec<SupervisionProfile>> {
    let _transaction_lock = acquire_transaction_lock()?;
    ensure_state_directory()?;
    let applied = load_all_states()?;
    let desired = validate_profiles_with_applied(desired, &applied)?;
    Ok(merge_supervision_profiles(desired, applied))
}

fn merge_supervision_profiles(
    desired: Vec<ProtectionProfile>,
    applied: Vec<ProtectionProfile>,
) -> Vec<SupervisionProfile> {
    let mut profiles = applied
        .into_iter()
        .map(|profile| SupervisionProfile {
            profile,
            applied: true,
            desired: false,
        })
        .collect::<Vec<_>>();

    for profile in desired {
        if let Some(item) = profiles
            .iter_mut()
            .find(|item| item.profile.id == profile.id && item.profile == profile)
        {
            item.desired = true;
        } else {
            profiles.push(SupervisionProfile {
                profile,
                applied: false,
                desired: true,
            });
        }
    }
    profiles.sort_by(|left, right| {
        left.profile
            .id
            .cmp(&right.profile.id)
            .then_with(|| right.applied.cmp(&left.applied))
    });
    profiles
}

pub fn status(desired: Vec<ProtectionProfile>) -> Result<(Vec<ProfileStatus>, bool)> {
    let _transaction_lock = acquire_transaction_lock()?;
    ensure_status_environment()?;
    ensure_state_directory()?;
    let applied = load_all_states()?;
    let desired = validate_profiles_with_applied(desired, &applied)?;
    let mut result = Vec::new();
    let mut converged = true;

    for profile in &desired {
        let state = match applied.iter().find(|item| item.id == profile.id) {
            None => "not-applied",
            Some(snapshot) if snapshot != profile => "configuration-drift",
            Some(_) if !profile_is_observed(profile)? => "system-drift",
            Some(_) => "applied",
        };
        converged &= state == "applied";
        result.push(ProfileStatus {
            id: profile.id,
            name: profile.name.clone(),
            state,
        });
    }

    for profile in applied {
        if desired.iter().any(|item| item.id == profile.id) {
            continue;
        }
        converged = false;
        result.push(ProfileStatus {
            id: profile.id,
            name: profile.name,
            state: "installed-without-config",
        });
    }
    result.sort_by_key(|item| item.id);
    Ok((result, converged))
}

fn acquire_transaction_lock() -> Result<File> {
    diagnostics::debug("cli", format_args!("acquiring the transaction lock"));
    fs::create_dir_all(RUNTIME_DIR)?;
    let runtime_metadata = fs::symlink_metadata(RUNTIME_DIR)?;
    if runtime_metadata.file_type().is_symlink()
        || !runtime_metadata.is_dir()
        || runtime_metadata.uid() != 0
        || runtime_metadata.permissions().mode() & 0o022 != 0
    {
        bail!("The Microvisor runtime directory must be a root-owned directory, not a symlink");
    }
    fs::set_permissions(RUNTIME_DIR, fs::Permissions::from_mode(0o700))?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(LOCK_FILE)
        .context("Could not open the Microvisor transaction lock")?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("The Microvisor transaction lock has unsafe ownership or permissions");
    }
    fs::set_permissions(LOCK_FILE, fs::Permissions::from_mode(0o600))?;
    // flock serializes module, fcontext, relabel, state-save, and rollback operations across every
    // CLI process. Releasing the File at function exit releases the lock.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if result != 0 {
        return Err(io::Error::last_os_error())
            .context("Could not lock Microvisor policy transactions");
    }
    diagnostics::debug("cli", format_args!("transaction lock acquired"));
    Ok(file)
}

fn ensure_environment() -> Result<()> {
    diagnostics::debug("cli", format_args!("checking the SELinux environment"));
    for command in [
        "checkmodule",
        "getenforce",
        "m4",
        "restorecon",
        "rpm",
        "semanage",
        "semodule",
        "semodule_package",
    ] {
        find_command(command)
            .with_context(|| format!("Required command '{command}' is not installed"))?;
    }
    policy_source_files()?;

    ensure_selinux_userspace_version()?;

    let mut command = trusted_command("getenforce")?;
    let enforcement = checked(&mut command)?;
    let enforcement = String::from_utf8_lossy(&enforcement.stdout);
    diagnostics::info(
        "cli",
        format_args!("SELinux enforcement state is {:?}", enforcement.trim()),
    );
    if enforcement.trim() == "Disabled" {
        bail!("SELinux is disabled");
    }

    ensure_state_directory()?;
    Ok(())
}

fn ensure_status_environment() -> Result<()> {
    for command in ["semanage", "semodule"] {
        find_command(command)
            .with_context(|| format!("Required command '{command}' is not installed"))?;
    }
    Ok(())
}

fn ensure_recovery_environment() -> Result<()> {
    for command in ["getenforce", "restorecon", "semanage", "semodule"] {
        find_command(command)
            .with_context(|| format!("Required recovery command '{command}' is not installed"))?;
    }
    let mut command = trusted_command("getenforce")?;
    let enforcement = checked(&mut command)?;
    if String::from_utf8_lossy(&enforcement.stdout).trim() == "Disabled" {
        bail!("SELinux is disabled");
    }
    ensure_state_directory()
}

fn ensure_state_directory() -> Result<()> {
    fs::create_dir_all(STATE_DIR)?;
    for directory in [STATE_ROOT, STATE_DIR] {
        let metadata = fs::symlink_metadata(directory)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.permissions().mode() & 0o022 != 0
        {
            bail!(
                "The Microvisor state path {directory} must be a root-owned directory, not a symlink"
            );
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn ensure_selinux_userspace_version() -> Result<()> {
    // semodule has no version option on Fedora. Query libsepol because it implements the CIL
    // parser, including the deny syntax that must be available before any policy mutation.
    let mut command = trusted_command("rpm")?;
    let output = checked(command.args(["-q", "--qf", "%{VERSION}\n", "libsepol"]))?;
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
        "cli",
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

#[derive(Debug, Eq, PartialEq)]
struct PolicyBuildConfig {
    policy_type: String,
    distribution: Option<String>,
    direct_initrc: bool,
    ubac: bool,
    mls_sensitivities: u32,
    mls_categories: u32,
    mcs_categories: u32,
}

impl Default for PolicyBuildConfig {
    fn default() -> Self {
        Self {
            policy_type: "standard".into(),
            distribution: None,
            direct_initrc: false,
            ubac: false,
            mls_sensitivities: 16,
            mls_categories: 1024,
            mcs_categories: 1024,
        }
    }
}

impl PolicyBuildConfig {
    fn uses_mls_symbols(&self) -> bool {
        matches!(self.policy_type.as_str(), "mcs" | "mls")
    }

    fn m4_arguments(&self) -> Vec<String> {
        let mut arguments = Vec::new();
        match self.policy_type.as_str() {
            "mcs" => arguments.extend(["-D".into(), "enable_mcs".into()]),
            "mls" => arguments.extend(["-D".into(), "enable_mls".into()]),
            _ => {}
        }
        if let Some(distribution) = &self.distribution {
            arguments.extend(["-D".into(), format!("distro_{distribution}")]);
        }
        if self.direct_initrc {
            arguments.extend(["-D".into(), "direct_sysadm_daemon".into()]);
        }
        if self.ubac {
            arguments.extend(["-D".into(), "enable_ubac".into()]);
        }
        arguments.extend([
            "-D".into(),
            "hide_broken_symptoms".into(),
            "-D".into(),
            format!("mls_num_sens={}", self.mls_sensitivities),
            "-D".into(),
            format!("mls_num_cats={}", self.mls_categories),
            "-D".into(),
            format!("mcs_num_cats={}", self.mcs_categories),
        ]);
        arguments
    }
}

struct PolicySources {
    support: Vec<PathBuf>,
    interfaces: Vec<PathBuf>,
    build_config: PathBuf,
}

fn policy_source_files() -> Result<PolicySources> {
    // M4 sources influence the policy loaded by a root process, so they are executable input in
    // the security model. Accept only bounded files below the root-controlled package tree.
    let include = Path::new(POLICY_INCLUDE_DIR);
    validate_policy_directory(include)?;

    let support_directory = include.join("support");
    validate_policy_directory(&support_directory)?;
    let support = collect_policy_files(&support_directory, "spt")?;
    if support.is_empty() {
        bail!("No SELinux reference-policy support files were found");
    }

    let mut interfaces = Vec::new();
    let mut layers = fs::read_dir(include)?.collect::<io::Result<Vec<_>>>()?;
    layers.sort_by_key(|entry| entry.file_name());
    for layer in layers {
        if layer.file_name() == "support" {
            continue;
        }
        let metadata = fs::symlink_metadata(layer.path())?;
        if !metadata.is_dir() {
            continue;
        }
        validate_policy_directory(&layer.path())?;
        interfaces.extend(collect_policy_files(&layer.path(), "if")?);
    }
    if interfaces.is_empty() {
        bail!("No SELinux reference-policy interfaces were found");
    }
    if support.len() + interfaces.len() > MAX_POLICY_SOURCE_FILES {
        bail!("The SELinux reference-policy source set is unexpectedly large");
    }

    let build_config = include.join("build.conf");
    validate_policy_file(&build_config)?;
    Ok(PolicySources {
        support,
        interfaces,
        build_config,
    })
}

fn collect_policy_files(directory: &Path, extension: &str) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) != Some(extension) {
            continue;
        }
        validate_policy_file(&path)?;
        files.push(path);
    }
    files.sort();
    Ok(files)
}

fn validate_policy_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "Could not inspect SELinux policy directory {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!(
            "SELinux policy directory {} must be root-owned and not writable by group or other users",
            path.display()
        );
    }
    Ok(())
}

fn validate_policy_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("Could not inspect SELinux policy source {}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != 0
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.len() > MAX_POLICY_SOURCE_SIZE
    {
        bail!(
            "SELinux policy source {} has unsafe ownership, mode, type, or size",
            path.display()
        );
    }
    Ok(())
}

fn read_policy_build_config(path: &Path) -> Result<PolicyBuildConfig> {
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "Could not read SELinux build configuration {}",
            path.display()
        )
    })?;
    parse_policy_build_config(&text)
}

fn parse_policy_build_config(text: &str) -> Result<PolicyBuildConfig> {
    let mut config = PolicyBuildConfig::default();
    for original_line in text.lines() {
        let mut line = original_line.split('#').next().unwrap_or_default().trim();
        if let Some(rest) = line.strip_prefix("override ") {
            line = rest.trim_start();
        }
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = split_make_assignment(line) else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "TYPE" => {
                if !matches!(value, "standard" | "mcs" | "mls") {
                    bail!("Unsupported SELinux policy type '{value}'");
                }
                config.policy_type = value.into();
            }
            "DISTRO" => {
                validate_build_token(value, "SELinux policy distribution")?;
                config.distribution = (!value.is_empty()).then(|| value.to_owned());
            }
            "DIRECT_INITRC" => config.direct_initrc = parse_yes_no(value, key)?,
            "UBAC" => config.ubac = parse_yes_no(value, key)?,
            "MLS_SENS" => config.mls_sensitivities = parse_build_number(value, key)?,
            "MLS_CATS" => config.mls_categories = parse_build_number(value, key)?,
            "MCS_CATS" => config.mcs_categories = parse_build_number(value, key)?,
            _ => {}
        }
    }
    Ok(config)
}

fn split_make_assignment(line: &str) -> Option<(&str, &str)> {
    for operator in [":=", "?=", "="] {
        if let Some((key, value)) = line.split_once(operator) {
            return Some((key, value));
        }
    }
    None
}

fn validate_build_token(value: &str, label: &str) -> Result<()> {
    if value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        bail!("{label} contains unsupported characters");
    }
    Ok(())
}

fn parse_yes_no(value: &str, key: &str) -> Result<bool> {
    match value {
        "y" => Ok(true),
        "n" => Ok(false),
        _ => bail!("SELinux build setting {key} must be 'y' or 'n'"),
    }
}

fn parse_build_number(value: &str, key: &str) -> Result<u32> {
    let number = value
        .parse::<u32>()
        .with_context(|| format!("SELinux build setting {key} must be a number"))?;
    if number == 0 || number > 65_536 {
        bail!("SELinux build setting {key} is outside the supported range");
    }
    Ok(number)
}

fn compile_type_enforcement(work: &Path, module: &str) -> Result<()> {
    // Reproduce the reference-policy compiler stages with explicit argv and private files. Keeping
    // each stage here avoids executing Make or a shell while preserving the installed interfaces.
    let sources = policy_source_files()?;
    let config = read_policy_build_config(&sources.build_config)?;
    let interface_error = work.join("iferror.m4");
    write_private_file(&interface_error, b"ifdef(`__if_error',`m4exit(1)')\n")?;

    let raw_interfaces = work.join("all_interfaces.raw");
    let mut m4 = trusted_command("m4")?;
    m4.args(&sources.support)
        .args(&sources.interfaces)
        .arg(&interface_error);
    checked_to_file(&mut m4, &raw_interfaces)
        .context("Could not expand SELinux reference-policy interfaces")?;
    let expanded_interfaces = read_bounded_generated_file(&raw_interfaces)?;
    let expanded_interfaces = String::from_utf8(expanded_interfaces)
        .context("SELinux reference-policy interfaces are not valid UTF-8")?
        .replace("dollarsstar", "$*");
    let all_interfaces = work.join("all_interfaces.conf");
    write_private_file(
        &all_interfaces,
        format!("divert(-1)\n{expanded_interfaces}\ndivert\n").as_bytes(),
    )?;

    let te = work.join(format!("{module}.te"));
    let expanded_te = work.join(format!("{module}.expanded"));
    let mut m4 = trusted_command("m4")?;
    m4.args(config.m4_arguments())
        .arg("-s")
        .args(&sources.support)
        .arg(&all_interfaces)
        .arg(&te);
    checked_to_file(&mut m4, &expanded_te)
        .context("Could not expand the SELinux type-enforcement module")?;

    let module_file = work.join(format!("{module}.mod"));
    let mut checkmodule = trusted_command("checkmodule")?;
    checkmodule.arg("-m");
    if config.uses_mls_symbols() {
        checkmodule.arg("-M");
    }
    checked(checkmodule.arg(&expanded_te).arg("-o").arg(&module_file))
        .context("Could not compile the SELinux type-enforcement module")?;

    let package = work.join(format!("{module}.pp"));
    let mut semodule_package = trusted_command("semodule_package")?;
    checked(
        semodule_package
            .arg("-o")
            .arg(package)
            .arg("-m")
            .arg(module_file),
    )
    .context("Could not package the SELinux type-enforcement module")?;
    Ok(())
}

fn checked_to_file(command: &mut Command, path: &Path) -> Result<()> {
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    command.stdout(Stdio::from(output));
    checked(command)?;
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_GENERATED_POLICY_SIZE {
        bail!("Generated SELinux policy exceeds the 64 MiB safety limit");
    }
    Ok(())
}

fn read_bounded_generated_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut data = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_GENERATED_POLICY_SIZE + 1)
        .read_to_end(&mut data)?;
    if data.len() as u64 > MAX_GENERATED_POLICY_SIZE {
        bail!("Generated SELinux policy exceeds the 64 MiB safety limit");
    }
    Ok(data)
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn apply_prepared_transaction(
    prepared: &PreparedProfile,
    previous: Option<&ProtectionProfile>,
) -> Result<()> {
    let profile = &prepared.profile;
    if let Some(old) = previous {
        if let Err(error) = teardown(old) {
            let recovery = teardown(old)
                .and_then(|_| PreparedProfile::new(old.clone()))
                .and_then(|old_prepared| install_prepared(&old_prepared))
                .and_then(|_| save_state(old));
            return match recovery {
                Ok(()) => Err(error.context(
                    "Could not remove the previous policy; the previous snapshot was restored",
                )),
                Err(recovery_error) => Err(error.context(format!(
                    "Could not remove the previous policy, and recovery also failed: \
                     {recovery_error:#}"
                ))),
            };
        }
    }

    match install_prepared(prepared).and_then(|_| save_state(profile)) {
        Ok(()) => {
            diagnostics::info(
                "cli.transaction",
                format_args!("committed profile {}", profile.id),
            );
            Ok(())
        }
        Err(error) => {
            diagnostics::error(
                "cli.transaction",
                format_args!(
                    "apply failed for profile {}; starting cleanup and rollback: {error:#}",
                    profile.id
                ),
            );
            let _ = remove_temporary_state(profile.id);
            let cleanup_error = teardown(profile).err();
            let rollback_error = previous.and_then(|old| {
                PreparedProfile::new(old.clone())
                    .and_then(|old_prepared| install_prepared(&old_prepared))
                    .and_then(|_| save_state(old))
                    .err()
            });

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

fn rollback_completed(completed: &[(ProtectionProfile, Option<ProtectionProfile>)]) -> Result<()> {
    let mut failures = Vec::new();
    for (current, previous) in completed.iter().rev() {
        if let Err(error) = teardown(current).and_then(|_| remove_state(current.id)) {
            failures.push(format!("could not remove {}: {error:#}", current.id));
            continue;
        }
        if let Some(previous) = previous {
            let restored = PreparedProfile::new(previous.clone())
                .and_then(|prepared| install_prepared(&prepared))
                .and_then(|_| save_state(previous));
            if let Err(error) = restored {
                failures.push(format!("could not restore {}: {error:#}", previous.id));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!(failures.join("; "))
    }
}

pub fn normalize_profile(profile: ProtectionProfile) -> Result<ProtectionProfile> {
    normalize_profile_with_applied(profile, None)
}

fn normalize_profile_with_applied(
    mut profile: ProtectionProfile,
    applied: Option<&ProtectionProfile>,
) -> Result<ProtectionProfile> {
    policy::validate_profile(&profile)?;

    // Resolve symlinks before overlap checks and before generating file-context expressions.
    // All later commands receive these canonical paths as individual argv entries.
    let executable = match applied.filter(|item| item.executable == profile.executable) {
        Some(item) => item.executable.clone(),
        None => fs::canonicalize(&profile.executable)
            .with_context(|| format!("Could not resolve {}", profile.executable.display()))?,
    };
    if !executable.is_file() {
        bail!("{} is not a regular file", executable.display());
    }
    if executable.metadata()?.permissions().mode() & 0o111 == 0 {
        bail!("{} is not executable", executable.display());
    }

    let mut directories = Vec::with_capacity(profile.data_directories.len());
    for directory in &profile.data_directories {
        if let Some(resolved) = applied
            .and_then(|item| item.data_directories.iter().find(|path| *path == directory))
            .cloned()
        {
            directories.push(resolved);
            continue;
        }
        let resolved = fs::canonicalize(directory)
            .with_context(|| format!("Could not resolve {}", directory.display()))?;
        let metadata = fs::metadata(&resolved)
            .with_context(|| format!("Could not inspect {}", resolved.display()))?;
        if !metadata.is_dir() {
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
    if directories.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("Protected directories resolve to the same canonical path");
    }

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

fn preflight_install(
    profile: &ProtectionProfile,
    previous: Option<&ProtectionProfile>,
) -> Result<()> {
    ensure_no_profile_conflicts(profile)?;
    let ids = profile.identifiers();
    if previous.is_none() {
        ensure_module_absent(&ids.module)?;
        ensure_module_absent(&ids.deny_module)?;
    }

    let executable_regex = policy::selinux_path_regex(&profile.executable)?;
    let previous_executable_regex = previous
        .map(|item| policy::selinux_path_regex(&item.executable))
        .transpose()?;
    if previous_executable_regex.as_deref() != Some(&executable_regex) {
        ensure_fcontext_absent(&executable_regex)?;
    }
    for directory in &profile.data_directories {
        let regex = policy::recursive_directory_regex(directory)?;
        let owned_by_previous = previous.is_some_and(|item| {
            item.data_directories
                .iter()
                .filter_map(|path| policy::recursive_directory_regex(path).ok())
                .any(|previous_regex| previous_regex == regex)
        });
        if !owned_by_previous {
            ensure_fcontext_absent(&regex)?;
        }
    }
    diagnostics::debug(
        "cli.transaction",
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
        let data = read_state_file(&entry.path())?;
        let existing = deserialize_state(&data)
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

fn ensure_profiles_do_not_overlap(
    profile: &ProtectionProfile,
    other: &ProtectionProfile,
) -> Result<()> {
    if profile.executable == other.executable {
        bail!(
            "Profiles '{}' and '{}' use the same executable {}",
            profile.name,
            other.name,
            profile.executable.display()
        );
    }
    for directory in &profile.data_directories {
        for other_directory in &other.data_directories {
            if paths_overlap(directory, other_directory) {
                bail!(
                    "Profiles '{}' and '{}' have overlapping data paths {} and {}",
                    profile.name,
                    other.name,
                    directory.display(),
                    other_directory.display()
                );
            }
        }
        if other.executable.starts_with(directory) {
            bail!(
                "Profile '{}' contains the executable managed by '{}'",
                profile.name,
                other.name
            );
        }
    }
    for other_directory in &other.data_directories {
        if profile.executable.starts_with(other_directory) {
            bail!(
                "Profile '{}' contains the executable managed by '{}'",
                other.name,
                profile.name
            );
        }
    }
    Ok(())
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

fn profile_is_observed(profile: &ProtectionProfile) -> Result<bool> {
    let ids = profile.identifiers();
    if !module_exists(&ids.module)? || !module_exists(&ids.deny_module)? {
        return Ok(false);
    }
    if !fcontext_rule_exists(&policy::selinux_path_regex(&profile.executable)?)? {
        return Ok(false);
    }
    for directory in &profile.data_directories {
        if !fcontext_rule_exists(&policy::recursive_directory_regex(directory)?)? {
            return Ok(false);
        }
    }
    Ok(true)
}

struct PreparedProfile {
    profile: ProtectionProfile,
    work: TempDir,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppliedState {
    state_schema_version: u32,
    profile: ProtectionProfile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyAppliedProfile {
    id: Uuid,
    name: String,
    executable: PathBuf,
    data_directories: Vec<PathBuf>,
    launch_domain: String,
    launch_role: String,
    block_ptrace: bool,
    block_fd_use: bool,
    applied: bool,
}

impl From<LegacyAppliedProfile> for ProtectionProfile {
    fn from(legacy: LegacyAppliedProfile) -> Self {
        let _was_applied = legacy.applied;
        Self {
            schema_version: crate::model::PROFILE_SCHEMA_VERSION,
            id: legacy.id,
            name: legacy.name,
            executable: legacy.executable,
            data_directories: legacy.data_directories,
            launch_domain: legacy.launch_domain,
            launch_role: legacy.launch_role,
            block_ptrace: legacy.block_ptrace,
            block_fd_use: legacy.block_fd_use,
        }
    }
}

impl PreparedProfile {
    fn new(profile: ProtectionProfile) -> Result<Self> {
        let ids = profile.identifiers();
        diagnostics::debug("cli.apply", format_args!("building module {}", ids.module));
        let work = TempDir::new_in(RUNTIME_DIR)
            .context("Could not create a root-only policy build directory")?;
        fs::write(
            work.path().join(format!("{}.te", ids.module)),
            policy::render_type_enforcement(&profile)?,
        )?;
        fs::write(
            work.path().join(format!("{}.cil", ids.deny_module)),
            policy::render_deny_cil(&profile)?,
        )?;

        compile_type_enforcement(work.path(), &ids.module)?;
        diagnostics::debug("cli.apply", format_args!("compiled module {}", ids.module));
        Ok(Self { profile, work })
    }
}

fn install_prepared(prepared: &PreparedProfile) -> Result<()> {
    let profile = &prepared.profile;
    let ids = profile.identifiers();

    // Install the base types before assigning them to files. The deny module is deliberately
    // installed only after every requested path has been relabeled successfully.
    let mut semodule = trusted_command("semodule")?;
    checked(
        semodule
            .arg("-i")
            .arg(prepared.work.path().join(format!("{}.pp", ids.module))),
    )
    .context("Could not install the SELinux type-enforcement module")?;
    diagnostics::info("cli.apply", format_args!("installed module {}", ids.module));

    add_file_context(&profile.executable, &ids.exec_type, true)?;
    let mut restorecon = trusted_command("restorecon")?;
    checked(restorecon.arg("-v").arg(&profile.executable))
        .context("Could not label the application executable")?;
    diagnostics::debug(
        "cli.apply",
        format_args!("labeled the executable for profile {}", profile.id),
    );

    for (index, directory) in profile.data_directories.iter().enumerate() {
        add_file_context(directory, &ids.data_type, false)?;
        let mut restorecon = trusted_command("restorecon")?;
        checked(restorecon.arg("-RFv").arg(directory))
            .with_context(|| format!("Could not label {}", directory.display()))?;
        diagnostics::debug(
            "cli.apply",
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
    let mut semodule = trusted_command("semodule")?;
    checked(
        semodule.arg("-i").arg(
            prepared
                .work
                .path()
                .join(format!("{}.cil", ids.deny_module)),
        ),
    )
    .context(
        "Could not install the SELinux deny module. SELinux userspace 3.6 or newer is required",
    )?;
    diagnostics::info(
        "cli.apply",
        format_args!("installed deny module {}", ids.deny_module),
    );

    Ok(())
}

fn teardown(profile: &ProtectionProfile) -> Result<()> {
    let ids = profile.identifiers();
    diagnostics::info(
        "cli.teardown",
        format_args!("tearing down profile {}", profile.id),
    );
    // Remove the deny complement first so recovery and relabeling are not themselves denied.
    remove_module_if_present(&ids.deny_module)?;
    diagnostics::debug(
        "cli.teardown",
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
        "cli.teardown",
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
        "cli.state",
        format_args!("saving root-side state for profile {}", profile.id),
    );
    let path = state_path(profile.id);
    let temporary = path.with_extension("json.tmp");
    // Write, secure, and atomically rename the snapshot only after policy application succeeds.
    // A future removal or rollback must never trust a partially written root-side profile.
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)?;
    let state = AppliedState {
        state_schema_version: STATE_SCHEMA_VERSION,
        profile: profile.clone(),
    };
    file.write_all(&serde_json::to_vec_pretty(&state)?)?;
    file.sync_all()?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
    fs::rename(&temporary, &path)?;
    File::open(STATE_DIR)?.sync_all()?;
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
    if !path.try_exists()? {
        return Ok(None);
    }
    let data = read_state_file(&path)
        .with_context(|| format!("Could not read stored profile {}", path.display()))?;
    deserialize_state(&data).map(Some)
}

fn load_all_states() -> Result<Vec<ProtectionProfile>> {
    let mut profiles = Vec::new();
    for entry in fs::read_dir(STATE_DIR)? {
        let entry = entry?;
        if entry.path().extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let data = read_state_file(&entry.path())?;
        profiles
            .push(deserialize_state(&data).with_context(|| {
                format!("Stored profile {} is invalid", entry.path().display())
            })?);
    }
    profiles.sort_by_key(|profile: &ProtectionProfile| profile.id);
    Ok(profiles)
}

fn deserialize_state(data: &[u8]) -> Result<ProtectionProfile> {
    match serde_json::from_slice::<AppliedState>(data) {
        Ok(state) => {
            if state.state_schema_version != STATE_SCHEMA_VERSION {
                bail!(
                    "Unsupported applied-state schema version {}",
                    state.state_schema_version
                );
            }
            policy::validate_profile(&state.profile)?;
            Ok(state.profile)
        }
        Err(current_error) => {
            let legacy: LegacyAppliedProfile = serde_json::from_slice(data).with_context(|| {
                format!("Invalid current state ({current_error}) and invalid legacy state")
            })?;
            let profile = ProtectionProfile::from(legacy);
            policy::validate_profile(&profile)?;
            Ok(profile)
        }
    }
}

fn read_state_file(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;

    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        bail!(
            "Stored profile {} has unsafe type, ownership, links, or permissions",
            path.display()
        );
    }
    let mut data = Vec::new();
    std::io::Read::take(&mut file, (MAX_STATE_SIZE + 1) as u64).read_to_end(&mut data)?;
    if data.len() > MAX_STATE_SIZE {
        bail!("Stored profile {} exceeds the 1 MiB limit", path.display());
    }
    Ok(data)
}

fn remove_state(id: Uuid) -> Result<()> {
    let path = state_path(id);
    if path.exists() {
        fs::remove_file(path)?;
        diagnostics::debug(
            "cli.state",
            format_args!("removed root-side state for profile {id}"),
        );
    }
    Ok(())
}

fn checked(command: &mut Command) -> Result<Output> {
    let program = command.get_program().to_string_lossy().into_owned();
    diagnostics::debug("cli.command", format_args!("executing {program}"));
    let output = command.output()?;
    if !output.status.success() {
        diagnostics::error(
            "cli.command",
            format_args!("{program} exited with {}", output.status),
        );
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        bail!(if stderr.is_empty() { stdout } else { stderr });
    }
    diagnostics::debug("cli.command", format_args!("{program} exited successfully"));
    Ok(output)
}

pub(crate) fn trusted_command(command: &str) -> Result<Command> {
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
        if let Ok(metadata) = candidate.metadata() {
            let mode = metadata.permissions().mode();
            if metadata.is_file() && metadata.uid() == 0 && mode & 0o111 != 0 && mode & 0o022 == 0 {
                return Ok(candidate);
            }
        }
    }
    bail!("Command not found")
}

#[cfg(test)]
mod tests {
    use super::{
        AppliedState, PolicyBuildConfig, STATE_SCHEMA_VERSION, deserialize_state,
        merge_supervision_profiles, normalize_profile_with_applied, parse_major_minor,
        parse_policy_build_config, validate_profiles,
    };
    use crate::model::ProtectionProfile;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    use tempfile::TempDir;
    use uuid::Uuid;

    #[test]
    fn parses_fedora_libsepol_versions() {
        assert_eq!(parse_major_minor("3.6"), Some((3, 6)));
        assert_eq!(parse_major_minor("3.10"), Some((3, 10)));
        assert_eq!(parse_major_minor("3.10.1"), Some((3, 10)));
    }

    #[test]
    fn rejects_non_version_tokens() {
        assert_eq!(parse_major_minor("libsepol"), None);
        assert_eq!(parse_major_minor("3"), None);
    }

    #[test]
    fn parses_reference_policy_build_settings_without_make() {
        let config = parse_policy_build_config(
            r#"
                TYPE ?= mcs
                DISTRO ?= redhat
                DIRECT_INITRC ?= n
                override UBAC := n
                override MLS_SENS := 16
                override MLS_CATS := 1024
                override MCS_CATS := 2048
            "#,
        )
        .unwrap();
        assert_eq!(
            config,
            PolicyBuildConfig {
                policy_type: "mcs".into(),
                distribution: Some("redhat".into()),
                direct_initrc: false,
                ubac: false,
                mls_sensitivities: 16,
                mls_categories: 1024,
                mcs_categories: 2048,
            }
        );
        assert!(config.uses_mls_symbols());
        assert!(config.m4_arguments().contains(&"enable_mcs".into()));
        assert!(config.m4_arguments().contains(&"distro_redhat".into()));
    }

    #[test]
    fn rejects_unsafe_reference_policy_build_settings() {
        assert!(parse_policy_build_config("DISTRO ?= redhat;touch_bad").is_err());
        assert!(parse_policy_build_config("TYPE ?= unexpected").is_err());
        assert!(parse_policy_build_config("MCS_CATS ?= 0").is_err());
        assert!(parse_policy_build_config("UBAC ?= maybe").is_err());
    }

    #[test]
    fn rejects_conflicts_across_the_complete_profile_set() {
        let root = TempDir::new().unwrap();
        let bin = root.path().join("bin");
        let data = root.path().join("data/application");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&data).unwrap();
        let executable = bin.join("application");
        fs::write(&executable, b"test").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();

        let mut first = ProtectionProfile::new();
        first.id = Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
        first.name = "First".into();
        first.executable = executable.clone();
        first.data_directories = vec![data.clone()];

        let mut second = first.clone();
        second.id = Uuid::parse_str("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee").unwrap();
        second.name = "Second".into();
        assert!(validate_profiles(vec![first.clone(), second.clone()]).is_err());

        let second_executable = bin.join("other-application");
        fs::write(&second_executable, b"test").unwrap();
        fs::set_permissions(&second_executable, fs::Permissions::from_mode(0o755)).unwrap();
        let nested = data.join("nested");
        fs::create_dir(&nested).unwrap();
        second.executable = second_executable;
        second.data_directories = vec![nested];
        assert!(validate_profiles(vec![first, second]).is_err());
    }

    #[test]
    fn rejects_two_paths_resolving_to_the_same_directory() {
        let root = TempDir::new().unwrap();
        let bin = root.path().join("bin");
        let data = root.path().join("data/application");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&data).unwrap();
        let executable = bin.join("application");
        fs::write(&executable, b"test").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        let alias = root.path().join("data/alias");
        symlink(&data, &alias).unwrap();

        let mut profile = ProtectionProfile::new();
        profile.name = "Aliases".into();
        profile.executable = executable;
        profile.data_directories = vec![data, alias];
        assert!(validate_profiles(vec![profile]).is_err());
    }

    #[test]
    fn reuses_applied_data_paths_that_the_deny_module_hides() {
        let root = TempDir::new().unwrap();
        let bin = root.path().join("bin");
        fs::create_dir_all(&bin).unwrap();
        let executable = bin.join("application");
        fs::write(&executable, b"test").unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();

        let hidden_data = root.path().join("data/application");
        let mut applied = ProtectionProfile::new();
        applied.name = "Applied profile".into();
        applied.executable = executable;
        applied.data_directories = vec![hidden_data.clone()];

        let desired = applied.clone();
        assert_eq!(
            normalize_profile_with_applied(desired, Some(&applied)).unwrap(),
            applied
        );

        let mut changed = applied.clone();
        changed.data_directories = vec![root.path().join("data/changed")];
        assert!(normalize_profile_with_applied(changed, Some(&applied)).is_err());
    }

    #[test]
    fn reads_current_and_legacy_root_state() {
        let mut profile = ProtectionProfile::new();
        profile.id = Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
        profile.name = "State compatibility".into();
        profile.executable = "/opt/test/bin/application".into();
        profile.data_directories = vec!["/var/lib/test/application".into()];

        let current = serde_json::to_vec(&AppliedState {
            state_schema_version: STATE_SCHEMA_VERSION,
            profile: profile.clone(),
        })
        .unwrap();
        assert_eq!(deserialize_state(&current).unwrap(), profile);

        let legacy = br#"{
            "id":"11111111-2222-4333-8444-555555555555",
            "name":"State compatibility",
            "executable":"/opt/test/bin/application",
            "data_directories":["/var/lib/test/application"],
            "launch_domain":"unconfined_t",
            "launch_role":"unconfined_r",
            "block_ptrace":true,
            "block_fd_use":false,
            "applied":true
        }"#;
        assert_eq!(deserialize_state(legacy).unwrap(), profile);
    }

    #[test]
    fn supervision_keeps_applied_and_drifted_desired_profiles_distinct() {
        let mut applied = ProtectionProfile::new();
        applied.id = Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
        applied.name = "Applied".into();
        applied.executable = "/opt/test/bin/application".into();
        applied.data_directories = vec!["/var/lib/test/application".into()];

        let mut desired = applied.clone();
        desired.name = "Changed configuration".into();
        let rows = merge_supervision_profiles(vec![desired.clone()], vec![applied.clone()]);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].profile, applied);
        assert!(rows[0].applied);
        assert!(!rows[0].desired);
        assert_eq!(rows[1].profile, desired);
        assert!(!rows[1].applied);
        assert!(rows[1].desired);

        let rows = merge_supervision_profiles(vec![applied.clone()], vec![applied]);
        assert_eq!(rows.len(), 1);
        assert!(rows[0].applied && rows[0].desired);
    }
}
