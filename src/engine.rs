use crate::{diagnostics, model::ProtectionProfile, policy};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::fd::AsRawFd,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;
use uuid::Uuid;

pub const STATE_DIR: &str = "/var/lib/microvisor/profiles";
const STATE_ROOT: &str = "/var/lib/microvisor";
const RUNTIME_DIR: &str = "/run/microvisor";
const LOCK_FILE: &str = "/run/microvisor/transaction.lock";
const POLICY_MAKEFILE: &str = "/usr/share/selinux/devel/Makefile";
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
    let mut normalized = profiles
        .into_iter()
        .map(normalize_profile)
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
    let profiles = validate_profiles(profiles)?;
    let _transaction_lock = acquire_transaction_lock()?;
    ensure_environment()?;

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

pub fn status(desired: Vec<ProtectionProfile>) -> Result<(Vec<ProfileStatus>, bool)> {
    let desired = validate_profiles(desired)?;
    let _transaction_lock = acquire_transaction_lock()?;
    ensure_status_environment()?;
    ensure_state_directory()?;
    let applied = load_all_states()?;
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
        "getenforce",
        "make",
        "restorecon",
        "rpm",
        "semanage",
        "semodule",
    ] {
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

pub fn normalize_profile(mut profile: ProtectionProfile) -> Result<ProtectionProfile> {
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

        let mut make = trusted_command("make")?;
        checked(
            make.current_dir(work.path())
                .arg("-f")
                .arg(POLICY_MAKEFILE)
                .arg(format!("{}.pp", ids.module)),
        )
        .context("Could not compile the SELinux type-enforcement module")?;
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
        AppliedState, STATE_SCHEMA_VERSION, deserialize_state, parse_major_minor, validate_profiles,
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
}
