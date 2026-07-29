use anyhow::{Context, Result};
use directories::ProjectDirs;
use microvisor::diagnostics;
use microvisor::model::ProtectionProfile;
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

fn profiles_path() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("me.nexryai", "nexryai", "microvisor")
        .context("Could not locate the user configuration directory")?;
    Ok(dirs.config_dir().join("profiles.json"))
}

pub fn load_profiles() -> Result<Vec<ProtectionProfile>> {
    let path = profiles_path()?;
    if !path.exists() {
        diagnostics::debug(
            "storage",
            format_args!("profile store does not exist; using an empty profile list"),
        );
        return Ok(Vec::new());
    }
    diagnostics::debug("storage", format_args!("reading the local profile store"));
    let data = fs::read(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let profiles: Vec<ProtectionProfile> = serde_json::from_slice(&data)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    diagnostics::debug(
        "storage",
        format_args!("read {} local profile(s)", profiles.len()),
    );
    Ok(profiles)
}

pub fn save_profiles(profiles: &[ProtectionProfile]) -> Result<()> {
    diagnostics::info(
        "storage",
        format_args!("saving {} local profile(s)", profiles.len()),
    );
    let path = profiles_path()?;
    let parent = path.parent().context("Profiles path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("Could not create {}", parent.display()))?;

    let data = serde_json::to_vec_pretty(profiles)?;
    let temporary = path.with_extension("json.tmp");
    // Replace the complete store atomically so an interrupted GUI write cannot leave truncated
    // JSON. This user-owned copy is only UI state; privileged recovery trusts the root-owned copy.
    fs::write(&temporary, data)
        .with_context(|| format!("Could not write {}", temporary.display()))?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Could not secure {}", temporary.display()))?;
    fs::rename(&temporary, &path)
        .with_context(|| format!("Could not replace {}", path.display()))?;
    diagnostics::debug(
        "storage",
        format_args!("local profile store replaced atomically"),
    );
    Ok(())
}
