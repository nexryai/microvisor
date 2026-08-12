use anyhow::{Context, Result, bail};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub fn default_path(_id: Uuid) -> PathBuf {
    PathBuf::from("microvisor.yml")
}

pub fn render(id: Uuid) -> String {
    format!(
        r#"# Replace the name and absolute paths before installing as /etc/microvisor.yml.
schema_version: 1
profiles:
  - id: {id}
    name: Replace with application name
    executable: /absolute/path/to/application
    data_directories:
      - /absolute/path/to/application-data
    launch_domain: unconfined_t
    launch_role: unconfined_r
    block_ptrace: true
    block_fd_use: false
"#
    )
}

pub fn write_new(path: &Path, id: Uuid) -> Result<()> {
    if path.extension().and_then(|extension| extension.to_str()) != Some("yml") {
        bail!("Generated configuration file names must end with '.yml'");
    }

    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("Could not create configuration template {}", path.display()))?;
    let result = file
        .write_all(render(id).as_bytes())
        .and_then(|()| file.sync_all());
    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error)
            .with_context(|| format!("Could not write configuration template {}", path.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{default_path, render, write_new};
    use crate::config;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
    use tempfile::TempDir;
    use uuid::Uuid;

    const ID: &str = "11111111-2222-4333-8444-555555555555";

    #[test]
    fn renders_a_parseable_profile_with_the_requested_uuid() {
        let id = Uuid::parse_str(ID).unwrap();
        let text = render(id);
        let profiles = config::parse_config(&text).unwrap();
        assert_eq!(profiles[0].id, id);
        assert_eq!(profiles[0].schema_version, 1);
        assert!(profiles[0].block_ptrace);
        assert!(!profiles[0].block_fd_use);
        assert_eq!(default_path(id), PathBuf::from("microvisor.yml"));
    }

    #[test]
    fn creates_a_private_file_without_overwriting() {
        let root = TempDir::new().unwrap();
        let path = root.path().join("microvisor.yml");
        let id = Uuid::parse_str(ID).unwrap();

        write_new(&path, id).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), render(id));
        assert!(write_new(&path, Uuid::new_v4()).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), render(id));
    }

    #[test]
    fn requires_the_loader_visible_yaml_extension() {
        let root = TempDir::new().unwrap();
        assert!(write_new(&root.path().join("profile.yaml"), Uuid::new_v4()).is_err());
    }
}
