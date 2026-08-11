use crate::{model::ProtectionProfile, policy};
use anyhow::{Context, Result, bail};
use serde_saphyr::options::MergeKeyPolicy;
use std::{
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
    },
    path::Path,
};

pub const DEFAULT_CONFIG_DIR: &str = "/etc/microvisor/profiles.d";
pub const MAX_PROFILE_SIZE: usize = 1024 * 1024;
pub const MAX_PROFILE_COUNT: usize = 256;

pub fn load_profiles(directory: &Path) -> Result<Vec<ProtectionProfile>> {
    validate_config_directory(directory)?;

    let mut paths = Vec::new();
    for entry in fs::read_dir(directory).with_context(|| {
        format!(
            "Could not read configuration directory {}",
            directory.display()
        )
    })? {
        let entry = entry?;
        if entry.path().extension() == Some(OsStr::new("yaml")) {
            paths.push(entry.path());
        }
    }
    paths.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });

    if paths.len() > MAX_PROFILE_COUNT {
        bail!(
            "Configuration contains {} profiles; the limit is {}",
            paths.len(),
            MAX_PROFILE_COUNT
        );
    }

    let mut profiles = Vec::with_capacity(paths.len());
    for path in paths {
        profiles.push(load_profile(&path)?);
    }
    ensure_unique_ids(&profiles)?;
    Ok(profiles)
}

fn validate_config_directory(directory: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("Could not inspect {}", directory.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!(
            "Configuration path {} must be a directory, not a symlink",
            directory.display()
        );
    }
    if metadata.uid() != 0 {
        bail!(
            "Configuration directory {} must be owned by root",
            directory.display()
        );
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "Configuration directory {} must not be writable by group or other users",
            directory.display()
        );
    }
    Ok(())
}

pub fn load_profile(path: &Path) -> Result<ProtectionProfile> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("Could not securely open {}", path.display()))?;
    validate_config_file(path, &file)?;

    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_PROFILE_SIZE + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Could not read {}", path.display()))?;
    if bytes.len() > MAX_PROFILE_SIZE {
        bail!(
            "Configuration file {} exceeds the 1 MiB limit",
            path.display()
        );
    }
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("Configuration file {} must be UTF-8", path.display()))?;
    parse_profile(text)
        .with_context(|| format!("Could not parse configuration file {}", path.display()))
}

fn validate_config_file(path: &Path, file: &File) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("Could not inspect {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "Configuration file {} must be a regular file",
            path.display()
        );
    }
    if metadata.nlink() != 1 {
        bail!(
            "Configuration file {} must not have hard links",
            path.display()
        );
    }
    if metadata.uid() != 0 {
        bail!(
            "Configuration file {} must be owned by root",
            path.display()
        );
    }
    if metadata.mode() & 0o022 != 0 {
        bail!(
            "Configuration file {} must not be writable by group or other users",
            path.display()
        );
    }
    Ok(())
}

fn ensure_unique_ids(profiles: &[ProtectionProfile]) -> Result<()> {
    let mut ids: Vec<_> = profiles.iter().map(|profile| profile.id).collect();
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        bail!("Configuration contains duplicate profile IDs");
    }
    Ok(())
}

fn parse_profile(text: &str) -> Result<ProtectionProfile> {
    reject_unsupported_yaml(text)?;
    let options = serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_events: 4_096,
            max_aliases: 0,
            max_anchors: 0,
            max_depth: 8,
            max_inclusion_depth: 0,
            max_documents: 1,
            max_nodes: 2_048,
            max_total_scalar_bytes: MAX_PROFILE_SIZE,
            max_total_comment_bytes: MAX_PROFILE_SIZE,
            max_merge_keys: 0,
        },
        merge_keys: MergeKeyPolicy::Error,
        strict_booleans: true,
    };
    let profile: ProtectionProfile = serde_saphyr::from_str_with_options(text, options)?;
    policy::validate_profile(&profile)?;
    Ok(profile)
}

// Microvisor deliberately accepts a small, auditable YAML subset. Strings containing these
// characters remain valid when quoted; outside quotes they could activate tags, anchors, aliases,
// merge keys, or extra stream documents that make privileged input harder to reason about.
fn reject_unsupported_yaml(text: &str) -> Result<()> {
    for (line_index, line) in text.lines().enumerate() {
        let mut single_quoted = false;
        let mut double_quoted = false;
        let mut escaped = false;
        let mut plain = String::with_capacity(line.len());

        let mut characters = line.chars().peekable();
        while let Some(character) = characters.next() {
            if double_quoted {
                if escaped {
                    escaped = false;
                } else if character == '\\' {
                    escaped = true;
                } else if character == '"' {
                    double_quoted = false;
                }
                plain.push(' ');
                continue;
            }
            if single_quoted {
                if character == '\'' {
                    if characters.peek() == Some(&'\'') {
                        characters.next();
                        plain.push(' ');
                    } else {
                        single_quoted = false;
                    }
                }
                plain.push(' ');
                continue;
            }
            match character {
                '#' => break,
                '"' => {
                    double_quoted = true;
                    plain.push(' ');
                }
                '\'' => {
                    single_quoted = true;
                    plain.push(' ');
                }
                '\t' => bail!("tabs are not allowed at line {}", line_index + 1),
                _ => plain.push(character),
            }
        }

        if single_quoted || double_quoted {
            bail!("unterminated quoted scalar at line {}", line_index + 1);
        }

        let trimmed = plain.trim();
        if trimmed == "---" || trimmed == "..." {
            bail!(
                "document stream markers are not allowed at line {}",
                line_index + 1
            );
        }
        if trimmed.contains("<<:") {
            bail!(
                "mapping merge keys are not allowed at line {}",
                line_index + 1
            );
        }
        if trimmed.contains(['!', '&', '*']) {
            bail!(
                "tags, anchors, and aliases are not allowed at line {}",
                line_index + 1
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_profile, reject_unsupported_yaml};

    const VALID: &str = "\
schema_version: 1
id: 11111111-2222-4333-8444-555555555555
name: Test application
executable: /opt/test/bin/application
data_directories:
  - /var/lib/test/application
launch_domain: unconfined_t
launch_role: unconfined_r
block_ptrace: true
block_fd_use: false
";

    #[test]
    fn rejects_yaml_indirection_features() {
        for yaml in [
            "name: &shared app\n",
            "name: *shared\n",
            "name: !include other.yaml\n",
            "<<: *defaults\n",
            "---\nname: app\n",
        ] {
            assert!(reject_unsupported_yaml(yaml).is_err(), "accepted {yaml:?}");
        }
    }

    #[test]
    fn permits_indicators_inside_quoted_strings_and_comments() {
        assert!(reject_unsupported_yaml("name: \"app ! & *\" # !tag\n").is_ok());
        assert!(reject_unsupported_yaml("name: 'Alice''s app'\n").is_ok());
    }

    #[test]
    fn parses_the_versioned_typed_schema() {
        let profile = parse_profile(VALID).unwrap();
        assert_eq!(profile.schema_version, 1);
        assert_eq!(profile.name, "Test application");
        assert!(profile.block_ptrace);
        assert!(!profile.block_fd_use);
    }

    #[test]
    fn rejects_unknown_and_duplicate_fields() {
        let unknown = format!("{VALID}unexpected: value\n");
        assert!(parse_profile(&unknown).is_err());

        let duplicate = VALID.replacen(
            "name: Test application",
            "name: First name\nname: Second name",
            1,
        );
        assert!(parse_profile(&duplicate).is_err());
    }

    #[test]
    fn rejects_unsupported_versions_and_ambiguous_booleans() {
        assert!(
            parse_profile(&VALID.replacen("schema_version: 1", "schema_version: 2", 1)).is_err()
        );
        assert!(
            parse_profile(&VALID.replacen("block_ptrace: true", "block_ptrace: yes", 1)).is_err()
        );
    }
}
