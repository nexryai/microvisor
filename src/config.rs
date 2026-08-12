use crate::{
    model::{PROFILE_SCHEMA_VERSION, ProtectionProfile},
    policy,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_saphyr::options::MergeKeyPolicy;
use std::{
    fs::{File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub const DEFAULT_CONFIG_FILE: &str = "/etc/microvisor.yml";
pub const MAX_CONFIG_SIZE: usize = 1024 * 1024;
pub const MAX_PROFILE_COUNT: usize = 256;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    schema_version: u32,
    profiles: Vec<DesiredProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesiredProfile {
    id: Uuid,
    name: String,
    executable: PathBuf,
    data_directories: Vec<PathBuf>,
    launch_domain: String,
    launch_role: String,
    block_ptrace: bool,
    block_fd_use: bool,
}

impl From<DesiredProfile> for ProtectionProfile {
    fn from(profile: DesiredProfile) -> Self {
        Self {
            schema_version: PROFILE_SCHEMA_VERSION,
            id: profile.id,
            name: profile.name,
            executable: profile.executable,
            data_directories: profile.data_directories,
            launch_domain: profile.launch_domain,
            launch_role: profile.launch_role,
            block_ptrace: profile.block_ptrace,
            block_fd_use: profile.block_fd_use,
        }
    }
}

pub fn load_profiles(path: &Path) -> Result<Vec<ProtectionProfile>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("Could not securely open {}", path.display()))?;
    validate_config_file(path, &file)?;

    let mut bytes = Vec::new();
    file.by_ref()
        .take((MAX_CONFIG_SIZE + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("Could not read {}", path.display()))?;
    if bytes.len() > MAX_CONFIG_SIZE {
        bail!(
            "Configuration file {} exceeds the 1 MiB limit",
            path.display()
        );
    }
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("Configuration file {} must be UTF-8", path.display()))?;
    parse_config(text)
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

pub(crate) fn parse_config(text: &str) -> Result<Vec<ProtectionProfile>> {
    reject_unsupported_yaml(text)?;
    let options = serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_events: 16_384,
            max_aliases: 0,
            max_anchors: 0,
            max_depth: 10,
            max_inclusion_depth: 0,
            max_documents: 1,
            max_nodes: 8_192,
            max_total_scalar_bytes: MAX_CONFIG_SIZE,
            max_total_comment_bytes: MAX_CONFIG_SIZE,
            max_merge_keys: 0,
        },
        merge_keys: MergeKeyPolicy::Error,
        strict_booleans: true,
    };
    let configuration: Configuration = serde_saphyr::from_str_with_options(text, options)?;
    if configuration.schema_version != PROFILE_SCHEMA_VERSION {
        bail!(
            "Unsupported configuration schema version {}; expected {}",
            configuration.schema_version,
            PROFILE_SCHEMA_VERSION
        );
    }
    if configuration.profiles.len() > MAX_PROFILE_COUNT {
        bail!(
            "Configuration contains {} profiles; the limit is {}",
            configuration.profiles.len(),
            MAX_PROFILE_COUNT
        );
    }
    let profiles = configuration
        .profiles
        .into_iter()
        .map(ProtectionProfile::from)
        .collect::<Vec<_>>();
    for profile in &profiles {
        policy::validate_profile(profile)?;
    }
    ensure_unique_ids(&profiles)?;
    Ok(profiles)
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
    use super::{MAX_PROFILE_COUNT, parse_config, reject_unsupported_yaml};

    const VALID: &str = "\
schema_version: 1
profiles:
  - id: 11111111-2222-4333-8444-555555555555
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
            "name: !include other.yml\n",
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
    fn parses_the_versioned_document_and_profile_list() {
        let profiles = parse_config(VALID).unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].schema_version, 1);
        assert_eq!(profiles[0].name, "Test application");
        assert!(profiles[0].block_ptrace);
        assert!(!profiles[0].block_fd_use);
        assert!(
            parse_config("schema_version: 1\nprofiles: []\n")
                .unwrap()
                .is_empty()
        );
        assert!(
            parse_config(include_str!("../data/microvisor.yml"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn rejects_unknown_duplicate_and_per_profile_schema_fields() {
        assert!(parse_config(&format!("{VALID}unexpected: value\n")).is_err());
        assert!(parse_config(&VALID.replacen("profiles:", "profiles:\nprofiles:", 1)).is_err());
        assert!(
            parse_config(&VALID.replacen(
                "    name: Test application",
                "    schema_version: 1\n    name: Test application",
                1,
            ))
            .is_err()
        );
    }

    #[test]
    fn rejects_duplicate_ids_unsupported_versions_and_ambiguous_booleans() {
        let duplicate = format!(
            "{VALID}{}",
            VALID
                .lines()
                .skip(2)
                .map(|line| format!("{line}\n"))
                .collect::<String>()
        );
        assert!(parse_config(&duplicate).is_err());
        assert!(
            parse_config(&VALID.replacen("schema_version: 1", "schema_version: 2", 1)).is_err()
        );
        assert!(
            parse_config(&VALID.replacen("block_ptrace: true", "block_ptrace: yes", 1)).is_err()
        );
    }

    #[test]
    fn rejects_more_than_the_profile_limit() {
        let profile = VALID.lines().skip(2).collect::<Vec<_>>().join("\n");
        let text = format!(
            "schema_version: 1\nprofiles:\n{}",
            (0..=MAX_PROFILE_COUNT)
                .map(|index| profile.replace(
                    "11111111-2222-4333-8444-555555555555",
                    &format!("11111111-2222-4333-8444-{index:012}"),
                ))
                .collect::<Vec<_>>()
                .join("\n")
        );
        assert!(parse_config(&text).is_err());
    }
}
