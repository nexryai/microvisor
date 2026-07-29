use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtectionProfile {
    pub id: Uuid,
    pub name: String,
    pub executable: PathBuf,
    pub data_directories: Vec<PathBuf>,
    pub launch_domain: String,
    pub launch_role: String,
    pub block_ptrace: bool,
    pub block_fd_use: bool,
    pub applied: bool,
}

impl ProtectionProfile {
    pub fn new() -> Self {
        Self {
            id: Uuid::new_v4(),
            name: String::new(),
            executable: PathBuf::new(),
            data_directories: Vec::new(),
            launch_domain: "unconfined_t".into(),
            launch_role: "unconfined_r".into(),
            block_ptrace: true,
            block_fd_use: false,
            applied: false,
        }
    }

    pub fn identifiers(&self) -> PolicyIdentifiers {
        // Derive every policy identifier from the UUID, never from user-provided text. This keeps
        // generated identifiers valid and prevents profile names from becoming policy syntax.
        let compact = self.id.simple().to_string();
        let module = format!("microvisor_{compact}");

        PolicyIdentifiers {
            app_type: format!("{module}_t"),
            exec_type: format!("{module}_exec_t"),
            data_type: format!("{module}_data_t"),
            deny_module: format!("{module}_deny"),
            allowed_attribute: format!("{module}_allowed_subjects"),
            denied_attribute: format!("{module}_denied_subjects"),
            module,
        }
    }
}

impl Default for ProtectionProfile {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyIdentifiers {
    pub module: String,
    pub deny_module: String,
    pub app_type: String,
    pub exec_type: String,
    pub data_type: String,
    pub allowed_attribute: String,
    pub denied_attribute: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
// This enum is the complete GUI-to-root protocol. Keep it narrow and consider backward
// compatibility before changing any serialized field or variant.
pub enum HelperRequest {
    Apply { profile: ProtectionProfile },
    Remove { id: Uuid },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelperResponse {
    pub ok: bool,
    pub message: String,
}
