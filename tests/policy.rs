use microvisor::{model::ProtectionProfile, policy};
use std::path::PathBuf;

fn example_profile() -> ProtectionProfile {
    let mut profile = ProtectionProfile::new();
    profile.name = "Google Chrome".into();
    profile.executable = PathBuf::from("/opt/google/chrome/chrome");
    profile.data_directories = vec![
        PathBuf::from("/home/test/.config/google-chrome"),
        PathBuf::from("/home/test/.cache/google-chrome"),
    ];
    profile
}

#[test]
fn generated_policy_has_allowlist_and_deny_complement() {
    let profile = example_profile();
    let ids = profile.identifiers();
    let cil = policy::render_deny_cil(&profile).unwrap();

    assert!(cil.contains(&format!(
        "(typeattributeset {} ({}))",
        ids.allowed_attribute, ids.app_type
    )));
    assert!(cil.contains(&format!(
        "(typeattributeset {} (not ({})))",
        ids.denied_attribute, ids.allowed_attribute
    )));
    assert!(cil.contains(&format!(
        "(deny {} {} (file (all)))",
        ids.denied_attribute, ids.data_type
    )));
    assert!(cil.contains(&format!(
        "(deny {} {} (chr_file (all)))",
        ids.denied_attribute, ids.data_type
    )));
    assert!(cil.contains(&format!(
        "(deny {} {} (blk_file (all)))",
        ids.denied_attribute, ids.data_type
    )));
    assert!(cil.contains("(process (ptrace))"));
}

#[test]
fn type_enforcement_transitions_from_configured_desktop_domain() {
    let profile = example_profile();
    let ids = profile.identifiers();
    let te = policy::render_type_enforcement(&profile).unwrap();

    assert!(te.contains(&format!(
        "domtrans_pattern(unconfined_t, {}, {})",
        ids.exec_type, ids.app_type
    )));
    assert!(te.contains(&format!("role unconfined_r types {};", ids.app_type)));
}

#[test]
fn path_regex_escapes_selinux_metacharacters() {
    let path = PathBuf::from("/home/test/.config/app+(stable)");
    let regex = policy::selinux_path_regex(&path).unwrap();
    assert_eq!(regex, "/home/test/\\.config/app\\+\\(stable\\)");
}

#[test]
fn root_directory_is_rejected() {
    let mut profile = example_profile();
    profile.data_directories = vec![PathBuf::from("/")];
    assert!(policy::validate_profile(&profile).is_err());
}

#[test]
fn broad_directory_is_rejected() {
    let mut profile = example_profile();
    profile.data_directories = vec![PathBuf::from("/home/test")];
    assert!(policy::validate_profile(&profile).is_err());
}

#[test]
fn launch_domain_and_role_suffixes_are_required() {
    let mut profile = example_profile();
    profile.launch_domain = "unconfined".into();
    assert!(policy::validate_profile(&profile).is_err());

    profile.launch_domain = "unconfined_t".into();
    profile.launch_role = "unconfined".into();
    assert!(policy::validate_profile(&profile).is_err());
}

#[test]
fn duplicate_directories_are_rejected() {
    let mut profile = example_profile();
    profile.data_directories = vec![
        PathBuf::from("/home/test/.config/google-chrome"),
        PathBuf::from("/home/test/.config/google-chrome"),
    ];
    assert!(policy::validate_profile(&profile).is_err());
}

#[test]
fn preview_contains_file_context_operations() {
    let profile = example_profile();
    let ids = profile.identifiers();
    let preview = policy::render_preview(&profile).unwrap();

    assert!(preview.contains(&format!("# {}.te", ids.module)));
    assert!(preview.contains("semanage fcontext -a -f f"));
    assert!(preview.contains("/home/test/\\.config/google-chrome(/.*)?"));
}
