use anyhow::{Context, Result, bail};
use microvisor::diagnostics;
use microvisor::model::{HelperRequest, HelperResponse};
#[cfg(debug_assertions)]
use std::os::unix::fs::PermissionsExt;
use std::{
    env,
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const INSTALLED_HELPER_PATH: &str = "/usr/libexec/microvisor-helper";

pub fn invoke(request: &HelperRequest) -> Result<HelperResponse> {
    let (operation, id) = request_summary(request);
    let helper = helper_path();
    diagnostics::info(
        "helper-client",
        format_args!("starting privileged {operation} request for profile {id}"),
    );
    diagnostics::debug(
        "helper-client",
        format_args!("using privileged helper {}", helper.display()),
    );

    // Send the typed request over stdin and pass no profile values as command-line arguments.
    // This preserves the narrow Polkit entry point and avoids shell interpretation entirely.
    let mut child = Command::new("/usr/bin/pkexec")
        .arg(&helper)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Could not start pkexec")?;
    diagnostics::debug(
        "helper-client",
        format_args!("pkexec started with process id {}", child.id()),
    );

    let request = serde_json::to_vec(request)?;
    diagnostics::debug(
        "helper-client",
        format_args!("sending a {} byte request", request.len()),
    );
    child
        .stdin
        .take()
        .context("Could not open helper stdin")?
        .write_all(&request)
        .context("Could not send request to helper")?;

    let output = child.wait_with_output()?;
    diagnostics::info(
        "helper-client",
        format_args!(
            "privileged {operation} process exited with {}",
            output.status
        ),
    );
    let helper_diagnostics = String::from_utf8_lossy(&output.stderr);
    for line in helper_diagnostics.lines().filter(|line| !line.is_empty()) {
        diagnostics::debug("helper-client.child", format_args!("{line}"));
    }
    // Standard output is reserved for the machine-readable response. The helper writes
    // diagnostics to standard error so logging can never corrupt the protocol payload.
    if let Ok(response) = serde_json::from_slice::<HelperResponse>(&output.stdout) {
        diagnostics::info(
            "helper-client",
            format_args!(
                "privileged {operation} response for profile {id}: ok={}",
                response.ok
            ),
        );
        return Ok(response);
    }

    if !output.status.success() {
        let stderr = helper_diagnostics.trim().to_string();
        if stderr.is_empty() {
            bail!("The privileged operation was cancelled or failed");
        }
        bail!(stderr);
    }

    bail!("The helper returned an invalid response")
}

fn helper_path() -> PathBuf {
    let current_executable = env::current_exe().ok();
    select_helper_path(
        env::var_os("MICROVISOR_HELPER"),
        current_executable.as_deref(),
    )
}

fn select_helper_path(
    explicit_helper: Option<OsString>,
    current_executable: Option<&Path>,
) -> PathBuf {
    if let Some(explicit_helper) = explicit_helper {
        return explicit_helper.into();
    }

    // Sibling discovery is restricted to debug artifacts so installed release builds remain
    // pinned to the path covered by the packaged Polkit policy.
    #[cfg(debug_assertions)]
    if let Some(sibling) = current_executable
        .and_then(Path::parent)
        .map(|directory| directory.join("microvisor-helper"))
        .filter(|candidate| is_executable_file(candidate))
    {
        return sibling;
    }

    #[cfg(not(debug_assertions))]
    let _ = current_executable;

    PathBuf::from(INSTALLED_HELPER_PATH)
}

#[cfg(debug_assertions)]
fn is_executable_file(path: &Path) -> bool {
    path.metadata()
        .is_ok_and(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
}

fn request_summary(request: &HelperRequest) -> (&'static str, uuid::Uuid) {
    match request {
        HelperRequest::Apply { profile } => ("apply", profile.id),
        HelperRequest::Remove { id } => ("remove", *id),
    }
}

#[cfg(test)]
mod tests {
    use super::{INSTALLED_HELPER_PATH, select_helper_path};
    use std::{
        ffi::OsString,
        fs,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
    };

    #[test]
    fn explicit_helper_overrides_debug_sibling() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("microvisor");
        let sibling = directory.path().join("microvisor-helper");
        make_executable(&sibling);
        let explicit = PathBuf::from("/tmp/explicit-microvisor-helper");

        assert_eq!(
            select_helper_path(
                Some(OsString::from(explicit.as_os_str())),
                Some(&executable)
            ),
            explicit
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_build_uses_executable_sibling_helper() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("microvisor");
        let sibling = directory.path().join("microvisor-helper");
        make_executable(&sibling);

        assert_eq!(select_helper_path(None, Some(&executable)), sibling);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn debug_build_ignores_non_executable_sibling_helper() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("microvisor");
        let sibling = directory.path().join("microvisor-helper");
        fs::write(&sibling, b"not executable").unwrap();
        fs::set_permissions(&sibling, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            select_helper_path(None, Some(&executable)),
            PathBuf::from(INSTALLED_HELPER_PATH)
        );
    }

    fn make_executable(path: &Path) {
        fs::write(path, b"helper").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
}
