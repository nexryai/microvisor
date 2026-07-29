use anyhow::{Context, Result, bail};
use microvisor::diagnostics;
use microvisor::model::{HelperRequest, HelperResponse};
use std::{
    env,
    io::Write,
    process::{Command, Stdio},
};

pub fn invoke(request: &HelperRequest) -> Result<HelperResponse> {
    let (operation, id) = request_summary(request);
    let helper =
        env::var("MICROVISOR_HELPER").unwrap_or_else(|_| "/usr/libexec/microvisor-helper".into());
    diagnostics::info(
        "helper-client",
        format_args!("starting privileged {operation} request for profile {id}"),
    );
    diagnostics::debug(
        "helper-client",
        format_args!("using privileged helper {helper}"),
    );

    // Send the typed request over stdin and pass no profile values as command-line arguments.
    // This preserves the narrow Polkit entry point and avoids shell interpretation entirely.
    let mut child = Command::new("/usr/bin/pkexec")
        .arg(helper)
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

fn request_summary(request: &HelperRequest) -> (&'static str, uuid::Uuid) {
    match request {
        HelperRequest::Apply { profile } => ("apply", profile.id),
        HelperRequest::Remove { id } => ("remove", *id),
    }
}
