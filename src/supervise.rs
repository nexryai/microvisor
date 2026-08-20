use crate::{
    engine::{self, SupervisionProfile},
    policy,
};
use anyhow::{Context, Result, bail};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs,
    io::{self, Read},
    os::{
        fd::{AsRawFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const MAX_FCONTEXT_OUTPUT: u64 = 16 * 1024 * 1024;
const MAX_POLICY_OUTPUT: u64 = 16 * 1024 * 1024;
const MAX_POLICY_ERROR_OUTPUT: u64 = 64 * 1024;
const MAX_POLICY_RULES: usize = 20_000;
const MAX_DISPLAYED_POLICY_RULES: usize = 1_000;
const REFRESH_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum View {
    Processes,
    Executables,
    Rules,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProtectionKind {
    Microvisor,
    System,
    Unconfined,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessRow {
    pid: u32,
    uid: u32,
    command: String,
    executable: Option<PathBuf>,
    context: String,
    domain: String,
    kind: ProtectionKind,
    profile_index: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutableRow {
    path: PathBuf,
    label: String,
    domain: String,
    process_count: usize,
    kind: ProtectionKind,
    profile_index: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FcontextRule {
    pattern: String,
    selinux_type: String,
    kind: ProtectionKind,
    profile_index: Option<usize>,
}

#[derive(Debug, Default)]
struct FcontextSnapshot {
    executable_rules: Vec<FcontextRule>,
    paths_by_type: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AllowRule {
    target: String,
    object_class: String,
    permissions: Vec<String>,
    condition: Option<String>,
    extended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PolicyInspection {
    Rules {
        rules: Vec<AllowRule>,
        truncated: bool,
    },
    Unavailable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessDetail {
    process: ProcessRow,
    policy: PolicyInspection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum PathScope {
    Home,
    Etc,
    VarLib,
    VarLog,
    VarSpool,
    OtherVar,
}

const PATH_SCOPES: [(PathScope, &str); 6] = [
    (PathScope::Home, "Home directory contents"),
    (PathScope::Etc, "System configuration (/etc)"),
    (
        PathScope::VarLib,
        "Service and application state (/var/lib)",
    ),
    (PathScope::VarLog, "System and service logs (/var/log)"),
    (
        PathScope::VarSpool,
        "Queues, mail, and spool data (/var/spool)",
    ),
    (PathScope::OtherVar, "Other sensitive variable data (/var)"),
];

#[derive(Debug, Default, PartialEq, Eq)]
struct PermissionEvidence {
    unconditional: bool,
    conditional: bool,
    targets: BTreeSet<String>,
    patterns: BTreeSet<String>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ScopePermissions {
    read: PermissionEvidence,
    write: PermissionEvidence,
}

#[derive(Debug)]
struct Snapshot {
    enforcement: String,
    profiles: Vec<SupervisionProfile>,
    processes: Vec<ProcessRow>,
    executables: Vec<ExecutableRow>,
    rules: Vec<FcontextRule>,
    paths_by_type: BTreeMap<String, BTreeSet<String>>,
    rule_error: Option<String>,
}

#[derive(Debug)]
struct UiState {
    view: View,
    selected: [usize; 3],
    process_detail: Option<ProcessDetail>,
    detail_scroll: usize,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            view: View::Processes,
            selected: [0; 3],
            process_detail: None,
            detail_scroll: 0,
        }
    }
}

impl UiState {
    fn slot(&self) -> usize {
        match self.view {
            View::Processes => 0,
            View::Executables => 1,
            View::Rules => 2,
        }
    }

    fn selected(&self) -> usize {
        self.selected[self.slot()]
    }

    fn set_selected(&mut self, value: usize) {
        self.selected[self.slot()] = value;
    }
}

pub fn run(profiles: &[SupervisionProfile]) -> Result<()> {
    let mut snapshot = collect_snapshot(profiles.to_vec());
    let stdin = io::stdin();
    let stdout = io::stdout();
    if !is_terminal(stdin.as_raw_fd()) || !is_terminal(stdout.as_raw_fd()) {
        print_plain(&snapshot);
        return Ok(());
    }

    let mut terminal = Terminal::enter(stdin.as_raw_fd(), stdout.as_raw_fd())?;
    let mut state = UiState::default();
    let mut refreshed = Instant::now();
    terminal.draw(&render_frame(&snapshot, &state, terminal.size(), true))?;

    loop {
        if let Some(input) = terminal.read_key(Duration::from_millis(200), state.view)? {
            if state.process_detail.is_some() {
                match input {
                    Key::Quit => break,
                    Key::Up => state.detail_scroll = state.detail_scroll.saturating_sub(1),
                    Key::Down => {
                        if let Some(detail) = &state.process_detail {
                            let max_scroll = process_detail_lines(&snapshot, detail)
                                .len()
                                .saturating_sub(terminal.size().1.max(12).saturating_sub(4).max(1));
                            state.detail_scroll =
                                state.detail_scroll.saturating_add(1).min(max_scroll);
                        }
                    }
                    Key::Back | Key::Open => {
                        state.process_detail = None;
                        state.detail_scroll = 0;
                    }
                    Key::Refresh => {
                        if let Some(detail) = &mut state.process_detail {
                            detail.policy = inspect_process_policy(&detail.process.domain);
                        }
                        state.detail_scroll = 0;
                    }
                    Key::Switch(_) | Key::Ignored => {}
                }
            } else {
                match input {
                    Key::Quit => break,
                    Key::Up => state.set_selected(state.selected().saturating_sub(1)),
                    Key::Down => {
                        let last = row_count(&snapshot, state.view).saturating_sub(1);
                        state.set_selected(state.selected().saturating_add(1).min(last));
                    }
                    Key::Switch(view) => {
                        state.view = view;
                        clamp_selection(&snapshot, &mut state);
                    }
                    Key::Refresh => {
                        snapshot = collect_snapshot(profiles.to_vec());
                        refreshed = Instant::now();
                        clamp_selection(&snapshot, &mut state);
                    }
                    Key::Open if state.view == View::Processes => {
                        if let Some(process) = snapshot.processes.get(state.selected()).cloned() {
                            let policy = inspect_process_policy(&process.domain);
                            state.process_detail = Some(ProcessDetail { process, policy });
                            state.detail_scroll = 0;
                        }
                    }
                    Key::Open | Key::Back | Key::Ignored => {}
                }
            }
            terminal.draw(&render_frame(&snapshot, &state, terminal.size(), true))?;
        }

        if state.process_detail.is_none() && refreshed.elapsed() >= REFRESH_INTERVAL {
            refresh_dynamic(&mut snapshot);
            refreshed = Instant::now();
            clamp_selection(&snapshot, &mut state);
            terminal.draw(&render_frame(&snapshot, &state, terminal.size(), true))?;
        }
    }
    Ok(())
}

fn collect_snapshot(profiles: Vec<SupervisionProfile>) -> Snapshot {
    let enforcement = match fs::read_to_string("/sys/fs/selinux/enforce") {
        Ok(value) if value.trim() == "1" => "Enforcing".to_owned(),
        Ok(value) if value.trim() == "0" => "Permissive".to_owned(),
        _ => "Unknown".to_owned(),
    };
    let processes = collect_processes(&profiles);
    let executables = collect_executables(&profiles, &processes);
    let (rules, paths_by_type, rule_error) = match collect_fcontext_rules(&profiles) {
        Ok(contexts) => (contexts.executable_rules, contexts.paths_by_type, None),
        Err(error) => (Vec::new(), BTreeMap::new(), Some(format!("{error:#}"))),
    };
    Snapshot {
        enforcement,
        profiles,
        processes,
        executables,
        rules,
        paths_by_type,
        rule_error,
    }
}

fn refresh_dynamic(snapshot: &mut Snapshot) {
    snapshot.enforcement = match fs::read_to_string("/sys/fs/selinux/enforce") {
        Ok(value) if value.trim() == "1" => "Enforcing".to_owned(),
        Ok(value) if value.trim() == "0" => "Permissive".to_owned(),
        _ => "Unknown".to_owned(),
    };
    snapshot.processes = collect_processes(&snapshot.profiles);
    snapshot.executables = collect_executables(&snapshot.profiles, &snapshot.processes);
}

fn collect_processes(profiles: &[SupervisionProfile]) -> Vec<ProcessRow> {
    let mut rows = Vec::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return rows;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let base = entry.path();
        let Ok(context) = fs::read_to_string(base.join("attr/current")) else {
            continue;
        };
        let context = clean(&context);
        let domain = context_type(&context).unwrap_or("unknown_t").to_owned();
        let profile_index = profiles
            .iter()
            .position(|item| item.profile.identifiers().app_type == domain);
        let kind = classify_domain(&domain, profile_index.is_some());
        let command = fs::read_to_string(base.join("comm"))
            .map(|value| clean(&value))
            .unwrap_or_else(|_| "?".to_owned());
        let executable = fs::read_link(base.join("exe")).ok();
        let uid = entry.metadata().map(|metadata| metadata.uid()).unwrap_or(0);
        rows.push(ProcessRow {
            pid,
            uid,
            command,
            executable,
            context,
            domain,
            kind,
            profile_index,
        });
    }
    rows.sort_by_key(|row| (row.kind, row.pid));
    rows
}

fn collect_executables(
    profiles: &[SupervisionProfile],
    processes: &[ProcessRow],
) -> Vec<ExecutableRow> {
    let mut rows = BTreeMap::<(PathBuf, String), ExecutableRow>::new();
    for (profile_index, item) in profiles.iter().enumerate() {
        let ids = item.profile.identifiers();
        rows.entry((item.profile.executable.clone(), ids.app_type.clone()))
            .or_insert_with(|| ExecutableRow {
                path: item.profile.executable.clone(),
                label: selinux_label(&item.profile.executable).unwrap_or(ids.exec_type),
                domain: ids.app_type,
                process_count: 0,
                kind: ProtectionKind::Microvisor,
                profile_index: Some(profile_index),
            });
    }
    for process in processes {
        let Some(path) = &process.executable else {
            continue;
        };
        let key = (path.clone(), process.domain.clone());
        let row = rows.entry(key).or_insert_with(|| ExecutableRow {
            path: path.clone(),
            label: selinux_label(path).unwrap_or_else(|| "label unavailable".to_owned()),
            domain: process.domain.clone(),
            process_count: 0,
            kind: process.kind,
            profile_index: process.profile_index,
        });
        row.process_count += 1;
        if row.domain == "unknown_t" {
            row.domain.clone_from(&process.domain);
        }
    }
    let mut rows = rows.into_values().collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        (left.kind, &left.path, &left.domain).cmp(&(right.kind, &right.path, &right.domain))
    });
    rows
}

fn collect_fcontext_rules(profiles: &[SupervisionProfile]) -> Result<FcontextSnapshot> {
    let mut command = engine::trusted_command("semanage")?;
    command
        .args(["fcontext", "-l"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .context("Could not query SELinux file-context rules")?;
    let mut output = Vec::new();
    child
        .stdout
        .take()
        .context("Could not capture SELinux file-context rules")?
        .take(MAX_FCONTEXT_OUTPUT + 1)
        .read_to_end(&mut output)?;
    if output.len() as u64 > MAX_FCONTEXT_OUTPUT {
        // Stop the producer before waiting; otherwise a larger listing could block forever on the
        // now-full stdout pipe after this bounded reader deliberately stops consuming it.
        let _ = child.kill();
        let _ = child.wait();
        bail!("SELinux file-context listing exceeds the 16 MiB safety limit");
    }
    let status = child.wait()?;
    if !status.success() {
        bail!("semanage fcontext -l exited with {status}");
    }
    let text = String::from_utf8(output).context("SELinux file-context output is not UTF-8")?;
    let parsed = text
        .lines()
        .filter_map(parse_fcontext_rule)
        .collect::<Vec<_>>();
    let mut paths_by_type = BTreeMap::<String, BTreeSet<String>>::new();
    for rule in &parsed {
        paths_by_type
            .entry(rule.selinux_type.clone())
            .or_default()
            .insert(rule.pattern.clone());
    }
    let mut rules = parsed
        .into_iter()
        .filter(|rule| rule.selinux_type.ends_with("_exec_t"))
        .map(|mut rule| {
            rule.profile_index = profiles
                .iter()
                .position(|item| item.profile.identifiers().exec_type == rule.selinux_type);
            rule.kind = if rule.profile_index.is_some() {
                ProtectionKind::Microvisor
            } else {
                ProtectionKind::System
            };
            rule
        })
        .collect::<Vec<_>>();
    rules.sort_by(|left, right| {
        (left.kind, &left.selinux_type, &left.pattern).cmp(&(
            right.kind,
            &right.selinux_type,
            &right.pattern,
        ))
    });
    rules.dedup_by(|left, right| {
        left.pattern == right.pattern && left.selinux_type == right.selinux_type
    });
    Ok(FcontextSnapshot {
        executable_rules: rules,
        paths_by_type,
    })
}

fn parse_fcontext_rule(line: &str) -> Option<FcontextRule> {
    let line = line.trim();
    let split = line.rfind(char::is_whitespace)?;
    let context = line[split..].trim();
    let selinux_type = context_type(context)?.to_owned();
    let mut pattern = line[..split].trim_end();
    for suffix in [
        "all files",
        "regular file",
        "directory",
        "character device",
        "block device",
        "socket",
        "symbolic link",
        "named pipe",
    ] {
        if let Some(value) = pattern.strip_suffix(suffix) {
            pattern = value.trim_end();
            break;
        }
    }
    if pattern.is_empty() {
        return None;
    }
    Some(FcontextRule {
        pattern: clean(pattern),
        selinux_type,
        kind: ProtectionKind::Unknown,
        profile_index: None,
    })
}

fn inspect_process_policy(domain: &str) -> PolicyInspection {
    if let Err(error) = policy::validate_selinux_identifier(domain) {
        return PolicyInspection::Unavailable(format!(
            "The process domain is not safe to query: {error}"
        ));
    }
    let mut command = match engine::trusted_command("sesearch") {
        Ok(command) => command,
        Err(_) => {
            return PolicyInspection::Unavailable(
                "Loaded-policy details are unavailable because sesearch was not found; Microvisor profile rules below remain exact."
                    .to_owned(),
            );
        }
    };
    command.args(policy_query_arguments(domain));
    let output = match read_bounded_output(
        &mut command,
        MAX_POLICY_OUTPUT,
        "sesearch output",
        "Could not query the loaded SELinux policy",
    ) {
        Ok(output) => output,
        Err(error) => {
            return PolicyInspection::Unavailable(format!(
                "Loaded-policy details could not be queried: {error:#}"
            ));
        }
    };
    let (mut rules, truncated) = parse_allow_rules(&output);
    rules.sort();
    rules.dedup();
    if truncated || rules.len() > MAX_POLICY_RULES {
        rules.truncate(MAX_POLICY_RULES);
    }
    PolicyInspection::Rules { rules, truncated }
}

fn policy_query_arguments(domain: &str) -> [&str; 3] {
    // SETools 4.6 removed the legacy -C option and includes conditional expressions in its normal
    // rule formatting. The remaining options also work on older versions without causing argparse
    // to terminate with exit status 2.
    ["-A", "-s", domain]
}

fn read_bounded_output(
    command: &mut Command,
    limit: u64,
    output_name: &str,
    spawn_context: &str,
) -> Result<String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn().with_context(|| spawn_context.to_owned())?;
    let stderr = child
        .stderr
        .take()
        .with_context(|| format!("Could not capture {output_name} errors"))?;
    let stderr_reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        stderr
            .take(MAX_POLICY_ERROR_OUTPUT + 1)
            .read_to_end(&mut output)?;
        let truncated = output.len() as u64 > MAX_POLICY_ERROR_OUTPUT;
        output.truncate(MAX_POLICY_ERROR_OUTPUT as usize);
        Ok::<_, io::Error>((output, truncated))
    });
    let mut output = Vec::new();
    let stdout_result = child
        .stdout
        .take()
        .with_context(|| format!("Could not capture {output_name}"))?
        .take(limit + 1)
        .read_to_end(&mut output);
    let output_too_large = output.len() as u64 > limit;
    if output_too_large {
        // Stop the producer before waiting, since this bounded reader deliberately stopped
        // consuming its pipe. Policy output is host-controlled but must not exhaust root memory.
        let _ = child.kill();
    }
    let status = child.wait()?;
    let (stderr, stderr_truncated) = stderr_reader
        .join()
        .map_err(|_| anyhow::anyhow!("Could not join the {output_name} error reader"))??;
    stdout_result?;
    if output_too_large {
        bail!(
            "{output_name} exceeds the {} MiB safety limit",
            limit / 1024 / 1024
        );
    }
    if !status.success() {
        let stderr = summarize_command_error(&stderr);
        if stderr.is_empty() {
            bail!("policy query exited with {status}");
        }
        bail!(
            "policy query exited with {status}: {stderr}{}",
            if stderr_truncated {
                " (error output truncated)"
            } else {
                ""
            }
        );
    }
    String::from_utf8(output).with_context(|| format!("{output_name} is not UTF-8"))
}

fn summarize_command_error(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(clean)
        .unwrap_or_default()
}

fn parse_allow_rules(output: &str) -> (Vec<AllowRule>, bool) {
    let mut rules = Vec::new();
    let mut statement = String::new();
    let mut truncated = false;
    for line in output.lines() {
        let line = line.trim();
        if statement.is_empty() {
            if !line.starts_with("allow ") && !line.starts_with("allowxperm ") {
                continue;
            }
            statement.push_str(line);
        } else {
            statement.push(' ');
            statement.push_str(line);
        }
        if !line.contains(';') {
            continue;
        }
        if let Some(rule) = parse_allow_rule(&statement) {
            rules.push(rule);
            if rules.len() >= MAX_POLICY_RULES {
                truncated = true;
                break;
            }
        }
        statement.clear();
    }
    (rules, truncated)
}

fn parse_allow_rule(statement: &str) -> Option<AllowRule> {
    let (body, extended) = if let Some(body) = statement.strip_prefix("allow ") {
        (body, false)
    } else {
        (statement.strip_prefix("allowxperm ")?, true)
    };
    let (_, body) = body.split_once(char::is_whitespace)?;
    let (target, body) = body.trim_start().split_once(':')?;
    let target = target.trim();
    let (object_class, permissions) = body.trim_start().split_once(char::is_whitespace)?;
    let (permissions, condition) = permissions.split_once(';')?;
    let condition = condition.trim();
    let (condition, condition_state) = condition
        .strip_suffix(":True")
        .map(|value| (value, Some("true")))
        .or_else(|| {
            condition
                .strip_suffix(":False")
                .map(|value| (value, Some("false")))
        })
        .unwrap_or((condition, None));
    let condition = condition
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();
    let condition = (!condition.is_empty()).then(|| match condition_state {
        Some(state) => format!("{condition} is {state}"),
        None => condition.to_owned(),
    });
    let permissions = permissions.trim();
    let permissions = permissions
        .split_whitespace()
        .map(|permission| permission.trim_matches(['{', '}']))
        .filter(|permission| !permission.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if target.is_empty() || object_class.is_empty() || permissions.is_empty() {
        return None;
    }
    Some(AllowRule {
        target: target.to_owned(),
        object_class: object_class.to_owned(),
        permissions,
        condition,
        extended,
    })
}

fn context_type(context: &str) -> Option<&str> {
    context.split(':').nth(2).filter(|value| !value.is_empty())
}

fn classify_domain(domain: &str, microvisor: bool) -> ProtectionKind {
    if microvisor {
        ProtectionKind::Microvisor
    } else if domain == "unconfined_t" || domain.starts_with("unconfined_") {
        ProtectionKind::Unconfined
    } else if domain == "unknown_t" || domain.is_empty() {
        ProtectionKind::Unknown
    } else {
        ProtectionKind::System
    }
}

fn selinux_label(path: &Path) -> Option<String> {
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let name = c"security.selinux";
    // The first call obtains the exact bounded allocation size. The second fills that buffer; a
    // concurrent relabel can make it fail, in which case the UI reports the label as unavailable.
    let length = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if !(1..=4096).contains(&length) {
        return None;
    }
    let mut value = vec![0_u8; length as usize];
    let read = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if read <= 0 {
        return None;
    }
    value.truncate(read as usize);
    while value.last() == Some(&0) {
        value.pop();
    }
    Some(clean(&String::from_utf8_lossy(&value)))
}

fn print_plain(snapshot: &Snapshot) {
    println!(
        "Microvisor supervise — SELinux {} — {} process(es), {} executable(s), {} exec rule(s)",
        snapshot.enforcement,
        snapshot.processes.len(),
        snapshot.executables.len(),
        snapshot.rules.len()
    );
    for row in &snapshot.processes {
        println!(
            "{}\tpid={}\t{}\t{}\t{}",
            kind_name(row.kind),
            row.pid,
            row.domain,
            row.command,
            row.executable
                .as_deref()
                .map(|path| clean(&path.display().to_string()))
                .unwrap_or_else(|| "-".to_owned())
        );
    }
    if let Some(error) = &snapshot.rule_error {
        eprintln!("SELinux executable rules unavailable: {error}");
    }
}

fn render_frame(snapshot: &Snapshot, state: &UiState, size: (usize, usize), color: bool) -> String {
    if let Some(detail) = &state.process_detail {
        return render_process_detail(snapshot, detail, state.detail_scroll, size, color);
    }
    let (width, height) = size;
    let width = width.max(40);
    let height = height.max(12);
    let mut lines = Vec::new();
    lines.push(styled(
        &fit(
            &format!(
                " Microvisor Supervise  SELinux: {}  Profiles: {}  Processes: {} ",
                snapshot.enforcement,
                snapshot
                    .profiles
                    .iter()
                    .map(|item| item.profile.id)
                    .collect::<BTreeSet<_>>()
                    .len(),
                snapshot.processes.len()
            ),
            width,
        ),
        "1;97;44",
        color,
    ));
    lines.push(fit(
        &format!(
            " {}  {}  {}",
            tab_name("1 Processes", state.view == View::Processes),
            tab_name("2 Executables", state.view == View::Executables),
            tab_name("3 SELinux rules", state.view == View::Rules),
        ),
        width,
    ));
    lines.push(styled(
        &fit(
            " GREEN Microvisor   YELLOW system policy   RED unconfined   GRAY unknown",
            width,
        ),
        "2",
        color,
    ));
    lines.push("─".repeat(width));

    let detail_height = 6;
    let list_height = height
        .saturating_sub(lines.len() + detail_height + 1)
        .max(1);
    let selected = state.selected();
    match state.view {
        View::Processes => {
            render_processes(snapshot, selected, list_height, width, color, &mut lines)
        }
        View::Executables => {
            render_executables(snapshot, selected, list_height, width, color, &mut lines)
        }
        View::Rules => render_rules(snapshot, selected, list_height, width, color, &mut lines),
    }
    while lines.len() < height.saturating_sub(detail_height) {
        lines.push(String::new());
    }
    lines.push("─".repeat(width));
    render_detail(snapshot, state, width, color, &mut lines);
    while lines.len() < height.saturating_sub(1) {
        lines.push(String::new());
    }
    lines.push(styled(
        &fit(
            " ↑/↓ or j/k Select   Enter/d Process details   Tab/1/2/3 View   r Refresh   q Quit",
            width,
        ),
        "30;47",
        color,
    ));
    lines.truncate(height);
    format!("\x1b[H{}", lines.join("\x1b[K\r\n"))
}

fn render_process_detail(
    snapshot: &Snapshot,
    detail: &ProcessDetail,
    scroll: usize,
    size: (usize, usize),
    color: bool,
) -> String {
    let (width, height) = (size.0.max(40), size.1.max(12));
    let process = &detail.process;
    let mut body = process_detail_lines(snapshot, detail);
    let total_lines = body.len();
    let body_height = height.saturating_sub(4).max(1);
    let max_scroll = body.len().saturating_sub(body_height);
    let scroll = scroll.min(max_scroll);
    let mut lines = vec![styled(
        &fit(
            &format!(
                " Process details  PID {}  {}  SELinux: {} ",
                process.pid, process.command, snapshot.enforcement
            ),
            width,
        ),
        "1;97;44",
        color,
    )];
    lines.push(row_style(
        &fit(
            &format!(
                " Protection: {}   Domain: {} ",
                kind_name(process.kind),
                process.domain
            ),
            width,
        ),
        process.kind,
        false,
        color,
    ));
    lines.push("─".repeat(width));
    for line in body.drain(..).skip(scroll).take(body_height) {
        lines.push(detail_line_style(&fit(&line, width), color));
    }
    while lines.len() < height.saturating_sub(1) {
        lines.push(String::new());
    }
    lines.push(styled(
        &fit(
            &format!(
                " ↑/↓ or j/k Scroll   Esc/Backspace/Enter Back   r Re-query policy   q Quit   Lines {}–{} of {}",
                if total_lines == 0 { 0 } else { scroll + 1 },
                (scroll + body_height).min(total_lines),
                total_lines
            ),
            width,
        ),
        "30;47",
        color,
    ));
    lines.truncate(height);
    format!("\x1b[H{}", lines.join("\x1b[K\r\n"))
}

fn detail_line_style(line: &str, color: bool) -> String {
    let text = line.trim_start();
    if text.starts_with("ALLOWED") || text.starts_with("ALLOW ") || text.starts_with("ALLOW-XPERM")
    {
        styled(line, "32", color)
    } else if text.starts_with("DENIED") || text.starts_with("PLANNED DENY") {
        styled(line, "31", color)
    } else if text.starts_with("PLANNED")
        || text.starts_with("NOT ACTIVE")
        || text.starts_with("NOT DENIED")
    {
        styled(line, "33", color)
    } else if !line.starts_with(' ') && !line.is_empty() {
        styled(line, "1", color)
    } else {
        line.to_owned()
    }
}

fn process_detail_lines(snapshot: &Snapshot, detail: &ProcessDetail) -> Vec<String> {
    let process = &detail.process;
    let mut lines = vec![
        "PROCESS IDENTITY".to_owned(),
        format!("  Command: {}", process.command),
        format!("  User ID: {}", process.uid),
        format!(
            "  Executable: {}",
            process
                .executable
                .as_deref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "not readable".to_owned())
        ),
        format!("  Full SELinux context: {}", process.context),
        String::new(),
        "HOW TO READ THIS".to_owned(),
        "  ALLOWED means an allow rule exists. DENIED means Microvisor has an explicit deny rule.".to_owned(),
        "  A conditional allow applies only when the condition shown on that rule selects its branch.".to_owned(),
        "  Everything else is denied by SELinux by default unless another matching allow rule exists.".to_owned(),
        "  AVC audit logs remain authoritative for a particular attempted operation.".to_owned(),
    ];

    if let Some(profile) = process
        .profile_index
        .and_then(|index| snapshot.profiles.get(index))
    {
        append_microvisor_policy(&mut lines, profile, snapshot);
    } else if process.kind == ProtectionKind::System {
        lines.push(String::new());
        append_system_file_permissions(&mut lines, &detail.policy, snapshot);
    } else {
        lines.push(String::new());
        lines.push("PROTECTION SUMMARY".to_owned());
        lines.extend(
            restriction_explanation(process.kind, process.profile_index, snapshot)
                .into_iter()
                .map(|line| format!("  {line}")),
        );
    }

    lines.push(String::new());
    append_loaded_policy(&mut lines, &detail.policy);
    lines
}

fn append_system_file_permissions(
    lines: &mut Vec<String>,
    inspection: &PolicyInspection,
    snapshot: &Snapshot,
) {
    lines.push("SYSTEM FILE PERMISSIONS".to_owned());
    lines.push(
        "  A check mark means the loaded SELinux policy has a matching allow for some labeled"
            .to_owned(),
    );
    lines.push(
        "  content in that location. It does not mean every file there is accessible; ordinary"
            .to_owned(),
    );
    lines.push(
        "  Unix permissions, SELinux conditions, and finer-grained labels still apply.".to_owned(),
    );

    let PolicyInspection::Rules { rules, .. } = inspection else {
        lines.push("  UNAVAILABLE: loaded-policy permissions could not be summarized.".to_owned());
        return;
    };
    let permissions = summarize_path_permissions(rules, &snapshot.paths_by_type);
    for (scope, title) in PATH_SCOPES {
        lines.push(format!("  {title}"));
        let access = permissions.get(&scope);
        append_permission_evidence(
            lines,
            "Read or inspect contents",
            access.map(|item| &item.read),
        );
        append_permission_evidence(
            lines,
            "Create, change, or delete contents",
            access.map(|item| &item.write),
        );
    }
    if snapshot.rule_error.is_some() {
        lines.push(
            "  Note: file-context paths were unavailable, so this list may omit labeled areas."
                .to_owned(),
        );
    }
}

fn append_permission_evidence(
    lines: &mut Vec<String>,
    action: &str,
    evidence: Option<&PermissionEvidence>,
) {
    let Some(evidence) = evidence.filter(|item| item.unconditional || item.conditional) else {
        lines.push(format!(
            "    — {action}: NO MATCHING ALLOW found in this summary"
        ));
        return;
    };
    let state = if evidence.unconditional {
        "✓ ALLOWED for some labeled content"
    } else {
        "◇ CONDITIONAL for some labeled content"
    };
    let examples = evidence
        .patterns
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>();
    let detail = if examples.is_empty() {
        evidence
            .targets
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        examples.join(", ")
    };
    lines.push(format!("    {state} — {action}"));
    if !detail.is_empty() {
        lines.push(format!("      Matches: {detail}"));
    }
}

fn summarize_path_permissions(
    rules: &[AllowRule],
    paths_by_type: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeMap<PathScope, ScopePermissions> {
    let mut summary = BTreeMap::<PathScope, ScopePermissions>::new();
    for rule in rules {
        if !is_file_object_class(&rule.object_class) {
            continue;
        }
        let Some(patterns) = paths_by_type.get(&rule.target) else {
            continue;
        };
        let read = rule.permissions.iter().any(|permission| {
            matches!(
                permission.as_str(),
                "read" | "open" | "getattr" | "search" | "map"
            )
        });
        let write = rule.permissions.iter().any(|permission| {
            matches!(
                permission.as_str(),
                "write"
                    | "append"
                    | "create"
                    | "add_name"
                    | "remove_name"
                    | "unlink"
                    | "rename"
                    | "setattr"
                    | "link"
                    | "reparent"
                    | "rmdir"
                    | "relabelfrom"
                    | "relabelto"
            )
        });
        if !read && !write {
            continue;
        }
        for pattern in patterns {
            let Some(scope) = path_scope(pattern) else {
                continue;
            };
            let access = summary.entry(scope).or_default();
            if read {
                record_permission_evidence(&mut access.read, rule, pattern);
            }
            if write {
                record_permission_evidence(&mut access.write, rule, pattern);
            }
        }
    }
    summary
}

fn record_permission_evidence(evidence: &mut PermissionEvidence, rule: &AllowRule, pattern: &str) {
    if rule.condition.is_some() {
        evidence.conditional = true;
    } else {
        evidence.unconditional = true;
    }
    evidence.targets.insert(rule.target.clone());
    evidence.patterns.insert(pattern.to_owned());
}

fn is_file_object_class(object_class: &str) -> bool {
    matches!(
        object_class,
        "dir" | "file" | "lnk_file" | "chr_file" | "blk_file" | "sock_file" | "fifo_file"
    )
}

fn path_scope(pattern: &str) -> Option<PathScope> {
    if pattern == "/home"
        || pattern.starts_with("/home/")
        || pattern.starts_with("/home(")
        || pattern == "/root"
        || pattern.starts_with("/root/")
        || pattern.starts_with("/root(")
    {
        Some(PathScope::Home)
    } else if pattern == "/etc" || pattern.starts_with("/etc/") || pattern.starts_with("/etc(") {
        Some(PathScope::Etc)
    } else if pattern == "/var/lib"
        || pattern.starts_with("/var/lib/")
        || pattern.starts_with("/var/lib(")
    {
        Some(PathScope::VarLib)
    } else if pattern == "/var/log"
        || pattern.starts_with("/var/log/")
        || pattern.starts_with("/var/log(")
    {
        Some(PathScope::VarLog)
    } else if pattern == "/var/spool"
        || pattern.starts_with("/var/spool/")
        || pattern.starts_with("/var/spool(")
    {
        Some(PathScope::VarSpool)
    } else if pattern == "/var" || pattern.starts_with("/var/") || pattern.starts_with("/var(") {
        Some(PathScope::OtherVar)
    } else {
        None
    }
}

fn append_microvisor_policy(
    lines: &mut Vec<String>,
    profile: &SupervisionProfile,
    snapshot: &Snapshot,
) {
    let ids = profile.profile.identifiers();
    let active = profile.applied;
    lines.push(String::new());
    lines.push(format!(
        "MICROVISOR PROFILE — {} ({})",
        profile.profile.name,
        profile_source(profile, snapshot)
    ));
    if !active {
        lines.push("  NOT ACTIVE: the following rules are planned by configuration, not installed protection.".to_owned());
    }
    lines.push(format!(
        "  {} launch: {} executing the labeled program transitions into {}.",
        if active { "ALLOWED" } else { "PLANNED" },
        profile.profile.launch_domain,
        ids.app_type
    ));
    lines.push(format!(
        "  {} protected data: this domain may list, search, read, create, change, rename, and delete",
        if active { "ALLOWED" } else { "PLANNED" }
    ));
    lines.push(
        "    directories, regular files, links, FIFOs, and local socket files under these paths:"
            .to_owned(),
    );
    for path in &profile.profile.data_directories {
        lines.push(format!("      - {}", path.display()));
    }
    lines.push(format!(
        "  {} direct data access: every SELinux subject type except {} is blocked from all",
        if active { "DENIED" } else { "PLANNED DENY" },
        ids.app_type
    ));
    lines.push(format!(
        "    permissions on data labeled {} (directories, files, links, devices, FIFOs, sockets).",
        ids.data_type
    ));
    lines.push(format!(
        "  {} ptrace/debugging by other domains: {}.",
        if profile.profile.block_ptrace {
            if active { "DENIED" } else { "PLANNED DENY" }
        } else {
            "NOT DENIED"
        },
        if profile.profile.block_ptrace {
            "blocked by this profile"
        } else {
            "not blocked by this profile"
        }
    ));
    lines.push(format!(
        "  {} use of file descriptors opened by this process from other domains: {}.",
        if profile.profile.block_fd_use {
            if active { "DENIED" } else { "PLANNED DENY" }
        } else {
            "NOT DENIED"
        },
        if profile.profile.block_fd_use {
            "blocked by this profile"
        } else {
            "not blocked by this profile"
        }
    ));
    lines.push(
        "  Compatibility note: the application domain also inherits broad unconfined-policy allows"
            .to_owned(),
    );
    lines.push(
        "    for resources outside its protected data type; it is not a general-purpose sandbox."
            .to_owned(),
    );
}

fn append_loaded_policy(lines: &mut Vec<String>, inspection: &PolicyInspection) {
    lines.push("LOADED SELINUX ALLOW RULES".to_owned());
    match inspection {
        PolicyInspection::Unavailable(message) => {
            lines.push(format!("  UNAVAILABLE: {message}"));
            lines.push(
                "  No additional permission or denial claim is made from the system policy."
                    .to_owned(),
            );
        }
        PolicyInspection::Rules { rules, .. } if rules.is_empty() => {
            lines.push("  No matching allow rules were reported for this domain.".to_owned());
            lines.push("  This does not prove every operation is denied; attribute and conditional policy may apply.".to_owned());
        }
        PolicyInspection::Rules { rules, truncated } => {
            let mut categories = BTreeMap::<&str, usize>::new();
            for rule in rules {
                *categories
                    .entry(rule_category(&rule.object_class))
                    .or_default() += 1;
            }
            if rules.len() > MAX_DISPLAYED_POLICY_RULES {
                lines.push(format!(
                    "  Showing the first {MAX_DISPLAYED_POLICY_RULES} rules of {}; use sesearch for a narrower query.",
                    rules.len()
                ));
            }
            lines.push(format!(
                "  sesearch found {} matching allow rule(s) in the currently loaded policy.",
                rules.len()
            ));
            lines.push(format!(
                "  Summary: {}",
                categories
                    .into_iter()
                    .map(|(category, count)| format!("{category} {count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
            lines.push("  Concrete rules (target type : object class — permissions):".to_owned());
            for rule in rules.iter().take(MAX_DISPLAYED_POLICY_RULES) {
                let condition = rule
                    .condition
                    .as_deref()
                    .map(|value| format!(" when {value}"))
                    .unwrap_or_default();
                lines.push(format!(
                    "    {} {}: {} : {} — {} [{}]{}",
                    if rule.extended {
                        "ALLOW-XPERM"
                    } else {
                        "ALLOW"
                    },
                    rule_category(&rule.object_class),
                    rule.target,
                    rule.object_class,
                    friendly_permissions(&rule.permissions),
                    rule.permissions.join(" "),
                    condition
                ));
            }
            if *truncated {
                lines.push(format!(
                    "  Output was capped at {MAX_POLICY_RULES} rules for safety."
                ));
            }
        }
    }
    lines.push(String::new());
    lines.push("DENIED BY DEFAULT".to_owned());
    lines.push("  SELinux does not keep a finite list of every rejected action. An action with no matching".to_owned());
    lines.push(
        "  allow rule is rejected while Enforcing; check AVC logs to explain a real rejection."
            .to_owned(),
    );
}

fn rule_category(object_class: &str) -> &'static str {
    match object_class {
        "dir" | "file" | "lnk_file" | "chr_file" | "blk_file" | "sock_file" | "fifo_file"
        | "filesystem" => "files",
        "tcp_socket" | "udp_socket" | "rawip_socket" | "unix_stream_socket"
        | "unix_dgram_socket" | "node" | "netif" | "packet" => "network",
        "process" | "process2" | "fd" => "process control",
        _ => "other",
    }
}

fn friendly_permissions(permissions: &[String]) -> String {
    let mut actions = BTreeSet::new();
    for permission in permissions {
        let action = match permission.as_str() {
            "read" | "open" | "getattr" | "search" | "map" => "read/inspect",
            "write" | "append" | "create" | "add_name" | "remove_name" | "unlink" | "rename"
            | "setattr" => "create/change/delete",
            "execute" | "execute_no_trans" | "entrypoint" | "transition" => "execute/transition",
            "connect" | "name_connect" | "listen" | "accept" | "bind" => "connect/listen",
            "send_msg" | "recv_msg" | "sendto" | "recvfrom" => "send/receive",
            "signal" | "sigkill" | "sigstop" | "ptrace" => "control another process",
            "use" => "use inherited/open descriptor",
            _ => "other operation",
        };
        actions.insert(action);
    }
    actions.into_iter().collect::<Vec<_>>().join(", ")
}

fn render_processes(
    snapshot: &Snapshot,
    selected: usize,
    count: usize,
    width: usize,
    color: bool,
    lines: &mut Vec<String>,
) {
    lines.push(styled(
        &fit(
            "    PID   USER   PROTECTION       DOMAIN                    COMMAND / EXECUTABLE",
            width,
        ),
        "1",
        color,
    ));
    if snapshot.processes.is_empty() {
        lines.push(" No readable process SELinux contexts.".to_owned());
        return;
    }
    let start = centered_start(selected, count, snapshot.processes.len());
    for (index, row) in snapshot
        .processes
        .iter()
        .enumerate()
        .skip(start)
        .take(count)
    {
        let path = row
            .executable
            .as_deref()
            .map(|value| value.display().to_string())
            .unwrap_or_else(|| "[not readable]".to_owned());
        let text = format!(
            "{} {:>6} {:>6} {:<16} {:<25} {} — {}",
            if index == selected { ">" } else { " " },
            row.pid,
            row.uid,
            kind_name(row.kind),
            row.domain,
            row.command,
            path
        );
        lines.push(row_style(
            &fit(&text, width),
            row.kind,
            index == selected,
            color,
        ));
    }
}

fn render_executables(
    snapshot: &Snapshot,
    selected: usize,
    count: usize,
    width: usize,
    color: bool,
    lines: &mut Vec<String>,
) {
    lines.push(styled(
        &fit(
            "   RUNNING  PROTECTION       PROCESS DOMAIN             EXECUTABLE / FILE LABEL",
            width,
        ),
        "1",
        color,
    ));
    if snapshot.executables.is_empty() {
        lines.push(" No readable executable information.".to_owned());
        return;
    }
    let start = centered_start(selected, count, snapshot.executables.len());
    for (index, row) in snapshot
        .executables
        .iter()
        .enumerate()
        .skip(start)
        .take(count)
    {
        let text = format!(
            "{} {:>7}  {:<16} {:<26} {} — {}",
            if index == selected { ">" } else { " " },
            row.process_count,
            kind_name(row.kind),
            row.domain,
            row.path.display(),
            row.label
        );
        lines.push(row_style(
            &fit(&text, width),
            row.kind,
            index == selected,
            color,
        ));
    }
}

fn render_rules(
    snapshot: &Snapshot,
    selected: usize,
    count: usize,
    width: usize,
    color: bool,
    lines: &mut Vec<String>,
) {
    lines.push(styled(
        &fit(
            "   SOURCE             EXECUTABLE LABEL                   PATH PATTERN",
            width,
        ),
        "1",
        color,
    ));
    if snapshot.rules.is_empty() {
        let message = snapshot
            .rule_error
            .as_deref()
            .unwrap_or("No executable file-context rules were reported.");
        lines.push(fit(&format!(" {message}"), width));
        return;
    }
    let start = centered_start(selected, count, snapshot.rules.len());
    for (index, row) in snapshot.rules.iter().enumerate().skip(start).take(count) {
        let text = format!(
            "{} {:<18} {:<34} {}",
            if index == selected { ">" } else { " " },
            kind_name(row.kind),
            row.selinux_type,
            row.pattern
        );
        lines.push(row_style(
            &fit(&text, width),
            row.kind,
            index == selected,
            color,
        ));
    }
}

fn render_detail(
    snapshot: &Snapshot,
    state: &UiState,
    width: usize,
    color: bool,
    lines: &mut Vec<String>,
) {
    let (title, details, kind) = match state.view {
        View::Processes => snapshot.processes.get(state.selected()).map(|row| {
            let mut details = restriction_explanation(row.kind, row.profile_index, snapshot);
            details.push(format!("Full process context: {}", row.context));
            (
                format!("PID {} — {}", row.pid, row.command),
                details,
                row.kind,
            )
        }),
        View::Executables => snapshot.executables.get(state.selected()).map(|row| {
            let mut details = restriction_explanation(row.kind, row.profile_index, snapshot);
            details.push(format!("Current file label: {}", row.label));
            (row.path.display().to_string(), details, row.kind)
        }),
        View::Rules => snapshot.rules.get(state.selected()).map(|row| {
            let mut details = restriction_explanation(row.kind, row.profile_index, snapshot);
            details.push(format!(
                "Matching files receive label {}. Access still depends on allow/deny policy.",
                row.selinux_type
            ));
            (row.pattern.clone(), details, row.kind)
        }),
    }
    .unwrap_or_else(|| {
        (
            "Nothing selected".to_owned(),
            vec!["No inspectable item is available in this view.".to_owned()],
            ProtectionKind::Unknown,
        )
    });
    lines.push(row_style(
        &fit(&format!(" {title}"), width),
        kind,
        false,
        color,
    ));
    for detail in details.into_iter().take(3) {
        lines.push(fit(&format!("   {detail}"), width));
    }
}

fn restriction_explanation(
    kind: ProtectionKind,
    profile_index: Option<usize>,
    snapshot: &Snapshot,
) -> Vec<String> {
    if let Some(profile) = profile_index.and_then(|index| snapshot.profiles.get(index)) {
        let ids = profile.profile.identifiers();
        let protection = if profile.applied {
            format!(
                "only {} may access {} protected data path(s)",
                ids.app_type,
                profile.profile.data_directories.len()
            )
        } else {
            format!(
                "if applied, only {} would access {} protected data path(s)",
                ids.app_type,
                profile.profile.data_directories.len()
            )
        };
        return vec![
            format!(
                "Microvisor profile '{}' ({}): {protection}.",
                profile.profile.name,
                profile_source(profile, snapshot),
            ),
            format!(
                "Launch {} → {}; ptrace {}, inherited-FD use {}.",
                profile.profile.launch_domain,
                ids.app_type,
                on_off(profile.profile.block_ptrace),
                on_off(profile.profile.block_fd_use)
            ),
        ];
    }
    match kind {
        ProtectionKind::System => vec![
            "This domain or executable label comes from the system SELinux policy.".to_owned(),
            "SELinux evaluates it under that policy, but the domain may have broad allows; inspect policy and AVC logs for exact decisions.".to_owned(),
        ],
        ProtectionKind::Unconfined => vec![
            "The process runs in unconfined_t, so normal SELinux domain confinement is minimal.".to_owned(),
            "Microvisor deny modules can still block direct access to their protected data types.".to_owned(),
        ],
        ProtectionKind::Unknown => vec![
            "The SELinux label or executable could not be read. No protection claim is made.".to_owned(),
        ],
        ProtectionKind::Microvisor => unreachable!(),
    }
}

fn on_off(value: bool) -> &'static str {
    if value { "blocked" } else { "not blocked" }
}

fn profile_source(profile: &SupervisionProfile, snapshot: &Snapshot) -> &'static str {
    match (profile.applied, profile.desired) {
        (true, true) => "applied and configured",
        (true, false)
            if snapshot
                .profiles
                .iter()
                .any(|item| item.desired && item.profile.id == profile.profile.id) =>
        {
            "applied; config differs"
        }
        (true, false) => "applied; config missing",
        (false, true) => "configured only",
        (false, false) => "unknown source",
    }
}

fn kind_name(kind: ProtectionKind) -> &'static str {
    match kind {
        ProtectionKind::Microvisor => "Microvisor",
        ProtectionKind::System => "system-policy",
        ProtectionKind::Unconfined => "unconfined",
        ProtectionKind::Unknown => "unknown",
    }
}

fn row_style(value: &str, kind: ProtectionKind, selected: bool, color: bool) -> String {
    let code = match (kind, selected) {
        (ProtectionKind::Microvisor, true) => "1;30;42",
        (ProtectionKind::System, true) => "1;30;43",
        (ProtectionKind::Unconfined, true) => "1;97;41",
        (ProtectionKind::Unknown, true) => "1;30;47",
        (ProtectionKind::Microvisor, false) => "32",
        (ProtectionKind::System, false) => "33",
        (ProtectionKind::Unconfined, false) => "31",
        (ProtectionKind::Unknown, false) => "2",
    };
    styled(value, code, color)
}

fn tab_name(value: &str, selected: bool) -> String {
    if selected {
        format!("[{value}]")
    } else {
        format!(" {value} ")
    }
}

fn styled(value: &str, code: &str, color: bool) -> String {
    if color {
        format!("\x1b[{code}m{value}\x1b[0m")
    } else {
        value.to_owned()
    }
}

fn clean(value: &str) -> String {
    value
        .trim_matches(['\0', '\n', '\r'])
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect()
}

fn fit(value: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    // Every value derived from /proc, xattrs, or policy listings crosses the terminal control
    // boundary here. Replace control bytes before adding Microvisor's own ANSI sequences.
    let value = clean(value);
    if display_width(&value) <= width {
        return value;
    }
    let limit = width.saturating_sub(1);
    let mut used = 0;
    let mut output = String::new();
    for character in value.chars() {
        let character_width = terminal_character_width(character);
        if used + character_width > limit {
            break;
        }
        output.push(character);
        used += character_width;
    }
    output.push('…');
    output
}

fn display_width(value: &str) -> usize {
    value.chars().map(terminal_character_width).sum()
}

fn terminal_character_width(character: char) -> usize {
    let value = character as u32;
    if matches!(value, 0x0300..=0x036f | 0x1ab0..=0x1aff | 0x1dc0..=0x1dff | 0x20d0..=0x20ff | 0xfe20..=0xfe2f)
    {
        0
    } else if matches!(
        value,
        0x1100..=0x115f
            | 0x2329..=0x232a
            | 0x2e80..=0xa4cf
            | 0xac00..=0xd7a3
            | 0xf900..=0xfaff
            | 0xfe10..=0xfe19
            | 0xfe30..=0xfe6f
            | 0xff00..=0xff60
            | 0xffe0..=0xffe6
            | 0x1f300..=0x1faff
            | 0x20000..=0x3fffd
    ) {
        2
    } else {
        1
    }
}

fn centered_start(selected: usize, visible: usize, total: usize) -> usize {
    selected
        .saturating_sub(visible / 2)
        .min(total.saturating_sub(visible))
}

fn row_count(snapshot: &Snapshot, view: View) -> usize {
    match view {
        View::Processes => snapshot.processes.len(),
        View::Executables => snapshot.executables.len(),
        View::Rules => snapshot.rules.len(),
    }
}

fn clamp_selection(snapshot: &Snapshot, state: &mut UiState) {
    let last = row_count(snapshot, state.view).saturating_sub(1);
    state.set_selected(state.selected().min(last));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    Quit,
    Up,
    Down,
    Open,
    Back,
    Switch(View),
    Refresh,
    Ignored,
}

fn parse_key(bytes: &[u8], current: View) -> Key {
    match bytes {
        b"q" | b"Q" | [3] => Key::Quit,
        b"k" | b"K" | b"\x1b[A" => Key::Up,
        b"j" | b"J" | b"\x1b[B" => Key::Down,
        b"\r" | b"\n" | b"d" | b"D" => Key::Open,
        b"\x1b" | [8] | [127] => Key::Back,
        b"1" => Key::Switch(View::Processes),
        b"2" => Key::Switch(View::Executables),
        b"3" => Key::Switch(View::Rules),
        b"\t" => Key::Switch(match current {
            View::Processes => View::Executables,
            View::Executables => View::Rules,
            View::Rules => View::Processes,
        }),
        b"r" | b"R" => Key::Refresh,
        _ => Key::Ignored,
    }
}

struct Terminal {
    input: RawFd,
    output: RawFd,
    original: libc::termios,
}

impl Terminal {
    fn enter(input: RawFd, output: RawFd) -> Result<Self> {
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(input, &mut original) } != 0 {
            return Err(io::Error::last_os_error()).context("Could not read terminal settings");
        }
        let mut raw = original;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
        raw.c_iflag &= !(libc::IXON | libc::ICRNL);
        raw.c_cc[libc::VMIN] = 0;
        raw.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(input, libc::TCSAFLUSH, &raw) } != 0 {
            return Err(io::Error::last_os_error()).context("Could not enter terminal raw mode");
        }
        let terminal = Self {
            input,
            output,
            original,
        };
        terminal.write_all(b"\x1b[?1049h\x1b[?25l\x1b[2J")?;
        Ok(terminal)
    }

    fn size(&self) -> (usize, usize) {
        let mut size = unsafe { std::mem::zeroed::<libc::winsize>() };
        if unsafe { libc::ioctl(self.output, libc::TIOCGWINSZ, &mut size) } == 0
            && size.ws_col > 0
            && size.ws_row > 0
        {
            (usize::from(size.ws_col), usize::from(size.ws_row))
        } else {
            (80, 24)
        }
    }

    fn read_key(&self, timeout: Duration, current: View) -> Result<Option<Key>> {
        let mut pollfd = libc::pollfd {
            fd: self.input,
            events: libc::POLLIN,
            revents: 0,
        };
        let milliseconds = timeout.as_millis().min(i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(&mut pollfd, 1, milliseconds) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(None);
            }
            return Err(error).context("Could not poll terminal input");
        }
        if ready == 0 {
            return Ok(None);
        }
        let mut bytes = [0_u8; 16];
        let read = unsafe { libc::read(self.input, bytes.as_mut_ptr().cast(), bytes.len()) };
        if read <= 0 {
            return Ok(None);
        }
        Ok(Some(parse_key(&bytes[..read as usize], current)))
    }

    fn draw(&mut self, frame: &str) -> Result<()> {
        self.write_all(frame.as_bytes())
    }

    fn write_all(&self, mut bytes: &[u8]) -> Result<()> {
        while !bytes.is_empty() {
            let written = unsafe { libc::write(self.output, bytes.as_ptr().cast(), bytes.len()) };
            if written < 0 {
                return Err(io::Error::last_os_error()).context("Could not write terminal output");
            }
            if written == 0 {
                bail!("Terminal output closed unexpectedly");
            }
            bytes = &bytes[written as usize..];
        }
        Ok(())
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = unsafe { libc::tcsetattr(self.input, libc::TCSAFLUSH, &self.original) };
        let _ = self.write_all(b"\x1b[?25h\x1b[?1049l");
    }
}

fn is_terminal(fd: RawFd) -> bool {
    unsafe { libc::isatty(fd) == 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProtectionProfile;
    use std::os::fd::{FromRawFd, OwnedFd};
    use uuid::Uuid;

    fn profile() -> SupervisionProfile {
        let mut profile = ProtectionProfile::new();
        profile.id = Uuid::parse_str("11111111-2222-4333-8444-555555555555").unwrap();
        profile.name = "Test browser".into();
        profile.executable = "/opt/browser/browser".into();
        profile.data_directories = vec!["/home/alice/.config/browser".into()];
        SupervisionProfile {
            profile,
            applied: true,
            desired: true,
        }
    }

    #[test]
    fn parses_system_and_microvisor_fcontext_lines() {
        let rule = parse_fcontext_rule(
            "/usr/sbin/sshd                                    regular file       system_u:object_r:sshd_exec_t:s0",
        )
        .unwrap();
        assert_eq!(rule.pattern, "/usr/sbin/sshd");
        assert_eq!(rule.selinux_type, "sshd_exec_t");

        let rule = parse_fcontext_rule(
            "/opt/browser/browser                              all files          system_u:object_r:microvisor_11111111222243338444555555555555_exec_t:s0",
        )
        .unwrap();
        assert_eq!(rule.pattern, "/opt/browser/browser");
        assert!(rule.selinux_type.ends_with("_exec_t"));
    }

    #[test]
    fn parses_single_and_multiline_allow_rules() {
        let output = r#"
allow sshd_t ssh_home_t : file { getattr open read map };
allow sshd_t http_port_t:tcp_socket {
    name_connect
}; [ ssh_sysadm_login ]:True
allowxperm sshd_t device_t:chr_file ioctl { 0x1234 0x1235 };
type_transition sshd_t user_t:process staff_t;
"#;
        let (rules, truncated) = parse_allow_rules(output);
        assert!(!truncated);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].target, "ssh_home_t");
        assert_eq!(rules[0].object_class, "file");
        assert_eq!(rules[0].permissions, ["getattr", "open", "read", "map"]);
        assert_eq!(rules[0].condition, None);
        assert!(!rules[0].extended);
        assert_eq!(rules[1].target, "http_port_t");
        assert_eq!(rules[1].object_class, "tcp_socket");
        assert_eq!(rules[1].permissions, ["name_connect"]);
        assert_eq!(
            rules[1].condition.as_deref(),
            Some("ssh_sysadm_login is true")
        );
        assert!(!rules[1].extended);
        assert_eq!(rules[2].target, "device_t");
        assert_eq!(rules[2].object_class, "chr_file");
        assert!(rules[2].permissions.contains(&"ioctl".to_owned()));
        assert!(rules[2].extended);

        let (rules, _) =
            parse_allow_rules("allow sshd_t shadow_t:file read; [ ssh_sysadm_login ]:False");
        assert_eq!(rules.len(), 1);
        assert_eq!(
            rules[0].condition.as_deref(),
            Some("ssh_sysadm_login is false")
        );
    }

    #[test]
    fn uses_setools_4_6_compatible_policy_query_arguments() {
        let arguments = policy_query_arguments("sshd_t");
        assert_eq!(arguments, ["-A", "-s", "sshd_t"]);
        assert!(!arguments.contains(&"-C"));
    }

    #[test]
    fn reports_the_actionable_final_policy_query_error_safely() {
        let stderr = b"usage: sesearch [options]\nsesearch: error: unrecognized arguments: -C\n";
        assert_eq!(
            summarize_command_error(stderr),
            "sesearch: error: unrecognized arguments: -C"
        );
        assert_eq!(summarize_command_error(b"bad\x1b[2J\n"), "bad�[2J");
    }

    #[test]
    fn translates_policy_permissions_without_hiding_raw_permissions() {
        let permissions = vec!["open".to_owned(), "read".to_owned(), "ioctl".to_owned()];
        assert_eq!(
            friendly_permissions(&permissions),
            "other operation, read/inspect"
        );
        assert_eq!(rule_category("tcp_socket"), "network");
        assert_eq!(rule_category("process"), "process control");
    }

    #[test]
    fn classifies_sensitive_path_scopes_without_folding_subtrees_into_var() {
        assert_eq!(path_scope("/home/[^/]+/.*"), Some(PathScope::Home));
        assert_eq!(path_scope("/root(/.*)?"), Some(PathScope::Home));
        assert_eq!(path_scope("/etc/shadow"), Some(PathScope::Etc));
        assert_eq!(
            path_scope("/var/lib/postgresql(/.*)?"),
            Some(PathScope::VarLib)
        );
        assert_eq!(path_scope("/var/log/audit(/.*)?"), Some(PathScope::VarLog));
        assert_eq!(
            path_scope("/var/spool/mail(/.*)?"),
            Some(PathScope::VarSpool)
        );
        assert_eq!(path_scope("/var/cache(/.*)?"), Some(PathScope::OtherVar));
        assert_eq!(path_scope("/usr/share"), None);
    }

    #[test]
    fn summarizes_read_write_and_conditional_file_permissions_by_location() {
        let rules = vec![
            AllowRule {
                target: "user_home_t".into(),
                object_class: "file".into(),
                permissions: vec!["open".into(), "read".into(), "write".into()],
                condition: None,
                extended: false,
            },
            AllowRule {
                target: "shadow_t".into(),
                object_class: "file".into(),
                permissions: vec!["open".into(), "read".into()],
                condition: Some("allow_shadow is true".into()),
                extended: false,
            },
            AllowRule {
                target: "var_log_t".into(),
                object_class: "file".into(),
                permissions: vec!["append".into()],
                condition: None,
                extended: false,
            },
            AllowRule {
                target: "http_port_t".into(),
                object_class: "tcp_socket".into(),
                permissions: vec!["name_connect".into()],
                condition: None,
                extended: false,
            },
        ];
        let paths = BTreeMap::from([
            (
                "user_home_t".into(),
                BTreeSet::from(["/home/[^/]+(/.*)?".into()]),
            ),
            ("shadow_t".into(), BTreeSet::from(["/etc/shadow".into()])),
            (
                "var_log_t".into(),
                BTreeSet::from(["/var/log(/.*)?".into()]),
            ),
        ]);
        let summary = summarize_path_permissions(&rules, &paths);
        let home = summary.get(&PathScope::Home).unwrap();
        assert!(home.read.unconditional);
        assert!(home.write.unconditional);
        let etc = summary.get(&PathScope::Etc).unwrap();
        assert!(!etc.read.unconditional);
        assert!(etc.read.conditional);
        assert_eq!(etc.read.patterns, BTreeSet::from(["/etc/shadow".into()]));
        assert!(!etc.write.unconditional);
        assert!(!etc.write.conditional);
        assert!(summary.get(&PathScope::VarLog).unwrap().write.unconditional);
    }

    #[test]
    fn classifies_domains_without_overstating_unconfined_protection() {
        assert_eq!(
            classify_domain("unconfined_t", false),
            ProtectionKind::Unconfined
        );
        assert_eq!(
            classify_domain("unconfined_service_t", false),
            ProtectionKind::Unconfined
        );
        assert_eq!(classify_domain("sshd_t", false), ProtectionKind::System);
        assert_eq!(
            classify_domain("anything_t", true),
            ProtectionKind::Microvisor
        );
        assert_eq!(classify_domain("unknown_t", false), ProtectionKind::Unknown);
    }

    #[test]
    fn renders_beginner_explanation_and_sanitizes_terminal_input() {
        let profile = profile();
        let ids = profile.profile.identifiers();
        let snapshot = Snapshot {
            enforcement: "Enforcing".into(),
            profiles: vec![profile],
            processes: vec![ProcessRow {
                pid: 42,
                uid: 1000,
                command: "browser\x1b[2J".into(),
                executable: Some("/opt/browser/browser".into()),
                context: format!("system_u:system_r:{}:s0", ids.app_type),
                domain: ids.app_type,
                kind: ProtectionKind::Microvisor,
                profile_index: Some(0),
            }],
            executables: Vec::new(),
            rules: Vec::new(),
            paths_by_type: BTreeMap::new(),
            rule_error: None,
        };
        let frame = render_frame(&snapshot, &UiState::default(), (220, 24), false);
        assert!(frame.contains("only microvisor_11111111222243338444555555555555_t may access"));
        assert!(!frame.contains("browser\x1b[2J"));
        assert!(frame.contains("browser�[2J"));
    }

    #[test]
    fn renders_process_detail_with_exact_allow_and_deny_explanations() {
        let profile = profile();
        let ids = profile.profile.identifiers();
        let process = ProcessRow {
            pid: 42,
            uid: 1000,
            command: "browser".into(),
            executable: Some("/opt/browser/browser".into()),
            context: format!("system_u:system_r:{}:s0", ids.app_type),
            domain: ids.app_type.clone(),
            kind: ProtectionKind::Microvisor,
            profile_index: Some(0),
        };
        let snapshot = Snapshot {
            enforcement: "Enforcing".into(),
            profiles: vec![profile],
            processes: vec![process.clone()],
            executables: Vec::new(),
            rules: Vec::new(),
            paths_by_type: BTreeMap::new(),
            rule_error: None,
        };
        let detail = ProcessDetail {
            process,
            policy: PolicyInspection::Rules {
                rules: vec![AllowRule {
                    target: "http_port_t".into(),
                    object_class: "tcp_socket".into(),
                    permissions: vec!["name_connect".into()],
                    condition: Some("browser_can_network is true".into()),
                    extended: false,
                }],
                truncated: false,
            },
        };
        let frame = render_process_detail(&snapshot, &detail, 0, (180, 40), false);
        assert!(frame.contains("ALLOWED protected data"));
        assert!(frame.contains("DENIED direct data access"));
        assert!(frame.contains("DENIED ptrace/debugging"));
        assert!(frame.contains("NOT DENIED use of file descriptors"));
        assert!(frame.contains("ALLOW network: http_port_t : tcp_socket"));
        assert!(frame.contains("when browser_can_network is true"));
        assert!(frame.contains("Anything else") || frame.contains("DENIED BY DEFAULT"));
    }

    #[test]
    fn renders_system_process_permissions_without_a_microvisor_profile_section() {
        let process = ProcessRow {
            pid: 7,
            uid: 0,
            command: "sshd".into(),
            executable: Some("/usr/sbin/sshd".into()),
            context: "system_u:system_r:sshd_t:s0".into(),
            domain: "sshd_t".into(),
            kind: ProtectionKind::System,
            profile_index: None,
        };
        let snapshot = Snapshot {
            enforcement: "Enforcing".into(),
            profiles: Vec::new(),
            processes: vec![process.clone()],
            executables: Vec::new(),
            rules: Vec::new(),
            paths_by_type: BTreeMap::from([
                (
                    "ssh_home_t".into(),
                    BTreeSet::from(["/home/[^/]+/.ssh(/.*)?".into()]),
                ),
                ("shadow_t".into(), BTreeSet::from(["/etc/shadow".into()])),
            ]),
            rule_error: None,
        };
        let detail = ProcessDetail {
            process,
            policy: PolicyInspection::Rules {
                rules: vec![
                    AllowRule {
                        target: "ssh_home_t".into(),
                        object_class: "file".into(),
                        permissions: vec!["open".into(), "read".into(), "write".into()],
                        condition: None,
                        extended: false,
                    },
                    AllowRule {
                        target: "shadow_t".into(),
                        object_class: "file".into(),
                        permissions: vec!["open".into(), "read".into()],
                        condition: Some("ssh_read_shadow is true".into()),
                        extended: false,
                    },
                ],
                truncated: false,
            },
        };
        let text = process_detail_lines(&snapshot, &detail).join("\n");
        assert!(text.contains("SYSTEM FILE PERMISSIONS"));
        assert!(text.contains("Home directory contents"));
        assert!(text.contains("✓ ALLOWED for some labeled content — Read or inspect contents"));
        assert!(text.contains("◇ CONDITIONAL for some labeled content"));
        assert!(text.contains("System and service logs (/var/log)"));
        assert!(text.contains("NO MATCHING ALLOW found in this summary"));
        assert!(!text.contains("MICROVISOR PROFILE"));
    }

    #[test]
    fn labels_configured_only_profile_rules_as_planned() {
        let mut profile = profile();
        profile.applied = false;
        let snapshot = Snapshot {
            enforcement: "Enforcing".into(),
            profiles: vec![profile.clone()],
            processes: Vec::new(),
            executables: Vec::new(),
            rules: Vec::new(),
            paths_by_type: BTreeMap::new(),
            rule_error: None,
        };
        let mut lines = Vec::new();
        append_microvisor_policy(&mut lines, &profile, &snapshot);
        let text = lines.join("\n");
        assert!(text.contains("NOT ACTIVE"));
        assert!(text.contains("PLANNED DENY direct data access"));
        assert!(!text.contains("DENIED direct data access"));
    }

    #[test]
    fn parses_navigation_keys() {
        assert_eq!(parse_key(b"\x1b[A", View::Processes), Key::Up);
        assert_eq!(
            parse_key(b"\t", View::Processes),
            Key::Switch(View::Executables)
        );
        assert_eq!(parse_key(&[3], View::Rules), Key::Quit);
        assert_eq!(parse_key(b"\n", View::Processes), Key::Open);
        assert_eq!(parse_key(b"\x1b", View::Processes), Key::Back);
    }

    #[test]
    fn fits_wide_profile_names_to_terminal_columns() {
        let value = fit(" 保護対象ブラウザーのプロファイル ", 16);
        assert!(display_width(&value) <= 16);
        assert!(value.ends_with('…'));
    }

    #[test]
    fn keeps_actual_unconfined_execution_separate_from_expected_profile_domain() {
        let profile = profile();
        let process = ProcessRow {
            pid: 7,
            uid: 1000,
            command: "browser".into(),
            executable: Some(profile.profile.executable.clone()),
            context: "unconfined_u:unconfined_r:unconfined_t:s0".into(),
            domain: "unconfined_t".into(),
            kind: ProtectionKind::Unconfined,
            profile_index: None,
        };
        let rows = collect_executables(&[profile], &[process]);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().any(|row| {
            row.domain == "unconfined_t"
                && row.kind == ProtectionKind::Unconfined
                && row.process_count == 1
        }));
        assert!(
            rows.iter()
                .any(|row| { row.kind == ProtectionKind::Microvisor && row.process_count == 0 })
        );
    }

    #[test]
    fn terminal_enters_raw_mode_reads_keys_and_restores_settings() {
        let mut master = -1;
        let mut slave = -1;
        // openpty initializes both descriptors on success; immediately wrapping them in OwnedFd
        // keeps every test failure path leak-free.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };

        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut original) },
            0
        );
        let terminal = Terminal::enter(slave.as_raw_fd(), slave.as_raw_fd()).unwrap();
        let mut raw = unsafe { std::mem::zeroed::<libc::termios>() };
        assert_eq!(unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut raw) }, 0);
        assert_eq!(raw.c_lflag & (libc::ICANON | libc::ECHO | libc::ISIG), 0);

        let input = b"j";
        assert_eq!(
            unsafe { libc::write(master.as_raw_fd(), input.as_ptr().cast(), input.len()) },
            1
        );
        assert_eq!(
            terminal
                .read_key(Duration::from_millis(100), View::Processes)
                .unwrap(),
            Some(Key::Down)
        );
        drop(terminal);

        let mut restored = unsafe { std::mem::zeroed::<libc::termios>() };
        assert_eq!(
            unsafe { libc::tcgetattr(slave.as_raw_fd(), &mut restored) },
            0
        );
        let flags = libc::ICANON | libc::ECHO | libc::ISIG;
        assert_eq!(restored.c_lflag & flags, original.c_lflag & flags);
    }
}
