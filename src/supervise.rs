use crate::engine::{self, SupervisionProfile};
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
    process::Stdio,
    time::{Duration, Instant},
};

const MAX_FCONTEXT_OUTPUT: u64 = 16 * 1024 * 1024;
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

#[derive(Debug)]
struct Snapshot {
    enforcement: String,
    profiles: Vec<SupervisionProfile>,
    processes: Vec<ProcessRow>,
    executables: Vec<ExecutableRow>,
    rules: Vec<FcontextRule>,
    rule_error: Option<String>,
}

#[derive(Debug)]
struct UiState {
    view: View,
    selected: [usize; 3],
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            view: View::Processes,
            selected: [0; 3],
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
                Key::Ignored => {}
            }
            terminal.draw(&render_frame(&snapshot, &state, terminal.size(), true))?;
        }

        if refreshed.elapsed() >= REFRESH_INTERVAL {
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
    let (rules, rule_error) = match collect_fcontext_rules(&profiles) {
        Ok(rules) => (rules, None),
        Err(error) => (Vec::new(), Some(format!("{error:#}"))),
    };
    Snapshot {
        enforcement,
        profiles,
        processes,
        executables,
        rules,
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

fn collect_fcontext_rules(profiles: &[SupervisionProfile]) -> Result<Vec<FcontextRule>> {
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
    let mut rules = text
        .lines()
        .filter_map(parse_fcontext_rule)
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
    Ok(rules)
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
            " ↑/↓ or j/k Select   Tab/1/2/3 View   r Refresh   q/Ctrl-C Quit",
            width,
        ),
        "30;47",
        color,
    ));
    lines.truncate(height);
    format!("\x1b[H{}", lines.join("\x1b[K\r\n"))
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
    Switch(View),
    Refresh,
    Ignored,
}

fn parse_key(bytes: &[u8], current: View) -> Key {
    match bytes {
        b"q" | b"Q" | [3] => Key::Quit,
        b"k" | b"K" | b"\x1b[A" => Key::Up,
        b"j" | b"J" | b"\x1b[B" => Key::Down,
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
            rule_error: None,
        };
        let frame = render_frame(&snapshot, &UiState::default(), (220, 24), false);
        assert!(frame.contains("only microvisor_11111111222243338444555555555555_t may access"));
        assert!(!frame.contains("browser\x1b[2J"));
        assert!(frame.contains("browser�[2J"));
    }

    #[test]
    fn parses_navigation_keys() {
        assert_eq!(parse_key(b"\x1b[A", View::Processes), Key::Up);
        assert_eq!(
            parse_key(b"\t", View::Processes),
            Key::Switch(View::Executables)
        );
        assert_eq!(parse_key(&[3], View::Rules), Key::Quit);
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
