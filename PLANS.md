# PLANS.md

## Product objective

Microvisor should let a desktop user select an application and sensitive data directories, inspect the generated SELinux policy, apply it through Polkit, verify that it is active, and safely remove or recover it. The long-term goal is a usable policy-management frontend without hiding SELinux's security model or recovery requirements.

## Current milestone: 0.1 MVP

Implemented in this repository:

- Rust/GTK 4/Libadwaita application shell.
- GNOME HIG-oriented protected-application list and adaptive dialogs.
- Code-defined `AdwShortcutsDialog` with Add, Shortcuts, and Quit actions.
- GNOME-style full-color and symbolic SVG icons.
- Per-profile model and user configuration storage.
- Pure generation of a reference-policy TE module and a CIL deny module.
- File-context preview for the executable and protected directories.
- Polkit-authenticated helper with root-side profile state.
- Copr-ready native RPM packaging with locked, vendored Rust dependencies.
- Helper-side path canonicalization, broad/overlapping path rejection, command allowlisting, and collision checks.
- SELinux userspace 3.6 minimum-version check before policy mutation.
- Apply, update with rollback attempt, remove, and label restoration flows.
- Optional ptrace and foreign-FD restrictions.
- Basic unit tests for policy output and path validation.
- GitHub Actions integration test that boots a pinned Fedora 44 Cloud image under QEMU, confirms
  SELinux Enforcing mode, and exercises apply, denial, domain transition, and removal.
- `AGENTS.md` contributor contract and CI outline.

The MVP is intentionally Fedora-first and should be treated as experimental until the integration test matrix below is completed.

## Milestone 0.2: correctness and recovery

Priority: highest.

- [ ] Compile and run the project on Fedora 44 with SELinux Enforcing.
- [x] Add a QEMU-based Fedora 44 Enforcing integration harness to GitHub Actions.
- [ ] Confirm the generated CIL complement syntax against SELinux userspace 3.6, 3.8, 3.9, and 3.10.
- [ ] Verify that `unconfined_domain()` plus the deny module produces the intended final allow graph using `sesearch`.
- [x] Detect the minimum SELinux userspace version before changing labels.
- [ ] Add a dry-run operation that compiles both modules without installing them.
- [ ] Add a helper status operation that compares installed modules, local fcontext rules, and root-side profile state.
- [ ] Detect partial installations and expose a Repair action.
- [ ] Journal every privileged transaction to `/var/log/microvisor/transactions.jsonl` without recording sensitive file contents.
- [ ] Add deterministic failpoints and integration tests for rollback at every apply stage.
- [ ] Preserve and restore pre-existing local fcontext rules rather than rejecting or overwriting them.
- [ ] Add a command-line recovery utility that does not depend on GTK.

Exit criteria:

- Applying, updating, interrupting, and removing a profile cannot leave orphaned custom labels in the tested matrix.
- Recovery is documented and tested from a TTY.

## Milestone 0.3: application discovery and UX

- [ ] Discover installed applications from desktop files.
- [ ] Resolve `Exec=` launchers to likely final executables while showing the resolution chain.
- [ ] Offer curated presets for Chrome, Chromium, Firefox, and selected Electron applications.
- [ ] Detect common data directories without selecting them automatically.
- [ ] Show the current SELinux process domain after launching an application.
- [ ] Add per-profile diagnostics with actionable AVC summaries.
- [ ] Add a first-run explanation of the threat model and a link to recovery instructions.
- [ ] Add search and sorting when the profile list becomes large.
- [ ] Add localization infrastructure and Japanese translations.
- [ ] Add help pages suitable for GNOME Help/Yelp.
- [ ] Add accessibility checks with Orca and keyboard-only navigation.

Exit criteria:

- A user can configure a supported application without manually locating its ELF binary.
- All essential operations work at 360 px width and with 200% text scaling.

## Milestone 0.4: stronger launch mediation

The current model transitions any execution of the selected entrypoint from the configured launch domain. A malicious process in that domain may deliberately launch the protected application with unsafe command-line flags or use it as a confused deputy.

Research and prototype:

- [ ] A dedicated launcher domain that is the only source permitted to transition into the application domain.
- [ ] A brokered launch protocol with an allowlisted argument schema per application.
- [ ] Systemd user service activation and whether same-user callers can bypass the intended policy.
- [ ] Separate UNIX account or user namespace designs for applications requiring stronger isolation.
- [ ] Interaction with Flatpak portals, Bubblewrap, and application sandboxing.
- [ ] Whether SELinux constraints or MLS/MCS categories can add a meaningful caller distinction.
- [ ] Safe handling of single-instance applications and D-Bus activation.

Do not ship a "Strict" label until the design is shown to resist a malicious process already running as the desktop user.

## Milestone 0.5: policy portability

- [ ] Define supported base-policy capabilities rather than assuming Fedora reference-policy interfaces.
- [ ] Detect distribution, policy type, policy store, and installed interfaces.
- [ ] Evaluate RHEL, CentOS Stream, AlmaLinux, Rocky Linux, and SELinux-enabled Debian derivatives.
- [ ] Generate policy from a capability model with explicit unsupported states.
- [x] Add package builds for RPM first; evaluate Flatpak only for the unprivileged UI, with a separately packaged host helper.
- [ ] Add AppStream screenshots after the UI stabilizes.

Exit criteria:

- Each supported distribution has automated install, apply, denial, update, and recovery tests.

## Milestone 1.0: release requirements

- [ ] Independent review of the privilege boundary and command construction.
- [ ] Independent SELinux policy review.
- [ ] Complete integration test matrix.
- [ ] Stable serialized helper protocol with version negotiation.
- [ ] Signed release artifacts and reproducible build notes.
- [ ] Security policy and vulnerability-reporting process.
- [ ] User documentation covering limitations and emergency recovery.
- [ ] No known path that leaves a system in an unrecoverable mislabeled state.

## Integration test matrix

Track results for each combination:

| Dimension | Initial targets |
|---|---|
| Distribution | Fedora 44 Workstation |
| SELinux userspace | 3.10; minimum-compatibility VM with 3.6 |
| Base policy | Fedora targeted policy current stable |
| Session | GNOME Wayland |
| Application | Google Chrome stable, Chromium, Firefox |
| Launch source | `unconfined_t` / `unconfined_r` |
| Data | config directory, cache directory, Unix socket, symlink, mmap |
| Adversary domain | `unconfined_t`, `staff_t`, `container_t`, a test service domain |
| Operations | fresh apply, update executable, add/remove directory, uninstall, interrupted apply |

For each row, record:

- process context before and after launch;
- file labels;
- relevant `sesearch` output;
- successful application functionality;
- denied direct access from every tested adversary domain;
- successful removal and restoration.

## Open technical questions

1. Does a complement-based `deny` remain stable when new policy modules and types are added after a Microvisor profile is installed, or must profiles be rebuilt after every policy transaction?
2. Which domains legitimately need `fd use` against a protected desktop application on modern GNOME, and can they be allowlisted without creating an exfiltration path?
3. How should Microvisor distinguish package updates that replace the selected executable from user-initiated profile drift?
4. Can existing distribution-specific application domains be reused safely instead of creating an unconfined-compatible domain?
5. What is the least disruptive way to protect browser profile data while preserving portals, keyrings, crash reporting, hardware acceleration, and native messaging?
6. How can root-side state and local user configuration be reconciled after restoring a system backup?
7. Should the deny module exclude a dedicated recovery domain in addition to the application domain, and how should access to that domain be authenticated?

## Deferred ideas

- Visual policy graph.
- Import/export of signed profile bundles.
- Organization-wide policy deployment.
- AVC learning mode with human-reviewed suggestions.
- MCS category allocation for containers and desktop applications.
- Integration with systemd-homed or encrypted per-application storage.

These are deferred until correctness, recovery, and the launch threat model are resolved.
