# PLANS.md

## Product objective

Microvisor will be a headless, root-operated command-line tool that reconciles versioned YAML
profiles into SELinux policy modules, file-context rules, and labels. It must work from a TTY, an
SSH session, configuration management, or a server provisioning pipeline without GTK, Libadwaita,
a display server, Polkit, or a separate privileged helper.

The security objective remains narrow: protect selected application data from direct
SELinux-mediated access by every domain except the selected application domain. Root operation
simplifies deployment but increases the impact of parser, path-validation, transaction, and command
construction bugs. YAML is therefore an untrusted root input and not merely a convenient settings
format.

## Architecture decision: headless root CLI

Accepted direction:

- One short-lived `microvisor` binary performs validation, rendering, status inspection, apply,
  removal, rollback, and recovery.
- Desired state is read from root-controlled files under `/etc/microvisor/profiles.d/*.yaml`.
- Applied snapshots and transaction records remain separate under `/var/lib/microvisor/`.
- Mutations are serialized with a lock under `/run/microvisor/`.
- No GUI, desktop integration, Polkit action, helper protocol, daemon, or network service is part of
  the target architecture.
- Cargo is the only source-build entry point. Runtime policy compilation invokes the installed
  reference-policy M4 sources, `checkmodule`, and `semodule_package` directly without Make or Meson.
- Server support means headless execution and automated lifecycle tests on named SELinux platforms;
  it does not mean policy portability is assumed.

This supersedes the 0.1 GNOME/Libadwaita and Polkit-helper design. That implementation is migration
history, not a second supported frontend.

## Development and production privilege boundary

- Development environments are strictly unprivileged. Contributors and coding agents must not use
  `sudo`, `su`, `pkexec`, root shells, root-owned development containers, or local root VMs.
- Formatting, unit tests, parsing and rendering tests, compilation, linting, and package-layout
  checks must be runnable without root.
- Privileged SELinux mutation and recovery tests run only in CI's disposable Enforcing VM.
- Root execution is permitted on explicitly designated production systems for installation and
  normal Microvisor operation. Production machines are not development test hosts.
- A test that cannot be completed without local root is deferred to the CI integration matrix; the
  missing local result must be reported rather than bypassing this boundary.

## CLI migration status

The repository now uses the headless architecture:

- Reused and hardened: deterministic TE/CIL generation, path and identifier validation, root UID check,
  transaction lock, applied-profile snapshots, apply/update rollback attempt, label restoration,
  Enforcing-mode QEMU integration harness, and RPM groundwork.
- Applied-state-aware validation allows idempotent commands to recognize unchanged protected paths
  that the active deny complement deliberately hides from the CLI's launch domain. It does not
  bypass filesystem checks for new or changed paths.
- Replaced: per-user JSON profile storage and GUI-to-helper JSON requests with a versioned YAML
  desired-state loader and typed full-set validation.
- Removed: GTK/Libadwaita UI, asynchronous GUI plumbing, `microvisor-helper`, Polkit policy, desktop
  file, AppStream metadata, application icons, GUI build features, and desktop-only dependencies.
- Rewritten: packaging, CI, diagnostics, integration tests, recovery documentation, and application
  discovery assumptions around the single CLI.

The CLI unit and policy tests pass locally. The rewritten CLI transaction path must still pass the
complete disposable-VM recovery matrix before this milestone exits.

## Milestone 0.2: CLI and YAML migration

Priority: highest.

- [x] Define a versioned `schema_version: 1` YAML profile with UUID, display name, executable,
  protected directories, launch domain/role, and explicit hardening booleans.
- [x] Select and review a YAML parser. Demonstrate rejection of duplicate keys, aliases, tags,
  ambiguous coercions, unknown fields, unsupported versions, excessive nesting, oversized files,
  and excessive profile counts.
- [x] Load only regular root-owned configuration files that are not group- or world-writable; use
  race-resistant no-follow opens and deterministic filename ordering.
- [x] Add `validate`, `render <id>`, `apply`, `status`, and `remove <id>` subcommands with stable exit
  codes. Reserve stdout for requested output and stderr for diagnostics.
- [x] Separate parsing, semantic validation, full-set conflict validation, policy rendering,
  reconciliation planning, and privileged execution.
- [x] Make `apply` validate all profiles and compile every generated module before the first host
  mutation.
- [x] Define explicit semantics for YAML deletion: report installed-but-undesired profiles and
  require a documented removal or prune operation rather than silently changing protection.
- [x] Fold the helper's allowlisted command execution, locking, state, apply, rollback, removal, and
  recovery logic into the CLI.
- [x] Make apply idempotent and detect desired/applied/observed drift.
- [x] Atomically persist schema-versioned applied snapshots independently from YAML desired state.
- [x] Replace JSON helper integration tests with CLI tests covering valid and invalid YAML,
  rendering, reconciliation, status, idempotent apply, denial, removal, and recovery ordering.
- [ ] Add deterministic interruption and rollback coverage for every transaction stage.
- [x] Remove GTK, Libadwaita, GLib/GIO, async GUI, directory-discovery, JSON-protocol, and Polkit
  dependencies that are no longer used.
- [x] Remove the GUI sources, helper binary, icons, resources, desktop file, AppStream metadata, and
  Polkit action after replacement tests pass.
- [x] Remove Meson, Ninja, Makefile execution, and build wrappers. Build only with Cargo and let the
  RPM spec install the binary, manual page, and configuration directory directly.
- [x] Add a migration note for users of the unreleased 0.1 JSON profiles; do not auto-import mutable
  per-user configuration as root.

Exit criteria:

- The default build has no GUI, desktop, Polkit, or helper artifacts or dependencies.
- All commands work from a text-only Fedora VM with no graphical packages installed.
- Invalid or unsafe YAML causes no SELinux, file-context, label, state, or log mutation.
- A complete apply/remove cycle is idempotent and recovery is tested from a TTY.

## Milestone 0.3: correctness, transactions, and recovery

- [ ] Confirm generated CIL complement syntax against supported SELinux userspace versions,
  including the declared 3.6 minimum.
- [ ] Verify the intended final allow graph with `sesearch`, including after unrelated policy-module
  changes.
- [ ] Add `apply --check` or equivalent dry-run behavior that compiles all modules and prints a
  deterministic reconciliation plan without installing it.
- [ ] Make `status` compare desired YAML, applied snapshots, installed modules, local fcontext rules,
  and observed labels.
- [ ] Detect partial installations and provide an explicit repair/recover workflow.
- [ ] Journal each mutating transaction to a root-only structured log without profile documents,
  generated policy, or file contents.
- [ ] Add deterministic failpoints and integration tests for interruption and rollback at every
  mutation stage.
- [ ] Preserve and restore compatible pre-existing local fcontext rules rather than blindly
  overwriting them.
- [ ] Define crash-safe directory and file fsync behavior for snapshots and transaction markers.
- [ ] Test configuration/state symlink swaps and path replacement between validation and relabeling.

Exit criteria:

- Applying, updating, interrupting, repairing, and removing any tested profile cannot leave
  orphaned custom labels or an unexplained partial state.
- Recovery remains possible when desired YAML is missing or corrupt because it uses the trusted
  applied snapshot.

## Milestone 0.4: server operations

- [ ] Document non-interactive provisioning with explicit exit codes and a versioned
  machine-readable status format.
- [ ] Provide example configuration-management deployment without adding a remote API or daemon.
- [ ] Define whether systemd oneshot reconciliation is useful and safe; do not enable automatic
  policy mutation at boot until failure and recovery behavior is tested.
- [ ] Detect package updates that replace a configured executable and report drift before relabeling.
- [ ] Add workload presets only as reviewed, static examples; never execute discovery commands from
  YAML.
- [ ] Test service launch domains and systemd-managed workloads in addition to interactive desktop
  applications.
- [ ] Define log rotation, audit retention, and integration with the system journal.
- [x] Add a manual page covering configuration ownership, deployment, status, rollback, and
  emergency recovery.

Exit criteria:

- A configuration-management system can validate, apply, verify, and remove profiles without a TTY
  or graphical session.
- Server support is backed by Enforcing-mode tests of real systemd services and documented launch
  domains.

## Milestone 0.5: stronger launch mediation

The current policy model transitions any execution of the selected entrypoint from the configured
launch domain. A malicious process in that domain may deliberately launch the protected application
with unsafe arguments or use it as a confused deputy.

Research and prototype:

- [ ] A dedicated launcher domain that is the only source permitted to transition into the
  application domain.
- [ ] An argument allowlist suitable for services and interactive applications without introducing
  a long-running root broker.
- [ ] Separate UNIX account or user-namespace designs for workloads requiring stronger isolation.
- [ ] Interaction with systemd service hardening, containers, Flatpak, Bubblewrap, and existing
  application sandboxes.
- [ ] Whether SELinux constraints or MLS/MCS categories add meaningful caller distinction.
- [ ] Safe handling of D-Bus activation, sockets, and single-instance applications.

Do not ship a "strict" mode until it is shown to resist a malicious process already running in the
configured launch domain.

## Milestone 0.6: policy portability

- [ ] Define supported base-policy capabilities rather than assuming Fedora reference-policy
  interfaces.
- [ ] Detect distribution, policy type, policy store, enabled mode, and installed interfaces.
- [ ] Evaluate Fedora Server and Workstation first, then RHEL, CentOS Stream, AlmaLinux, Rocky Linux,
  and SELinux-enabled Debian derivatives.
- [ ] Generate policy from a capability model with explicit unsupported states.
- [ ] Build native RPM packages without desktop dependencies; evaluate other packaging only after
  the target distribution has an integration test.

Exit criteria:

- Every supported distribution has automated headless install, validate, apply, denial, update,
  drift, recovery, and removal tests.

## Milestone 1.0: release requirements

- [ ] Independent review of root input parsing, path handling, race resistance, command construction,
  state storage, and transaction recovery.
- [ ] Independent SELinux policy review.
- [ ] Complete Enforcing-mode integration matrix.
- [ ] Stable versioned YAML schema and machine-readable output with documented compatibility rules.
- [ ] Signed release artifacts and reproducible build notes.
- [ ] Security policy and vulnerability-reporting process.
- [ ] Administrator documentation covering threat model, limitations, deployment, audit, and
  emergency recovery.
- [ ] No known path that leaves a tested system in an unrecoverable mislabeled state.

## Integration test matrix

Track results for each combination:

| Dimension | Initial targets |
|---|---|
| Distribution | Fedora 44 Server and Workstation |
| SELinux userspace | Current Fedora version; minimum-compatibility VM with 3.6 |
| Base policy | Fedora targeted policy current stable |
| Host environment | Text-only systemd server; GNOME Wayland workstation |
| Workload | A systemd service; Google Chrome; Chromium; Firefox |
| Launch source | Service-specific domain; `unconfined_t` / `unconfined_r` |
| Data | Config directory, cache/state directory, Unix socket, symlink, mmap |
| Adversary domain | `unconfined_t`, `staff_t`, `container_t`, test service domain |
| Configuration | Valid, duplicate key, unknown field, unsafe mode/owner, symlink, oversized |
| Operations | Validate, render, fresh apply, idempotent apply, update, drift, prune/remove, interrupted apply, repair |

For each tested combination, record:

- exact OS, SELinux userspace, kernel, and base-policy versions;
- desired, applied, and observed status before and after reconciliation;
- process contexts and file labels;
- relevant `sesearch` output;
- successful workload functionality;
- denied direct access from every tested adversary domain;
- successful removal, label restoration, and absence of both modules;
- behavior after interruption at every transaction stage.

## Open technical questions

1. Which Rust YAML implementation can enforce duplicate-key rejection, disable aliases/tags and
   ambiguous coercions, and apply resource limits without maintaining a custom parser?
2. Should `apply` require an explicit `--prune` to remove installed profiles missing from desired
   YAML, or should removal remain exclusively `remove <id>`?
3. How can configuration and target paths be opened and revalidated to minimize symlink, mount, and
   replacement races across external SELinux commands?
4. Does a complement-based `deny` remain stable when new policy modules and types are added, or must
   profiles be rebuilt after every policy transaction?
5. Which domains legitimately need `fd use` or `ptrace` access to protected desktop and server
   workloads, and can they be allowed without creating an exfiltration path?
6. Can existing distribution-specific application or service domains be reused safely instead of
   creating an unconfined-compatible domain?
7. How should applied snapshots evolve across YAML schema and Microvisor binary upgrades without
   compromising recovery?
8. Should a dedicated recovery domain be excluded from the deny complement, and how should access
   to it be authenticated?

## Deferred ideas

- Signed organization-wide profile bundles.
- MCS category allocation for containers and services.
- Human-reviewed AVC suggestions based on explicitly selected audit records.
- A read-only local status exporter after the CLI and threat model are stable.

These are deferred until configuration parsing, correctness, recovery, and the launch threat model
are resolved. A GUI, Polkit helper, daemon, and remote mutation API are intentionally not deferred
features; they are outside the chosen architecture.
