# AGENTS.md

## Purpose

This file defines the working contract for coding agents contributing to Microvisor. The project is
security-sensitive: syntactically valid code can still weaken isolation, damage host labeling, or
make a server unbootable. Microvisor is a headless, YAML-configured CLI that runs entirely as root.

Production execution and development are separate trust domains. Never use `sudo`, `su`,
`pkexec`, a root shell, or a root-owned container in a developer workstation or other development
environment. Build, lint, unit-test, render-test, and package-layout checks must run as an
unprivileged user. Root execution is permitted only in CI's disposable SELinux Enforcing VM and on
an explicitly designated production target. Do not use a production host for development tests.

## Target architecture

- `microvisor` is a short-lived command-line program. It has no GUI, display-server, desktop-session,
  Polkit, or helper-process dependency.
- Root-only operations and orchestration live in the main binary. Do not reintroduce an RPC or
  privilege-separation protocol without an approved design change.
- Desired profiles are versioned YAML files under `/etc/microvisor/profiles.d/`.
- Applied-state snapshots under `/var/lib/microvisor/` are root-owned recovery data and are never a
  substitute for validating desired configuration.
- Mutating transactions are serialized by a root-owned runtime lock under `/run/microvisor/`.
- The CLI must work without a graphical session and must keep stdout suitable for requested policy
  or machine-readable output.

## Project map

- `src/main.rs`: root CLI argument handling and output/exit-code contract.
- `src/config.rs`: secure YAML discovery, bounded parsing, ownership checks, and schema loading.
- `src/engine.rs`: privileged SELinux orchestration, state, locking, transactions, and recovery.
- `src/policy.rs`: pure SELinux policy generation and input validation; preserve and extend it.
- `src/model.rs`: versioned YAML profile and derived policy identifiers.
- `tests/policy.rs`: deterministic policy-generator and validation tests.
- `tests/selinux-integration.sh`: CLI reconciliation and recovery coverage in a disposable SELinux
  Enforcing Fedora VM.
- `.github/scripts/run-fedora-selinux-vm.rs`: QEMU lifecycle and guest provisioning for CI.
- `.github/workflows/ci.yml`: fast headless build, unit, lint, and package-layout checks.
- `.github/workflows/selinux-integration.yml`: destructive Enforcing-mode integration tests.
- `data/microvisor.8`: installed command, configuration, exit-status, and recovery reference.
- `PLANS.md`: roadmap and decisions not yet implemented.

## Non-negotiable security boundaries

1. Refuse every command except non-mutating help/version output unless the effective UID is zero.
2. Never invoke a shell with configuration values. Use `std::process::Command` argument arrays and
   an explicit executable allowlist.
3. Treat YAML as hostile input even when read from `/etc`. Bound total file size and profile count;
   reject unknown and duplicate fields, unsupported schema versions, aliases, tags, non-UTF-8 or
   control characters, and ambiguous scalar coercions.
4. Read only regular, root-owned configuration files that are not group- or world-writable. Do not
   follow symlinks when discovering or opening configuration and state files.
5. Reject relative or overly broad paths, `/`, invalid SELinux identifiers, missing targets,
   filesystem-boundary surprises, and executable or data paths that overlap another profile.
6. Validate the complete configuration set and compile every generated module before the first
   host mutation. A failure in one profile must not cause a partial reconciliation.
7. Install the deny module only after executable and data relabeling succeeds. Remove the deny
   module before attempting recovery or relabeling.
8. Keep applied-state and transaction-log directories root-owned with mode `0700` and sensitive
   files at `0600`. Commit state atomically with fsync and rename; do not trust partially written
   snapshots for recovery.
9. Serialize mutations with the root-owned runtime lock. Interrupted apply/update/remove operations
   must be detectable, and failed updates must attempt rollback to the previous applied snapshot.
10. Never replace policy review with `audit2allow -a`. Understand AVCs individually.
11. Do not weaken the deny complement or add allowed domains without documenting the threat-model
    impact and adding deterministic tests.
12. Treat `unconfined_domain()` as a compatibility mechanism, not confinement. The deny module is
    what protects profile data.
13. Do not add a daemon, network listener, remote API, templating engine, environment substitution,
    or arbitrary include mechanism merely to support servers. Each expands the root input surface.

## CLI and configuration requirements

- Use subcommands with explicit semantics: `validate` and `render` are read-only; `apply` and
  `remove` mutate host state; `status` compares desired, applied, and observed SELinux state.
- `apply` reconciles the complete configuration directory. Never silently preserve an installed
  profile whose desired YAML was removed; require an explicit, documented removal policy.
- Version the YAML schema from the first release. Unknown fields are errors, not warnings.
- Ensure stable deterministic rendering independent of YAML field order and filesystem enumeration
  order.
- Keep user-facing errors actionable without printing whole configuration documents or sensitive
  paths unnecessarily. Machine-readable output must use an explicitly versioned schema.
- Destructive or recovery commands must identify their exact profile and planned changes. An
  interactive prompt is not a security boundary and must not be required for automation.
- Defaults affecting policy strength must be explicit in documentation and tests. Do not silently
  change them between schema versions.

## Build and test workflow

During the migration, run the checks applicable to the code that remains. The target fast workflow
is:

```bash
cargo fmt --check
cargo test --locked
cargo check --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
meson setup build --wipe
meson compile -C build
```

The default feature set must build the headless CLI and must not link GTK or Libadwaita. Packaging
checks must verify that no desktop, AppStream, icon-cache, helper, or Polkit artifacts are installed.

For SELinux integration changes, test in a disposable Fedora VM with Enforcing mode enabled. At
minimum verify the following in CI. Do not run these privileged integration steps in a development
environment:

```bash
# Validate and preview without mutation
microvisor validate
microvisor render '<profile-id>'

# Apply and inspect
microvisor apply
microvisor status
ps -eZ | grep -i '<application>'
sesearch -A -s unconfined_t -t microvisor_<id>_data_t
sesearch -A -s microvisor_<id>_t -t microvisor_<id>_data_t

# Direct access from a non-allowed domain must fail
cat /path/to/protected/file

# Removal must restore labels and remove both modules
microvisor remove '<profile-id>'
semodule -l | grep microvisor_<id>
semanage fcontext -l -C | grep microvisor_<id>
```

Also test invalid YAML, unsafe ownership/modes, symlinks, duplicate keys, oversized inputs,
overlapping profiles, interrupted transactions, rollback, idempotent apply, stale installed state,
and operation from a TTY with no graphical session. Record the exact Fedora version, SELinux
userspace version, base policy version, init/service context, launch domain, and tested workload in
the pull request.

## Code style

- Rust edition 2024; the minimum Rust version is declared in `Cargo.toml`.
- Keep parsing, semantic validation, policy rendering, reconciliation planning, and host mutation as
  separate layers. Parsing or rendering tests must not require root.
- Keep policy rendering and reconciliation plans pure, deterministic, and independently testable.
- Prefer typed errors with context over string-only error propagation.
- Keep unsafe code isolated and document its invariant. Root checks and race-resistant filesystem
  operations require focused review.
- Do not add a dependency for functionality available in the standard library without justification.
  A YAML dependency requires review for duplicate-key behavior, aliases/tags, resource limits, and
  maintenance status.
- Public configuration and machine-output structures require backward-compatibility consideration.
- Write code comments in English. Comment the reason, invariant, or security consequence at root
  input boundaries, policy-ordering constraints, recovery paths, filesystem race defenses, unsafe
  code, and non-obvious transaction boundaries.
- Do not add comments that merely restate straightforward code.

## Change protocol for agents

Before editing:

1. Read `README.md`, this file, and the relevant section of `PLANS.md`.
2. Identify whether the change touches root input handling, policy semantics, installation,
   transaction ordering, state compatibility, or recovery.
3. For policy or configuration changes, write or update deterministic tests first.
4. Inspect the Git worktree and keep pre-existing user changes out of agent-created commits.

While editing:

1. Keep each patch scoped to one migration or security objective.
2. Update documentation when the schema, assumptions, commands, paths, or supported versions change.
3. Do not silently alter defaults that affect policy strength.
4. At suitable checkpoints, run focused checks, inspect the diff, and commit with
   `git commit -m "<imperative summary>"`.
5. Keep each validated behavioral or documentation unit independently reviewable and reversible.
6. Do not amend, squash, or rewrite existing commits unless the user explicitly requests it.

After editing:

1. Run the applicable checks.
2. State which checks were not possible and why.
3. Add newly discovered work to `PLANS.md` rather than leaving undocumented TODO comments.

## Prohibited shortcuts

- Using root anywhere in a development environment, including local VMs or containers. Privileged
  testing belongs in CI's disposable integration VM; root execution on designated production
  systems is permitted for deployment and operation only.
- Retaining the GUI or helper as a second supported architecture.
- Loading configuration from a non-root user's home directory or environment variables.
- Passing arbitrary command strings to a shell.
- Generating policy from raw, unvalidated identifiers or paths.
- Mutating the host before validating and compiling the complete desired configuration.
- Using broad writable temporary locations for policy build artifacts.
- Installing a deny rule before a tested recovery path exists.
- Treating YAML file ownership alone as sufficient validation.
- Claiming server or cross-distribution support based only on compilation.
- Treating a successful command or workload start as proof of isolation.
