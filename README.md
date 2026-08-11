# Microvisor

Microvisor is a planned headless, root-operated command-line tool for managing per-application
SELinux protection profiles. Profiles are declared as YAML files, so the same configuration can be
reviewed, versioned, and deployed on workstations and servers without a graphical session.

A profile creates:

- a dedicated application domain such as `microvisor_<id>_t`;
- a dedicated executable type and data type;
- a type transition from a configured launch domain;
- an unconfined-compatible application domain for software without an existing confined domain;
- a CIL `deny` module that subtracts access to the protected data type from every type except the
  protected application domain;
- optional cross-domain `ptrace` and file-descriptor restrictions.

## Transition status

The repository is changing architecture. The checked-in 0.1 implementation still contains the
GNOME/Libadwaita frontend, a Polkit helper, and JSON request handling. Those components are legacy
code and will be removed. The YAML CLI described below is the target architecture and is not yet a
usable release.

Do not deploy the current code as a security product. SELinux base policies vary between
distributions, and generated policy and recovery behavior require review and Enforcing-mode tests.
See `PLANS.md` for the migration sequence and acceptance criteria.

## Target operation

Microvisor will run as one short-lived root process. It will not contain a GUI, depend on a desktop
session, use Polkit, or delegate work to a separate helper. Root is required because policy module
installation, file-context changes, and relabeling are privileged operations.

The initial command interface is planned as:

```bash
sudo microvisor validate
sudo microvisor render <profile-id>
sudo microvisor apply
sudo microvisor status
sudo microvisor remove <profile-id>
```

`apply` will reconcile the complete desired configuration under
`/etc/microvisor/profiles.d/`. It must validate every profile and compile all generated policy
before changing the host. Mutating operations will be serialized by a root-owned runtime lock and
will retain root-owned applied-state snapshots under `/var/lib/microvisor/` for rollback and
recovery. The implementation must never invoke a shell with values taken from YAML.

## Planned YAML configuration

Each `/etc/microvisor/profiles.d/*.yaml` file will contain one versioned profile. The provisional
schema is:

```yaml
schema_version: 1
id: 11111111-2222-4333-8444-555555555555
name: Google Chrome
executable: /opt/google/chrome/chrome
data_directories:
  - /home/alice/.config/google-chrome
  - /home/alice/.cache/google-chrome
launch_domain: unconfined_t
launch_role: unconfined_r
block_ptrace: true
block_fd_use: true
```

The exact schema remains subject to change until the migration milestone is complete. Parsers will
reject unknown or duplicate fields, unsupported schema versions, aliases or non-scalar tricks,
oversized input, invalid SELinux identifiers, relative or broad paths, missing targets, and
profiles whose paths overlap. Configuration files must be regular, root-owned, and not writable by
group or other users. Applied-state snapshots are internal data, not configuration inputs.

## Target requirements

The first supported platform remains Fedora with SELinux Enforcing. The headless build will require:

- Rust 1.85 or newer;
- SELinux userspace 3.6 or newer, because Microvisor relies on CIL `deny` rules;
- `policycoreutils`, `policycoreutils-python-utils`, `libselinux-utils`, `checkpolicy`, and the
  reference-policy development Makefile from `selinux-policy-devel`.

GTK, Libadwaita, a display server, a desktop environment, and Polkit will not be required after the
migration. Server support means headless operation on explicitly tested SELinux distributions; it
does not imply that every SELinux policy family is supported.

## Diagnostics and audit trail

The CLI will write human-readable diagnostics to standard error and reserve standard output for
requested output such as rendered policy or machine-readable status. Diagnostics must not dump
complete YAML documents, generated policy, or sensitive file contents. Mutating transactions are
planned to be recorded in a root-only audit log with profile ID, operation, stage, and result.

## Threat model and limitations

Microvisor is intended to block **direct SELinux-mediated access** from unrelated applications,
services, containers, and other TE domains. It does not defend against:

- an administrator who can modify Microvisor configuration, SELinux policy, or boot settings;
- kernel compromise;
- malicious code executing inside the protected application's own domain;
- abuse of the protected application's arguments, debugging interfaces, plugins, extensions, or
  IPC APIs;
- data intentionally exported by the protected application;
- confused-deputy attacks permitted by the chosen launch domain.

Running Microvisor as root does not make YAML trusted. A hostile or accidentally malformed profile
could otherwise direct privileged relabeling at critical system paths. Validation, deterministic
command construction, transaction ordering, rollback, and recovery are therefore security
boundaries.

## Recovery principles

Microvisor must remove the profile-specific deny module before attempting recovery or relabeling.
It must then restore file contexts and remove the base module. Never remove a base module while
files still carry its custom types.

Until the new CLI and its recovery flow are implemented and tested in a disposable SELinux
Enforcing VM, use the existing integration test only as evidence for the legacy helper—not as
evidence that the target architecture is complete.
