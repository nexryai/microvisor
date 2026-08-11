# Microvisor

Microvisor is a headless, root-operated command-line tool for managing per-application SELinux
protection profiles. Profiles are declared as YAML files, so the same configuration can be
reviewed, versioned, and deployed on workstations and servers without a graphical session.

A profile creates:

- a dedicated application domain such as `microvisor_<id>_t`;
- a dedicated executable type and data type;
- a type transition from a configured launch domain;
- an unconfined-compatible application domain for software without an existing confined domain;
- a CIL `deny` module that subtracts access to the protected data type from every type except the
  protected application domain;
- optional cross-domain `ptrace` and file-descriptor restrictions.

Microvisor runs as one short-lived root process. It has no GUI, helper process, Polkit, desktop
session, display-server, or network-service dependency. Root is required because policy module
installation, file-context changes, and relabeling are privileged operations.

## Status

This repository is an experimental Fedora-first implementation, not a finished security product.
The headless YAML CLI is implemented, but the new transaction path still requires completion of the
SELinux Enforcing integration matrix before production use. SELinux base policies vary between
distributions, and generated policy and recovery behavior require review.

## Requirements

The initial target is Fedora 44 Server and Workstation with SELinux Enforcing and:

- Rust 1.85 or newer for building;
- SELinux userspace 3.6 or newer, because Microvisor relies on CIL `deny` rules;
- `policycoreutils`, `policycoreutils-python-utils`, `libselinux-utils`, `checkpolicy`, `m4`, and the
  reference-policy headers from `selinux-policy-devel`.

GTK, Libadwaita, a display server, a desktop environment, and Polkit are not required. Server
support means headless operation on explicitly tested SELinux distributions; it does not imply
that every SELinux policy family is supported.

CI container provisioning example (the CI container runs as root):

```bash
dnf install \
  cargo rust \
  policycoreutils policycoreutils-python-utils \
  libselinux-utils selinux-policy-devel checkpolicy m4
```

Provision equivalent dependencies before entering a local development environment. Development
must stay unprivileged: do not run `sudo`, a root shell, a root-owned container, or Microvisor as
root on a developer machine. Formatting, unit tests, compilation, and package-layout checks do not
require root. Privileged SELinux integration runs only in CI's disposable Enforcing VM. Root is
allowed on a designated production target for installation and normal Microvisor operation.

## Build and install

Build as an unprivileged user:

```bash
cargo build --release --locked
```

The project has no Makefile or Meson layer. Cargo is the only source-build entry point.

Install only on a designated production target (or use the RPM package):

```bash
sudo install -Dpm 0755 target/release/microvisor /usr/local/bin/microvisor
sudo install -Dpm 0644 data/microvisor.8 /usr/local/share/man/man8/microvisor.8
sudo install -d -m 0755 /etc/microvisor/profiles.d
```

This installs the CLI, its manual page, and `/etc/microvisor/profiles.d/`. It does not install a
daemon or enable automatic policy mutation at boot.

## YAML configuration

Each `/etc/microvisor/profiles.d/*.yaml` file contains one versioned profile:

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

On a designated production target, configuration files must be regular, root-owned, have exactly
one hard link, and not be writable by group or other users. The configuration directory must also
be root-owned, non-writable by group or other users, and not a symlink. A typical setup is:

```bash
sudo install -d -m 0755 /etc/microvisor/profiles.d
sudo install -o root -g root -m 0600 chrome.yaml \
  /etc/microvisor/profiles.d/chrome.yaml
```

The loader accepts a deliberately restricted YAML subset. It rejects unknown or duplicate fields,
unsupported schema versions, ambiguous booleans, tags, anchors, aliases, merge keys, document
streams, excessive nesting or node counts, oversized files, invalid SELinux identifiers, unsafe
paths, missing targets, and overlapping profiles.

## Commands

Run these commands as root only on a designated production target or in the CI integration VM:

```bash
sudo microvisor validate
sudo microvisor render <profile-id>
sudo microvisor apply
sudo microvisor status
sudo microvisor remove <profile-id>
```

- `validate` parses, normalizes, and validates the complete configuration without changing SELinux.
- `render` prints deterministic TE/CIL policy and file-context operations for review.
- `apply` validates all profiles and builds every base module before the first host mutation. It is
  idempotent and attempts batch rollback if a later profile fails.
- `status` compares desired profiles, root-owned snapshots, installed modules, and local
  file-context rules. Exit status 2 means drift.
- `remove` trusts the root-owned applied snapshot rather than mutable YAML when restoring labels.

Deleting YAML does not silently remove installed protection. `status` reports
`installed-without-config`; use `remove <profile-id>` explicitly.

Mutating operations are serialized by `/run/microvisor/transaction.lock`. Applied-state snapshots
are atomically stored with mode `0600` under `/var/lib/microvisor/profiles/`, whose mode is `0700`.
Snapshots are internal recovery data, not configuration input.

## Diagnostics

Microvisor writes diagnostics to standard error and reserves standard output for requested output
such as rendered policy and status. Diagnostics identify the component, operation, profile ID, and
result without dumping YAML documents, generated policy, or file contents.

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
command construction, transaction ordering, rollback, and recovery are security boundaries.

## Recovery principles

Microvisor removes the profile-specific deny module before attempting recovery or relabeling. It
then restores file contexts and removes the base module. Never remove a base module while files
still carry its custom types.

Inspect state with:

```bash
sudo microvisor status
sudo semodule -l | grep microvisor
sudo semanage fcontext -l -C | grep microvisor
```

Use `microvisor remove <profile-id>` whenever the applied snapshot is intact. Manual recovery must
preserve the same deny-module-first ordering described in the manual page and `AGENTS.md`.

## Legacy 0.1 profiles

Microvisor does not import the unreleased GUI version's per-user `profiles.json`. Automatically
trusting mutable user configuration in a root process would cross the new privilege boundary.
Recreate required profiles as reviewed, root-owned YAML files and validate them before applying.
