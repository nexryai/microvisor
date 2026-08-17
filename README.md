# Microvisor

Microvisor is a headless, root-operated command-line tool for managing per-application SELinux
protection profiles. Profiles are declared together in one YAML file, so the same configuration can
be reviewed, versioned, and deployed on workstations and servers without a graphical session.

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
- `policycoreutils`, `policycoreutils-python-utils`, `libselinux-utils`, `checkpolicy`, `m4`,
  `setools-console`, and the reference-policy headers from `selinux-policy-devel`.

GTK, Libadwaita, a display server, a desktop environment, and Polkit are not required. Server
support means headless operation on explicitly tested SELinux distributions; it does not imply
that every SELinux policy family is supported.

CI container provisioning example (the CI container runs as root):

```bash
dnf install \
  cargo rust \
  policycoreutils policycoreutils-python-utils \
  libselinux-utils selinux-policy-devel checkpolicy m4 setools-console
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
sudo install -o root -g root -m 0600 data/microvisor.yml /etc/microvisor.yml
```

This installs the CLI, its manual page, and an empty `/etc/microvisor.yml`. It does not install a
daemon or enable automatic policy mutation at boot.

## COPR packaging

COPR's SCM `make_srpm` method is supported by the dedicated [.copr/Makefile](.copr/Makefile). It
archives the checked-out Git commit, vendors the exact `Cargo.lock` dependency set, and writes one
SRPM to COPR's requested `outdir`. This Makefile is packaging-only; normal source builds continue to
use Cargo directly.

Register the Git repository once and trigger a build with a configured `copr-cli`:

```bash
copr-cli add-package-scm OWNER/PROJECT \
  --name microvisor \
  --clone-url https://github.com/nexryai/microvisor.git \
  --spec microvisor.spec \
  --method make_srpm
copr-cli build-package OWNER/PROJECT --name microvisor --enable-net on
```

COPR invokes `.copr/Makefile` itself and uploads the resulting SRPM into the selected project. To
build and upload an SRPM manually instead:

```bash
make -f .copr/Makefile srpm outdir="$PWD" spec=microvisor.spec
copr-cli build OWNER/PROJECT ./microvisor-*.src.rpm
```

The SCM source-build step needs network access to download the locked Cargo crates before placing
them in `Source1`; the binary RPM build itself uses that vendored archive offline. Local SRPM
generation runs without root when `cargo`, `cargo-rpm-macros`, `git`, `make`, `rpmbuild`, `rpmspec`,
`tar`, and `xz` are already installed. Dependency installation with root is limited to COPR's
disposable source-build environment.

## YAML configuration

Create an editable template without root privileges:

```bash
microvisor generate microvisor.yml
```

The command generates a UUID v4, writes a mode `0600` complete configuration, and refuses to
overwrite an existing path. If the output path is omitted, the file is named `microvisor.yml` in
the current directory. Explicit output names must end in `.yml`. Edit the placeholder profile,
append any additional profiles to the same `profiles` list, review the result, and then install it
on the designated production target.

`/etc/microvisor.yml` is the only desired-configuration input. The document schema is versioned
once at the top level and contains all profiles:

```yaml
schema_version: 1
profiles:
  - id: 11111111-2222-4333-8444-555555555555
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

On a designated production target, the configuration must be a regular root-owned file with
exactly one hard link. It must not be writable by group or other users and must not be a symlink.
A typical deployment is:

```bash
sudo install -o root -g root -m 0600 microvisor.yml /etc/microvisor.yml
```

The loader accepts a deliberately restricted YAML subset. It rejects unknown or duplicate fields,
unsupported schema versions, ambiguous booleans, tags, anchors, aliases, merge keys, document
streams, excessive nesting or node counts, oversized files, invalid SELinux identifiers, unsafe
paths, missing targets, and overlapping profiles.

## Commands

Template generation is intentionally available without root:

```bash
microvisor generate [output.yml]
```

Run these commands as root only on a designated production target or in the CI integration VM:

```bash
sudo microvisor validate
sudo microvisor render <profile-id>
sudo microvisor apply
sudo microvisor status
sudo microvisor supervise
sudo microvisor remove <profile-id>
```

- `validate` parses, normalizes, and validates the complete configuration without changing SELinux.
- `generate` creates a new, editable YAML template with a random UUID and never overwrites a file.
- `render` prints deterministic TE/CIL policy and file-context operations for review.
- `apply` validates all profiles and builds every base module before the first host mutation. It is
  idempotent and attempts batch rollback if a later profile fails. After protection is active, an
  unchanged data path is recognized from the root-owned applied snapshot because the deny rule may
  prevent the CLI's own launch domain from inspecting that directory. New and changed paths still
  undergo canonicalization and filesystem metadata checks.
- `status` compares desired profiles, root-owned snapshots, installed modules, and local
  file-context rules. Exit status 2 means drift.
- `supervise` opens a color, full-terminal inspector for current processes, their executable labels,
  Microvisor profiles, and system `*_exec_t` file-context rules. In the process view, press `Enter`
  or `d` for a scrollable explanation of the selected process: identity, exact active or planned
  Microvisor data/ptrace/file-descriptor rules, loaded SELinux allow rules grouped into plain-language
  file, network, and process-control actions, and the default-deny boundary. The screen uses
  `sesearch` to inspect the loaded distribution policy; the RPM installs it through its required
  `setools-console` dependency. The screen still reports an actionable error if policy inspection
  fails. Allowed rules are green, explicit and default denies are red, and configured-only plans are
  yellow. Use arrow keys or `j`/`k` to move or scroll,
  `Esc`, Backspace, or `Enter` to leave details, `Tab` or `1`/`2`/`3` to switch views, `r` to reload,
  and `q` to quit. When standard input or output is not a terminal, it prints one tab-separated
  process snapshot instead.
- `remove` trusts the root-owned applied snapshot rather than mutable YAML when restoring labels.

Deleting YAML does not silently remove installed protection. `status` reports
`installed-without-config`; use `remove <profile-id>` explicitly.

Mutating operations are serialized by `/run/microvisor/transaction.lock`. Applied-state snapshots
are atomically stored with mode `0600` under `/var/lib/microvisor/profiles/`, whose mode is `0700`.
Snapshots are internal recovery data, not configuration input.

The supervisor uses green for an observed or configured Microvisor domain, yellow for a distinct
system SELinux domain, red for `unconfined_t`, and gray when a label cannot be read. A file-context
rule assigns a label; it does not by itself prove every allowed or denied operation. The process
detail screen distinguishes installed Microvisor denies from configured-only plans and from allow
rules found in the currently loaded distribution policy. SELinux normally records what is allowed,
not a finite list of everything denied, so the screen labels absence of an allow as default-deny and
still directs administrators to AVC logs for the authoritative explanation of an attempted action.

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
Recreate required profiles in one reviewed, root-owned `/etc/microvisor.yml` and validate it before
applying. Earlier development builds using `/etc/microvisor/profiles.d/*.yaml` are not imported;
merge those profile mappings manually under the new top-level `profiles` list, removing each
profile-level `schema_version` field.
