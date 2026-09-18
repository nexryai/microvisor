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

## Configuration

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


## Usage

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
  Microvisor data/ptrace/file-descriptor rules, or—for system-policy processes—a modern permission
  list showing read and write access matched to labeled content under home directories, `/etc`, and
  sensitive `/var` subtrees. A check mark means some labeled content matches; it never claims that
  every file in the directory is accessible. The raw loaded SELinux allow rules remain grouped into
  plain-language file, network, and process-control actions below the permission list. The screen uses
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
Microvisor uses the SETools 4.6-compatible `sesearch -A -s <domain>` form; the removed legacy `-C`
option must not be reintroduced.

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
