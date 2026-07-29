# Microvisor

Microvisor is a GNOME/Libadwaita application written in Rust for generating and applying per-application SELinux protection profiles.

A profile creates:

- a dedicated application domain such as `microvisor_<id>_t`;
- a dedicated executable type and data type;
- a type transition from a configured desktop launch domain;
- an unconfined-compatible application domain, so ordinary desktop applications continue to work;
- a CIL `deny` module that subtracts access to the protected data type from every type except the protected application domain;
- optional cross-domain `ptrace` and file-descriptor restrictions.

The GTK process is unprivileged. Policy compilation, module installation, file-context changes, and relabeling are performed by `/usr/libexec/microvisor-helper` after Polkit authentication. The helper canonicalizes paths, rejects broad or overlapping directories, refuses to overwrite matching local file-context entries, serializes policy transactions with a root-owned runtime lock, and stores its applied profile state in a root-only directory.

## Status

This repository is an **MVP/development implementation**, not a finished security product. SELinux base policies vary between distributions, and generated policies must be reviewed before production use. The UI exposes a complete policy preview before applying changes.

## Requirements

The current target is Fedora Workstation 44 or a comparable system with:

- Rust 1.85 or newer;
- GTK 4.18 or newer;
- Libadwaita 1.8 or newer;
- SELinux userspace 3.6 or newer, because Microvisor relies on CIL `deny` rules;
- `policycoreutils`, `policycoreutils-python-utils`, `libselinux-utils`, `checkpolicy`,
  and the reference-policy development Makefile from `selinux-policy-devel`;
- Polkit.

Typical Fedora development dependencies:

```bash
sudo dnf install \
  cargo rust gtk4-devel libadwaita-devel glib2-devel \
  meson ninja-build policycoreutils policycoreutils-python-utils \
  libselinux-utils selinux-policy-devel checkpolicy polkit
```

## Build and install

```bash
meson setup build
meson compile -C build
sudo meson install -C build
```

Run:

```bash
microvisor
```

## Fedora Copr packaging

The repository contains `microvisor.spec` and `.copr/Makefile` for building a native RPM from
Copr's SCM source type. The RPM contains both the unprivileged GUI and the Polkit-authenticated
helper. Rust dependencies are vendored from the locked dependency graph while creating the source
RPM; the architecture-specific RPM build then runs without network access.

Create a Copr project with the Fedora 44 chroots you intend to support, then add an SCM package with:

- Clone URL: `https://github.com/nexryai/microvisor.git`
- Committish: the release tag or branch to publish
- Spec file: `microvisor.spec`
- Build method: `make srpm`

After a successful build, users can install it with:

```bash
sudo dnf copr enable <owner>/microvisor
sudo dnf install microvisor
```

The RPM intentionally depends on Polkit and Fedora's SELinux policy-development utilities because
the helper compiles and installs profiles on the target system. Copr publication does not replace
the SELinux Enforcing integration tests described in `AGENTS.md`.

## Continuous integration

GitHub Actions runs the fast build and unit checks from `.github/workflows/ci.yml` in a Fedora 44
container. The separate `.github/workflows/selinux-integration.yml` workflow uses an
`ubuntu-24.04` GitHub-hosted job to boot the official Fedora 44 Cloud image under QEMU and verifies
that the guest is in SELinux Enforcing mode before running the privileged integration test.

The Cloud image filename and SHA-256 checksum are pinned in
`.github/workflows/selinux-integration.yml`. The image is cached only after the host script
verifies that checksum. QEMU uses KVM if `/dev/kvm` is available on the hosted runner and
otherwise falls back to TCG software emulation.

The guest test invokes the Fedora-built helper through its JSON protocol and covers module
installation, real file labels, process-domain transition, denial from `unconfined_t`, root-side
state permissions, and complete removal and relabeling. It uses a disposable test profile and
removes the deny module first during failure recovery. This headless job does not cover the GTK UI,
interactive Polkit authentication, GNOME Wayland integration, or the full application matrix in
`PLANS.md`.

## Diagnostics

Microvisor writes structured, single-line diagnostic messages to standard error. Logs identify
the component, operation, profile UUID, processing stage, and result without dumping serialized
profile requests or policy contents.

For a development run:

```bash
cargo run --bin microvisor 2>&1
```

When Microvisor is launched from GNOME, inspect the user journal:

```bash
journalctl --user --since today | grep microvisor
```

Diagnostics from the privileged helper are captured by the GUI process and relayed into the same
log stream. The helper keeps its JSON protocol response on standard output.

For a developer build without installation, the GUI can point to a manually installed helper:

```bash
MICROVISOR_HELPER=/absolute/path/to/microvisor-helper cargo run --bin microvisor
```

`pkexec` normally requires the helper path to match the path declared in the installed Polkit action, so installing into a test prefix or virtual machine is recommended.

## Chrome example

For Google Chrome, select the final ELF executable rather than only the shell launcher when possible:

```text
/opt/google/chrome/chrome
```

Typical protected directories:

```text
~/.config/google-chrome
~/.cache/google-chrome
```

## Threat model and limitations

Microvisor is intended to block **direct SELinux-mediated access** from unrelated desktop applications, services, containers, and other TE domains. It does not defend against:

- an administrator who can modify SELinux policy or boot configuration;
- kernel compromise;
- malicious code executing inside the protected application's own domain;
- abuse of the protected application's command-line flags, remote-debugging interfaces, extensions, plugins, or IPC APIs;
- data intentionally exported by the protected application;
- all same-user confused-deputy attacks.

Any process allowed to execute the protected entrypoint from the configured launch domain can cause the domain transition. A stronger future design may require a dedicated broker or a separate UNIX account. See `PLANS.md`.

## Recovery

If an application no longer starts, remove its profile from Microvisor. If the GUI cannot be used, inspect installed modules and local file-context rules:

```bash
sudo semodule -l | grep microvisor
sudo semanage fcontext -l -C | grep microvisor
```

Then remove the profile-specific deny module first, restore labels, and remove the base module. Root-side profile state is stored under:

```text
/var/lib/microvisor/profiles
```

Do not remove a base module while files still carry its custom types. Microvisor currently rejects matching pre-existing local `semanage fcontext` entries rather than overwriting or preserving them.

## License

MIT.
