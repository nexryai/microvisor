# AGENTS.md

## Purpose

This file defines the working contract for coding agents contributing to Microvisor. The project is security-sensitive: a syntactically valid change can still weaken isolation, make a desktop session unusable, or leave files with orphaned SELinux labels.

## Project map

- `src/main.rs`: application startup and application-scoped actions.
- `src/ui/`: Libadwaita UI definitions and behavior written in Rust. Keep privileged operations
  out of this directory.
- `src/model.rs`: serialized profile and helper request/response types.
- `src/policy.rs`: pure SELinux policy generation and input validation.
- `src/bin/microvisor-helper.rs`: Polkit-invoked root helper.
- `data/icons/`: full-color and symbolic GNOME app icons.
- `tests/policy.rs`: deterministic policy-generator tests.
- `PLANS.md`: roadmap and design decisions that are not yet implemented.

## Non-negotiable security boundaries

1. The GUI must remain unprivileged. Never run the GTK process with `sudo`, as root, or under `pkexec`.
2. All root operations go through `microvisor-helper` and a narrow serialized request schema.
3. Never invoke a shell with user-controlled profile values. Use `std::process::Command` argument arrays.
4. Reject relative or overly broad paths, `/`, non-UTF-8 or control-character file-context paths, invalid SELinux identifiers, oversized requests, missing files, and overlapping profiles.
5. Install the deny module only after executable and data relabeling succeeds. Remove the deny module before attempting recovery or relabeling.
6. Store a root-owned copy of every applied profile so updates and removal do not trust mutable user configuration. Keep the state directory mode at `0700` and profile files at `0600`.
7. Serialize privileged transactions with the root-owned runtime lock. A failed update must attempt rollback to the previous root-side profile.
8. Never replace policy review with `audit2allow -a`. AVCs must be understood individually.
9. Do not weaken the deny complement or add allowed domains without documenting the threat-model impact.
10. Treat `unconfined_domain()` as a compatibility mechanism, not as confinement. The deny module is what protects the profile data.

## GNOME and Libadwaita requirements

- Follow the current GNOME Human Interface Guidelines.
- Prefer standard Libadwaita rows, dialogs, banners, toasts, and adaptive containers.
- Keep the main window focused on the protected-application list.
- Put application-wide actions in the primary menu. Do not add Quit or Close to that menu.
- Use symbolic icons for controls and list rows. The full-color app icon is only for app identity.
- Use header capitalization for titles and menu commands, sentence capitalization for descriptions.
- Every icon-only button requires a tooltip.
- Keep destructive actions visually separated and require confirmation.
- The UI must remain usable at a 360 px window width.
- Do not add custom CSS for ordinary layout or colors when a platform style class exists.

## Icon constraints

The application icon metaphor is a rounded yellow shield with a protected-data aperture.

- Full-color icon: 128×128 SVG, 2 px construction grid, simple shapes, no external shadow.
- Symbolic icon: monochrome SVG that remains legible at 16 px.
- Preserve the current metaphor unless a design change is explicitly approved.
- Do not embed raster images or fonts in the SVG.

## Build and test workflow

Run before submitting changes:

```bash
cargo fmt --check
cargo test --no-default-features
cargo check --all-targets
meson setup build --wipe
meson compile -C build
appstream-util validate-relax data/me.nexryai.microvisor.metainfo.xml.in
```

For SELinux integration changes, test in a disposable Fedora virtual machine with Enforcing mode enabled. At minimum verify:

```bash
# Before applying
ps -eZ | grep -i '<application>'

# After applying
ps -eZ | grep -i '<application>'
sesearch -A -s unconfined_t -t microvisor_<id>_data_t
sesearch -A -s microvisor_<id>_t -t microvisor_<id>_data_t

# Direct access from a non-allowed domain must fail
cat /path/to/protected/file

# Removal must restore labels and remove both modules
semodule -l | grep microvisor_<id>
semanage fcontext -l -C | grep microvisor_<id>
```

Record the exact Fedora version, SELinux userspace version, base policy version, desktop session type, and tested application in the pull request.

## Code style

- Rust edition 2024; minimum Rust version is declared in `Cargo.toml`.
- Keep policy rendering pure and deterministic.
- Prefer typed errors with context over string-only error propagation.
- Keep unsafe code isolated; currently only the effective UID check requires it.
- Avoid blocking the GTK main loop. Privileged calls run on a worker thread and return through an async channel.
- Do not add a new dependency for functionality available in the standard library or gtk-rs without justification.
- Public structures serialized across the privilege boundary require backward-compatibility consideration.

## Change protocol for agents

Before editing:

1. Read `README.md`, this file, and the relevant section of `PLANS.md`.
2. Identify whether the change touches the GUI, the privilege boundary, policy semantics, installation, or recovery.
3. For policy changes, write or update a deterministic test first.

While editing:

1. Keep the patch scoped to one objective.
2. Update documentation when assumptions or supported versions change.
3. Do not silently alter defaults that affect policy strength.

After editing:

1. Run the applicable checks.
2. State which checks were not possible and why.
3. Add newly discovered work to `PLANS.md` rather than leaving undocumented TODO comments.

## Prohibited shortcuts

- Running the entire app as root.
- Passing arbitrary command strings to the helper.
- Generating policy from raw, unvalidated identifiers.
- Using broad writable temporary locations for policy build artifacts.
- Installing a deny rule before a tested recovery path exists.
- Claiming cross-distribution support based only on compilation.
- Treating successful application startup as proof of isolation.
