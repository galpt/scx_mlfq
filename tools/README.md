# scx_mlfq beta-testing tools for CachyOS

This directory contains the beta-testing tooling for **scx_mlfq** on CachyOS.

| File | Purpose |
|---|---|
| `install_scx_mlfq.sh` | **Single install entry point**. Scheduler binary, loader and GUI integration |
| `uninstall_scx_mlfq.sh` | **Single uninstall entry point**. Clean removal of everything, safe even after upstream ships `scx_mlfq` in a package |
| `install_scx_mlfq_loader.sh` | Internal. Patched `scx_loader` layer (invoked by the installer, run directly to rebuild it after a package upgrade) |
| `install_scx_mlfq_gui.sh` | Internal. Patched `libscxctl-ui.so` layer (invoked by the installer, run directly to rebuild it after a package upgrade) |
| `scx_loader-mlfq.patch` | The patch applied to the published `scx_loader` crate by the loader and GUI layers |

The install and uninstall scripts are bash, must be run as **root**
(`sudo`), and are safe to run repeatedly. Run them with `--dry-run` first
to preview what they would do.

## What scx_mlfq is

`scx_mlfq` is an experimental sched_ext CPU scheduler for Linux, written in
Rust with a BPF component. It implements a Multilevel Feedback Queue (MLFQ)
discipline on top of EEVDF-style virtual-time scheduling. Three queues per
CPU (Q1/Q2/Q3), each a vtime-ordered dispatch queue, hold the tasks, and a
continuous EMA-based interactivity gauge (plus hysteresis) decides which
queue a task lives in. Interactive-first desktop and latency workloads are
served from Q1, batch work is demoted toward Q3. Like all sched_ext
schedulers it handles **non-RT tasks only**, so the kernel's rt and dl
classes are untouched. The scheduler attaches directly to the kernel and is
observed through the kernel's sched_ext interface, `scx_mlfq --stats`, and,
since 1.3.0, a realtime web UI on the loopback port 50005 (see the "Web UI
and the loader network sandbox" section below).

## Prerequisites

- **CachyOS** (any Arch-like distro with `pacman` and systemd is treated as a
  match, the installer warns and asks for confirmation on anything else).
- A **sched_ext-capable kernel**. The installer checks
  `/sys/kernel/sched_ext` and the kernel config
  (`CONFIG_SCHED_CLASS_EXT=y`). CachyOS kernels ship with this.
- A build toolchain. `git`, `cargo` (Rust, stable), and the `clang`/libbpf
  toolchain used by the `sched-ext/scx` workspace. No packages are installed
  by these scripts.
- `scx-tools` / `scx_loader` is **optional** for running scx_mlfq directly,
  but it is what the CachyOS Kernel Manager GUI uses to list and switch
  schedulers. The GUI can manage scx_mlfq only after
  `install_scx_mlfq_loader.sh` has added scx_mlfq to the loader's
  compiled-in scheduler list (see the loader section below).
- **Root**. All four scripts refuse to run as a non-root user, including
  with `--dry-run`.

## Installing

```bash
sudo bash install_scx_mlfq.sh [options]
```

This is the only command needed. By default it installs all three layers.

1. the scheduler binary and its `scx.service` drop-in,
2. the patched `scx_loader` (the GUI dropdown), and
3. the patched GUI library (select and apply in the GUI).

Pass `--beta-only` to install only the scheduler binary and drop-in,
skipping the GUI integration.

Defaults (matching the beta-testing workflow).

| Option | Default |
|---|---|
| `--repo` | `https://github.com/galpt/scx.git` |
| `--branch` | `scx_mlfq` |
| `--source-dir` | unset (clone from `--repo`/`--branch` instead) |

Options.

- `--repo URL`. Repository to clone (must be a full `scx` workspace).
- `--branch NAME`. Branch to clone.
- `--source-dir DIR`. Build from a local `scx` workspace instead of cloning.
  `DIR` must contain `Cargo.toml` with `scheds/experimental/scx_mlfq` listed
  as a workspace member. `--repo`/`--branch` are ignored when set.
- `--beta-only`. Install only the scheduler binary and its drop-in,
  skipping the loader and GUI integration layers.
- `--force`. Skip the interactive confirmation when `/usr/bin/scx_mlfq` is
  owned by a package, and back up and replace a conflicting pre-existing
  drop-in instead of refusing.
- `--dry-run`. Validate inputs and print every action **without** cloning,
  building, or changing the system.
- `--help`, `-h`. Print help.

Examples.

```bash
# Default. Clone galpt/scx branch scx_mlfq and install everything
sudo bash install_scx_mlfq.sh

# Preview without touching the system
sudo bash install_scx_mlfq.sh --dry-run

# Build from a local scx tree
sudo bash install_scx_mlfq.sh --source-dir /home/user/scx

# Scheduler only, no GUI integration
sudo bash install_scx_mlfq.sh --beta-only

# Reinstall over a package-owned binary without prompting
sudo bash install_scx_mlfq.sh --force
```

What the installer does, in order.

1. Checks that you are root, that the distro is CachyOS/Arch-like (parsed
   from `/etc/os-release`, never sourced), and that sched_ext is available.
2. Clones the branch into a temporary directory (or uses `--source-dir`) and
   runs `cargo build --release -p scx_mlfq`, then verifies the built binary
   exists. Flag values are validated up front. Control characters and a
   leading `-` are rejected, and `--branch` is restricted to
   `[A-Za-z0-9._/-]`.
3. Checks the systemd drop-in (read-only, before any other change). If
   `/etc/systemd/system/scx.service.d/scx_mlfq-beta.conf` already exists and
   differs byte-for-byte from the content this installer writes, it refuses
   to proceed unless `--force` is given (then the existing file is backed up
   to `/usr/lib/scx/scx.service.d.scx_mlfq-beta.conf.bak` and replaced).
4. Stops `scx.service` (errors ignored). If a scheduler is currently attached
   (`/sys/kernel/sched_ext/state` != `disabled`) **and** `scx_loader` is
   active, it also stops `scx_loader.service`. The loader is **not disabled**.
   scx_mlfq is never auto-started.
5. Checks package ownership of `/usr/bin/scx_mlfq` with `pacman -Qo`.
   - exit 0 (owned by a package, e.g. a future upstream release) requires
     `--force` or an interactive `y/N` before overwriting. The original is
     backed up with `cp -p` to `/usr/lib/scx/scx_mlfq.scx_mlfq-beta.bak`, and
     the owner plus its sha256 are recorded.
   - exit 1 (unowned) installs directly.
   - any other exit code (database locked or corrupt) **aborts**. The
     installer never silently treats a pacman error as "unowned".
6. Stages the binary, writes the install manifest `/usr/lib/scx/scx_mlfq-beta.manifest`
   (version, `installed_sha256`, `orig_owner`, `orig_sha256`, `backup_path`,
   `dropins`, `dropin_backup` when one was made, `loader_entry` when the
   scx_loader config was updated, install time, source and branch),
   and only then swaps the binary into place with an atomic staged copy
   (`cp`, `chmod 755`, then `mv -f`). **The manifest is written BEFORE the
   swap, so an interrupted run never leaves a new binary without a manifest.
   A leftover stage file is removed by the EXIT trap.**
7. Runs `systemctl daemon-reload`.
8. Registers scx_mlfq in the `scx_loader` config. When
   `/etc/scx_loader.toml` exists, it appends the `[scheds.scx_mlfq]` section
   (empty mode arrays, since the scheduler is knob-free) unless it is already
   present. This supplies the per-mode flags. The GUI list itself is
   compiled into the loader binary and needs the loader installer below.
   The manifest records `loader_entry=1`.
9. Runs a smoke test (`scx_mlfq --version`). A failure is reported as a clear
   warning, not fatal.
10. Prints a status summary. **scx_mlfq is NOT auto-started.**

Start it now, one of.

```bash
# Direct run (foreground). Ctrl+C detaches. The kernel reverts to CFS.
sudo /usr/bin/scx_mlfq

# Via systemd (uses the drop-in above)
sudo systemctl restart scx.service
```

## Loader integration (CachyOS Kernel Manager GUI)

The GUI asks `scx_loader` for its supported schedulers, and the loader's
list is compiled into the binary (`SupportedSched` enum). scx_mlfq is not
in the shipped list, so the GUI cannot select it without this step. The
installer above runs this script automatically. Run it directly only to
rebuild the layer, for example after a package upgrade replaced the stock
loader.

```bash
sudo bash install_scx_mlfq_loader.sh [options]
```

Options.

- `--force`. Back up and replace a conflicting pre-existing loader drop-in
  (to `/usr/lib/scx/scx_loader.service.d.mlfq-loader.conf.bak`) instead of
  refusing.
- `--no-webui`. Skip the web UI network unblock. The loader sandbox stays
  in place and the web UI uses the unix-socket fallback
  `/tmp/scx_mlfq.sock` (see the web UI section below).
- `--dry-run`. Validate inputs and print every action without downloading,
  building, or changing the system.
- `--help`, `-h`. Print help.

What it does, in order.

1. Downloads the published `scx_loader` and `scxctl` crates (pinned
   version 1.1.2) from crates.io, extracts them, and applies
   `tools/scx_loader-mlfq.patch`, which adds scx_mlfq to the
   supported-scheduler enum.
2. Builds both with `cargo build --release` in a workspace that pins
   scxctl's `scx_loader` dependency to the patched source, so the
   command-line tool parses the same enum the patched loader runs.
3. Installs the patched loader as `/usr/local/bin/scx_loader` and writes a
   systemd drop-in (`scx_loader.service.d/mlfq-loader.conf`) that overrides
   `ExecStart` to use it, so package upgrades of the stock loader do not
   replace it.
4. Installs the patched scxctl as `/usr/local/bin/scxctl`, ahead of the
   packaged binary in PATH, so `scxctl switch --sched mlfq` works.
5. Enables `scx_loader.service`, so the patched loader (and with it the
   scx_mlfq entry in the GUI) survives reboots.
6. Records the install in `/usr/lib/scx/scx_mlfq-loader.manifest`
   (its own manifest, separate from the beta manifest), so the uninstaller
   can undo exactly this step.
7. Unblocks the web UI's network path. It writes
   `scx_loader.service.d/mlfq-webui.conf`, whose empty
   `RestrictAddressFamilies=` / `SocketBindDeny=` assignments lift the
   network sandbox the packaged `scx_loader.service` applies to its
   scheduler children, so a loader-spawned scx_mlfq can bind its loopback
   web UI port (50005). The write is atomic and idempotent, the drop-in
   carries a marker comment, `webui_unblock=1` is recorded in the loader
   manifest, and the `daemon-reload` in the restart step activates it. The
   unblock applies to the next loader-spawned scheduler. `--no-webui`
   skips this step entirely (the web UI then uses the unix-socket
   fallback).

After it finishes, the Kernel Manager GUI dropdown lists scx_mlfq. One
more step is needed before the GUI can apply it (see below).

## Web UI and the loader network sandbox

Since 1.3.0, scx_mlfq ships a realtime web UI (loopback-only, port 50005 on
`[::1]`/`127.0.0.1`, no auth, the localhost trust boundary). The packaged
`scx_loader.service` sandboxes the schedulers it spawns with
`RestrictAddressFamilies=AF_UNIX` and `SocketBindDeny=...`, so a
loader-spawned scx_mlfq inherits the restriction and cannot bind the TCP
port. The loader installer therefore writes a systemd drop-in
`scx_loader.service.d/mlfq-webui.conf` whose empty assignments
(`RestrictAddressFamilies=`, `SocketBindDeny=`) reset both settings for the
loader and the scheduler children it spawns.

- **Lifecycle.** The installer writes the drop-in atomically
  (`mktemp` + `mv`) and idempotently (re-runs leave byte-identical bytes).
  The uninstaller removes it only when the loader manifest records
  `webui_unblock=1` or the file byte-matches the installer's content, then
  reloads systemd and restarts an active loader, restoring the
  packaged sandbox. If the install fails after the drop-in was written, an
  EXIT trap removes it again. The fixed filename
  `mlfq-webui.conf` plus the byte check guarantee that a foreign drop-in
  in the same directory is never touched.
- **State detection.** Both scripts query the effective merged values with
  `systemctl show -p RestrictAddressFamilies -p SocketBindDeny
  scx_loader.service` and report whether the sandbox is in force, already
  lifted (e.g. by a foreign drop-in), or our drop-in is present and
  matching. The detection reports but never gates the write.
- **Opt-out.** `--no-webui` skips the unblock entirely. The web UI then
  falls back to the unix socket `/tmp/scx_mlfq.sock` (AF_UNIX is permitted
  by the sandbox, only inet binds are denied). The socket is created mode
  0600, so connecting needs root. View it with
  `sudo socat TCP-LISTEN:50005 UNIX-CONNECT:/tmp/scx_mlfq.sock`.
- **Security tradeoff.** The drop-in is per-unit, not per-binary. It lifts
  the network sandbox for the loader and **every** scheduler it spawns, not
  just scx_mlfq. systemd drop-ins cannot target a single child binary, so
  no narrower alternative exists. The tradeoff is printed by the installer,
  the unblock is removable through the uninstaller, and `--no-webui`
  avoids it entirely.

## GUI integration (select and apply scx_mlfq in the GUI)

The GUI front-ends (the Kernel Manager scheduler page and scx-manager)
link `libscxctl-ui.so`, which embeds a Rust client whose
supported-scheduler list comes from the published `scx_loader` crate.
Even with the patched loader binary above, that embedded list does not
know scx_mlfq, so the GUI cannot fetch its flags or apply it. The
installer above runs this script automatically. Run it directly only to
rebuild the layer.

```bash
sudo bash install_scx_mlfq_gui.sh [options]
```

Options.

- `--force`. Replace a conflicting pre-existing GUI library without
  prompting (still backed up first).
- `--dry-run`. Validate inputs and print every action without cloning,
  building, or changing the system.
- `--help`, `-h`. Print help.

What it does, in order.

1. Clones `CachyOS/scx-manager` at a pinned commit (project version
   1.15.12, the version shipped by CachyOS), vendors the patched
   `scx_loader` crate into its Rust library as a path dependency, and
   applies `tools/scx_loader-mlfq.patch`.
2. Builds the project with cmake (needs cmake, ninja, Qt 6 base and
   tools, and the Rust toolchain, no packages are installed by the
   script).
3. Backs up `/usr/lib/libscxctl-ui.so.1.15.12` and replaces it with the
   build result. Both GUI front-ends resolve the library by soname, so
   no other file needs replacing.
4. Records the install in `/usr/lib/scx/scx_mlfq-gui.manifest` (own
   manifest, with the original's sha256), so the uninstaller restores
   the packaged library.

After it finishes, selecting scx_mlfq in the GUI shows no flag error and
Apply works. Switching back and forth between scx_mlfq and the packaged
schedulers works entirely from the GUI.

## Uninstalling

```bash
sudo bash uninstall_scx_mlfq.sh [--force] [--dry-run]
```

The uninstaller is **manifest-driven and idempotent**.

- If none of the beta, loader and GUI manifests exists it prints
  `Nothing to uninstall` and exits 0 without touching any file.
- Both manifests are parsed **strictly**. Duplicate keys, unknown keys, and
  values containing control characters abort the run without touching
  anything.
- It stops `scx.service` if it is active (safe, it may be running the beta),
  but never disables or removes the unit.
- Binary handling depends on what the manifest records.
  - the installer had replaced a **package-owned** file. If the current
    binary still matches the recorded beta sha256, the backup is moved back
    (only after the backup is verified to be a regular, non-symlink file)
    and verified against the recorded original sha256, then
    `pacman -Qkk <owner>` is run and reported. If the package already
    re-placed the file (sha256 differs), the binary is left untouched and
    only the backup and manifest are removed.
  - the installer had installed an **unowned** file. It is removed only if it
    still matches the recorded beta sha256, otherwise it is left in place
    with a warning.
- It removes **only** the installer's own drop-in
  (`scx_mlfq-beta.conf`, and only if it byte-matches what the installer
  writes, otherwise it is left in place with a warning, and the parent
  `scx.service.d/` is removed only if now empty), any recorded drop-in
  backup, the binary backup, and the manifest, then runs
  `systemctl daemon-reload`.
- If the beta manifest records `loader_entry=1`, it removes the
  `[scheds.scx_mlfq]` section from `/etc/scx_loader.toml` (preserving the
  rest of the file).
- If the loader manifest exists, it removes the patched loader
  `/usr/local/bin/scx_loader` (only when its sha256 still matches the
  record), the patched scxctl `/usr/local/bin/scxctl` (sha-verified the
  same way), and the loader drop-in (only when it byte-matches), reloads
  systemd so the stock loader's `ExecStart` takes effect, and restarts an
  active loader. The loader service itself is never disabled.
- It removes the web UI unblock drop-in
  `scx_loader.service.d/mlfq-webui.conf` only when the loader manifest
  records `webui_unblock=1` or the file byte-matches the loader
  installer's content (an extra check for a lost manifest), reloads
  systemd and restarts an active loader, then reports the effective
  `RestrictAddressFamilies`/`SocketBindDeny` values. "Network sandbox
  restored", or "still lifted" when a foreign drop-in remains (reported,
  never touched). The summary gains a `Web UI unblock:` row.
- If the GUI manifest exists, it restores the packaged
  `/usr/lib/libscxctl-ui.so.1.15.12` from the recorded backup (only when
  the current library still matches the patched build, otherwise the
  package has already taken the file back and only the backup and
  manifest are removed).
- It never disables or modifies `scx_loader.service` (an active loader may
  be restarted so the stock binary takes effect) and never touches
  `/etc/default/scx`. The two unrecorded edits are documented exceptions,
  each gated. The `default_sched = "scx_mlfq"` line in the loader config
  when the beta manifest records `loader_entry=1`, and stale loader-config
  backups (regular files only, newest kept). Every path read from the manifests
  is confined before use. Traversal
  components (`..`, `.`) and control characters are rejected, the path is
  canonicalized with `realpath`, and it must resolve inside its expected
  directory (`/usr/lib/scx/` for backups, the exact drop-in path for the
  drop-in).

## FAQ

**How does the CachyOS Kernel Manager GUI manage scx_mlfq?**

The GUI asks `scx_loader` for its supported schedulers, and the loader's
supported list is compiled into the binary. The `scx_loader` config file
(`/etc/scx_loader.toml`) only supplies per-mode flags. `install_scx_mlfq_loader.sh`
builds a patched loader with scx_mlfq added to that compiled list and
installs it with a service override, which is what makes scx_mlfq appear in
the GUI. The beta installer's `[scheds.scx_mlfq]` config entry is the
matching flags entry for the patched loader. Uninstalling removes both.
(The direct run and the `scx.service` drop-in remain available as fallback
launch paths.)

**How do I go back to my previous scheduler?**

From the Kernel Manager GUI, select any other scheduler (the loader stops
scx_mlfq and starts the new one). To remove the beta entirely, run the
uninstaller, which also removes the `[scheds.scx_mlfq]` entry from the
loader config. Without the installer's drop-in, `scx.service` uses the
default scheduler configured in `/etc/default/scx`. You can also reinstall
the packaged schedulers at any time.

```bash
sudo pacman -S scx-scheds
```

The kernel reverts to CFS automatically whenever a scheduler detaches, so
there is never a window with no scheduler.

**What happens when upstream ships scx_mlfq in a package?**

Once `scx_mlfq` is merged, `scx-scheds` (and `scx-scheds-git`) will ship
`/usr/bin/scx_mlfq` automatically. Before upgrading or installing the package
over your beta binary, run.

```bash
sudo bash uninstall_scx_mlfq.sh
```

The uninstaller restores the package-owned file from its backup (or, if the
package already re-placed the file, just removes the backup and manifest).
After that, normal CachyOS tooling owns the binary. The GUI manages
scx_mlfq directly once CachyOS also adds it to the loader's scheduler list
(their pattern when packaging a new scheduler), and until then the
patched-loader installer above keeps working.

**Does scx_mlfq have a web UI or listen on a port?**

Since 1.3.0, yes by default. A realtime web UI on the loopback address
(`[::1]:50005`, falling back to `127.0.0.1:50005`), no auth (the localhost
trust boundary, any local process can already read the scheduler's
counters, no secrets are exposed). Disable it with `--no-webui`. Under the
loader sandbox the TCP bind is denied, so the UI falls back to the unix
socket `/tmp/scx_mlfq.sock` (mode 0600, root-only connect, use `sudo`
with socat) unless the network unblock drop-in from the
loader installer is in place (see the "Web UI and the loader network
sandbox" section). Scheduler state is otherwise visible through the
kernel's sched_ext interface (e.g. `cat /sys/kernel/sched_ext/root/ops`)
and `scx_mlfq --stats`.

**Is it safe to run as root / what if something goes wrong?**

- Only **one** sched_ext scheduler can be attached at a time. The beta
  installer and the uninstaller stop the currently attached scheduler
  gracefully (the kernel then reverts to CFS automatically). The loader
  installer never touches scheduler units directly, though restarting an
  active loader to pick up a rebuilt layer does stop and re-start whatever
  scheduler the loader is managing.
- The scripts never edit `/etc/default/scx`, never disable `scx_loader` or
  `scx.service`, and never remove `scx.service` itself.
- The uninstaller removes manifest-recorded files plus the two documented
  gated exceptions (the loader-config `default_sched` line, matched by
  exact regex, and stale config backups). Nothing else is touched.
- Reinstalling simply replaces the binary. The manifest is rewritten with the
  new state. An existing backup is overwritten with a warning.
- If `/etc/systemd/system/scx.service.d/scx_mlfq-beta.conf` already exists
  with different content, the installer refuses until you remove it or pass
  `--force` (which backs it up first). It never silently overwrites or
  records a drop-in it did not write.
- If the installer is interrupted after writing the manifest but before the
  binary swap, the old binary stays in place and the leftover stage file is
  cleaned up by the EXIT trap. Re-run the installer to finish.
- `--dry-run` requires root, performs no clone and no build, and changes
  nothing. It is a safe way to check the installer's decisions (including
  whether `/usr/bin/scx_mlfq` is currently package-owned).
- The installers use only owned temporary build directories (under
  `/tmp/scx_mlfq-build.*`, `/tmp/scx_mlfq-loader-build.*` and
  `/tmp/scx_mlfq-gui-build.*`, created with `mktemp`) and remove them on
  exit.

## Safety notes for reviewers

- All four scripts use `set -euo pipefail`, an unconditional EUID/root
  gate, no `eval`, and no `rm -rf` outside the owned temporary build
  directories.
  File removals are `rm -f` on manifest-recorded paths that are first
  confined. Traversal and control-character rejection, `realpath`
  canonicalization, a directory prefix re-check, and a regular-file
  (non-symlink) requirement for any backup that is used. The two gated
  exceptions (the `default_sched` line and the config-backup pruning) are
  matched by exact regex and regular-file checks respectively.
- The manifest is parsed strictly (duplicate and unknown keys abort), and the
  uninstaller removes the drop-in only if it byte-matches the installer's
  content.
- All prompts default to "no" when no input is available.
- Interpolation is limited to validated values. User-supplied flags are
  checked for control characters and leading `-` at parse time, `--branch`
  is restricted to `[A-Za-z0-9._/-]`, and values are sanitized (control
  characters replaced) before they are printed.
