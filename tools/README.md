# scx_mlfq beta-testing tools for CachyOS

This directory contains the beta-testing tooling for **scx_mlfq** on CachyOS:

| File | Purpose |
|---|---|
| `install_scx_mlfq.sh` | Build and install (or replace) the beta scheduler binary |
| `uninstall_scx_mlfq.sh` | Manifest-driven clean removal, safe even after upstream ships `scx_mlfq` in a package |

Both scripts are bash, must be run as **root** (`sudo`), and are safe to run
repeatedly. Run either with `--dry-run` first to preview what it would do.

## What scx_mlfq is

`scx_mlfq` is an experimental sched_ext CPU scheduler for Linux, written in
Rust with a BPF component. It implements a Multilevel Feedback Queue (MLFQ)
discipline on top of EEVDF-style virtual-time scheduling: three global queues
(Q1/Q2/Q3) ordered by a per-task virtual deadline, with a continuous EMA-based
interactivity gauge (plus hysteresis) deciding which queue a task lives in.
Interactive-first desktop/latency workloads are served from Q1, batch work is
demoted toward Q3. Like all sched_ext schedulers it handles **non-RT tasks
only**, so the kernel's rt/dl classes are untouched. It is the successor to
`scx_flow`. There is **no web UI and no TCP listener**, so the scheduler
attaches directly to the kernel and can only be observed through the
kernel's sched_ext interface and `scx_mlfq --stats`.

## Prerequisites

- **CachyOS** (any Arch-like distro with `pacman` and systemd is treated as a
  match; the installer warns and asks for confirmation on anything else).
- A **sched_ext-capable kernel**. The installer checks
  `/sys/kernel/sched_ext` and the kernel config
  (`CONFIG_SCHED_CLASS_EXT=y`). CachyOS kernels ship with this.
- A build toolchain: `git`, `cargo` (Rust, stable), and the `clang`/libbpf
  toolchain used by the `sched-ext/scx` workspace. No packages are installed
  by these scripts.
- `scx-tools` / `scx_loader` is **optional**. scx_mlfq does not need it, and
  scx_loader cannot manage scx_mlfq yet anyway (see FAQ).
- **Root**. Both scripts refuse to run as a non-root user, including with
  `--dry-run`.

## Installing

```bash
sudo bash install_scx_mlfq.sh [options]
```

Defaults (matching the beta-testing workflow):

| Option | Default |
|---|---|
| `--repo` | `https://github.com/galpt/scx.git` |
| `--branch` | `scx_mlfq` |
| `--source-dir` | unset (clone from `--repo`/`--branch` instead) |

Options:

- `--repo URL` - repository to clone (must be a full `scx` workspace).
- `--branch NAME` - branch to clone.
- `--source-dir DIR` - build from a local `scx` workspace instead of cloning.
  `DIR` must contain `Cargo.toml` with `scheds/experimental/scx_mlfq` listed
  as a workspace member. `--repo`/`--branch` are ignored when set.
- `--force` - skip the interactive confirmation when `/usr/bin/scx_mlfq` is
  owned by a package; also backs up and replaces a conflicting pre-existing
  drop-in instead of refusing.
- `--dry-run` - validate inputs and print every action **without** cloning,
  building, or changing the system.
- `--help`, `-h` - print help.

Examples:

```bash
# Default: clone galpt/scx branch scx_mlfq and install
sudo bash install_scx_mlfq.sh

# Preview without touching the system
sudo bash install_scx_mlfq.sh --dry-run

# Build from a local scx tree
sudo bash install_scx_mlfq.sh --source-dir /home/user/scx

# Reinstall over a package-owned binary without prompting
sudo bash install_scx_mlfq.sh --force
```

What the installer does, in order:

1. Checks that you are root, that the distro is CachyOS/Arch-like (parsed
   from `/etc/os-release`, never sourced), and that sched_ext is available.
2. Clones the branch into a temporary directory (or uses `--source-dir`) and
   runs `cargo build --release -p scx_mlfq`; verifies the built binary
   exists. Flag values are validated up front: control characters and a
   leading `-` are rejected, and `--branch` is restricted to
   `[A-Za-z0-9._/-]`.
3. Checks the systemd drop-in (read-only, before any other change): if
   `/etc/systemd/system/scx.service.d/scx_mlfq-beta.conf` already exists and
   differs byte-for-byte from the content this installer writes, it refuses
   to proceed unless `--force` is given (then the existing file is backed up
   to `/usr/lib/scx/scx.service.d.scx_mlfq-beta.conf.bak` and replaced).
4. Stops `scx.service` (errors ignored). If a scheduler is currently attached
   (`/sys/kernel/sched_ext/state` != `disabled`) **and** `scx_loader` is
   active, it also stops `scx_loader.service`. The loader is **not disabled**;
   it may be left stopped because it cannot run scx_mlfq anyway.
5. Checks package ownership of `/usr/bin/scx_mlfq` with `pacman -Qo`:
   - exit 0 (owned by a package, e.g. a future upstream release) → requires
     `--force` or an interactive `y/N` before overwriting. The original is
     backed up with `cp -p` to `/usr/lib/scx/scx_mlfq.scx_mlfq-beta.bak`, and
     the owner plus its sha256 are recorded;
   - exit 1 (unowned) → install directly;
   - any other exit code (database locked or corrupt) → **abort**; the
     installer never silently treats a pacman error as "unowned".
6. Stages the binary, writes the install manifest `/usr/lib/scx/scx_mlfq-beta.manifest`
   (version, `installed_sha256`, `orig_owner`, `orig_sha256`, `backup_path`,
   `dropins`, `dropin_backup` when one was made, install time, source/branch),
   and only then swaps the binary into place with an atomic staged copy
   (`cp` → `chmod 755` → `mv -f`). **The manifest is written BEFORE the swap,
   so an interrupted run never leaves a new binary without a manifest; a
   leftover stage file is removed by the EXIT trap.**
7. Runs `systemctl daemon-reload`.
8. Runs a smoke test (`scx_mlfq --version`). A failure is reported as a clear
   warning, not fatal.
9. Prints a status summary. **scx_mlfq is NOT auto-started.**

Start it now, one of:

```bash
# Direct run (foreground). Ctrl+C detaches; the kernel reverts to CFS.
sudo /usr/bin/scx_mlfq

# Via systemd (uses the drop-in above)
sudo systemctl restart scx.service
```

## Uninstalling

```bash
sudo bash uninstall_scx_mlfq.sh [--force] [--dry-run]
```

The uninstaller is **manifest-driven and idempotent**:

- If no manifest exists it prints `Nothing to uninstall` and exits 0 without
  touching any file.
- The manifest is parsed **strictly**: duplicate keys, unknown keys, and
  values containing control characters abort the run without touching
  anything.
- It stops `scx.service` if it is active (safe: it may be running the beta),
  but never disables or removes the unit.
- Binary handling depends on what the manifest records:
  - the installer had replaced a **package-owned** file: if the current
    binary still matches the recorded beta sha256, the backup is moved back
    (only after the backup is verified to be a regular, non-symlink file)
    and verified against the recorded original sha256, then
    `pacman -Qkk <owner>` is run and reported. If the package already
    re-placed the file (sha256 differs), the binary is left untouched and
    only the backup and manifest are removed.
  - the installer had installed an **unowned** file: it is removed only if it
    still matches the recorded beta sha256; otherwise it is left in place
    with a warning.
- It removes **only** the installer's own drop-in
  (`scx_mlfq-beta.conf`, and only if it byte-matches what the installer
  writes, otherwise it is left in place with a warning, and the parent
  `scx.service.d/` is removed only if now empty), any recorded drop-in
  backup, the binary backup, and the manifest, then runs
  `systemctl daemon-reload`.
- It never touches `scx_loader.service`, `/etc/default/scx`, or any other
  file. Every path read from the manifest is confined before use: traversal
  components (`..`, `.`) and control characters are rejected, the path is
  canonicalized with `realpath`, and it must resolve inside its expected
  directory (`/usr/lib/scx/` for backups, the exact drop-in path for the
  drop-in).

## FAQ

**Why can't the CachyOS Kernel Manager GUI manage scx_mlfq?**

`scx_loader` (from `scx-tools`) ships with a *hardcoded* list of supported
schedulers, and `scx_mlfq` is not in it. Because of that, `scx_loader`,
`scxctl`, `scx-manager`, and the CachyOS Kernel Manager GUI can neither list
nor start scx_mlfq today. The two working beta launch paths are the direct
run and the `scx.service` drop-in shown above. Once scx_mlfq is merged
upstream and a future `scx-tools` includes it in the loader enum, the GUI
will be able to manage it normally.

**How do I go back to my previous scheduler?**

Stop the beta (Ctrl+C if you ran it directly, or `sudo systemctl stop
scx.service`) and run the uninstaller. Without the installer's drop-in,
`scx.service` uses the default scheduler configured in `/etc/default/scx`.
You can also reinstall the packaged schedulers at any time:

```bash
sudo pacman -S scx-scheds
```

The kernel reverts to CFS automatically whenever a scheduler detaches, so
there is never a window with no scheduler.

**What happens when upstream ships scx_mlfq in a package?**

Once `scx_mlfq` is merged, `scx-scheds` (and `scx-scheds-git`) will ship
`/usr/bin/scx_mlfq` automatically. Before upgrading or installing the package
over your beta binary, run:

```bash
sudo bash uninstall_scx_mlfq.sh
```

The uninstaller restores the package-owned file from its backup (or, if the
package already re-placed the file, just removes the backup and manifest).
After that, normal CachyOS tooling owns the binary and the GUI can manage it.

**Does scx_mlfq have a web UI or listen on a port?**

No. There is no web UI and no TCP listener (locked design decision), and the
installer deliberately creates **no** `scx_loader.service` drop-in. Scheduler
state is only visible through the kernel's sched_ext interface
(e.g. `cat /sys/kernel/sched_ext/root/ops`) and `scx_mlfq --stats`.

**Is it safe to run as root / what if something goes wrong?**

- Only **one** sched_ext scheduler can be attached at a time; both scripts
  stop the currently attached scheduler gracefully (the kernel then reverts
  to CFS automatically).
- The scripts never edit `/etc/default/scx`, never disable `scx_loader` or
  `scx.service`, and never remove `scx.service` itself.
- The uninstaller never touches a file without a manifest.
- Reinstalling simply replaces the binary; the manifest is rewritten with the
  new state. An existing backup is overwritten with a warning.
- If `/etc/systemd/system/scx.service.d/scx_mlfq-beta.conf` already exists
  with different content, the installer refuses until you remove it or pass
  `--force` (which backs it up first). It never silently overwrites or
  records a drop-in it did not write.
- If the installer is interrupted after writing the manifest but before the
  binary swap, the old binary stays in place and the leftover stage file is
  cleaned up by the EXIT trap; re-run the installer to finish.
- `--dry-run` requires root, performs no clone and no build, and changes
  nothing, it is a safe way to check the installer's decisions (including
  whether `/usr/bin/scx_mlfq` is currently package-owned).
- The installer uses only owned temporary build directories (under
  `/tmp/scx_mlfq-build.*`, created with `mktemp`) and removes them on exit.

## Safety notes for reviewers

- Both scripts use `set -euo pipefail`, an unconditional EUID/root gate, no
  `eval`, and no `rm -rf` outside the owned temporary build directory.
  File removals are `rm -f` on manifest-recorded paths that are first
  confined: traversal/control-character rejection, `realpath`
  canonicalization, a directory prefix re-check, and a regular-file
  (non-symlink) requirement for any backup that is used.
- The manifest is parsed strictly (duplicate/unknown keys abort), and the
  uninstaller removes the drop-in only if it byte-matches the installer's
  content.
- All prompts default to "no" when no input is available.
- Interpolation is limited to validated values: user-supplied flags are
  checked for control characters and leading `-` at parse time, `--branch`
  is restricted to `[A-Za-z0-9._/-]`, and values are sanitized (control
  characters replaced) before they are printed.
