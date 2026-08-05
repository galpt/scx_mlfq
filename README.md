# scx_mlfq

A Multilevel Feedback Queue (MLFQ) scheduler for sched_ext, with per-queue
EEVDF-style virtual-time scheduling.

scx_mlfq manages non-RT tasks (SCHED_NORMAL/BATCH/IDLE/EXT) in three queues:

- **Q1** — interactive tasks (short sleeps, low EMA gauge), 1 ms slices
- **Q2** — tasks the scheduler cannot yet classify, 2 ms slices
- **Q3** — CPU-bound tasks, 4 ms slices

Each queue is a vtime-ordered dispatch queue: the virtual deadline
(`vruntime + slice/weight`) is used as the insertion key, so the kernel's
DSQ rbtree provides earliest-virtual-deadline-first selection. Task
classification uses an EMA interactivity gauge in the style of the
infinity scheduler; promotion and demotion follow MLFQ rules with
hysteresis, and a periodic aging pass bounds the wait of lower-queue
tasks. See `scx/README.md` for the full design.

RT/DL tasks are scheduled by the kernel rt/dl classes — sched_ext sits
below the fair class, so this scheduler handles non-RT tasks only.

## Repository layout

```
scx/    scheduler sources — drop-in for scheds/experimental/scx_mlfq/
        in a checkout of sched-ext/scx (see below)
tools/  CachyOS beta-testing scripts (install / uninstall)
LICENSE GPL-2.0
```

## Creating the upstream branch

The `scx/` directory mirrors the layout of `scheds/experimental/scx_mlfq/`
in the sched-ext/scx repository, so the merge is a directory copy plus a
one-line workspace edit. From a checkout of your scx fork:

```sh
git checkout -b scx_mlfq
cp -r <this-repo>/scx scheds/experimental/scx_mlfq
# add "scheds/experimental/scx_mlfq" to [workspace].members in Cargo.toml
cargo build --locked            # regenerates Cargo.lock for the new member
cargo fmt --check
cargo test --profile ci --locked -p scx_mlfq
git add scheds/experimental/scx_mlfq Cargo.toml Cargo.lock
git commit -s
```

The upstream CI runs, for every PR: `cargo fmt --check`, `cargo check
--profile ci --locked`, workspace unit tests (`cargo nextest`), BPF
verifier acceptance on the stable kernel matrix (6.13.y, 6.16.y, 6.18.y,
rolling-stable) via `cargo veristat`, and a stress-ng smoke run of each
scheduler in the test matrix (`-v`, 45 s, exit 0). `scx_mlfq -v` is
required for the stress gate; the scheduler exits 0 on SIGTERM.

## Beta testing on CachyOS

See `tools/README.md`. In short:

```sh
sudo bash tools/install_scx_mlfq.sh --dry-run   # preflight, read-only
sudo bash tools/install_scx_mlfq.sh             # build + install
sudo bash tools/uninstall_scx_mlfq.sh           # clean removal
```

The install script builds the scheduler from a git branch (default
`galpt/scx` branch `scx_mlfq`, or `--source-dir` for a local checkout),
installs `/usr/bin/scx_mlfq`, and records everything in a manifest under
`/usr/lib/scx/` so the uninstall script restores the previous state —
including the case where a future upstream release ships scx_mlfq in the
distro package.

## License

GPL-2.0-only. Copyright (c) 2026 Galih Tama <galpt@v.recipes>
