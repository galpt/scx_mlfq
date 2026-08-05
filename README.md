# scx_mlfq

A Multilevel Feedback Queue scheduler for sched_ext, with per-queue
EEVDF-style virtual-time scheduling.

scx_mlfq manages non-RT tasks in three queues. Q1 holds interactive tasks
with 1 ms slices, Q2 holds tasks the scheduler cannot classify yet with 2 ms
slices, and Q3 holds CPU-bound tasks with 4 ms slices. Each queue is a
vtime-ordered dispatch queue, where the virtual deadline of a task is the
insertion key, so the kernel dispatch queue rbtree provides
earliest-virtual-deadline-first selection. Task classification uses an EMA
interactivity gauge in the style of the infinity scheduler, with promotion
and demotion following MLFQ rules and hysteresis, and a periodic aging pass
bounds the wait of lower-queue tasks. See `scx/README.md` for an overview of
the design.

RT and DL tasks are scheduled by the kernel rt and dl classes. sched_ext
sits below the fair class, so this scheduler handles non-RT tasks only.

## Repository layout

```
scx/    scheduler sources, a drop-in for scheds/experimental/scx_mlfq/
        in a checkout of sched-ext/scx (see below)
tools/  CachyOS beta-testing scripts (install / uninstall)
LICENSE GPL-2.0
```

## Creating the upstream branch

The `scx/` directory mirrors the layout of `scheds/experimental/scx_mlfq/`
in the sched-ext/scx repository, so the merge is a directory copy plus a
one-line workspace edit. From a checkout of your scx fork, run

```sh
git checkout -b scx_mlfq
cp -r <this-repo>/scx scheds/experimental/scx_mlfq
# the scheduler package carries the repo LICENSE symlink, like every
# other scheduler; the standalone copy keeps the full text instead
rm scheds/experimental/scx_mlfq/LICENSE
ln -s ../../../LICENSE scheds/experimental/scx_mlfq/LICENSE
# add "scheds/experimental/scx_mlfq" to [workspace].members in Cargo.toml
cargo build --locked            # regenerates Cargo.lock for the new member
cargo fmt --check
cargo test --profile ci --locked -p scx_mlfq
git add scheds/experimental/scx_mlfq Cargo.toml Cargo.lock
git commit -s
```

The upstream CI runs, for every PR, `cargo fmt --check`, `cargo check
--profile ci --locked`, workspace unit tests with `cargo nextest`, BPF
verifier acceptance on the stable kernel matrix (6.13.y, 6.16.y, 6.18.y,
rolling-stable) via `cargo veristat`, and a stress-ng smoke run of each
scheduler in the test matrix (`-v`, 45 s, exit 0). `scx_mlfq -v` is required
for the stress gate, and the scheduler exits 0 on SIGTERM.

## Beta testing on CachyOS

See `tools/README.md` for the full instructions. In short, run

```sh
sudo bash tools/install_scx_mlfq.sh --dry-run   # preflight, read-only
sudo bash tools/install_scx_mlfq.sh             # build + install
sudo bash tools/uninstall_scx_mlfq.sh           # clean removal
```

The install script builds the scheduler from a git branch (default `galpt/scx`
branch `scx_mlfq`, or `--source-dir` for a local checkout), installs
`/usr/bin/scx_mlfq`, and records everything in a manifest under
`/usr/lib/scx/` so the uninstall script restores the previous state,
including the case where a future upstream release ships scx_mlfq in the
distro package.

## License

GPL-2.0-only. Copyright (c) 2026 Galih Tama <galpt@v.recipes>
