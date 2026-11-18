# scx_mlfq

A Multilevel Feedback Queue scheduler for sched_ext.

Tasks drop through eight feedback levels while they run without sleeping.
The top level allows 20 ms of runtime and each level below it twice as
much as the one above, and a task goes back to the top level when it wakes
up. Lower levels are charged more virtual time, so CPU-bound work loses
priority the longer it runs while tasks that sleep often run first. Tasks
wait in one virtual deadline DSQ per LLC, or in a per-CPU DSQ when pinned,
and the deadline also weighs how latency critical a task is. See
`scx/README.md` for an overview of the design.

RT and DL tasks are scheduled by the kernel rt and dl classes. sched_ext
sits below the fair class, so this scheduler handles non-RT tasks only.

## Typical Use Cases

- Latency sensitive work, such as audio editing.
- Desktop use, such as gaming with browser tabs open.
- Batch work, such as compiling and rendering.

## Repository layout

```
scx/    scheduler sources, a drop-in for scheds/experimental/scx_mlfq/
        in a checkout of sched-ext/scx (see below)
tools/  CachyOS beta-testing scripts (install / uninstall, GUI integration
        via a patched scx_loader and libscxctl-ui; see tools/README.md)
LICENSE GPL-2.0
```

## Creating the upstream branch

The `scx/` directory mirrors the layout of `scheds/experimental/scx_mlfq/`
in the sched-ext/scx repository, which already lists the scheduler as a
workspace member, so the update replaces that directory. From a checkout of
your scx fork, run

```sh
git checkout -b scx_mlfq
rsync -a --delete <this-repo>/scx/ scheds/experimental/scx_mlfq/
# the scheduler package carries the repo LICENSE symlink, like every
# other scheduler; the standalone repo keeps the full text at the root LICENSE
rm scheds/experimental/scx_mlfq/LICENSE
ln -s ../../../LICENSE scheds/experimental/scx_mlfq/LICENSE
cargo update -p scx_mlfq       # syncs Cargo.lock with the new sources
cargo fmt --check
cargo test --profile ci --locked -p scx_mlfq
git add scheds/experimental/scx_mlfq Cargo.lock
git commit -s
```

The upstream CI runs, for every PR, `cargo fmt --check`, `cargo check
--profile ci --locked`, workspace unit tests with `cargo nextest`, BPF
verifier acceptance on rolling-stable, bpf-next and sched_ext for-next via
`cargo veristat`, and a stress-ng smoke run of each
scheduler in the test matrix (`-v`, 45 s, exit 0). `scx_mlfq -v` is required
for the stress gate, and the scheduler exits 0 on SIGTERM.

## Beta testing on CachyOS

See `tools/README.md` for the full instructions. In short, run

```sh
sudo bash tools/install_scx_mlfq.sh --dry-run   # preflight, read-only
sudo bash tools/install_scx_mlfq.sh             # full install (scheduler + GUI integration)
sudo bash tools/install_scx_mlfq.sh --beta-only # scheduler binary only
sudo bash tools/uninstall_scx_mlfq.sh           # clean removal of everything
```

The install script builds the scheduler from this repository: it clones
the standalone repo (branch `archive/v2.0.2`), copies the `scx/` sources
into a sched-ext workspace (cloned from `galpt/scx`, branch `main`, or
`--source-dir` for a local workspace), installs `/usr/bin/scx_mlfq`, and records everything in a
manifest under `/usr/lib/scx/` so the uninstall script restores the
previous state, including the case where a future upstream release ships
scx_mlfq in the distro package.

## Credits

scx_mlfq is made possible by the support we received from the sched_ext
community. Credit goes to the developers and contributors whose work
inspired it and who helped with its development.

## License

GPL-2.0-only. Copyright (c) 2026 Galih Tama <galpt@v.recipes>
