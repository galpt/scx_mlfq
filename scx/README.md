# scx_mlfq — Multilevel Feedback Queue with EEVDF per-queue scheduling (sched_ext)

A [sched_ext](https://www.kernel.org/doc/html/latest/scheduler/sched-ext.html)
CPU scheduler implementing a Multilevel Feedback Queue (MLFQ) discipline over
an EEVDF-style virtual-time substrate. See the [MLFQ reference](https://en.wikipedia.org/wiki/Multilevel_feedback_queue)
for the classic discipline this scheduler instantiates.

RT/DL tasks are scheduled by the kernel rt/dl classes — sched_ext sits below
the fair class, so this scheduler handles non-RT tasks only.

This is an experimental-tier sched_ext scheduler built on the standard scx
architecture: a Rust userspace front-end (CLI, stats server, monitor,
topology discovery) and a fully BPF-side scheduling core in `src/bpf/`.

## Overview

Three global, virtual-time-ordered user DSQs — **Q1** (interactive), **Q2**
(default), **Q3** (batch) — where the `vtime` passed to
`scx_bpf_dsq_insert_vtime()` is the EEVDF *virtual deadline* computed by our
own per-task vruntime/lag accounting. The kernel's DSQ rbtree then provides
min-deadline (earliest-virtual-deadline-first) selection.

Tasks are classified by an EMA interactivity gauge mapped onto the three
queues with band hysteresis:

| Event | Condition | Action |
|---|---|---|
| wakeup, ema < T_L/2 ×2 short sleeps | promote | Q2→Q1 |
| run-out ×2, ema > T_L | demote | Q1→Q2 |
| run-out ×2, ema > T_H (or once if > 2·T_H) | demote | Q2→Q3 |
| wakeup, ema < T_H/2 ×2 | promote | Q3→Q2 |
| wakeup, sleep > 120 ms | (EMA→0) | effective boost to Q1 by mapping |
| queued in Q2/Q3 ≥ 1 s (wall clock, sleep excluded) | aging | elevate to Q1 placement |

A Q1 wakeup preempts the lower-queue task running on the wakee's previous CPU
(`SCX_KICK_PREEMPT`). Dispatch serves Q1 (quota 4) → Q2 (quota 8) → Q3
(remainder) within `dispatch_max_batch` (32), which bounds a Q3 task's wait.

## Hybrid-capacity CPU placement

On asymmetric-capacity systems (Intel P/E cores, ARM big.LITTLE), Q1
(interactive) wakeups prefer **idle primary (big) cores**:

- The prev-CPU fast path is taken for Q1 only when prev is idle **and** a
  primary core — an interactive task does not stick to an efficiency core.
- Otherwise Q1 scans the primary-core bitmap for an idle and allowed CPU:
  the bitmap is walked in ascending CPU order and the **first** match wins —
  there is no capacity ordering.
- Q2/Q3 are unchanged: prev-if-idle, else any idle CPU (including efficiency
  cores — throughput work is welcome there).
- On uniform-capacity systems (one cluster, or no core-type data) the
  scheduler keeps the SMT-aware simple path: `mlfq_primary_all` short-circuits
  all hybrid logic.

The primary set is discovered from the system topology at startup: the
primary membership bitmap is written after load into an ARRAY map value
(`mlfq_primary_bitmap`); `mlfq_primary_all` is written into rodata before
load. Discovery is best-effort — any failure falls back to the
uniform-capacity behavior with a warning, never aborting the scheduler.

## Cache and NUMA locality

Wakeup and fork placement keeps the task in the waker's cache domain. The
placement order is:

1. **prev CPU** when idle (cache warmth; on hybrid systems an interactive
   task only sticks to prev when it is a primary core).
2. **An idle CPU in the waker's LLC** (the waker is the current CPU):
   interactive (Q1) wakeups additionally require a big core in that LLC, and
   an all-efficiency waker LLC is skipped entirely so the wakeup can land on
   an idle primary of a faster LLC; Q2/Q3 take any idle CPU in the LLC,
   efficiency cores included. A found CPU is served on its local DSQ.
3. The global fallbacks: Q1 prefers an idle primary core (SMT-aware whole-core
   preference on uniform systems), Q2/Q3 take any idle CPU; otherwise the
   kernel default and the shared vtime DSQ.

The per-LLC membership bitmaps are written from the discovered topology
into the `mlfq_llc_bitmaps` ARRAY map after load; `mlfq_nr_llcs` (0 disables
the LLC step), `mlfq_llc_has_primary[]` and `mlfq_cpu_llc[]` are written
into rodata before load. Machines with more than 32 LLC domains, or any
topology/population failure, degrade to the base placement behavior with a
warning.

**Honest NUMA note.** The kernel's built-in global DSQ is split per-NUMA-node
since 6.13 (each node consumes from its own node's DSQ), but the MLFQ queues
are *user* DSQs created via `scx_bpf_create_dsq()` — single host-wide
instances by construction — so node locality is not automatic for them. Likewise,
`scx_bpf_pick_idle_cpu()` is not node-biased on the 6.13-6.18 kernels this
scheduler targets. Locality here comes from wakeup placement and the local-DSQ
fast path; per-node queue sharding is documented future work, not implemented.

## Design details

**Pattern map** (refactoring.guru):

- **Strategy** — `src/bpf/vtime.bpf.c`, `src/bpf/classify.bpf.c`,
  `src/bpf/select_cpu.bpf.c`: interchangeable per-queue algorithms (placement
  math, classification, CPU selection) behind fixed call sites.
- **State** — `struct task_ctx` / `struct queue_ctx` in `src/bpf/intf.h` plus
  the hysteresis counters (`reenq_cnt` / `wake_cnt`) that gate band crossings.
- **Builder** — `src/bpf/enqueue.bpf.c`: routes each task by classification
  and aging state (fast path → migration-disabled → global vtime DSQ).
- **Observer** — `src/bpf/lifecycle.bpf.c`: the lifecycle callbacks observe
  running and stopping transitions to advance vruntime and the EMA gauge.
- **Template Method** — `SCX_OPS_DEFINE(mlfq_ops, ...)` in
  `src/bpf/main.bpf.c`: the fixed algorithm skeleton with overridable ops
  hooks.
- Userspace `src/config.rs` uses the Builder pattern to assemble a validated
  `Config`, written into BPF rodata before load; `src/topology.rs` feeds the
  hybrid-placement data.

**EEVDF mechanics — *preserved* exactly** (formulas match `kernel/sched/fair.c`
in the scx weight scale, nice-0 = 100):

- Virtual runtime advance: `vruntime += delta_exec * 100 / weight`
  (`calc_delta_fair`).
- Weighted-average virtual time `V_q = \Sum(v_i·w_i) / \Sum w_i`, computed in
  the relative form against `zero_vruntime` (s64-safe).
- Deadline: `vd_i = vruntime + calc_delta_fair(slice_i, weight_i)`.
- Lag-based placement with lag-conserving inflation and the lag clamp
  `±calc_delta_fair(max_slice + TICK, weight)`.
- Slice protection: the `slice` argument of `scx_bpf_dsq_insert_vtime()` is
  the runtime grant — the dispatch loop will not displace a task with
  remaining slice.
- Selection: the kernel DSQ rbtree pops the minimum `dsq_vtime`; since we
  insert `vtime = deadline`, this is earliest virtual deadline first with
  wrapping handled natively.
- First-placement boost: `PLACE_DEADLINE_INITIAL` (half vslice) via the
  `FIRST_RUN` flag.

**EEVDF mechanics — *approximated*** (each honest about the deviation):

- **(a) Eligibility enforced at placement, not selection.** EEVDF never picks
  an ineligible entity; the kernel uses an augmented tree walk we cannot
  replicate over a BPF DSQ. We clamp `vruntime_new = V_q` (lag → 0) at
  placement instead — `DELAY_ZERO` semantics — so every queued task is
  eligible by construction and min-deadline ≡ EEVDF over the queued set.
- **(b) Running-task fold.** `fair.c` folds `cfs_rq->curr` into the average;
  we fold only the *local* CPU's running task. The lag clamp absorbs the
  staleness of other CPUs' running tasks on re-enqueue.
- **(c) s64-only aggregate math.** No 128-bit products; the relative-form
  aggregates stay within s64 because `zero_vruntime` is advanced on every
  place/dequeue event.
- **(d) u64 wraparound convention** for all of our own vruntime comparisons.
- **EMA climb is per run segment** (with the delta clamp), not per tick;
  because the climb is a saturating exponential, a CPU-bound task converges to
  the same gauge value.
- **Wakeup preemption** is a simplified `wakeup_preempt_fair`: queue priority
  already encodes "slice comparison", and the kick is restricted to genuine
  promotions (into Q1 from Q2/Q3, or Q2 from Q3) to avoid IPI storms.

**Non-portable mechanisms and their approximations** (see `src/bpf/` for the
detail): futex-boost and IPC-gradient wakeup hooks are approximated by the
rate-limited short-sleep boost; the capacity-adaptive climb aggressiveness is
fixed at 3072; the continuous weight modulation of the reference work is
replaced by discrete queue promotion/demotion; the cgroup shield is dropped
(the kernel folds cgroup shares into `p->scx.weight` by construction).

## Use case

Interactive-first desktop and latency workloads: Q1 gives short-slice,
frequently-refreshed deadlines for interactive tasks, and on hybrid systems
keeps them on big cores; sustained CPU consumers demote to Q3 where larger
requests amortize switching cost and efficiency cores are acceptable; aging
and the EMA decay guarantee that no task is stuck in Q3.

## Options

```
Usage: scx_mlfq [OPTIONS]

Options:
      --stats <STATS>      Serve scheduler statistics over the unix socket at the given interval
      --monitor <MONITOR>  Run in statistics monitoring mode; the scheduler is not launched
  -d, --debug              Enable BPF debugging via /sys/kernel/tracing/trace_pipe
  -v, --verbose            Enable verbose output, including libbpf details
  -V, --version            Print scheduler version and exit
  -h, --help               Print help

Libbpf Options:
      --relaxed-maps <RELAXED_MAPS>
      --pin-root-path <PIN_ROOT_PATH>
      --kconfig <KCONFIG>
      --btf-custom-path <BTF_CUSTOM_PATH>
      --bpf-token-path <BPF_TOKEN_PATH>
```

`--completions <SHELL>` (hidden) generates shell completions for
bash/zsh/fish/elvish/powershell and exits. All tunables are `intf.h` constants
(no runtime knobs); `src/config.rs` validates them and writes them into BPF
rodata before load.

## Building / installing / running

```
# from the sched-ext/scx repo root (requires a BPF toolchain: clang + llvm)
BPF_CLANG=clang cargo build --profile ci --locked -p scx_mlfq

# unit tests (BPF-free; the C math harness compiles src/bpf/intf.h natively)
cargo test --profile ci --locked -p scx_mlfq

# run (requires root to attach; -V and --help work without it)
sudo target/ci/scx_mlfq

# monitor stats without attaching the scheduler
sudo target/ci/scx_mlfq --monitor 5
```

`veristat/9950x.json` and `veristat/9950x_hybrid.json` are the cargo-veristat
rodata-materialization configs for the BPF objects (uniform-capacity and
hybrid branches respectively). The BPF side is licensed GPL-2.0 and carries
the GPL license marker; the whole package is GPL-2.0-only.

**Watchdog & exit semantics:** `timeout_ms = 5000`; a stalled runnable task
triggers `SCX_EXIT_ERROR_STALL` and clean unregistration. On any exit the
kernel reverts all tasks to CFS; the UEI mechanism records the exit reason.
SIGINT/SIGTERM trigger the Ctrl-C handler, which unregisters cleanly and
exits 0.

## Limitations & honest deviations

- **RT/DL are never handled** — kernel class precedence (`stop > dl > rt >
  fair > ext > idle`) routes them before sched_ext is considered. This is a
  kernel-architecture property, not a feature gap.
- **EEVDF approximations** (a)–(d) above: eligibility is placement-time,
  `DELAY_ZERO` semantics rather than the augmented-tree walk; only the local
  CPU's running task is folded into `V_q`; no 128-bit products; u64 wraparound
  convention.
- **Global DSQs** mean shared-DSQ lock contention under heavy wakeup load,
  mitigated by the idle-CPU fast path (a wakeup selects an idle CPU and is
  served on its local DSQ). Per-LLC Q3 sharding is a documented v2 fallback.
- **No cgroup ops** — the kernel folds effective cgroup shares into
  `p->scx.weight`, so EEVDF ordering honors cgroup weights by construction.
- **Out of scope:** GPU/DRM coupling, cpufreq/cpuperf hints, web UI,
  procfs/sysctls (not available to BPF schedulers), PELT-based load balancing,
  `ops.runnable`/`ops.yield`/`ops.cpu_release`.
- **Implementation deviations** (each traceable to the code):
  - `task_ctx` carries three extra fields beyond the baseline layout —
    `last_ss_boost_at` (short-sleep boost rate limit), `queued_at`
    (wall-clock stay start for aging) and `wake_cpu_state` (select_cpu
    fast-path handoff); ~80 bytes instead of ~64.
  - The per-queue spinlock lives in a separate `queue_locks` array map so
    `intf.h` stays bindgen- and native-harness-safe.
  - The wakeup-preemption kick additionally guards on `running_pid != p->pid`
    and never kicks the local CPU, beyond the promotion-only guard.
  - **Aging is wall-clock stay-based, not epoch-timer-based.** The original
    design used a global `bpf_timer` bumping a per-queue epoch that enqueues
    compared against; the timer measured elapsed wall time even across sleep
    gaps between placements, so a task sleeping > 1 s was repeatedly
    boosted. The timer and epoch were dropped: `queued_at` is refreshed only
    at wakeup-enqueue and queue changes (never at run-out re-enqueues), and
    the enqueue check elevates a stay once `now - queued_at >=
    MLFQ_AGING_PERIOD_NS`. A stay is continuous Q2/Q3 wall-clock residency;
    sleeping resets it. There is no `aging_ticks` counter anymore — the
    existing `aging_boosts` counter reports aging activity.
  - **The demotion trigger is the run-out re-enqueue with `flags == 0`.**
    `SCX_ENQ_REENQ` is set by the kernel only for SCX_ENQ_IMMED re-enqueues
    and for `scx_bpf_reenqueue_local()`/`scx_bpf_dsq_reenq()` (ext.c:3102,
    4165, 4280) — none of which this scheduler uses — while slice-exhaustion
    re-enqueues arrive via `put_prev_task_scx()`'s
    `do_enqueue_task(rq, p, 0, -1)` (ext.c:3125). The demotion state machine
    therefore keys on `enq_flags == 0`; wakeup/fork/LAST enqueues reset the
    counters.
  - **select_cpu decline returns prev_cpu, never negative.** The kernel
    treats any negative `ops.select_cpu()` return as invalid and aborts the
    scheduler (`scx_cpu_valid()`, ext.c:1093-1101), so the selector returns
    prev_cpu when no idle CPU is found and lets the kernel handle the wakeup
    through the normal enqueue path.
  - **The place_entity behind-clamp.** The placed vruntime is clamped to
    `[V_q - limit, V_q]` (the eligibility clamp in `intf.h`, around line
    430): an inflated lag that would push the placed position past the lag
    bound — and, in the u64 encoding, past the wrap point — is clamped back
    to V_q with vlag zeroed. This is the wrap-safety fix for lag-inflation
    overflow; it is conservative (enforces `lag ∈ [0, limit]`) and deviates
    from the bare fair.c lag-conservation formula only at the clamp bound.
  - **EMA decay uses ln2-based coefficients** (`intf.h`): the residual
    factor is `1 - x·ln2 + (x·ln2)²/2` in fixed point, realizing the
    documented 24 ms half-life (`2^-x`) exactly. The reference
    implementation's `1 - x + x²/2` approximates `e^-x` (≈16.6 ms effective
    half-life); ours is the accurate half-life form.
  - **`zero_vruntime` is advanced on place/dequeue events only** (not on
    aging); aggregate keys stay bounded by the place/dequeue cadence.
  - **`deadline == 0` is the wrap sentinel** (intf.h): a deadline that wraps
    exactly to zero is bumped to 1, since zero is the placement-failure
    sentinel.
  - The `uclamp_min` demotion bypass is compile-gated
    (`MLFQ_HAVE_TASK_UCLAMP_MIN`, default 0) because the vmlinux.h this tree
    builds against does not expose `task_struct::uclamp_req`; it is silently
    dropped when unavailable.
  - The hybrid primary-bitmap scan is a compile-time-bounded word/bit walk
    over the whole CPU range (≤ 1024); the bitmap is an optional placement
    hint, so a missing or partially populated bitmap degrades gracefully to
    the all-primary / any-idle behavior.
  - Built with `BPF_CLANG=clang` (host clang, e.g. 22.x) against the repo's
    compat headers; `build.rs` suppresses `-Wno-missing-declarations` from
    generated vmlinux.h.

## Performance measurements

_No numbers yet — this section is filled after the verification plan runs
(Q1 wakeup latency, Q3 throughput, promotion/demotion churn,
`SCX_EV_REFILL_SLICE_DFL`/watchdog events, aging-boost counter). Nothing is
pre-filled per the accurate-README rule._
