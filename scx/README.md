# scx_mlfq

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

### Queues and virtual time
scx_mlfq is a Multilevel Feedback Queue scheduler. Tasks are classified into three queues, Q1 for interactive tasks, Q2 for tasks the scheduler cannot classify yet, and Q3 for CPU-bound tasks. Each queue is a vtime-ordered dispatch queue. The virtual deadline of a task, computed as its virtual runtime plus its slice scaled by weight (`slice * 100 / weight` on the scx weight scale, nice-0 = 100), is used as the insertion key, so the kernel dispatch queue rbtree serves the task with the earliest virtual deadline first, in the style of EEVDF.

### Classification
Classification is driven by a machine-learned regression tree that predicts a task's next CPU burst from its recent behavior: the previous burst length, the sleep that just ended, the EMA interactivity gauge, the I/O-wait flag and the recent wakeup count. The prediction is mapped onto the queues by the burst it fits — under 1 ms to Q1, under 3 ms to Q2, longer to Q3 — so a task that will finish quickly is served with the interactive slice, and a task that will run long is not. The tree is trained in the user-space daemon on samples of the machine's own task behavior, captured at each classification point and labeled with the run segment that followed, and is republished every minute from a sliding window of recent samples. Until the first model is trained, classification falls back to the EMA gauge exactly.

### Queue stability
The EMA gauge still climbs while a task runs and decays while it sleeps, and queue changes are asymmetric. The wakeup path is promotion-only: the regression tree, the short-sleep and I/O boost and the band hysteresis can only raise a task's queue, so a single wakeup prediction can never demote a task and bypass the demotion hysteresis. The one wakeup-path exception is the untrained fallback: before the first model is published, the long-sleep base remap can lower the queue back to the EMA base mapping — the tree itself never demotes at the wakeup. Demotions flow through the run-out gate, which requires a sustained run without sleeping — eight consecutive slice exhaustions under a CPU-bound classification — before a task drops to a lower queue. An aging pass re-classifies tasks that re-enqueue after a long stay in Q2 or Q3. The guaranteed Q3 share of every dispatch batch is the starvation bound.

### Preemption
A wakeup preempts the task running on its previous CPU when it belongs to a higher queue. A same-queue interactive wakeup (Q1 onto Q1) preempts immediately, so a task that just became runnable is served ahead of the resident at the next scheduling event; a same-queue wakeup in Q2 or Q3 preempts only when its freshly placed deadline is earlier than the resident's, the conservative virtual-time rule. Same-queue wakeups that do not meet their rule are served in virtual-time order at dispatch, so a resident is not displaced mid-slice by a wakeup it does not owe its CPU to. A preempting wakeup is granted a bounded slice (150 us), so the displaced task — typically the thread that woke it — resumes promptly; the policy slice governs all other paths.

### Dispatch
Slices are 1 ms for Q1, 2 ms for Q2 and 4 ms for Q3. Dispatch serves the queues within a bounded batch: Q1 up to a quota of four, then Q2 up to a quota of eight, then Q3. Each dispatch slot serves the CPU's own head of the queue being dispatched first, in virtual-time order, and then, when the own queue is drained, the earliest eligible remote head of the same queue, scanned over a rotating window of remote CPUs. A CPU whose queues are empty keeps its running task with a fresh slice instead of idling with runnable work.

### Wakeup boosts
Wakeups from a short sleep — up to 32 ms, the size of a 60 Hz frame interval with presentation margin — or from I/O get a rate-limited promotion to Q1, granted at most once per task every two milliseconds, so a bursty consumer of CPU such as a video decoder stays in Q1 for its whole burst. Higher refresh rates sleep for a shorter interval per frame and fall inside the same window.

### Placement
Placement is cache and capacity aware. Wakeups prefer the previous CPU when it is idle, then an idle CPU in the waker's LLC. On hybrid systems such as Intel P/E cores and ARM big.LITTLE, interactive tasks additionally prefer idle big cores and never stick to an efficiency core. The big-core preference follows the wakeup-path interactivity signal — the task's current queue or the short-sleep/I/O boost mirror — so on its first wakeup a task the tree classifies as interactive without a short-sleep or I/O boost gets the generic placement and moves to the big-core preference only on the wakeups that follow. Through the sched_ext cpuperf API the scheduler raises the schedutil performance target to its maximum for interactive tasks and follows the CPU's recent activity for the other queues, so the frequency tracks the load instead of staying pinned at the last level.

### Configuration
The scheduler is deliberately knob-free. The scheduling constants default to compile-time values in `src/bpf/intf.h` and are fixed into read-only data at load time; no command-line option changes the scheduling behavior, so there is nothing to misconfigure and no mode to get wrong.

While the scheduler runs it holds a PM QoS constraint on `/dev/cpu_dma_latency` at 10 us, the maximum tolerated idle-exit latency. The cpuidle governor then keeps the CPUs in the shallowest idle states that fit the cap (C1 on the target hardware), so wakeup latency is not dominated by the exits of the deeper core and package C-states. The constraint is applied automatically at attach, needs no configuration, and is released when the scheduler exits: closing the file drops the PM QoS request and restores the previous latency.

## Typical Use Cases

- Gaming and other latency-sensitive applications. Interactive tasks wake from short sleeps or I/O, promote to Q1, preempt lower-priority tasks, run at the maximum performance target, and prefer idle big cores on hybrid systems, so wakeup latency stays low.
- General desktop use. The desktop session stays responsive while background work such as software updates, file indexing, or compilation is demoted to Q3 and no longer competes with interactive tasks.
- Mixed workloads on laptops and desktops. CPU-bound jobs keep throughput with larger slices while the aging pass re-classifies tasks that wait in the lower queues for more than a second.

## Limitations

- The EEVDF substrate is approximated where BPF cannot express the kernel's exact machinery. Eligibility is enforced at placement with DELAY_ZERO semantics instead of an augmented-tree walk, and the weighted-average virtual time is replaced by a per-queue virtual clock: placement clamps each task's lag to within one lag bound of the clock, which preserves the bounded-lag safety property without a shared, lock-protected aggregate. Each approximation is documented in the code.
- The queues are per-CPU user dispatch queues. A CPU serves its own queues first, each head in virtual-time order, and steals the earliest-eligible remote same-queue head when its own queue is drained, so NUMA locality comes from wakeup placement while idle CPUs pull owed tasks from wherever they sit.
- sched_ext cannot schedule RT and DL tasks: the kernel resolves them to the rt and dl classes before sched_ext, so this scheduler handles SCHED_NORMAL, SCHED_BATCH and SCHED_IDLE tasks only.

## Status

The scheduler passes the project's CI stress simulation, including the affinity-pinned stressor variant, and has been exercised under full CPU load and in regular desktop use without stalls.

On the development machine (8-core, 16-thread desktop under a live desktop session), the burst-prediction model reports a mean absolute error of 299 us against the observed bursts, versus 1852 us for the EMA gauge on the same samples. The MAE is reported on the published (gate-passing) models: a retrained model that does not beat the EMA baseline on its held-out slice, or that was fit on too few distinct tasks, is kept out and the previous model stays committed, so the reported numbers describe the models that actually ran. With `schbench -m 2`, the wakeup latency holds at p50 10 us, p90 14 us, p99 23-24 us, with no throughput regression (average RPS 1608 versus 1612 in the previous version), and a CPU-bound task under interactive load keeps 32-50% more throughput than with the EMA-only classification.
