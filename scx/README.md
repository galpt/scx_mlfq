# scx_mlfq

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), the Linux kernel feature that enables implementing thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

### Queues and virtual time

scx_mlfq is a Multilevel Feedback Queue scheduler. Tasks are classified into three queues, Q1 for interactive tasks, Q2 for tasks the scheduler cannot classify yet, and Q3 for CPU-bound tasks. Each queue is a dispatch queue ordered by virtual time. A task's virtual deadline, computed as its virtual runtime plus its slice scaled by weight (`slice * 100 / weight` on the scx weight scale, nice-0 = 100), is the insertion key, so the kernel dispatch queue rbtree serves the task with the earliest virtual deadline first, in the style of EEVDF.

### Classification

Classification is driven by a machine-learned regression tree that predicts a task's next CPU burst from its recent behavior, namely the previous burst length, the sleep that just ended, the EMA interactivity gauge, the I/O-wait flag and the recent wakeup count. The prediction is mapped onto the queues by the burst it fits, under 1 ms to Q1, under 3 ms to Q2 and longer to Q3, so a task that will finish quickly is served with the interactive slice and a task that will run long is not. The tree is trained in the user-space daemon on samples of the machine's own task behavior, captured at each classification point and labeled with the run segment that followed, and is republished every minute from a sliding window of recent samples. Until the first model is trained, classification falls back to the EMA gauge exactly.

### Queue stability

The EMA gauge still climbs while a task runs and decays while it sleeps, and queue changes are asymmetric. The wakeup path is promotion-only. The regression tree, the short-sleep and I/O boost, and the band hysteresis can only raise a task's queue, so a single wakeup prediction can never demote a task past the demotion hysteresis. The one wakeup-path exception is the untrained fallback, where before the first model is published the long-sleep base remap can lower the queue back to the EMA base mapping. The tree itself never demotes at the wakeup. Demotions flow through the run-out gate, which requires a sustained run without sleeping, eight consecutive slice exhaustions under a CPU-bound classification, before a task drops to a lower queue. An aging pass re-classifies tasks that re-enqueue after a long stay in Q2 or Q3. The guaranteed Q3 share of every dispatch batch is the starvation bound.

### Preemption

A wakeup preempts the task running on its previous CPU when it belongs to a higher queue. A same-queue interactive wakeup (Q1 onto Q1) preempts immediately, so a task that just became runnable is served ahead of the resident at the next scheduling event. A same-queue wakeup in Q2 or Q3 preempts only when its freshly placed deadline is earlier than the resident's, the conservative virtual-time rule. Same-queue wakeups that do not meet their rule are served in virtual-time order at dispatch, so a resident is not displaced mid-slice by a wakeup it does not owe its CPU to. A preempting wakeup is granted a bounded slice of 150 us, so the displaced task, typically the thread that woke it, resumes promptly. The policy slice governs all other paths.

### Dispatch

Slices are 1 ms for Q1, 2 ms for Q2 and 4 ms for Q3. Dispatch serves the queues within a bounded batch, granting Q1 a quota of four, then Q2 a quota of eight, then Q3. Each dispatch slot serves the CPU's own head of the queue being dispatched first, in virtual-time order, and then, when the own queue is drained, the earliest eligible remote head of the same queue, scanned over a rotating window of remote CPUs. A CPU whose queues are empty keeps its running task with a fresh slice instead of idling with runnable work.

### Wakeup boosts

Wakeups from a short sleep, up to 32 ms or the size of a 60 Hz frame interval with presentation margin, and wakeups from I/O get a rate-limited promotion to Q1, granted at most once per task every two milliseconds. A bursty consumer of CPU such as a video decoder therefore stays in Q1 for its whole burst. Higher refresh rates sleep for a shorter interval per frame and fall inside the same window.

### Placement

Placement is cache and capacity aware. Wakeups prefer the previous CPU when it is idle, then an idle CPU in the waker's LLC. On hybrid systems such as Intel P/E cores and ARM big.LITTLE, interactive tasks additionally prefer idle big cores and never stick to an efficiency core. The big-core preference follows the wakeup-path interactivity signal, the task's current queue or the short-sleep and I/O boost mirror, so on its first wakeup a task the tree classifies as interactive without a short-sleep or I/O boost gets the generic placement and moves to the big-core preference only on the wakeups that follow. Through the sched_ext cpuperf API the scheduler raises the schedutil performance target to its maximum for interactive tasks and follows the CPU's recent activity for the other queues, so the frequency tracks the load instead of staying pinned at the last level.

### Configuration

The scheduler is deliberately knob-free. The scheduling constants default to compile-time values in `src/bpf/intf.h` and are fixed into read-only data at load time. No command-line option changes the scheduling behavior, so there is nothing to misconfigure and no mode to get wrong.

While the scheduler runs it holds a PM QoS constraint on `/dev/cpu_dma_latency` at 10 us, the maximum tolerated idle-exit latency. The cpuidle governor then keeps the CPUs in the shallowest idle states that fit the cap, C1 on the target hardware, so wakeup latency is not dominated by the exits of the deeper core and package C-states. The constraint is applied automatically at attach, needs no configuration, and is released when the scheduler exits. Closing the file drops the PM QoS request and restores the previous latency.

## Typical Use Cases

- Gaming and other latency-sensitive applications. Interactive tasks wake from short sleeps or I/O, promote to Q1, preempt lower-priority tasks, run at the maximum performance target, and prefer idle big cores on hybrid systems, so wakeup latency stays low.
- General desktop use. The desktop session stays responsive while background work such as software updates, file indexing, or compilation is demoted to Q3 and no longer competes with interactive tasks.
- Mixed workloads on laptops and desktops. CPU-bound jobs keep throughput with larger slices while the aging pass re-classifies tasks that wait in the lower queues for more than a second.

## Limitations

- The EEVDF substrate is approximated where BPF cannot express the kernel's exact machinery. Eligibility is enforced at placement with DELAY_ZERO semantics instead of an augmented-tree walk, and the weighted-average virtual time is replaced by a per-queue virtual clock. Placement clamps each task's lag to within one lag bound of the clock, which preserves the bounded-lag safety property without a shared, lock-protected aggregate. Each approximation is documented in the code.
- The queues are per-CPU user dispatch queues. A CPU serves its own queues first, each head in virtual-time order, and steals the earliest-eligible remote same-queue head when its own queue is drained, so NUMA locality comes from wakeup placement while idle CPUs pull owed tasks from wherever they sit.
- sched_ext cannot schedule RT and DL tasks. The kernel resolves them to the rt and dl classes before sched_ext, so this scheduler handles SCHED_NORMAL, SCHED_BATCH and SCHED_IDLE tasks only. The coexistence of those classes with the scheduler is described in the following section.

## Real-time core avoidance

sched_ext cannot run RT, DL and stop tasks either. The kernel resolves them to their own classes before sched_ext, so a realtime task that becomes runnable on a CPU running an SCX task takes the CPU over, and the scheduler only gets the CPU back when the higher-priority queue empties. The scheduler detects every such takeover on the context switch itself and keeps a per-CPU occupancy flag, so it always knows which cores are running realtime tasks. On a takeover it drains the DSQs of the CPU that was taken over through the kernel's reenqueue paths, rate-limited to at most one pass per millisecond so a takeover storm cannot burn the CPU in the hook, and wakeups whose target core is occupied are redirected to a core that is not.

The coexistence guarantees are structural. The kernel's class-pick loop reaches sched_ext only when no higher-priority class has a runnable task, so dispatch never runs on an occupied core. The built-in idle masks update only on idle-thread transitions, so an occupied CPU never appears idle to the idle scans. Wakeups are additionally redirected off occupied cores at enqueue time, and the queue DSQs of different CPUs share the per-queue virtual clock, so a redirected placement is identical to the original one apart from the owning CPU.

The limits of the approach are these. If every core is saturated by realtime tasks for longer than the 30-second watchdog, the scheduler exits and the kernel reverts to the CFS scheduler. A task pinned to an occupied core waits on its allowed CPU until the realtime load there clears. A kernel-bound per-CPU worker on a core a realtime task monopolizes is starved the same way under CFS, and since no scheduler can relocate it, the watchdog exits after the 30-second window. The takeover drain re-anchors the stranded tasks and the placement redirect relocates them to a non-occupied core. On kernels before 6.20, where the generic reenqueue is unavailable, the queue DSQs are served by the cross-CPU steal scans. The kernel-side mitigation for runaway realtime load is `sched_rt_runtime_us`. On kernels that have the deadline server, sched_ext is protected against deadline tasks, while realtime tasks have no server.

## Measuring wakeup latency

To measure the wakeup latency the scheduler delivers with cyclictest, pin the measurement threads to the measured CPUs with `-a`, move the device IRQs off those CPUs, use the `-c` monotonic clock option, and run the performance governor so frequency ramps do not gate the wakeup path. The kernel defers timers within a task's timer slack, so cyclictest reports bound the scheduler's contribution to the wakeup latency rather than a hardware-accurate measurement.

## Status

The scheduler passes the project's CI stress simulation, including the affinity-pinned stressor variant, and has been exercised under full CPU load and in regular desktop use without stalls.

On the development machine (8-core, 16-thread desktop under a live desktop session), the burst-prediction model reports a mean absolute error of 299 us against the observed bursts, versus 1852 us for the EMA gauge on the same samples. The MAE is reported on the published, gate-passing models. A retrained model that does not beat the EMA baseline on its held-out slice, or that was fit on too few distinct tasks, is kept out and the previous model stays committed, so the reported numbers describe the models that actually ran. With `schbench -m 2`, the wakeup latency holds at p50 10 us, p90 14 us, p99 23-24 us, with no throughput regression (average RPS 1608 versus 1612 in the previous version), and a CPU-bound task under interactive load keeps 32-50% more throughput than with the EMA-only classification.
