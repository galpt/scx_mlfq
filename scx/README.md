# scx_mlfq

scx_mlfq is a user-defined scheduler for Linux, written in Rust with a BPF core, that runs inside [`sched_ext`](https://github.com/sched-ext/scx/tree/main). It is a multilevel feedback queue built on EEVDF-style virtual time, and it is deliberately knob-free.


## Overview

Tasks are classified into three per-CPU queues. Q1 holds interactive tasks with 1 ms slices, Q2 holds unclassified tasks with 2 ms slices, and Q3 holds CPU-bound tasks with 4 ms slices. All queues serve in virtual-deadline order within a bounded dispatch batch.

Classification uses a per-task EMA interactivity gauge. The gauge climbs by run time and decays at wakeup by a half-life step. A task that has run more than it slept accumulates gauge and crosses the CPU-bound threshold. A task that sleeps enough zeroes the gauge.

Queue moves happen only at period boundaries. Wakeup promotes, run-out demotes. An 8-exhaustion gate demotes tasks that repeatedly exhaust their slices. Aging elevates any task that has sat in Q2 or Q3 for one second back to Q1. The scheduler never demotes at wakeup.

The scheduler also implements cache-aware stealing, placement tiers, keep-path dispatch, a guaranteed Q3 share of every dispatch batch, and RT/DL kernel-side avoidance. Every placement clamps a task's lag to within one lag bound of its queue's virtual clock. The details live in the code comments.


## Production Ready?

Yes


## Configuration

The scheduler is deliberately knob-free. The scheduling constants are compile-time values in `src/bpf/intf.h`, and no command-line option changes the scheduling behavior. The runtime footprint depends only on the reporting options (`--stats`, `--monitor`, `--no-webui`). At startup a topology banner reports the CPU count, the big-core split, the LLC domains, the SMT state, and whether one LLC domain is strictly the largest. The run also holds a 10 us PM QoS constraint on `/dev/cpu_dma_latency`.


## Web UI

A dashboard is served on the loopback address, port 50005, with a unix-socket fallback. It shows a plain-language Summary built from the live counters, a compact per-CPU grid and the System counters, with no authentication, since the loopback address is the trust boundary. `--no-webui` disables it.

The loader's network sandbox is a seccomp filter the scheduler inherits and cannot lift in place. When the TCP bind is denied, the dashboard serves via the unix socket and the scheduler writes a per-boot runtime drop-in under `/run` that lifts the sandbox for the next start, removing it on exit. `/run` is tmpfs, so an unclean exit self-heals. The full mechanics live in the `src/webui.rs` comments.


## Real-time Core Avoidance

Realtime tasks take a CPU over when they become runnable, since the kernel resolves them to their own classes before sched_ext. The scheduler detects every takeover through `ops.cpu_release()`/`ops.cpu_acquire()`, drains the DSQs of the taken-over CPU, and skips occupied cores in placement. On kernels before 6.19 the drain is a no-op, since the kernel re-enqueues the local DSQ itself. If a scheduling callback stalls for longer than the 30 s watchdog, the scheduler exits and the kernel reverts to CFS. The details live in `src/bpf/rtdl.bpf.c`.


## Measuring Wakeup Latency

To measure the wakeup latency the scheduler delivers with cyclictest, pin the measurement threads to dedicated CPUs with `-a`, use the monotonic clock (`-c 0`), a realtime priority (`-p 99`), and the performance governor, and move the device IRQs off the measured CPUs. For percentiles, run schbench with two message threads (`-m 2`) on an otherwise quiet machine. `clock_nanosleep` passes the task's timer slack to the timer as an expiry range, so the kernel may defer the wakeup by up to the slack, 50 us by default. The measured value therefore includes the deferral, the interrupt path and the scheduler's wakeup latency, so cyclictest reports a conservative upper bound on the scheduler's contribution, not the scheduler's latency alone.


## Limitations

- The bounded-lag guarantee is per-queue. Cross-queue lag conservation is absent.
- The queues are per-CPU user dispatch queues, so locality comes from placement while idle CPUs steal owed tasks from wherever they sit.
- The runnable gauges cover tracked tasks only and are advisory.
- The largest-LLC bias trades clock speed for cache capacity, is Q1-only and non-exclusive, and is off on single-LLC and equal-size machines.
- The topology is snapshotted at attach, so a CPU hotplug needs a restart.
- RT and DL tasks are handled by the kernel's own classes before sched_ext.
- Requires Linux 6.18 or newer. The realtime-takeover drain degrades by kernel version. On 6.18 the drain is a no-op and the kernel re-enqueues the local DSQ itself. The scheduler-side local re-enqueue needs 6.19, and the queue-DSQ re-enqueue needs 7.1.
- On 6.18, 6.19, 7.1, and 7.2, reenqueue path differences may affect steal and drain behavior under high load.
