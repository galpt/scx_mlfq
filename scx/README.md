# scx_mlfq

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

scx_mlfq is a Multilevel Feedback Queue scheduler. Tasks are classified into three queues, Q1 for interactive tasks, Q2 for tasks the scheduler cannot classify yet, and Q3 for CPU-bound tasks. Each queue is a vtime-ordered dispatch queue. The virtual deadline of a task, computed as its virtual runtime plus its slice divided by its weight, is used as the insertion key, so the kernel dispatch queue rbtree serves the task with the earliest virtual deadline first, in the style of EEVDF.

Classification relies on an EMA interactivity gauge that climbs while a task runs and decays while it sleeps. The gauge maps onto the queues with hysteresis, so short-sleeping tasks promote to a higher queue, slice-exhausting CPU consumers demote to a lower queue, and an aging pass elevates tasks that have been queued in Q2 or Q3 for more than a second, which prevents starvation. A wakeup into a higher queue preempts the lower-queue task running on the wakee's previous CPU. Slices are 1 ms for Q1, 2 ms for Q2, and 4 ms for Q3, and dispatch serves Q1 up to a quota of four, then Q2 up to a quota of eight, then Q3, within a bounded batch. Wakeups from a short sleep or from I/O get a rate-limited virtual-slice boost, granted at most once per task every two milliseconds.

Placement is cache and capacity aware. Wakeups prefer the previous CPU when it is idle, then an idle CPU in the waker's LLC. On hybrid systems such as Intel P/E cores and ARM big.LITTLE, interactive tasks additionally prefer idle big cores and never stick to an efficiency core. Through the sched_ext cpuperf API the scheduler raises the schedutil performance target to its maximum for interactive tasks and lowers it to half for CPU-bound tasks.

RT and DL tasks are scheduled by the kernel rt and dl classes. sched_ext sits below the fair class, so this scheduler handles non-RT tasks only.

## Typical Use Case

Interactive-first desktop and latency workloads running alongside CPU-intensive background tasks. Interactive tasks get short, frequently refreshed deadlines on big cores, while CPU-bound work is demoted to Q3, where larger requests amortize switching cost.

## Limitations

The EEVDF substrate is approximated where BPF cannot express the kernel's exact machinery. Eligibility is enforced at placement with DELAY_ZERO semantics instead of an augmented-tree walk, only the local CPU's running task is folded into the weighted average, and the aggregate math is s64-only. Each approximation is documented in the code.

The MLFQ queues are host-wide user dispatch queues, so NUMA locality comes from wakeup placement, since the kernel's built-in per-node global dispatch queue does not apply to user dispatch queues. Per-node queue sharding is future work.

There are no cgroup ops. The kernel folds cgroup shares into the task weight, which the EEVDF ordering honors by construction.

## Production Ready?

Experimental. The scheduler is verifier-clean across the CI kernel range and passes the stress gate without stalls, but it has not been formally benchmarked against the fair scheduler yet.
