# scx_mlfq

This is a single user-defined scheduler used within [`sched_ext`](https://github.com/sched-ext/scx/tree/main), which is a Linux kernel feature which enables implementing kernel thread schedulers in BPF and dynamically loading them. [Read more about `sched_ext`](https://github.com/sched-ext/scx/tree/main).

## Overview

`scx_mlfq` is a Multilevel Feedback Queue (MLFQ) scheduler. Tasks are
classified into three queues — **Q1** (interactive), **Q2** (unclassified),
**Q3** (CPU-bound) — and each queue is a vtime-ordered DSQ: the virtual
deadline (`vruntime + slice/weight`) is used as the insertion key, so the
kernel's DSQ rbtree provides earliest-virtual-deadline-first selection
within a queue, in the style of EEVDF.

Classification uses an EMA interactivity gauge that climbs with runtime and
decays with sleep, mapped onto the queues with hysteresis: short-sleeping
tasks promote, slice-exhausting CPU consumers demote, and an aging pass
elevates tasks queued in Q2/Q3 for over a second so no task starves. A
wakeup into a higher queue preempts the lower-queue task on the wakee's
previous CPU. Slices are 1/2/4 ms for Q1/Q2/Q3; dispatch serves Q1 (quota 4),
then Q2 (quota 8), then Q3, within a bounded batch.

Placement is cache- and capacity-aware: wakeups prefer the prev CPU when
idle, then an idle CPU in the waker's LLC; on hybrid systems (P/E cores,
big.LITTLE) interactive tasks additionally prefer idle big cores and never
stick to an efficiency core.

RT/DL tasks are scheduled by the kernel rt/dl classes — sched_ext sits below
the fair class, so this scheduler handles non-RT tasks only.

## Typical Use Case

Interactive-first desktop and latency workloads running alongside
CPU-intensive background tasks: interactive tasks get short, frequently
refreshed deadlines on big cores, while CPU-bound work is demoted to Q3
where larger requests amortize switching cost.

## Limitations

- The EEVDF substrate is approximated where BPF cannot express the kernel's
  exact machinery: eligibility is enforced at placement (DELAY_ZERO
  semantics) instead of by an augmented-tree walk, only the local CPU's
  running task is folded into the weighted average, and the aggregate math
  is s64-only. Each approximation is documented in the code.
- The MLFQ queues are host-wide user DSQs; NUMA locality comes from wakeup
  placement, since the kernel's built-in per-node global DSQ does not apply
  to user DSQs. Per-node queue sharding is future work.
- No cgroup ops: the kernel folds cgroup shares into `p->scx.weight`, which
  the EEVDF ordering honors by construction.

## Production Ready?

Experimental. The scheduler is verifier-clean across the CI kernel range and
passes the stress gate without stalls, but it has not been formally
benchmarked against the fair scheduler yet.
