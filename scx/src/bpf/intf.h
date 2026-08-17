/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multilevel Feedback Queue scheduling with per-queue EEVDF virtual time.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * This header is shared between BPF, the Rust front-end (via bindgen) and
 * the native unit-test harness. It holds every scheduling constant, the
 * task/queue state layouts and the pure virtual-time and classification
 * math, and it defines its own kernel type aliases so the harness can
 * compile it without the kernel headers.
 */
#ifndef __SCX_MLFQ_INTF_H
#define __SCX_MLFQ_INTF_H

#ifndef __VMLINUX_H__
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long s64;
typedef int pid_t;
#endif

#include <stdbool.h>

#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif

/*
 * Native-harness fallback for the iterator-based bpf_for loops below.
 * The BPF build gets the real iterator macro from scx/common.bpf.h
 * (included by main.bpf.c before this header). The pure-math harness
 * compiles this header without any BPF machinery, so a plain bounded
 * for-loop preserves the same semantics for the pure functions. The
 * iterator form is what keeps the verifier's exploration of the loop
 * flat. A plain constant-bound loop is not unrolled and the verifier
 * processes each iteration until its states converge, which blows the
 * instruction budget for the steering scan.
 */
#ifndef __VMLINUX_H__
#ifndef bpf_for
/*
 * Harness-only stand-in for the kernel's iterator loop: the native
 * unit-test build has no BPF iterator machinery, and the call sites
 * pass a plain loop variable, which is the iterator contract (the
 * first argument is always a fresh scalar). The BPF build uses the
 * kernel's bpf_for from the toolchain headers instead.
 */
#define bpf_for(i, start, end) for ((i) = (start); (i) < (end); (i)++)
#endif
#endif

/*
 * Instrumentation. Set to 1 to compile the invariant checks
 * into the BPF object. They are compiled out by default. The check
 * predicates themselves live under the same guard and are exercised by the
 * native unit-test harness with MLFQ_CHECK forced on.
 */
#ifndef MLFQ_CHECK
#define MLFQ_CHECK 0
#endif

enum mlfq_consts {
	NSEC_PER_USEC			= 1000ULL,
	NSEC_PER_MSEC			= (1000ULL * NSEC_PER_USEC),
	NSEC_PER_SEC			= (1000ULL * NSEC_PER_MSEC),

	/*
	 * Per-queue request sizes. The values are powers of two in nsecs
	 * (nominal 1/2/4 ms, exact 2^20/2^21/2^22 ns) so the CBS period
	 * decay and the cpuperf fold are pure shifts.
	 */
	MLFQ_Q1_SLICE_NS		= (1ULL << 20),
	MLFQ_Q2_SLICE_NS		= (1ULL << 21),
	MLFQ_Q3_SLICE_NS		= (1ULL << 22),

	/*
	 * Assumed tick length for the lag clamp horizon. The tick is used as
	 * the HZ=1000 approximation in the lag bound. The bound is
	 * limit = calc_delta_fair(max_slice + TICK, weight), the one used by
	 * entity_lag() in kernel/sched/fair.c.
	 */
	MLFQ_TICK_NS			= (1ULL * NSEC_PER_MSEC),

	/*
	 * Ceiling of the per-task burst gauge, in nsecs. The gauge is the
	 * clamped excess of run time over the CBS-period refunded sleep,
	 * and the ceiling is 2^23 ns (about 8.4 ms, nominal "8 ms"), four
	 * times the T_H threshold, so a saturated gauge sits well past the
	 * CPU-bound edge.
	 */
	MLFQ_GAUGE_MAX_NS		= (1ULL << 23),

	/* Classification thresholds. */
	MLFQ_T_L_NS			= (250ULL * NSEC_PER_USEC),
	MLFQ_T_H_NS			= (4ULL * NSEC_PER_MSEC),

	/*
	 * CBS server period multiplier. Each queue's server is (Q_q, P_q)
	 * with P_q = MLFQ_CBS_PERIOD_MULT * Q_q, a 50 % soft reservation.
	 * The period is a power of two because the slice is, so the period
	 * decay is a pure shift.
	 */
	MLFQ_CBS_PERIOD_MULT		= 2,

	/*
	 * Consecutive slice exhaustions that gate a demotion. The run-out
	 * counter saturates at this value, so a Q3 task that never demotes
	 * cannot wrap the u8 counter.
	 */
	MLFQ_DEMOTE_EXHAUSTIONS		= 8,

	/*
	 * Short-sleep boost window. Covers periodic wakeup cadences such
	 * as the 60 Hz frame interval, so latency-sensitive consumers of
	 * CPU are recognized as interactive even when their runtime
	 * consumption would otherwise classify them as CPU-bound. The
	 * per-task boost rate limit keeps the churn bounded.
	 * The value is set against the slowest common cadence, and faster
	 * refresh rates sleep for a shorter interval per frame and fall
	 * inside the window as well.
	 */
	MLFQ_SHORT_SLEEP_NS		= (32ULL * NSEC_PER_MSEC),
	MLFQ_SHORT_SLEEP_RATE_LIMIT_NS	= (2ULL * NSEC_PER_MSEC),
	MLFQ_HYSTERESIS_SLEEP_NS	= (4ULL * NSEC_PER_MSEC),

	/* Aging. */
	MLFQ_AGING_PERIOD_NS		= (1ULL * NSEC_PER_SEC),

	/*
	 * Minimum residency before a same-queue wakeup may preempt the
	 * running task, in nsecs. The interactive same-queue rule (Q1 onto
	 * Q1) preempts on this guard alone, and the non-interactive rule
	 * additionally requires the wakeup's fresh deadline to precede the
	 * resident's. Zero, the default, makes the interactive rule
	 * unconditional, so a wakeup that just became runnable is served
	 * ahead of the resident at the next scheduling event. Internal
	 * tuning constant, not a user-facing knob.
	 */
	MLFQ_SAMEQ_PREEMPT_MIN_RUN_NS	= 0ULL,

	/*
	 * Slice cap for a preempting wakeup, in nsecs. The preempt path
	 * displaces a running task, so the grant is a bounded burst. The
	 * displaced task (typically the thread that woke this one, whose
	 * early deadline puts it first in the virtual-time order) resumes
	 * at the next scheduling event once the cap expires. The policy
	 * slice still governs the regular path and the continuation after
	 * the run-out re-enqueue. Internal tuning constant, not a
	 * user-facing knob.
	 */
	MLFQ_PREEMPT_SLICE_NS		= (150ULL * NSEC_PER_USEC),

	/*
	 * UAPI linux/sched.h policy value. sched_ext only receives
	 * SCHED_NORMAL/BATCH/IDLE/EXT tasks.
	 */
	MLFQ_SCHED_IDLE			= 5,

	/* Dispatch quotas. */
	MLFQ_Q1_QUOTA			= 4ULL,
	MLFQ_Q2_QUOTA			= 8ULL,
	MLFQ_DISPATCH_MAX_BATCH		= 32ULL,

	/*
	 * Cap on the remote CPUs scanned per dispatch slot. The scan
	 * starts at a rotating per-CPU offset so no remote CPU is
	 * permanently excluded. The runtime bound (mlfq_steal_scan) is
	 * this value clamped to the CPU count in init(), so the window
	 * never exceeds the machine size and a small machine does not
	 * re-peek the same remote DSQs. The static bound also bounds the
	 * verifier's exploration of the nested steal loops, and it must
	 * stay low enough that mlfq_dispatch() verifies within the
	 * kernel's jump-sequence limit.
	 */
	MLFQ_STEAL_SCAN_MAX		= 64ULL,

	/*
	 * sched_ext cpuperf level (scx_bpf_cpuperf_set(), the schedutil
	 * target hint). The perf argument is a linear relative level in
	 * [0, SCX_CPUPERF_ONE], and SCX_CPUPERF_ONE is 0x400 (1024), the
	 * maximum level. The kernel stores the target per-CPU and it
	 * persists until overwritten, so ops.running() states the level of
	 * the task now on the CPU on every context switch and schedutil
	 * follows. The interactive queue requests the maximum level and
	 * the other queues request the level matching the CPU's recent
	 * activity (mlfq_cpuperf_level()), so a CPU that once ran an
	 * interactive task does not stay at the maximum level for the
	 * background work that follows. With the scheduler in switch-all
	 * mode the target is the only utilization signal schedutil sees.
	 */
	MLFQ_CPUPERF_Q1			= 1024ULL,

	/*
	 * Length of the per-CPU busy window for the windowed cpuperf
	 * fold, in nsecs. 2^24 ns is about 16.8 ms, nominal "16 ms". The
	 * level is busy_win_ns >> 14, bit-identical to
	 * busy_win_ns * 1024 / W because W = 2^24 and the level scale is
	 * 2^10.
	 */
	MLFQ_CPUPERF_WINDOW_NS		= (1ULL << 24),

	MLFQ_NR_QUEUES			= 3ULL,

	/*
	 * Per-CPU vtime-ordered queue DSQ id space. Every CPU owns
	 * MLFQ_NR_QUEUES DSQs, laid out as MLFQ_DSQ_BASE +
	 * cpu * MLFQ_DSQ_STRIDE + (qid - 1) so the owning CPU and queue
	 * decode arithmetically (see mlfq_dsq_id()). The range ends far
	 * below SCX_DSQ_LOCAL_ON, which reserves the top bits for the
	 * kernel DSQ flags, and init() validates this at load time.
	 */
	MLFQ_DSQ_BASE			= 0x1000ULL,
	MLFQ_DSQ_STRIDE			= MLFQ_NR_QUEUES,

	/*
	 * Compile-time CPU bound for the per-CPU capacity array. Matches the
	 * per-CPU state map bound (cpu_state_stor, 1024 entries), and init()
	 * rejects machines with more online CPUs.
	 */
	MLFQ_MAX_CPUS			= 1024ULL,

	/*
	 * Compile-time bound for the per-LLC bitmap array. Machines with
	 * more LLC domains than this have LLC-aware placement disabled at
	 * startup (the userspace side refuses to populate the bitmaps).
	 */
	MLFQ_MAX_LLCS			= 32ULL,

	/*
	 * Tier-A same-LLC steal window. The flat scan over the consuming
	 * CPU's own-LLC CPU list, one peek per slot. The compile-time
	 * bound keeps the verifier's exploration flat, identical in shape
	 * to the cross-LLC window it gates.
	 */
	MLFQ_LLC_SCAN_MAX		= 32ULL,

	/*
	 * Per-LLC CPU-list bound. The largest CPU count any LLC domain may
	 * publish into the mlfq_llc_cpus map values. Equal to the Tier-A
	 * scan window, so the window's constant modulo covers the whole
	 * populated list. The front-end populates a domain's list only up
	 * to MLFQ_LLC_SCAN_MAX CPUs, and a domain that exceeds the bound
	 * gets an EMPTY list (nr == 0) instead. Tier A then skips it and
	 * the Tier B rotating window covers the domain, never a silently
	 * shrunk subset of it. The cpus[] array is exactly the window
	 * width, so every published entry is reachable by the scan.
	 */
	MLFQ_MAX_LLC_CPUS		= MLFQ_LLC_SCAN_MAX,

	/*
	 * Steering scan cap. The number of least-loaded-LLC selection
	 * attempts the steering path may make before falling through
	 * to the global fallbacks. The tuning knob lives with the other
	 * steering constants.
	 */
	MLFQ_STEER_LLC_MAX		= 4ULL,

	/*
	 * Number of 64-bit words needed to hold one CPU bit per CPU.
	 */
	MLFQ_BITMAP_WORDS		= (MLFQ_MAX_CPUS + 63) / 64,

	/*
	 * The ops watchdog timeout, in milliseconds. The kernel's
	 * maximum detection latency for a stalled scheduler, and the
	 * scheduler exits and the kernel reverts to CFS when it fires.
	 */
	MLFQ_OPS_TIMEOUT_MS		= 30000,

	/*
	 * Drain interval of the realtime-takeover evacuation. At most one
	 * pass per CPU per millisecond. The rate limit bounds the churn a
	 * takeover can stir up, which otherwise has no kernel-side repeat
	 * guard. The stop-class blips that punctuate a takeover, RT tasks
	 * that ping-pong between runnable states, and the pinned-task
	 * reenqueue loop are all absorbed by the window.
	 */
	MLFQ_RTDL_DRAIN_INTERVAL_NS	= (1ULL * NSEC_PER_MSEC),
};

/* task_ctx flags */
enum mlfq_task_flags {
	MLFQ_TF_FIRST_RUN		= 1U << 0,	/* first placement */
};

/*
 * Sentinel "no LLC owner" value for task_ctx.last_llc. Valid LLC domain
 * ids are 0..MLFQ_MAX_LLCS-1 (0..31), which fit in a u8. 0xFF marks a
 * task that is not counted in the per-LLC runnable gauges: it is not
 * runnable, or it is parked on the kernel-owned global DSQ where no LLC
 * owns it.
 */
#define MLFQ_LLC_UNOWNED 0xFFU

/*
 * Per-task state in BPF task storage. All timestamps are scx_bpf_now()
 * nsecs. vruntime is on the owning queue's virtual-time clock and is
 * re-anchored to the queue's clock at every placement. The struct is
 * 88 bytes. g is the burst gauge, the classification input, and
 * last_grant_ns is the last slice grant, the FCBS slack donor.
 */
struct task_ctx {
	u64 vruntime;			/* last placed virtual runtime */
	s64 vlag;			/* clamped lag at placement, >= 0 */
	u64 deadline;			/* last computed virtual deadline */
	u64 g;				/* burst gauge [0, MLFQ_GAUGE_MAX_NS] */
	u64 last_run_at;		/* scx_bpf_now() at ops.running() */
	u64 last_sleep_at;		/* scx_bpf_now() at stopping(!runnable) */
	u64 queued_at;			/* start of the current Q2/Q3 stay */
	u64 last_ss_boost_at;		/* last short-sleep boost, rate limit */
	u32 weight;			/* cached p->scx.weight [1..10000] */
	u8  queue;			/* current queue, 1..3 */
	u8  reenq_cnt;			/* consecutive slice exhaustions */
	u8  wake_cnt;			/* consecutive short-sleep wakeups */
	u8  flags;			/* MLFQ_TF_* */
	u8  wake_cpu_state;		/* bit0 idle, bit1 valid */
	/*
	 * Runnable-ownership record, maintained by the accounting helpers
	 * (mlfq_runnable_enter/exit). last_llc is the LLC domain owning
	 * the task's current DSQ or running CPU, MLFQ_LLC_UNOWNED when
	 * the task is not runnable or is parked on the kernel-owned
	 * global DSQ, and last_qid is the queue (1..3) of the last
	 * counted placement, 0 when unowned. The pair is the single
	 * source of truth for "is this task counted in the per-LLC and
	 * per-queue runnable gauges". The helpers treat last_llc ==
	 * MLFQ_LLC_UNOWNED as not counted. The read-modify-write is
	 * lock-free. The kernel serializes enqueue/dequeue/stopping per
	 * task, so the counter RMWs stay exact in the absence of a
	 * cross-rq race, and a torn read can only defer one release,
	 * self-healed by the next episode entry.
	 */
	u8  last_llc;			/* owning LLC, MLFQ_LLC_UNOWNED if none */
	u8  last_qid;			/* queue of the last placement, 0 if none */
	u8  pad[2];
	/*
	 * The last slice grant, in nsecs. Every grant path writes it, and
	 * the FCBS slack donation at ops.stopping() compares it against
	 * the run segment. The preempt path writes zero, so a preempt
	 * burst never donates slack.
	 */
	u64 last_grant_ns;
};

/* wake_cpu_state bits */
#define MLFQ_WAKE_CPU_IDLE	0x01U
#define MLFQ_WAKE_CPU_VALID	0x02U

/*
 * Per-queue virtual clock. clock is the service point the queue
 * has reached. It advances monotonically as the queue's tasks run, and
 * placement anchors a task's lag to it. No weighted-average aggregate is
 * maintained because computing it needs consistent reads of two shared
 * sums, which in BPF would require mutual exclusion. The bounded-lag
 * theorem is instead enforced by clamping the task lag to the clock at
 * placement, which is exact enough for the safety properties and keeps
 * the placement lock-free.
 */
struct queue_ctx {
	/*
	 * Virtual clock of the queue. Read without a lock by
	 * every placement. The aligned 64-bit load is atomic on the
	 * supported targets, and a stale read only lowers the clock,
	 * which the placement clamp absorbs.
	 */
	u64 clock;
	u64 max_slice_ns;		/* per-queue request size */
	/*
	 * FCBS reclaim bonus. bonus_ns is the unspent budget donated by
	 * early-completing tasks, clamped to max_slice_ns, and the next
	 * task granted a slice of this queue consumes it. bonus_since is
	 * the scx_bpf_now() of the last deposit, the idle-decay anchor.
	 * Both are bss-zeroed by default.
	 */
	u64 bonus_ns;
	u64 bonus_since;
	u64 pad[4];			/* one queue_ctx per cacheline */
};

/*
 * Global idle tracking. mlfq_idle_count is the number of currently idle
 * CPUs, maintained by ops.update_idle() with atomic RMWs (a single u32,
 * the only consumer treats it as a zero/non-zero test). mlfq_idle_tracking
 * is a rodata gate written by the Rust front-end. It is 1 only when the
 * kernel keeps its built-in idle tracking alongside the callback (the
 * KEEP_BUILTIN_IDLE flag), 0 otherwise. Declared here so the modules and
 * the pure-math harness share the same contract.
 */
extern volatile u32 mlfq_idle_count;
extern const volatile u32 mlfq_idle_tracking;

/*
 * Per-CPU state, BPF_MAP_TYPE_ARRAY keyed by cpu. 48 bytes, one cacheline.
 */
struct mlfq_cpu_state {
	s32 running_queue;		/* queue of the running task, 0 none */
	u32 running_pid;
	u32 steal_scan_off;		/* rotating remote-scan start for Q2/Q3 */
	u32 perf_level;			/* windowed cpuperf level [0, CPUPERF_Q1] */
	u64 busy_win_ns;		/* busy time in the current window */
	u64 busy_win_start;		/* scx_bpf_now() of the window start */
	u64 running_deadline;		/* running task's deadline, 0 unknown */
	u64 run_start_at;		/* scx_bpf_now() at ops.running() */
};

/* Per-CPU realtime-occupancy flags. */
#define MLFQ_RTDL_OCCUPIED			(1U << 0)

/*
 * Per-CPU realtime-occupancy state, keyed by cpu id in the
 * rtdl_state_stor array map. flags reflects the class of the last task
 * that ran on the CPU (see the sched_switch hook in rtdl.bpf.c), which
 * decides whether the CPU is treated as unavailable to the SCX classes.
 * last_drain_at rate-limits the evacuation pass of the takeover path.
 */
struct mlfq_rtdl_state {
	u32 flags;			/* MLFQ_RTDL_* bits */
	u32 pad;
	u64 last_drain_at;		/* scx_bpf_now() of the last drain */
};

/*
 * Op-latency histogram. Each slot (MLFQ_OP_LAT_* below) charges the
 * wall time its callback spends running into one of eight buckets that
 * delimit the elapsed microseconds. The buckets are [0, 2), [2, 5), [5, 10), [10, 20),
 * [20, 50), [50, 100), [100, 250) and [250, inf). The preemption path is
 * healthy when its charges stay in the first few buckets. A regression
 * shows up as a visible shift toward the tail.
 */
enum mlfq_op_lat_slots {
	MLFQ_OP_LAT_STOPPING		= 0,
	MLFQ_OP_LAT_DISPATCH		= 1,
	MLFQ_OP_LAT_ENQUEUE		= 2,
	MLFQ_OP_LAT_CPU_RELEASE		= 3,
	MLFQ_OP_LAT_OPS			= 4,
};

/* Histogram bucket count and the bucket edges, in microseconds. */
enum mlfq_op_lat_consts {
	MLFQ_OP_LAT_BUCKETS		= 8,
	MLFQ_OP_LAT_EDGE_2		= 2,
	MLFQ_OP_LAT_EDGE_5		= 5,
	MLFQ_OP_LAT_EDGE_10		= 10,
	MLFQ_OP_LAT_EDGE_20		= 20,
	MLFQ_OP_LAT_EDGE_50		= 50,
	MLFQ_OP_LAT_EDGE_100		= 100,
	MLFQ_OP_LAT_EDGE_250		= 250,
};

/* One op's latency histogram, a BPF_MAP_TYPE_PERCPU_ARRAY value. */
struct mlfq_op_lat {
	u64 buckets[MLFQ_OP_LAT_BUCKETS];
};

/* System-level BPF counters, reported to userspace through the stats module. */
struct mlfq_stats {
	u64 total_runtime;
	u64 on_cpu;
	u64 q1_placements;
	u64 q2_placements;
	u64 q3_placements;
	u64 promotions;
	u64 demotions;
	u64 aging_boosts;
	u64 short_sleep_boosts;
	u64 preemption_kicks;
	u64 cpuperf_boosts;
	/* Dispatch-path counters: remote-DSQ moves and solo-task keep grants. */
	u64 steals;
	u64 steals_same_llc;		/* steals within one LLC domain */
	u64 steals_cross_llc;		/* steals across LLC domains */
	u64 keep_running;
	/* Enqueue-path diagnostics: the early-return drop counters. */
	u64 enq_no_tctx;
	u64 enq_bad_weight;
	u64 enq_no_deadline;
	u64 enq_fastpath;
	u64 enq_regular;
	u64 enq_pinned_idle;
	u64 enq_pinned_busy;
	u64 enq_pinned_global;
	/* Realtime-takeover diagnostics (rtdl.bpf.c, enqueue.bpf.c). */
	u64 rt_takeovers;		/* 0->1 occupied transitions observed */
	u64 rt_evacuations;		/* DSQ evacuation passes that ran */
	u64 rt_redirects;		/* wakeups redirected off occupied CPUs */
	u64 rt_reenqs;			/* SCX_ENQ_REENQ re-enqueues counted */
	/* FCBS within-queue reclaim diagnostics. */
	u64 fcbs_grants;		/* bonus grants consumed */
	u64 fcbs_slack_events;		/* slack deposits made */
	/*
	 * The counter struct is 29 u64s = 232 bytes. The pad is a
	 * zero-length marker that keeps the field count explicit.
	 */
	u64 pad[0];
};

/*
 * Plain u64 bitmap of CPU membership (bit N set = CPU N present). The
 * primary-core set and each LLC domain use one of these, stored in
 * BPF_MAP_TYPE_ARRAY values so the maps are writable from userspace
 * without any kernel cpumask machinery.
 */
struct mlfq_bitmap {
	u64 words[MLFQ_BITMAP_WORDS];
};

/*
 * One LLC domain's CPU list, the value type of the mlfq_llc_cpus array
 * map. Written by the Rust front-end after load. The dispatch Tier-A
 * scan walks the consuming CPU's own-LLC entry as its same-LLC steal
 * window. 132 bytes per value (4 + 32 * 4), far under the ARRAY-map
 * value-size limit. The unpopulated map state means "feature off", and
 * an empty per-domain list (nr == 0, an oversized domain) means "Tier A
 * skips this domain, Tier B's full window covers it".
 */
struct mlfq_llc_cpu_list {
	u32 nr;				/* valid CPUs in cpus[] */
	u32 cpus[MLFQ_MAX_LLC_CPUS];	/* the domain's CPU ids */
};

/*
 * One virtual-time DSQ per queue per CPU. The id is
 * MLFQ_DSQ_BASE + cpu * MLFQ_DSQ_STRIDE + (qid - 1), so the owning
 * CPU and queue decode arithmetically: (id - base) / stride and
 * (id - base) % stride. The range ends far below SCX_DSQ_LOCAL_ON,
 * which reserves the top bits for the kernel DSQ flags.
 */
static __always_inline u64 mlfq_dsq_id(u8 qid, s32 cpu)
{
	return MLFQ_DSQ_BASE + (u64)cpu * MLFQ_DSQ_STRIDE + (u64)(qid - 1);
}

/**
 * mlfq_bitmap_test_cpu - Test a CPU's bit in a bitmap.
 * @bm: The bitmap.
 * @cpu: The CPU id.
 *
 * Out-of-range CPUs never have their bit set.
 *
 * Return: True if @cpu's bit is set.
 */
static __always_inline bool mlfq_bitmap_test_cpu(const struct mlfq_bitmap *bm,
						 u32 cpu)
{
	if (cpu >= MLFQ_MAX_CPUS)
		return false;
	return bm->words[cpu >> 6] & (1ULL << (cpu & 63));
}

/**
 * mlfq_bitmap_set_cpu - Set a CPU's bit in a bitmap.
 * @bm: The bitmap.
 * @cpu: The CPU id.
 *
 * Out-of-range CPUs are ignored.
 */
static __always_inline void mlfq_bitmap_set_cpu(struct mlfq_bitmap *bm, u32 cpu)
{
	if (cpu >= MLFQ_MAX_CPUS)
		return;
	bm->words[cpu >> 6] |= (1ULL << (cpu & 63));
}

/**
 * mlfq_time_before - Wrapping-safe u64 "before" comparison.
 * @a: First comparable as u64.
 * @b: Second comparable as u64.
 *
 * Same convention as fair.c vruntime_cmp()/time_before64(): the kernel
 * DSQ orders by min deadline with the same wrapping semantics.
 *
 * Return: true if @a is before @b.
 */
static __always_inline bool mlfq_time_before(u64 a, u64 b)
{
	return (s64)(b - a) > 0;
}

/**
 * mlfq_ss_boost_allowed - Short-sleep boost rate-limit check.
 * @last_boost_at: scx_bpf_now() of the last short-sleep boost (0 = never).
 * @now: Current time.
 * @rate_limit: Minimum spacing between boosts (MLFQ_SHORT_SLEEP_RATE_LIMIT_NS).
 *
 * At most one short-sleep boost per task per @rate_limit window: the boost
 * fires only once the previous window has fully elapsed, so a wakeup burst
 * cannot chain boosts. The first boost (never boosted before) is always
 * allowed.
 *
 * Return: true if a new boost may be granted at @now.
 */
static __always_inline bool mlfq_ss_boost_allowed(u64 last_boost_at, u64 now,
						  u64 rate_limit)
{
	if (!last_boost_at)
		return true;
	return mlfq_time_before(last_boost_at + rate_limit, now);
}

/**
 * mlfq_boost_eligible - IPC boost eligibility at wakeup.
 * @sleep_ns: Sleep duration at wakeup (scx_bpf_now() delta, 0 = none).
 * @window_ns: Short-sleep window (MLFQ_SHORT_SLEEP_NS).
 * @io_wait: True when the wakeup is an I/O completion
 *	(task_struct::in_iowait).
 *
 * A wakeup is boost-eligible when it is an I/O wakeup regardless of the
 * sleep length, or when the sleep fell within the short-sleep window. The
 * I/O-wait case covers the other classic interactive wakeup source beside
 * the short-sleep window. The rate limit is applied separately by the
 * caller (mlfq_ss_boost_allowed()), so an I/O wakeup burst cannot chain
 * boosts.
 *
 * Return: true if the wakeup is boost-eligible.
 */
static __always_inline bool mlfq_boost_eligible(u64 sleep_ns, u64 window_ns,
						bool io_wait)
{
	if (io_wait)
		return true;
	return sleep_ns && sleep_ns <= window_ns;
}

/**
 * mlfq_ss_boost_pending - Short-sleep boost decision for a wakeup.
 * @tctx: The task context.
 * @sleep_ns: Sleep duration at wakeup.
 * @io_wait: True when the wakeup is an I/O completion.
 * @now: Current time (scx_bpf_now()).
 * @short_sleep: Short-sleep window (MLFQ_SHORT_SLEEP_NS).
 * @rate_limit: Minimum spacing between boosts (MLFQ_SHORT_SLEEP_RATE_LIMIT_NS).
 *
 * Combines the wakeup test (mlfq_boost_eligible()) with the per-task
 * boost rate limit (mlfq_ss_boost_allowed()). The wakeup classification
 * uses it to apply the boost, and the CPU selection uses it to know
 * whether a wakeup will be treated as interactive before the
 * classification runs, so both paths agree on the same condition.
 *
 * Return: true if the wakeup qualifies for the Q1 boost.
 */
static __always_inline bool mlfq_ss_boost_pending(const struct task_ctx *tctx,
						  u64 sleep_ns, bool io_wait,
						  u64 now, u64 short_sleep,
						  u64 rate_limit)
{
	return mlfq_boost_eligible(sleep_ns, short_sleep, io_wait) &&
	       mlfq_ss_boost_allowed(tctx->last_ss_boost_at, now, rate_limit);
}

/**
 * mlfq_cpuperf_level - CPU performance level for a busy-window gauge.
 * @busy_ns: The CPU's busy time in the current window.
 *
 * Maps the windowed busy-ns gauge to the sched_ext cpuperf scale. A CPU
 * that ran tasks for the whole window requests the maximum level and a
 * lightly loaded CPU requests a proportionally lower one. The window is
 * MLFQ_CPUPERF_WINDOW_NS = 2^24 ns and the level scale is 2^10, so
 * busy_ns * 1024 / W is bit-identical to busy_ns >> 14, a pure shift.
 *
 * Return: The cpuperf level in [0, SCX_CPUPERF_ONE].
 */
static __always_inline u32 mlfq_cpuperf_level(u64 busy_ns)
{
	u64 level = busy_ns >> 14;

	return level > MLFQ_CPUPERF_Q1 ? MLFQ_CPUPERF_Q1 : (u32)level;
}

/**
 * calc_delta_fair_bpf - Scale a runtime delta to virtual time.
 * @delta: Physical time in nsecs.
 * @weight: Task weight in scx scale (nice-0 = 100, min 1).
 *
 * EEVDF virtual time grows at rate w_i/NICE_0_LOAD while running. With
 * the scx weight scale this is delta * 100 / weight.
 *
 * Return: The virtual time delta.
 */
static __always_inline u64 calc_delta_fair_bpf(u64 delta, u32 weight)
{
	return delta * 100 / weight;
}

/**
 * mlfq_lag_limit - Placement lag bound (fair.c entity_lag()).
 * @q: The queue.
 * @weight: Task weight.
 *
 * limit = calc_delta_fair(max_slice + TICK, weight). A task is placed at
 * most one request plus one tick behind the queue's virtual clock, the
 * bounded-lag horizon of entity_lag() in kernel/sched/fair.c.
 *
 * Return: The lag bound in virtual-time nsecs.
 */
static __always_inline u64 mlfq_lag_limit(const struct queue_ctx *q, u32 weight)
{
	return calc_delta_fair_bpf(q->max_slice_ns + MLFQ_TICK_NS, weight);
}

/**
 * mlfq_queue_advance_clock - Advance a queue's virtual clock.
 * @q: The queue.
 * @vruntime: The virtual runtime just charged for the queue.
 *
 * The clock follows the service given to the queue. It is advanced to
 * @vruntime whenever @vruntime is ahead of it, as a monotone max update.
 * The clock never moves backward. The compare-and-swap stores only when
 * the clock still holds the value the advance read, and the winner of a
 * contended update is the store that lands first, not necessarily the
 * largest one. A losing update can therefore leave the clock behind the
 * true service point by at most the virtual-time spread of the
 * concurrent updates. The placement clamp bounds the error this creates
 * and the next advance heals it. The single-shot compare-and-swap never
 * retries, so the update cost is constant and contention degrades to a
 * stale clock, never to a convoy.
 */
static __always_inline void mlfq_queue_advance_clock(struct queue_ctx *q,
						     u64 vruntime)
{
	u64 cur = q->clock;

	if (mlfq_time_before(cur, vruntime))
		__sync_val_compare_and_swap(&q->clock, cur, vruntime);
}

/**
 * mlfq_place_entity_deadline - Compute a placement deadline, read-only.
 * @q: The queue being placed into.
 * @tctx: The task being placed.
 *
 * The placement formula of mlfq_place_entity() without the commit. The
 * deadline a placement against @q's virtual clock would produce, computed
 * from the pre-placement task state. The wakeup-preemption decision uses
 * it to compare a wakeup's fresh deadline against the resident's before
 * deciding to preempt. The preempt path inserts into the local DSQ
 * without placement (the deadline is re-anchored on the next real
 * placement), so the comparison must not consume the placement.
 *
 * Return: The deadline the placement would commit.
 */
static __always_inline u64
mlfq_place_entity_deadline(const struct queue_ctx *q,
			   const struct task_ctx *tctx)
{
	u64 w = tctx->weight;
	u64 limit = mlfq_lag_limit(q, (u32)w);
	u64 clock = q->clock;
	u64 lag, vslice, vruntime_new, deadline;

	/*
	 * The lag is measured in the wrapping order of the virtual-time
	 * clock: a task ahead of the clock sits at it (fair.c
	 * DELAY_ZERO), a task behind is clamped to the clock minus
	 * the bound. The wrapping-aware comparison keeps the u64 epoch
	 * boundary indistinguishable from any other point.
	 */
	lag = mlfq_time_before(clock, tctx->vruntime) ? 0 : clock - tctx->vruntime;
	if (lag > limit)
		lag = limit;

	vruntime_new = clock - lag;

	vslice = calc_delta_fair_bpf(q->max_slice_ns, (u32)w);
	/* fair.c PLACE_DEADLINE_INITIAL: new tasks start with half a slice. */
	if (tctx->flags & MLFQ_TF_FIRST_RUN)
		vslice /= 2;

	deadline = vruntime_new + vslice;
	/*
	 * A deadline that lands exactly on the wrap point computes to zero.
	 * Zero is the sentinel for a failed placement, so move the wrapped
	 * deadline to one, which is positionally identical in the wrapping
	 * order the DSQ rbtree uses.
	 */
	if (!deadline)
		deadline = 1;
	return deadline;
}

/**
 * mlfq_place_entity - Place a task on the virtual-time timeline.
 * @q: The queue being placed into.
 * @tctx: The task being placed.
 *
 * EEVDF placement against the queue's virtual clock is this.
 *
 *   limit        = calc_delta_fair(max_slice + TICK, weight)
 *   lag          = clamp(clock - vruntime, 0, limit)
 *   vruntime_new = clock - lag       (== clamp(vruntime, clock - limit, clock))
 *   vslice       = calc_delta_fair(slice_q, weight)
 *   if (FIRST_RUN) vslice /= 2
 *   deadline     = vruntime_new + vslice
 *
 * A task that has fallen behind the service point is re-anchored within
 * one lag limit of the clock, the bounded-lag property of fair.c
 * entity_lag(). A task that is ahead of the clock is placed at the
 * clock itself, the fair.c DELAY_ZERO semantics that do not carry
 * leading credit. The stored lag is therefore bounded in [0, limit],
 * and every queued task is eligible, so min-deadline
 * selection over the queue DSQs is EEVDF selection over the queued set.
 *
 * Updates tctx->vruntime, tctx->vlag (>= 0) and tctx->deadline.
 *
 * Return: The placement deadline, also stored in tctx->deadline.
 */
static __always_inline u64 mlfq_place_entity(const struct queue_ctx *q,
					     struct task_ctx *tctx)
{
	u64 w = tctx->weight;
	u64 limit = mlfq_lag_limit(q, (u32)w);
	u64 clock = q->clock;
	u64 lag, vruntime_new, deadline;

	/*
	 * The commit of the mlfq_place_entity_deadline() formula: the
	 * deadline is computed first from the pre-placement state, then
	 * the clamped lag and its vruntime are committed.
	 */
	deadline = mlfq_place_entity_deadline(q, tctx);

	lag = mlfq_time_before(clock, tctx->vruntime) ? 0 : clock - tctx->vruntime;
	if (lag > limit)
		lag = limit;
	vruntime_new = clock - lag;

	tctx->vruntime = vruntime_new;
	tctx->vlag = (s64)lag;
	tctx->deadline = deadline;

	return deadline;
}

/**
 * mlfq_sameq_preempt_owed - Same-queue wakeup preemption test.
 * @qid: Queue of the wakeup (equal to @running_queue at the call site).
 * @running_queue: Queue of the task running on the wakeup's previous CPU.
 * @wakee_deadline: Fresh placement deadline of the wakeup, 0 when no
 *	placement was computed.
 * @running_deadline: Deadline of the resident, or 0 when the resident has
 *	no known deadline (started running without a placement).
 * @run_start_at: scx_bpf_now() at the resident's ops.running(), 0 when
 *	never recorded.
 * @now: Current time.
 * @min_run_ns: Minimum residency before the resident may be displaced.
 *
 * There are two same-queue rules.
 *
 * - Interactive (Q1 onto Q1): the residency guard alone decides.
 *   Interactive wakeups need immediate service. The virtual-time order
 *   still governs the queue DSQ ordering, while the preemption is the
 *   wakeup-latency mechanism. The guard protects the waker's own run
 *   (the wake-all walk executes in the first tens of microseconds of the
 *   waker's run) and prevents preemption thrash.
 * - Non-interactive (Q2/Q3): the guard gates the deadline rule, where a
 *   dispatch pass over the queue would already have picked the wakeup
 *   first (an earlier fresh deadline than the resident's). The resident
 *   must have a known deadline. An unknown wakeup deadline (failed
 *   placement) never preempts.
 *
 * The residency is measured from the resident's ops.running(). An
 * unknown or future run start cannot prove the guard window, so the
 * elapsed time falls back to zero (which is conservative only when the
 * guard is non-zero).
 *
 * Return: true when the resident owes the wakeup its CPU.
 */
static __always_inline bool mlfq_sameq_preempt_owed(u8 qid, u8 running_queue,
						    u64 wakee_deadline,
						    u64 running_deadline,
						    u64 run_start_at, u64 now,
						    u64 min_run_ns)
{
	u64 run_elapsed = 0;

	if (run_start_at && !mlfq_time_before(now, run_start_at))
		run_elapsed = now - run_start_at;

	if (mlfq_time_before(run_elapsed, min_run_ns))
		return false;

	if (qid == 1 && running_queue == 1)
		return true;

	if (!running_deadline || !wakee_deadline)
		return false;

	return mlfq_time_before(wakee_deadline, running_deadline);
}

/**
 * mlfq_log2_pow2 - Binary logarithm of a power of two.
 * @v: A power of two.
 *
 * The bit position of the single set bit. The CBS period is a power of
 * two, so the period count of a sleep is a pure shift by this amount.
 * __builtin_ctzll lowers to inline bit math on both the BPF and the
 * host targets, with no division and no libcall.
 *
 * Return: log2(@v).
 */
static __always_inline u32 mlfq_log2_pow2(u64 v)
{
	return __builtin_ctzll(v);
}

/**
 * mlfq_gauge_decay - Decay the burst gauge for a sleep.
 * @g: Current gauge value.
 * @sleep_ns: Physical sleep time in nsecs.
 * @q_i: The queue's CBS budget (the slice).
 * @p_i: The queue's CBS period (MLFQ_CBS_PERIOD_MULT * q_i).
 *
 * The period-step decay of the burst gauge. Each full server period of
 * sleep refunds one budget, so the step is
 *
 *   periods = sleep_ns / p_i
 *   d = periods * q_i
 *   g' = g > d ? g - d : 0
 *
 * with the division implemented as a shift because p_i is a power of
 * two. The step is quantized to multiples of q_i, so a sleep shorter
 * than one period refunds nothing. A sleep of at least two gauge
 * ceilings refunds the whole gauge in every queue. The subtraction is
 * guarded, so the result is never negative.
 *
 * Return: The updated gauge.
 */
static __always_inline u64 mlfq_gauge_decay(u64 g, u64 sleep_ns, u64 q_i,
					    u64 p_i)
{
	u64 periods = sleep_ns >> mlfq_log2_pow2(p_i);
	u64 d = periods * q_i;

	return g > d ? g - d : 0;
}

/**
 * mlfq_gauge_decayed - Read-only gauge decay for a wakeup.
 * @tctx: The task.
 * @sleep_ns: Physical sleep time in nsecs.
 * @q_i: The queue's CBS budget (the slice).
 * @p_i: The queue's CBS period (MLFQ_CBS_PERIOD_MULT * q_i).
 *
 * The decayed gauge value without the commit. The CPU-selection mirror
 * uses it to predict the classification result before ops.enqueue()
 * runs, so the placement and the classification agree on the same
 * decayed gauge.
 *
 * Return: The gauge the wakeup classification would commit.
 */
static __always_inline u64 mlfq_gauge_decayed(const struct task_ctx *tctx,
					      u64 sleep_ns, u64 q_i, u64 p_i)
{
	return mlfq_gauge_decay(tctx->g, sleep_ns, q_i, p_i);
}

/**
 * mlfq_queue_from_gauge - Base queue mapping from the burst gauge.
 * @g: The gauge value.
 * @t_l: Interactive threshold (MLFQ_T_L_NS).
 * @t_h: CPU-bound threshold (MLFQ_T_H_NS).
 *
 * The base mapping is g <= T_L -> Q1, g >= T_H -> Q3, else Q2. The
 * mapping is never applied as a queue assignment at wakeup, where the
 * classification is promotion-only. It serves the run-out cpu-bound
 * test (g >= T_H) and the CPU-selection mirror.
 *
 * Return: 1, 2 or 3.
 */
static __always_inline u8 mlfq_queue_from_gauge(u64 g, u64 t_l, u64 t_h)
{
	if (g <= t_l)
		return 1;
	if (g >= t_h)
		return 3;
	return 2;
}

/**
 * mlfq_reenq_cnt_step - Saturating run-out counter increment.
 * @cnt: The current consecutive-exhaustion count.
 *
 * The counter saturates at MLFQ_DEMOTE_EXHAUSTIONS, so a task that
 * never demotes (a Q3 task, including SCHED_IDLE) cannot wrap the u8
 * counter and reset its history.
 *
 * Return: The updated count.
 */
static __always_inline u8 mlfq_reenq_cnt_step(u8 cnt)
{
	return cnt < MLFQ_DEMOTE_EXHAUSTIONS ? cnt + 1 : MLFQ_DEMOTE_EXHAUSTIONS;
}

/**
 * mlfq_fcbs_slack - Unspent budget from an early completion.
 * @grant: The last grant given to the task (slice or Q_q + B_q).
 * @delta: The run segment length (time from running to stopping).
 *
 * FCBS slack is the difference between the budget granted and the budget
 * consumed. When the task blocks before using its full grant, the
 * remainder is donated back to the queue's bonus. When last_grant_ns is
 * zero (the preemption path, H2), the slack is zero by construction: a
 * preempt burst is not full-service budget and must not generate bonus.
 * The subtraction is guarded.
 *
 * Return: The unspent budget in nsecs.
 */
static __always_inline u64 mlfq_fcbs_slack(u64 grant, u64 delta)
{
	return grant > delta ? grant - delta : 0;
}

/**
 * mlfq_queue_grant - FCBS grant: slice plus bonus.
 * @slice: The queue's CBS budget (Q_q).
 * @bonus: The consumed bonus, after idle decay and exchange.
 *
 * The bonus is bounded by Q_q (the deposit clamp), so the grant
 * is bounded by 2*Q_q. No runtime clamping is needed. The bound
 * is structural.
 *
 * Return: slice + bonus.
 */
static __always_inline u64 mlfq_queue_grant(u64 slice, u64 bonus)
{
	return slice + bonus;
}

/**
 * mlfq_fcbs_deposit - Atomic FCBS bonus deposit into a queue.
 * @bonus_ns: Pointer to the queue's bonus accumulator.
 * @s: The slack to deposit (unspent budget from an early completion).
 * @q_i: The queue's max slice (Q_q), the deposit cap.
 *
 * Atomic read-modify-write: __atomic_fetch_add with a post-clamp
 * (a guarded subtract when the sum exceeds q_i). A consumed bonus
 * can never be resurrected. The exchange-to-zero at consume time
 * happens-before any later deposit, so a racing deposit cannot
 * restore a value already exchanged away (H3).
 *
 * The deposit is within-queue only: cross-queue lag conservation
 * remains absent.
 */
static __always_inline void mlfq_fcbs_deposit(volatile u64 *bonus_ns,
					       u64 s, u64 q_i)
{
	u64 old = __atomic_fetch_add(bonus_ns, s, __ATOMIC_RELAXED);
	u64 new_val = old + s;

	if (new_val > q_i)
		__atomic_fetch_sub(bonus_ns, new_val - q_i,
				   __ATOMIC_RELAXED);
}

/**
 * mlfq_fcbs_consume_bonus - Consume the queue's FCBS bonus.
 * @q: The queue whose bonus to consume.
 * @slice: The base grant (Q_q).
 * @now: Current time (scx_bpf_now()).
 *
 * Read-first-conditional (perf F3): a plain read of bonus_ns. When
 * non-zero, the idle decay is computed from bonus_since and the
 * bonus is atomically exchanged to zero. The returned grant is
 * slice + decayed bonus, bounded by 2*Q_q (structural from B_q
 * <= Q_q).
 *
 * Return: The grant (slice + bonus, or slice alone when no bonus).
 */
static __always_inline u64 mlfq_fcbs_consume_bonus(struct queue_ctx *q,
						    u64 slice, u64 now)
{
	u64 cur = q->bonus_ns;	/* plain read, perf F3 */

	if (!cur)
		return slice;

	u64 idle = 0;

	if (q->bonus_since && mlfq_time_before(q->bonus_since, now))
		idle = now - q->bonus_since;

	u64 bonus = cur > idle ? cur - idle : 0;

	__atomic_exchange_n(&q->bonus_ns, 0, __ATOMIC_RELAXED);
	return mlfq_queue_grant(slice, bonus);
}

/**
 * mlfq_promote_on_wakeup - Wakeup promotion state machine.
 * @tctx: The task.
 * @sleep_ns: Sleep duration at wakeup.
 * @t_l: Interactive threshold.
 * @t_h: CPU-bound threshold.
 * @short_sleep: A sleep at most this long counts toward wake_cnt.
 *
 * The hysteresis promotes Q2->Q1 when g < T_L/2 and wake_cnt >= 2
 * consecutive short sleeps, and Q3->Q2 when g < T_H/2 and wake_cnt >= 2.
 * wake_cnt is reset on a long sleep. reenq_cnt is left for the caller to
 * clear on the wakeup path.
 *
 * Return: true if the task was promoted.
 */
static __always_inline bool mlfq_promote_on_wakeup(struct task_ctx *tctx,
						   u64 sleep_ns,
						   u64 t_l, u64 t_h,
						   u64 short_sleep)
{
	bool promoted = false;

	if (sleep_ns <= short_sleep)
		tctx->wake_cnt++;
	else
		tctx->wake_cnt = 0;

	if (tctx->queue == 2 && tctx->g < t_l / 2 && tctx->wake_cnt >= 2) {
		tctx->queue = 1;
		promoted = true;
	} else if (tctx->queue == 3 && tctx->g < t_h / 2 &&
		   tctx->wake_cnt >= 2) {
		tctx->queue = 2;
		promoted = true;
	}

	if (promoted)
		tctx->wake_cnt = 0;
	return promoted;
}

/**
 * mlfq_demote_on_reenq - Slice-exhaustion demotion state machine.
 * @tctx: The task.
 * @t_h: CPU-bound threshold (MLFQ_T_H_NS).
 *
 * Called on run-out re-enqueues (ops.enqueue() with flags == 0, the
 * do_enqueue_task(rq, p, 0, -1) slice-exhaustion path). Consecutive
 * slice exhaustions accumulate in reenq_cnt, which saturates at
 * MLFQ_DEMOTE_EXHAUSTIONS and gates the band crossings.
 *
 * The CPU-bound test is the gauge test g >= T_H. Demotion requires a
 * sustained run without sleeping. Eight consecutive exhaustions (about
 * 8 ms at the interactive slice) must accumulate while the task is
 * CPU-bound. A task that sleeps between bursts is re-boosted at its
 * wakeup, which resets reenq_cnt, so a bursty consumer of CPU such as
 * a video decoder keeps its queue for the whole burst. An impostor
 * that never sleeps accumulates the counter and is demoted after the
 * same sustained window.
 *
 * Return: true if the task was demoted.
 */
static __always_inline bool mlfq_demote_on_reenq(struct task_ctx *tctx,
						 u64 t_h)
{
	bool demoted = false;

	tctx->reenq_cnt = mlfq_reenq_cnt_step(tctx->reenq_cnt);

	if ((tctx->queue == 1 || tctx->queue == 2) &&
	    tctx->g >= t_h && tctx->reenq_cnt >= MLFQ_DEMOTE_EXHAUSTIONS) {
		tctx->queue++;
		demoted = true;
	}

	if (demoted)
		tctx->reenq_cnt = 0;
	return demoted;
}

/**
 * mlfq_reset_classification - Fork/exec classification reset.
 * @tctx: The task.
 *
 * New tasks start in Q2 with a zeroed gauge and counters.
 */
static __always_inline void mlfq_reset_classification(struct task_ctx *tctx)
{
	tctx->g = 0;
	tctx->queue = 2;
	tctx->reenq_cnt = 0;
	tctx->wake_cnt = 0;
	tctx->last_ss_boost_at = 0;
}

#if MLFQ_CHECK
/*
 * Invariant predicates. Compiled only under MLFQ_CHECK; the
 * BPF side reports violations via scx_bpf_error() at the natural points.
 */

static __always_inline bool mlfq_check_gauge_bounds(u64 g, u64 gauge_max)
{
	return g <= gauge_max;
}

static __always_inline bool mlfq_check_queue(u8 queue)
{
	return queue >= 1 && queue <= MLFQ_NR_QUEUES;
}

static __always_inline bool mlfq_check_weight(u32 weight)
{
	return weight >= 1;
}

static __always_inline bool mlfq_check_queued_vlag(s64 vlag)
{
	return vlag >= 0;
}

static __always_inline bool mlfq_check_bonus_bounds(u64 bonus_ns, u64 q_i)
{
	return bonus_ns <= q_i;
}
#endif /* MLFQ_CHECK */

#ifdef __VMLINUX_H__
/*
 * The per-CPU realtime-occupancy state as a BPF array map, defined in
 * main.bpf.c. The type and the extern are declared here so the BPF
 * modules can look up the state. Both are skipped outside the BPF
 * build, where the native harness has no map machinery.
 */
struct mlfq_rtdl_state_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_MAX_CPUS);
	__type(key, u32);
	__type(value, struct mlfq_rtdl_state);
};

extern struct mlfq_rtdl_state_map rtdl_state_stor;

/*
 * The op-latency histogram as a per-CPU array map, defined in
 * main.bpf.c. The type, the extern and the charge helper are declared
 * here so the modules can charge their callbacks. All of it is skipped
 * outside the BPF build, where the native harness has no map machinery.
 */
struct mlfq_op_lat_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, MLFQ_OP_LAT_OPS);
	__type(key, u32);
	__type(value, struct mlfq_op_lat);
};

extern struct mlfq_op_lat_map mlfq_op_lat;

/*
 * The per-CPU wakeup-arrival counters as a one-entry per-CPU array map,
 * defined in main.bpf.c. The type and the extern are declared here so
 * the enqueue module can bump the counters. Each CPU owns its own
 * slot, so the wakeup path needs no locked operation on a shared line.
 * The value is the lifetime arrival count of the owning CPU, a u64 so
 * it cannot wrap, and the Rust front-end sums the slots for the stats
 * output.
 */
struct mlfq_wakeup_stats_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, u64);
};

extern struct mlfq_wakeup_stats_map mlfq_wakeup_stats;

/**
 * mlfq_op_lat_bucket - Histogram bucket covering an elapsed time.
 * @delta_us: Elapsed microseconds.
 *
 * The eight buckets delimit [0, 2) [2, 5) [5, 10) [10, 20) [20, 50)
 * [50, 100) [100, 250) [250, inf) microseconds.
 *
 * Return: The bucket index in [0, MLFQ_OP_LAT_BUCKETS).
 */
static __always_inline u32 mlfq_op_lat_bucket(u64 delta_us)
{
	if (delta_us < MLFQ_OP_LAT_EDGE_2)
		return 0;
	if (delta_us < MLFQ_OP_LAT_EDGE_5)
		return 1;
	if (delta_us < MLFQ_OP_LAT_EDGE_10)
		return 2;
	if (delta_us < MLFQ_OP_LAT_EDGE_20)
		return 3;
	if (delta_us < MLFQ_OP_LAT_EDGE_50)
		return 4;
	if (delta_us < MLFQ_OP_LAT_EDGE_100)
		return 5;
	if (delta_us < MLFQ_OP_LAT_EDGE_250)
		return 6;
	return 7;
}

/**
 * mlfq_op_lat_charge - Charge one op into its latency histogram.
 * @op: The MLFQ_OP_LAT_* slot.
 * @start_ns: scx_bpf_now() captured at the op entry.
 *
 * Computes the elapsed time and increments the covering bucket of the
 * per-CPU histogram. A failed map lookup is a no-op. The per-CPU
 * counters never contend, and the Rust front-end sums the CPUs for the
 * stats output.
 */
static __always_inline void mlfq_op_lat_charge(u32 op, u64 start_ns)
{
	struct mlfq_op_lat *lat;
	u64 now, delta_us;
	u32 key = op;

	now = scx_bpf_now();
	if (mlfq_time_before(now, start_ns))
		return;
	lat = bpf_map_lookup_elem(&mlfq_op_lat, &key);
	if (!lat)
		return;
	delta_us = (now - start_ns) / NSEC_PER_USEC;
	lat->buckets[mlfq_op_lat_bucket(delta_us)]++;
}

#endif /* __VMLINUX_H__ */

/*
 * The per-LLC and per-queue runnable gauges, defined in the main.bpf.c
 * bss block before mlfq_stats. The externs are declared here, outside
 * the BPF-only guard above, so the accounting helpers below can
 * reference them in every build. The BPF build links them against the
 * bss block, and the native harness supplies its own shadow storage.
 */
extern volatile u32 mlfq_llc_runnable[MLFQ_MAX_LLCS];
extern volatile u32 mlfq_queue_runnable[MLFQ_NR_QUEUES + 1];

/**
 * mlfq_llc_add - One atomic step on the per-LLC runnable gauge.
 * @llc: The LLC domain id.
 * @delta: +1 to count, -1 to un-count.
 *
 * The index is validated against the hard array bound; an out-of-range
 * id (the MLFQ_MAX_LLCS sentinel the call sites pass for an unpopulated
 * domain) is a no-op. The gauge is advisory, so a lost update under
 * contention is absorbed by the next RMW.
 */
static __always_inline void mlfq_llc_add(u32 llc, s64 delta)
{
	if (llc >= MLFQ_MAX_LLCS)
		return;
	if (delta > 0)
		__sync_fetch_and_add(&mlfq_llc_runnable[llc], (u32)delta);
	else
		__sync_fetch_and_sub(&mlfq_llc_runnable[llc], (u32)(-delta));
}

/**
 * mlfq_queue_add - One atomic step on the per-queue runnable gauge.
 * @qid: The queue id (1..3; index 0 is unused).
 * @delta: +1 to count, -1 to un-count.
 *
 * The index is validated against the queue range; an out-of-range id is
 * a no-op (defense in depth on top of the classification range checks).
 */
static __always_inline void mlfq_queue_add(u32 qid, s64 delta)
{
	if (qid < 1 || qid > MLFQ_NR_QUEUES)
		return;
	if (delta > 0)
		__sync_fetch_and_add(&mlfq_queue_runnable[qid], (u32)delta);
	else
		__sync_fetch_and_sub(&mlfq_queue_runnable[qid], (u32)(-delta));
}

/**
 * mlfq_runnable_enter - Count a task's LLC/queue ownership at an insert.
 * @tctx: The task being placed.
 * @qid: The queue it is placed into (1..3).
 * @llc: The LLC owning the target CPU (mlfq_llc_of_cpu(). The sentinel
 *	is a no-op).
 *
 * Called once per DSQ insert, after the queue and the owning CPU are
 * final. A task with no recorded ownership starts a runnable episode
 * (wakeup, fork, class-switch-in) and is counted once at the destination
 * LLC and queue. A task already counted is a continuation (run-out,
 * preemption, REENQ, a dispatch move) and the call only moves its LLC
 * and/or queue ownership when either changed, leaving the total count
 * unchanged. The mlfq_llc_of_cpu() sentinel makes the whole call a no-op
 * when LLC awareness is disabled (nr_llcs == 0), so an unpopulated
 * machine never moves any gauge.
 */
static __always_inline void mlfq_runnable_enter(struct task_ctx *tctx,
						u8 qid, u32 llc)
{
	/*
	 * The llc guard is the populated-state gate: the call sites pass
	 * mlfq_llc_of_cpu(), which yields the MLFQ_MAX_LLCS sentinel for
	 * an unknown domain or when nr_llcs == 0. The whole call is a
	 * no-op then, counters and ownership record alike.
	 */
	if (llc >= MLFQ_MAX_LLCS)
		return;

	if (tctx->last_llc == MLFQ_LLC_UNOWNED) {
		mlfq_llc_add(llc, 1);
		mlfq_queue_add(qid, 1);
		tctx->last_llc = (u8)llc;
		tctx->last_qid = qid;
		return;
	}

	/* Continuation: the task is counted, only its ownership moves. */
	if (tctx->last_llc != (u8)llc) {
		mlfq_llc_add(tctx->last_llc, -1);
		mlfq_llc_add(llc, 1);
		tctx->last_llc = (u8)llc;
	}
	if (tctx->last_qid != qid) {
		mlfq_queue_add(tctx->last_qid, -1);
		mlfq_queue_add(qid, 1);
		tctx->last_qid = qid;
	}
}

/**
 * mlfq_runnable_exit - Release a task's LLC/queue ownership.
 * @tctx: The task leaving the runnable set (or leaving LLC ownership).
 *
 * The single release primitive. A task that was counted is removed from
 * the per-LLC and per-queue gauges and its ownership record returns to
 * the unowned state. A task with no recorded ownership (never counted,
 * or already released) is a no-op, which makes the call idempotent
 * against a racing double-release.
 */
static __always_inline void mlfq_runnable_exit(struct task_ctx *tctx)
{
	if (tctx->last_llc == MLFQ_LLC_UNOWNED)
		return;
	mlfq_llc_add(tctx->last_llc, -1);
	mlfq_queue_add(tctx->last_qid, -1);
	tctx->last_llc = MLFQ_LLC_UNOWNED;
	tctx->last_qid = 0;
}

/**
 * mlfq_steer_pick_llc - Least-loaded eligible LLC selection.
 * @runnable: Per-LLC runnable gauge (advisory, stale-tolerant).
 * @idle: Per-LLC idle-CPU gate. A zero entry excludes the domain.
 * @nr_llcs: Number of populated LLC domains; domains at or above it are
 *	excluded (defense in depth on top of the idle gate, which already
 *	keeps the unpopulated-domain gauges at zero).
 * @waker_llc: The waker's own domain, always excluded.
 * @visited: Bitmask of domains already tried by earlier selection passes
 *	of this steering step (bit llc set = excluded).
 *
 * One min-selection pass over the eligible domains (idle-populated,
 * other than @waker_llc, not visited), returning the one with the lowest
 * runnable count; ties are broken by ascending domain id, so the
 * selection is deterministic. The caller repeats the pass up to
 * MLFQ_STEER_LLC_MAX times, marking each returned domain visited, so at
 * most MLFQ_STEER_LLC_MAX distinct domains are ever probed and the
 * bitmap walks (the expensive part) stay bounded.
 *
 * The step is advisory: a stale runnable count costs one suboptimal
 * (still idle) placement in a race window, never a correctness issue.
 * This is the same trust model as the idle-count saturation fast path. The
 * empty state (nr_llcs == 0, or every idle gauge zero) yields the
 * sentinel and the step dies; placement then proceeds unchanged.
 *
 * The scan is compile-time bounded (MLFQ_MAX_LLCS iterations) and uses
 * the iterator form (bpf_for) so the verifier explores the pass once
 * instead of re-walking a plain loop until its states converge; the
 * native harness drives the same code through the fallback macro above.
 *
 * Return: The chosen domain id, or MLFQ_MAX_LLCS when no domain is
 * eligible.
 */
static __always_inline u32
mlfq_steer_pick_llc(const volatile u32 *runnable, const volatile u32 *idle,
		    u32 nr_llcs, u32 waker_llc, u64 visited)
{
	u32 llc, best = MLFQ_MAX_LLCS;

	bpf_for(llc, 0, MLFQ_MAX_LLCS) {
		if (llc >= nr_llcs)
			continue;
		if (llc == waker_llc)
			continue;
		if (visited & (1ULL << llc))
			continue;
		if (!idle[llc])
			continue;
		if (best >= MLFQ_MAX_LLCS ||
		    runnable[llc] < runnable[best] ||
		    (runnable[llc] == runnable[best] && llc < best))
			best = llc;
	}

	return best;
}
#endif /* __SCX_MLFQ_INTF_H */
