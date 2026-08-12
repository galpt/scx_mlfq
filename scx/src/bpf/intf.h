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
 * Instrumentation. Set to 1 to compile the invariant checks
 * into the BPF object; they are compiled out by default. The check
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

	/* Per-queue request sizes. */
	MLFQ_Q1_SLICE_NS		= (1ULL * NSEC_PER_MSEC),
	MLFQ_Q2_SLICE_NS		= (2ULL * NSEC_PER_MSEC),
	MLFQ_Q3_SLICE_NS		= (4ULL * NSEC_PER_MSEC),

	/*
	 * Assumed tick length for the lag clamp horizon. The tick is used as
	 * the HZ=1000 approximation in the lag bound; limit =
	 * calc_delta_fair(max_slice + TICK, weight), the bound used by
	 * entity_lag() in kernel/sched/fair.c.
	 */
	MLFQ_TICK_NS			= (1ULL * NSEC_PER_MSEC),

	/* EMA interactivity gauge. */
	MLFQ_BUDGET_MAX_NS		= (6ULL * NSEC_PER_MSEC),
	FP_SHIFT			= 8,
	FP_ONE				= (1ULL << FP_SHIFT),
	MLFQ_ALPHA			= 3072ULL,

	/* Classification thresholds. */
	MLFQ_T_L_NS			= (250ULL * NSEC_PER_USEC),
	MLFQ_T_H_NS			= (2ULL * NSEC_PER_MSEC),

	/* EMA decay half-life. */
	MLFQ_EMA_HALF_LIFE_NS		= (24ULL * NSEC_PER_MSEC),

	/*
	 * Short-sleep boost window: covers periodic wakeup cadences such
	 * as the 60 Hz frame interval, so latency-sensitive consumers of
	 * CPU are recognized as interactive even when their runtime
	 * consumption would otherwise classify them as CPU-bound; the
	 * per-task boost rate limit keeps the churn bounded.
	 * The value is set against the slowest common cadence: faster refresh
	 * rates sleep for a shorter interval per frame and fall inside the
	 * window as well.
	 */
	MLFQ_SHORT_SLEEP_NS		= (32ULL * NSEC_PER_MSEC),
	MLFQ_SHORT_SLEEP_RATE_LIMIT_NS	= (2ULL * NSEC_PER_MSEC),
	MLFQ_HYSTERESIS_SLEEP_NS	= (4ULL * NSEC_PER_MSEC),

	/* Aging. */
	MLFQ_AGING_PERIOD_NS		= (1ULL * NSEC_PER_SEC),

	/*
	 * Minimum residency before a same-queue wakeup may preempt the
	 * running task, in nsecs. The interactive same-queue rule (Q1 onto
	 * Q1) preempts on this guard alone; the non-interactive rule
	 * additionally requires the wakeup's fresh deadline to precede the
	 * resident's. Zero, the default, makes the interactive rule
	 * unconditional: a wakeup that just became runnable is served
	 * ahead of the resident at the next scheduling event. Internal
	 * tuning constant, not a user-facing knob.
	 */
	MLFQ_SAMEQ_PREEMPT_MIN_RUN_NS	= 0ULL,

	/*
	 * Slice cap for a preempting wakeup, in nsecs. The preempt path
	 * displaces a running task, so the grant is a bounded burst: the
	 * displaced task (typically the thread that woke this one, whose
	 * early deadline puts it first in the virtual-time order) resumes
	 * at the next scheduling event once the cap expires. The policy
	 * slice still governs the regular path and the continuation after
	 * the run-out re-enqueue. Internal tuning constant, not a
	 * user-facing knob.
	 */
	MLFQ_PREEMPT_SLICE_NS		= (150ULL * NSEC_PER_USEC),

	/*
	 * A sleep longer than this collapses the gauge to (near) zero; the
	 * wakeup then re-adopts the base mapping. Five EMA half-lives =
	 * 120 ms.
	 */
	MLFQ_LONG_SLEEP_NS		= (120ULL * NSEC_PER_MSEC),

	/*
	 * UAPI linux/sched.h policy value; sched_ext only receives
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
	 * verifier's exploration of the nested steal loops; it must stay
	 * low enough that mlfq_dispatch() verifies within the kernel's
	 * jump-sequence limit.
	 */
	MLFQ_STEAL_SCAN_MAX		= 64ULL,

	/*
	 * sched_ext cpuperf level (scx_bpf_cpuperf_set(), the schedutil
	 * target hint). The perf argument is a linear relative level in
	 * [0, SCX_CPUPERF_ONE]; SCX_CPUPERF_ONE is 0x400 (1024), the
	 * maximum level. The kernel stores the target per-CPU and it
	 * persists until overwritten, so ops.running() states the level of
	 * the task now on the CPU on every context switch and schedutil
	 * follows. The interactive queue requests the maximum level and
	 * the other queues request the level matching the CPU's recent
	 * activity (mlfq_cpuperf_from_ema()), so a CPU that once ran an
	 * interactive task does not stay at the maximum level for the
	 * background work that follows. With the scheduler in switch-all
	 * mode the target is the only utilization signal schedutil sees.
	 */
	MLFQ_CPUPERF_Q1			= 1024ULL,

	MLFQ_NR_QUEUES			= 3ULL,

	/*
	 * Per-CPU vtime-ordered queue DSQ id space. Every CPU owns
	 * MLFQ_NR_QUEUES DSQs, laid out as MLFQ_DSQ_BASE +
	 * cpu * MLFQ_DSQ_STRIDE + (qid - 1) so the owning CPU and queue
	 * decode arithmetically (see mlfq_dsq_id()). The range ends far
	 * below SCX_DSQ_LOCAL_ON, which reserves the top bits for the
	 * kernel DSQ flags; init() validates this at load time.
	 */
	MLFQ_DSQ_BASE			= 0x1000ULL,
	MLFQ_DSQ_STRIDE			= MLFQ_NR_QUEUES,

	/*
	 * Compile-time CPU bound for the per-CPU capacity array. Matches the
	 * per-CPU state map bound (cpu_state_stor, 1024 entries); init()
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
	 * Number of 64-bit words needed to hold one CPU bit per CPU.
	 */
	MLFQ_BITMAP_WORDS		= (MLFQ_MAX_CPUS + 63) / 64,

	/*
	 * MLFQ regression-tree constants. The tree predicts the next CPU
	 * burst from per-task features and maps the prediction to a queue
	 * band (pred < T_INT -> Q1, pred < T_BOUND -> Q2, else Q3); the
	 * EMA gauge stays on as a tree feature and as the untrained
	 * fallback. Internal tuning constants, not user-facing knobs.
	 */
	MLFQ_TREE_MAX_NODES		= 2048,		/* node budget, power of two */
	MLFQ_TREE_MAX_DEPTH		= 12,		/* walk depth bound */
	MLFQ_TREE_T_INT_NS		= (1ULL * NSEC_PER_MSEC), /* Q1/Q2 split */
	MLFQ_TREE_T_BOUND_NS		= (3ULL * NSEC_PER_MSEC), /* Q2/Q3 split */

	/*
	 * Global training-sample emission limiter: at most one sample per
	 * 500 us across the whole system (the compare-and-swap single-winner
	 * pattern in the stopping path). The per-task spacing is the
	 * separate MLFQ_TREE_PER_TASK_LIMIT_NS gate on the same emission.
	 */
	MLFQ_TREE_SAMPLE_RATE_LIMIT_NS	= (500ULL * NSEC_PER_USEC),

	/*
	 * Per-task training-sample spacing: a task can emit at most one
	 * sample per 10 ms, so no single pid can dominate the training
	 * window. At the global 2k/s rate one task's share of the window is
	 * bounded to ~5%, which stops a chatty task from over-fitting the
	 * tree to its own behavior.
	 */
	MLFQ_TREE_PER_TASK_LIMIT_NS	= (10ULL * NSEC_PER_MSEC),

	/*
	 * Emitted label clamp. The prediction only needs the queue band
	 * (the walk maps the predicted burst to Q1/Q2/Q3), so labels beyond
	 * 64x the Q2/Q3 split bound carry no scheduling information; the
	 * clamp bounds the exact-integer range the f64 SSE in the fitter
	 * sees, so the training math never sums near-u64 values.
	 */
	MLFQ_TREE_LABEL_MAX_NS		= (MLFQ_TREE_T_BOUND_NS * 64),

	MLFQ_TREE_MIN_SAMPLES		= 2048,		/* training set size */

	/*
	 * Drain interval of the realtime-takeover evacuation: at most one
	 * pass per CPU per millisecond. The rate limit bounds the churn a
	 * takeover can stir up, which otherwise has no kernel-side repeat
	 * guard: the stop-class blips that punctuate a takeover, RT tasks
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
 * MLFQ regression tree. The tree predicts the next CPU burst in nsecs
 * from the per-task feature vector. The userspace daemon trains a CART
 * model on emitted samples and publishes it through the double-buffered
 * two-entry map below; the classification path walks the active entry.
 * The node format and the walk are shared with the Rust front-end and
 * the native unit-test harness, so field order and sizes below are part
 * of the scheduler's ABI.
 */

/*
 * Feature vector of the prediction tree, one value per split feature.
 * 32 bytes. Field order is part of the shared ABI: emitted samples
 * (mlfq_tree_sample) and the Rust-side TreeFeats use the same layout.
 */
struct mlfq_tree_feats {
	u64 prev_burst_ns;		/* last completed run segment */
	u64 sleep_ns;			/* sleep before the current wakeup */
	u64 ema;			/* EMA interactivity gauge */
	u32 io_wait;			/* 1 if the wakeup is an I/O completion */
	u32 wake_cnt;			/* consecutive short-sleep wakeups */
};

/*
 * One node of the serialized tree. threshold is the split point in
 * nsecs; left is the left child index, or the leaf prediction in nsecs
 * when right == 0; right is the right child index, 0 marking a leaf;
 * feature is the split feature id (0..4, indexing the walk's feat[]
 * slots). 24 bytes.
 */
struct mlfq_tree_node {
	u64 threshold;
	u32 left;
	u32 right;
	u8  feature;
	u8  pad[7];
};

/*
 * One buffer of the double-buffered published tree, and the value type
 * of the two-entry mlfq_tree_map: entry 0 and entry 1 form the double
 * buffer. The daemon fills the inactive entry and flips to it with a
 * single meta write (mlfq_tree_ctrl.meta), so a reader that has loaded
 * the meta once walks a consistent tree and never observes a torn
 * publish: the meta commit is the last write of a publish, and the tree
 * contents it points at were fully written before it.
 *
 * The protocol is sound at the 60 s publish cadence: a reader could
 * only observe a torn tree if two publishes completed within one tree
 * walk, and each walk is a few dozen memory reads while a publish moves
 * up to 2048 nodes, so two consecutive publishes cannot complete inside
 * one walk. The consequence of the theoretical race (a reader that
 * loaded the meta between two back-to-back publishes and walks the
 * freshly overwritten buffer) is one mispredicted burst, which the
 * queue-band nets absorb -- it is not a memory-safety issue because the
 * walk masks every index to the buffer bound. 49152 bytes.
 */
struct mlfq_tree_store {
	struct mlfq_tree_node nodes[MLFQ_TREE_MAX_NODES];
};

#define MLFQ_TREE_META_TRAINED			(1ULL << 0)
#define MLFQ_TREE_META_ACTIVE			(1ULL << 1)
#define MLFQ_TREE_META_NR_NODES_SHIFT		8
#define MLFQ_TREE_META_NR_NODES_MASK		0xFFFFFF00ULL
#define MLFQ_TREE_META_GENERATION_SHIFT		32
#define MLFQ_TREE_META_GENERATION_MASK		0xFFFFFFFF00000000ULL

/*
 * Published-tree control state, one dedicated cache line (64 bytes, the
 * instance in main.bpf.c is aligned to 64).
 *
 * The tree meta is read by every inference and the sample limiter by
 * every pending-sample emission check, but the pair is written only by
 * the publish (once per 60 s cadence) and the single compare-and-swap
 * winner of each sample window, so the line must not share a cache line
 * with the write-hammered mlfq_stats counters. Keeping the pair alone on
 * a line prevents every counter update from dirtying the line the
 * classification hot path reads.
 *
 * bss defaults zeroed, which is exactly the untrained state (trained bit
 * clear). The meta bit layout is the same as the former combined store:
 *   bit 0   trained (set once a tree has been published)
 *   bit 1   active buffer index (0 or 1)
 *   bits 8..31  number of nodes in the active tree
 *   bits 32..63 generation counter, bumped on every publish
 *   bits 2..7 reserved, zero
 */
struct mlfq_tree_ctrl {
	u64 meta;		/* committed-tree meta, see MLFQ_TREE_META_* */
	u64 sample_last_at;	/* scx_bpf_now() of the last sample emission */
	u64 pad[6];		/* one dedicated cache line */
};

extern volatile struct mlfq_tree_ctrl mlfq_tree_ctrl;

/*
 * One training sample emitted by the scheduler and consumed by the
 * daemon. pid and queue identify the emitter, feats is the feature
 * vector at classification time and label_ns the run segment that
 * followed. 48 bytes; field order is shared with the Rust front-end.
 */
struct mlfq_tree_sample {
	u32 pid;
	u32 queue;
	struct mlfq_tree_feats feats;
	u64 label_ns;
};

/*
 * Per-task state in BPF task storage. All timestamps are scx_bpf_now()
 * nsecs. vruntime is on the owning queue's virtual-time clock and is
 * re-anchored to the queue's clock at every placement. The struct is
 * 144 bytes: the 96-byte classification/vtime block below plus the
 * 48-byte MLFQ tree sample block (pending_feats + pending_queue rounded
 * to a u64 for pending_valid).
 */
struct task_ctx {
	u64 vruntime;			/* last placed virtual runtime */
	s64 vlag;			/* clamped lag at placement, >= 0 */
	u64 deadline;			/* last computed virtual deadline */
	u64 ema;			/* EMA interactivity gauge [0, BUDGET_MAX] */
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
	u8  pad[4];
	u64 prev_burst_ns;		/* last completed run segment, tree feature */
	u64 last_sample_at;		/* scx_bpf_now() of the last emitted
					 * training sample, per-task rate limit */
	/*
	 * Pending MLFQ tree sample: the feature vector and the queue are
	 * captured at the classification enqueue, and the sample is
	 * completed with the run segment (the label) and emitted at the
	 * segment end in ops.stopping(). pending_queue is the queue at the
	 * capture, so the emitted sample is not mislabeled by later
	 * placement decisions (aging, a subsequent classification).
	 * pending_valid is 1 between capture and emission.
	 */
	struct mlfq_tree_feats pending_feats;
	u32 pending_queue;		/* queue at the capture */
	u64 pending_valid;
};

/* wake_cpu_state bits */
#define MLFQ_WAKE_CPU_IDLE	0x01U
#define MLFQ_WAKE_CPU_VALID	0x02U

/*
 * Per-queue virtual clock. clock is the service point the queue
 * has reached: it advances monotonically as the queue's tasks run, and
 * placement anchors a task's lag to it. No weighted-average aggregate is
 * maintained because computing it needs consistent reads of two shared
 * sums, which in BPF would require mutual exclusion; the bounded-lag
 * theorem is instead enforced by clamping the task lag to the clock at
 * placement, which is exact enough for the safety properties and keeps
 * the placement lock-free.
 */
struct queue_ctx {
	/*
	 * Virtual clock of the queue. Read without a lock by
	 * every placement; the aligned 64-bit load is atomic on the
	 * supported targets, and a stale read only lowers the clock,
	 * which the placement clamp absorbs.
	 */
	u64 clock;
	u64 max_slice_ns;		/* per-queue request size */
	u64 pad[6];			/* one queue_ctx per cacheline */
};

/*
 * Global idle tracking. mlfq_idle_count is the number of currently idle
 * CPUs, maintained by ops.update_idle() with atomic RMWs (a single u32;
 * the only consumer treats it as a zero/non-zero test). mlfq_idle_tracking
 * is a rodata gate written by the Rust front-end: it is 1 only when the
 * kernel keeps its built-in idle tracking alongside the callback (the
 * KEEP_BUILTIN_IDLE flag), 0 otherwise. Declared here so the modules and
 * the pure-math harness share the same contract.
 */
extern volatile u32 mlfq_idle_count;
extern const volatile u32 mlfq_idle_tracking;

/*
 * Per-CPU state, BPF_MAP_TYPE_ARRAY keyed by cpu. 56 bytes, one cacheline.
 */
struct mlfq_cpu_state {
	s32 running_queue;		/* queue of the running task, 0 none */
	u32 running_pid;
	u32 steal_scan_off;		/* rotating remote-scan start for Q2/Q3 */
	u64 cpu_ema;			/* busy-ns EMA of this CPU's activity */
	u64 cpu_ema_at;			/* scx_bpf_now() of the last update */
	u64 running_deadline;		/* running task's deadline, 0 unknown */
	u64 run_start_at;		/* scx_bpf_now() at ops.running() */
	u64 idle_since;			/* scx_bpf_now() at update_idle(true), 0 busy */
};

/* Per-CPU realtime-occupancy flags. */
#define MLFQ_RTDL_OCCUPIED			(1U << 0)

/*
 * Per-CPU realtime-occupancy state, keyed by cpu id in the
 * rtdl_state_stor array map. flags reflects the class of the last task
 * that ran on the CPU (see the sched_switch hook in rtdl.bpf.c), which
 * decides whether the CPU is treated as unavailable to the SCX classes;
 * last_drain_at rate-limits the evacuation pass of the takeover path.
 */
struct mlfq_rtdl_state {
	u32 flags;			/* MLFQ_RTDL_* bits */
	u32 pad;
	u64 last_drain_at;		/* scx_bpf_now() of the last drain */
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
	/* MLFQ tree diagnostics: prediction and sample bookkeeping. */
	u64 tree_inference;		/* prediction walks run */
	u64 tree_fallback;		/* predictions served by the EMA fallback */
	u64 tree_disagree;		/* tree and EMA queue mappings disagreed */
	u64 tree_samples_emitted;	/* completed samples emitted to the daemon */
	u64 tree_samples_dropped;	/* samples dropped (ring buffer full) */
	/* Realtime-takeover diagnostics (rtdl.bpf.c, enqueue.bpf.c). */
	u64 rt_takeovers;		/* 0->1 occupied transitions observed */
	u64 rt_evacuations;		/* DSQ evacuation passes that ran */
	u64 rt_redirects;		/* wakeups redirected off occupied CPUs */
	u64 rt_reenqs;			/* SCX_ENQ_REENQ re-enqueues counted */
	/*
	 * Pad the counter struct to a 64-byte multiple: the counters
	 * before the pad are write-hammered by the hot paths, and the
	 * published tree meta line (mlfq_tree_ctrl) must not share a line
	 * with them. The isolation itself comes from the
	 * __attribute__((aligned(64))) on the mlfq_tree_ctrl instance in
	 * main.bpf.c, which pins that line to a dedicated cache line; the
	 * padding here is the size hygiene that lets the aligned instance
	 * sit on the following boundary by the plain declaration order,
	 * so the two never land on the same line by layout accident.
	 */
	u64 pad[2];
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
 * mlfq_cpuperf_from_ema - CPU performance level for a busy-ns gauge.
 * @ema: The per-CPU EMA of the recent run time.
 *
 * Maps the busy-ns gauge to the sched_ext cpuperf scale: a CPU that ran
 * tasks for the whole gauge window requests the maximum level and a
 * lightly loaded CPU requests a proportionally lower one. The gauge
 * ceiling is the per-task budget, so a CPU saturated over the gauge
 * window maps to the maximum.
 *
 * Return: The cpuperf level in [0, SCX_CPUPERF_ONE].
 */
static __always_inline u32 mlfq_cpuperf_from_ema(u64 ema)
{
	u64 perf = ema * MLFQ_CPUPERF_Q1 / MLFQ_BUDGET_MAX_NS;

	return perf > MLFQ_CPUPERF_Q1 ? MLFQ_CPUPERF_Q1 : (u32)perf;
}

/**
 * calc_delta_fair_bpf - Scale a runtime delta to virtual time.
 * @delta: Physical time in nsecs.
 * @weight: Task weight in scx scale (nice-0 = 100, min 1).
 *
 * EEVDF virtual time grows at rate w_i/NICE_0_LOAD while running; with
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
 * limit = calc_delta_fair(max_slice + TICK, weight): a task is placed at
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
 * The clock follows the service given to the queue: it is advanced to
 * @vruntime whenever @vruntime is ahead of it, as a monotone max update.
 * The clock never moves backward: the compare-and-swap stores only when
 * the clock still holds the value the advance read, and the winner of a
 * contended update is the store that lands first, not necessarily the
 * largest one. A losing update can therefore leave the clock behind the
 * true service point by at most the virtual-time spread of the
 * concurrent updates; the placement clamp bounds the error this creates
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
 * The placement formula of mlfq_place_entity() without the commit: the
 * deadline a placement against @q's virtual clock would produce, computed
 * from the pre-placement task state. The wakeup-preemption decision uses
 * it to compare a wakeup's fresh deadline against the resident's before
 * deciding to preempt; the preempt path inserts into the local DSQ
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
	 * A deadline that lands exactly on the wrap point computes to zero;
	 * zero is the sentinel for a failed placement, so move the wrapped
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
 * EEVDF placement against the queue's virtual clock:
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
 * entity_lag(); a task that is ahead of the clock is placed at the
 * clock itself, the fair.c DELAY_ZERO semantics that do not carry
 * leading credit. The stored lag is therefore bounded in [0, limit], and
 * every queued task is eligible by construction, so min-deadline
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
 * Two same-queue rules:
 *
 * - Interactive (Q1 onto Q1): the residency guard alone decides.
 *   Interactive wakeups need immediate service; the virtual-time order
 *   still governs the queue DSQ ordering, while the preemption is the
 *   wakeup-latency mechanism. The guard protects the waker's own run
 *   (the wake-all walk executes in the first tens of microseconds of the
 *   waker's run) and prevents preemption thrash.
 * - Non-interactive (Q2/Q3): the guard gates the deadline rule, where a
 *   dispatch pass over the queue would already have picked the wakeup
 *   first (an earlier fresh deadline than the resident's). The resident
 *   must have a known deadline; an unknown wakeup deadline (failed
 *   placement) never preempts.
 *
 * The residency is measured from the resident's ops.running(); an
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
 * mlfq_ema_climb - Advance the EMA gauge for a run segment.
 * @ema: Current gauge value.
 * @delta: Physical run time in nsecs.
 * @budget_max: Gauge ceiling (MLFQ_BUDGET_MAX_NS).
 * @alpha: Climb aggressiveness (MLFQ_ALPHA).
 *
 * Saturating exponential climb:
 *
 *   step = (budget_max - ema) * delta * alpha / (budget_max * FP_ONE)
 *   ema += min(step, budget_max - ema)
 *
 * with delta clamped to budget_max. The step factorizes the remaining gap,
 * so a CPU-bound task converges to budget_max; the rate is 1/tau_climb
 * with tau_climb = budget_max * FP_ONE / alpha. alpha is fixed.
 *
 * Return: The updated gauge.
 */
static __always_inline u64 mlfq_ema_climb(u64 ema, u64 delta, u64 budget_max,
					  u64 alpha)
{
	u64 gap, step;

	if (delta > budget_max)
		delta = budget_max;
	gap = budget_max - ema;
	if (gap == 0)
		return ema;

	step = gap * delta * alpha / (budget_max * FP_ONE);
	if (step > gap)
		step = gap;
	return ema + step;
}

/**
 * mlfq_ema_decay - Decay the EMA gauge for a sleep.
 * @ema: Current gauge value.
 * @sleep_ns: Physical sleep time in nsecs.
 * @half_life: Gauge half-life (MLFQ_EMA_HALF_LIFE_NS).
 *
 * Shift decay with a 2nd-order Taylor residual for the sub-period: whole
 * half-lives shift the gauge right; the fractional period is
 * approximated by 2^-x ~= 1 - x*ln2 + (x*ln2)^2/2 in FP_ONE fixed point
 * (relative error < 10% for x in [0,1)). The gauge is zeroed at or beyond
 * 64 half-lives.
 *
 * Return: The updated gauge.
 */
static __always_inline u64 mlfq_ema_decay(u64 ema, u64 sleep_ns, u64 half_life)
{
	u64 periods, sub, x_fp, a_fp, factor_fp, decayed;

	if (sleep_ns >= (half_life << 6))	/* >= 64 periods -> zero */
		return 0;

	periods = sleep_ns / half_life;
	sub = sleep_ns % half_life;
	decayed = ema >> periods;

	if (sub == 0 || decayed == 0)
		return decayed;

	x_fp = sub * FP_ONE / half_life;
	a_fp = x_fp * 177 / FP_ONE;		/* 177 ~= FP_ONE * ln(2) */
	factor_fp = FP_ONE - a_fp + (a_fp * a_fp) / (FP_ONE << 1);
	return decayed * factor_fp / FP_ONE;
}

/**
 * mlfq_queue_from_ema - Base queue mapping from the EMA gauge.
 * @ema: The gauge value.
 * @t_l: Interactive threshold (MLFQ_T_L_NS).
 * @t_h: CPU-bound threshold (MLFQ_T_H_NS).
 *
 * Base mapping: ema <= T_L -> Q1, ema >= T_H -> Q3, else Q2.
 *
 * Return: 1, 2 or 3.
 */
static __always_inline u8 mlfq_queue_from_ema(u64 ema, u64 t_l, u64 t_h)
{
	if (ema <= t_l)
		return 1;
	if (ema >= t_h)
		return 3;
	return 2;
}

/**
 * mlfq_promote_on_wakeup - Wakeup promotion state machine.
 * @tctx: The task.
 * @sleep_ns: Sleep duration at wakeup.
 * @t_l: Interactive threshold.
 * @t_h: CPU-bound threshold.
 * @short_sleep: A sleep at most this long counts toward wake_cnt.
 *
 * Hysteresis: Q2->Q1 when ema < T_L/2 and wake_cnt >= 2
 * consecutive short sleeps; Q3->Q2 when ema < T_H/2 and wake_cnt >= 2.
 * wake_cnt is reset on a long sleep; reenq_cnt is left for the caller to
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

	if (tctx->queue == 2 && tctx->ema < t_l / 2 && tctx->wake_cnt >= 2) {
		tctx->queue = 1;
		promoted = true;
	} else if (tctx->queue == 3 && tctx->ema < t_h / 2 &&
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
 * @t_h: CPU-bound threshold.
 * @pred: The tree's predicted next burst (0 while untrained).
 *
 * Called on run-out re-enqueues (ops.enqueue() with flags == 0, the
 * do_enqueue_task(rq, p, 0, -1) slice-exhaustion path). Consecutive
 * slice exhaustions accumulate in reenq_cnt, which gates the band
 * crossings.
 *
 * The CPU-bound test switches on the predictor: with a trained tree the
 * predicted burst itself gates the demotion (a prediction at or above
 * the Q2/Q3 band bound is CPU-bound), and the EMA gauge test is the
 * untrained fallback. The gate is the plain EMA-gauge test while
 * untrained.
 *
 * Demotion requires a sustained run without sleeping: eight consecutive
 * exhaustions (about 8 ms at the interactive slice) must accumulate
 * while the task is CPU-bound. A task that sleeps between bursts is
 * re-boosted at its wakeup, which resets reenq_cnt, so a bursty
 * consumer of CPU such as a video decoder keeps its queue for the whole
 * burst. An impostor that never sleeps accumulates the counter and is
 * demoted after the same sustained window.
 *
 * Return: true if the task was demoted.
 */
static __always_inline bool mlfq_demote_on_reenq(struct task_ctx *tctx,
						 u64 t_h, u64 pred)
{
	bool demoted = false;
	bool cpu_bound;

	tctx->reenq_cnt++;

	cpu_bound = pred ? pred >= MLFQ_TREE_T_BOUND_NS : tctx->ema > t_h;

	if ((tctx->queue == 1 || tctx->queue == 2) &&
	    cpu_bound && tctx->reenq_cnt >= 8) {
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
	tctx->ema = 0;
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

static __always_inline bool mlfq_check_ema_bounds(u64 ema, u64 budget_max)
{
	return ema <= budget_max;
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

static __always_inline bool mlfq_check_tree_node_index(u32 idx)
{
	return idx < MLFQ_TREE_MAX_NODES;
}

static __always_inline bool mlfq_check_tree_feature(u8 feature)
{
	/* Only the five populated feat[] slots may be split on. */
	return (feature & 0x7) < 5;
}
#endif /* MLFQ_CHECK */

/**
 * mlfq_tree_walk - Walk a tree buffer and predict the next CPU burst.
 * @store: The tree buffer (one entry of mlfq_tree_map).
 * @f: The feature vector.
 *
 * The descent is a compile-time bound of MLFQ_TREE_MAX_DEPTH steps.
 * Every index is masked to the node budget (MLFQ_TREE_MAX_NODES - 1),
 * so a corrupted tree can never address outside the buffer: an
 * out-of-range feature id reads a zeroed feat[] slot, and a walk past
 * the tree tail lands on a zeroed node, which is a leaf predicting 0.
 * A leaf is a node with right == 0 and carries its prediction in left.
 * A tree deeper than the bound is cut: the walk returns the last
 * reachable node's left, and only when that node is a leaf -- a
 * deeper-than-the-bound internal node returns 0 instead of leaking a
 * child index as a prediction.
 *
 * The feat[] array lays out the five feature slots in order followed by
 * three zero slots, so a split feature id above 4 reads zero and routes
 * to the left of any non-zero threshold.
 *
 * Return: The predicted burst in nsecs.
 */
static __always_inline u64
mlfq_tree_walk(const struct mlfq_tree_store *store,
	       const struct mlfq_tree_feats *f)
{
	u64 feat[8] = { f->prev_burst_ns, f->sleep_ns, f->ema,
			f->io_wait, f->wake_cnt, 0, 0, 0 };
	u32 idx = 0, nidx;
	const struct mlfq_tree_node *n;
	u8 feature;
	int i;

	for (i = 0; i < MLFQ_TREE_MAX_DEPTH; i++) {
		nidx = idx & (MLFQ_TREE_MAX_NODES - 1);
		n = &store->nodes[nidx];
#if MLFQ_CHECK
		if (!mlfq_check_tree_node_index(nidx))
			return 0;
#endif
		if (n->right == 0)
			return n->left;

		feature = n->feature & 0x7;
#if MLFQ_CHECK
		if (!mlfq_check_tree_feature(feature))
			return 0;
#endif
		idx = feat[feature] <= n->threshold ? n->left : n->right;
	}

	/*
	 * Depth exhausted: the last reachable node is returned as a leaf
	 * only when it really is one. An internal node here means the
	 * tree is deeper than the walk bound; returning its left would
	 * leak a child index as a prediction, so a non-leaf yields 0.
	 */
	nidx = idx & (MLFQ_TREE_MAX_NODES - 1);
	n = &store->nodes[nidx];
#if MLFQ_CHECK
	if (!mlfq_check_tree_node_index(nidx))
		return 0;
#endif
	return n->right == 0 ? n->left : 0;
}

/**
 * mlfq_tree_map_queue - Promotion-only queue mapping of a prediction.
 * @pred: The predicted next burst, 0 while untrained.
 * @cur: The task's current queue (1..3).
 *
 * The wakeup path is promotion-only: a Q1-band prediction raises the
 * queue to 1, a Q2-band prediction raises a Q3 task to 2, and a
 * Q3-band or untrained prediction leaves the queue unchanged. Demotions
 * are the run-out gate's job (mlfq_demote_on_reenq), so a single wakeup
 * prediction can never demote a task and bypass the exhaustion
 * hysteresis -- the classic MLFQ asymmetry where the wakeup only
 * promotes and the run-out only demotes.
 *
 * Return: The new queue.
 */
static __always_inline u8 mlfq_tree_map_queue(u64 pred, u8 cur)
{
	/* 0 is the untrained sentinel: it never moves the queue. */
	if (pred && pred < MLFQ_TREE_T_INT_NS)
		return 1;
	if (pred && pred < MLFQ_TREE_T_BOUND_NS && cur > 2)
		return 2;
	return cur;
}

#ifdef __VMLINUX_H__
/*
 * The published tree as a two-entry array map, defined in main.bpf.c.
 * The type and the extern are declared here so the BPF wrapper can look
 * up the active entry; both are skipped outside the BPF build, where
 * the native harness has no map machinery.
 */
struct mlfq_tree_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, u32);
	__type(value, struct mlfq_tree_store);
};

extern struct mlfq_tree_map mlfq_tree_map;

/*
 * The per-CPU realtime-occupancy state as a BPF array map, defined in
 * main.bpf.c. The type and the extern are declared here so the BPF
 * modules can look up the state; both are skipped outside the BPF
 * build, where the native harness has no map machinery.
 */
struct mlfq_rtdl_state_map {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_MAX_CPUS);
	__type(key, u32);
	__type(value, struct mlfq_rtdl_state);
};

extern struct mlfq_rtdl_state_map rtdl_state_stor;

/**
 * mlfq_tree_predict - Predict the next CPU burst from a feature vector.
 * @f: The feature vector.
 *
 * The BPF entry point. Reads mlfq_tree_ctrl.meta exactly once: the
 * trained bit gates the inference and the active bit selects the buffer
 * entry of mlfq_tree_map, so a reader sees either the tree before a
 * publish or the fully committed tree after it, never a partially
 * written one (the daemon writes the inactive entry first and commits
 * the meta last).
 *
 * Return: The predicted burst in nsecs; 0 while untrained or on a
 * failed map lookup.
 */
static __always_inline u64 mlfq_tree_predict(const struct mlfq_tree_feats *f)
{
	u64 meta = mlfq_tree_ctrl.meta;
	struct mlfq_tree_store *store;
	u32 key;

	if (!(meta & MLFQ_TREE_META_TRAINED))
		return 0;

	key = (meta & MLFQ_TREE_META_ACTIVE) ? 1 : 0;
	store = bpf_map_lookup_elem(&mlfq_tree_map, &key);
	if (!store)
		return 0;

	return mlfq_tree_walk(store, f);
}
#endif /* __VMLINUX_H__ */

#endif /* __SCX_MLFQ_INTF_H */
