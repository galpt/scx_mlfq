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
 * Instrumentation. Set to 1 to compile the check predicates
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

	/*
	 * Ceiling of the per-task service-quality EMA, in nsecs. A task
	 * that waits 100 ms in a queue under overload saturates at 16 ms,
	 * the "latency pressure" signal of the per-task gauge.
	 */
	MLFQ_SQ_EMA_MAX_NS		= (16ULL * NSEC_PER_MSEC),

	/*
	 * Ceiling of the system wakeup-latency gauge, in nsecs. The
	 * gauge reads the machine's average wakeup latency, and the
	 * ceiling keeps every downstream threshold and product in a
	 * small, overflow-free range.
	 */
	MLFQ_SYS_LAT_MAX_NS		= (16ULL * NSEC_PER_MSEC),

	/* EMA decay half-life. */
	MLFQ_EMA_HALF_LIFE_NS		= (24ULL * NSEC_PER_MSEC),

	/*
	 * Seconds-scale time constant of the system gauges (wakeup
	 * latency and wakeup rate). The gauges smooth the workload over
	 * seconds while the per-task classification reacts in
	 * milliseconds, so the adaptation they drive cannot chase
	 * sample-level noise.
	 */
	MLFQ_SYS_GAUGE_HALF_LIFE_NS	= (1ULL * NSEC_PER_SEC),

	/*
	 * Ceiling of the wakeup-rate gauge, in wakeups per second. The
	 * rate is carried in FP_SHIFT fixed point, so the ceiling sits
	 * below the u32 fixed-point overflow point and the stored value
	 * (a u64) is exact.
	 */
	MLFQ_SYS_RATE_MAX		= 1000000ULL,

	/*
	 * Short-sleep boost window: covers periodic wakeup cadences such
	 * as the 60 Hz frame interval, so latency-sensitive consumers of
	 * CPU are recognized as interactive even when their runtime
	 * consumption would otherwise classify them as CPU-bound. The
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
	 * ahead of the resident at the next scheduling event. The grant
	 * is capped to MLFQ_PREEMPT_SLICE_NS, so the displaced task
	 * resumes at the next event and the zero guard cannot thrash.
	 * Internal tuning constant, not a user-facing knob.
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
	 * A sleep longer than this collapses the gauge to (near) zero. The
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
	 * Tier-A same-LLC steal window: the flat scan over the consuming
	 * CPU's own-LLC CPU list, one peek per slot. The compile-time
	 * bound keeps the verifier's exploration flat, identical in shape
	 * to the cross-LLC window it gates.
	 */
	MLFQ_LLC_SCAN_MAX		= 32ULL,

	/*
	 * Per-LLC CPU-list bound: the largest CPU count any LLC domain may
	 * publish into the mlfq_llc_cpus map values. Equal to the Tier-A
	 * scan window, so the window's constant modulo covers the whole
	 * populated list: the front-end populates a domain's list only up
	 * to MLFQ_LLC_SCAN_MAX CPUs, and a domain that exceeds the bound
	 * gets an EMPTY list (nr == 0) instead. Tier A then skips it and
	 * the Tier B rotating window covers the domain, never a silently
	 * shrunk subset of it. The cpus[] array is exactly the window
	 * width, so every published entry is reachable by the scan.
	 */
	MLFQ_MAX_LLC_CPUS		= MLFQ_LLC_SCAN_MAX,

	/*
	 * Steering scan cap: the number of least-loaded-LLC selection
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
	 * MLFQ regression-tree constants. The tree predicts the next CPU
	 * burst from per-task features and maps the prediction to a queue
	 * band (pred < T_INT -> Q1, pred < T_BOUND -> Q2, else Q3). The
	 * EMA gauge stays on as a tree feature and as the untrained
	 * fallback. Internal tuning constants, not user-facing knobs.
	 */
	MLFQ_TREE_MAX_NODES		= 2048,		/* node budget, power of two */
	MLFQ_TREE_MAX_DEPTH		= 12,		/* walk depth bound */
	MLFQ_TREE_T_INT_NS		= (1ULL * NSEC_PER_MSEC), /* Q1/Q2 split */
	MLFQ_TREE_T_BOUND_NS		= (3ULL * NSEC_PER_MSEC), /* Q2/Q3 split */

	/*
	 * Size of the training-sample ring buffer, in bytes. One
	 * megabyte holds roughly fifteen thousand sample records, a
	 * multiple of the per-minute sample budget, so the daemon drain
	 * cadence never finds the ring full.
	 */
	MLFQ_SAMPLE_RING_BYTES		= (1 * 1024 * 1024),

	/*
	 * The ops watchdog timeout, in milliseconds. The kernel's
	 * maximum detection latency for a stalled scheduler; the
	 * scheduler exits and the kernel reverts to CFS when it fires.
	 */
	MLFQ_OPS_TIMEOUT_MS		= 30000,

	/*
	 * Version tag of the emitted training-sample record layout. The
	 * ring-buffer records are parsed by the daemon with a
	 * byte-for-byte struct mirror compiled from this same header, and
	 * the native harness pins the layout at compile time; the tag is
	 * the runtime check of that contract, so a record produced by an
	 * out-of-tree builder (or a daemon built against a different
	 * intf.h) fails loudly at the parse instead of misreading the
	 * fields.
	 */
	MLFQ_TREE_SAMPLE_VERSION	= 4,

	/*
	 * Number of features the CART splitter may use. The fitter caps
	 * split feature ids to [0, MLFQ_TREE_NR_FEATURES), so a value
	 * here is the contract with mlfq_tree.rs and the walk's feat[]
	 * indexing. The 1.3.11 ABI carries nine split features
	 * (prev_burst, sleep, ema, io_wait, wake_cnt, wake_lat,
	 * queue_wait, sq_ema, gpu_submit) with sleep_var_ratio remain
	 * carry-along quantised via FP_SHIFT (0..4 steps).
	 */
	MLFQ_TREE_NR_FEATURES		= 9,
/* Nine split ids stay the shared ABI. */

	/*
	 * Adaptation control law. The adaptation is a proportional-only
	 * controller on the system wakeup-latency gauge. The band edges
	 * move by a common relative shift, slew-limited per step, within
	 * the hard floor/ceiling ranges below. The target latency equals
	 * the interactive slice, the base service target of the Q1
	 * boost; k = 0.5 maps a full-range gauge error to half the shift
	 * range, and the slew caps a single step at 10% of the base, so a
	 * full swing needs at least five steps and one bad sample can
	 * never move the bands more than one step. The shift only widens
	 * the bands: a machine at or below the target latency keeps the
	 * base bands, the measured-good configuration, and only a slower
	 * machine widens them. The symmetric negative range was dropped
	 * because narrowing the bands below the base measurably worsened
	 * the wakeup-latency tail under load.
	 */
	MLFQ_ADAPT_MIN_INTERVAL_NS	= (1ULL * NSEC_PER_SEC),
	MLFQ_ADAPT_TARGET_LAT_NS	= (1ULL * NSEC_PER_MSEC),
	MLFQ_ADAPT_K			= (FP_ONE / 2),
	MLFQ_ADAPT_MAX_SHIFT		= (FP_ONE / 2),
	MLFQ_ADAPT_MAX_STEP		= (FP_ONE / 10),

	/*
	 * Hard bounds of the effective band edges. The floor/ceiling
	 * ranges are disjoint per band pair (T_L ceiling 500 us sits below
	 * the T_H floor 1.2 ms, and the T_INT ceiling 1.6 ms below the
	 * T_BOUND floor 1.8 ms), so no admissible shift can collapse a
	 * band to zero width or invert the queue semantics. T_H - T_L
	 * >= 700 us and T_BOUND - T_INT >= 200 us for every reachable
	 * shift. The bounds are enforced on the effective value, never on
	 * the shift input.
	 */
	MLFQ_ADAPT_T_L_FLOOR_NS		= (150ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_L_CEIL_NS		= (500ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_H_FLOOR_NS		= (1200ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_H_CEIL_NS		= (3200ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_INT_FLOOR_NS	= (600ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_INT_CEIL_NS	= (1600ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_BND_FLOOR_NS	= (1800ULL * NSEC_PER_USEC),
	MLFQ_ADAPT_T_BND_CEIL_NS	= (4800ULL * NSEC_PER_USEC),

	/*
	 * Wakeup-rate storm gate. When the system wakeup-rate gauge
	 * exceeds this high threshold (200k wakeups per second, an order
	 * of magnitude above a normal desktop wakeup cadence), the
	 * positive shift is capped at +0.25 instead of +0.5: under a
	 * wakeup storm the band edges must not chase the latency error as
	 * far as in the normal regime. The threshold is in FP_SHIFT fixed
	 * point to match the gauge.
	 */
	MLFQ_ADAPT_RATE_GATE_HIGH	= (200000ULL << FP_SHIFT),
	MLFQ_ADAPT_RATE_GATE_SHIFT	= (FP_ONE / 4),

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
	MLFQ_TF_FIRST_RUN		= 1U << 0,	/* first run, half slice */
	/*
	 * The current enqueue was a wakeup: the enqueue-to-run wait
	 * measured at ops.running() is a wakeup-to-run latency and feeds
	 * the wakeup-latency features and gauges. Set on the wakeup
	 * insert paths only, cleared at the measurement and on every
	 * non-wakeup re-enqueue, so a re-enqueued (takeover-drained) task
	 * is never attributed a wakeup latency it did not have.
	 */
	MLFQ_TF_ENQ_WAKEUP		= 1U << 1,
	/*
	 * The enqueue was a DRM gpu_submit wakeup (amdgpu_cs). Set by
	 * the amdgpu tracepoints, observed by select_cpu to broaden
	 * WAKE_SYNC, cleared after the insert. The flag is advisory
	 * and is not persisted across the measurement.
	 */
	MLFQ_TF_DRM_WAKE			= 1U << 2,
	/*
	 * First ever enqueue of the task. Set at reset alongside
	 * FIRST_RUN, cleared at the first placement. While set, the
	 * placement initializes vruntime to the queue average instead
	 * of preserving lag, so a new task joins at zero lag. FIRST_RUN
	 * is separate and controls the half slice only, cleared at the
	 * first running instead.
	 */
	MLFQ_TF_INITIAL			= 1U << 3,
	/*
	 * The stored deadline is relative to the queue average. Set on
	 * a weight change where the absolute deadline was converted to
	 * relative form, cleared when the next placement commits it.
	 * The placement adds vruntime back, so a reweighted task keeps
	 * its request position across the weight change.
	 */
	MLFQ_TF_REL_DEADLINE		= 1U << 4,
	/*
	 * The task holds a per-queue sums entry for the queue stored in
	 * bits 6-7. Set when the task joins the sums, cleared when it
	 * leaves. A task in a local DSQ or running holds no entry, so a
	 * re-enqueue from the local DSQ must not subtract. The queue
	 * bits hold qid - 1 while set, so the leave subtracts from the
	 * queue the task joined, not the queue it is rejoining.
	 */
	MLFQ_TF_IN_SUMS		= 1U << 5,
};

/*
 * Sums-queue bits in task_ctx.flags. Bits 6-7 hold qid - 1 while
 * MLFQ_TF_IN_SUMS is set (0..2 for qid 1..3, 3 never stored). The
 * size of task_ctx stays 240 bytes, no ABI change.
 */
#define MLFQ_SUM_QID_SHIFT	6
#define MLFQ_SUM_QID_MASK	(0xC0U)

/*
 * EEVDF ABI version of this header. Bumped when the placement math
 * or the queue sums change in a way that alters scheduling behavior.
 * The task storage stays 240 bytes for 1.3.12, so no storage migration
 * is needed, and the tree sample stays version 4.
 */
enum mlfq_eevdf_abi {
	MLFQ_EEVDF_ABI_VERSION		= 1,
	MLFQ_AVG_MIN_WEIGHT		= 2,
	MLFQ_SUM_SHIFT_MAX		= 10,
};

/*
 * Upper bound of the rate-fold window, the longest idle gap a fold may
 * smooth over before the instantaneous rate is judged against a full
 * minute. A multi-minute gap (the boot, a long idle stretch before the
 * first step) must not inflate the rate beyond what one busy minute
 * would produce. A macro, not an enum member, because the value exceeds
 * the enum's int range and would widen the bindgen-mirrored type.
 */
#define MLFQ_SYS_RATE_WINDOW_MAX_NS	(60ULL * NSEC_PER_SEC)

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
 * struct mlfq_tree_feats - Feature vector of the prediction tree.
 *
 * Fact. the vector is the per-task state the CART predictor may
 * split on. Rule. field order and offsets are the shared ABI
 * with emitted samples (mlfq_tree_sample) and the Rust TreeFeats
 * mirror; any reordering breaks bindgen and the ring-buffer parse.
 *
 * Steps. prev_burst/sleep/ema/io_wait/wake_cnt are the original
 * 32-byte prefix. wake_lat/queue_wait/sq_ema measure the previous
 * episode's enqueue-to-run service, appended without reordering. The
 * 7.1 ABI adds sleep_var_ratio, the fixed-point (FP_SHIFT=8) variation
 * ratio of sleep intervals, to capture frame-cadence regularity; it
 * stays carry-along until the fitter promotes it. sq_ema remains at
 * offset 40, sleep_var_ratio at 48. The 1.3.11 ABI adds gpu_submit,
 * the quantised (FP_SHIFT 0..4) gpu submission count, at offset 56
 * with pad2 for 64-byte alignment. The resulting 64-byte record keeps
 * every u64 at an 8-byte offset and the packed sample at 84 bytes.
 *
 * Bound. wake_lat/queue_wait are bounded via _MAX constants and
 * label clamp, so the fitter's f64 sums stay overflow-free; the var
 * ratio is FP_ONE-scaled and clamped to [0, FP_ONE*2] to bound
 * threshold midpoints; gpu_submit is clamped to [0,4] quant steps.
 *
 * path helper: classification selects the queue via the tree
 * walk (path) observing this feature state (reader) without a
 * indirect; helpers are static inline.
 *
 * 64 bytes, packed fields plainly aligned.
 */
struct mlfq_tree_feats {
	u64 prev_burst_ns;		/* last completed run segment */
	u64 sleep_ns;			/* sleep before the current wakeup */
	u64 ema;			/* EMA interactivity gauge */
	u32 io_wait;			/* 1 if the wakeup is an I/O completion */
	u32 wake_cnt;			/* consecutive short-sleep wakeups */
	u32 wake_lat_us;		/* last wakeup-to-run latency, us */
	u32 queue_wait_us;		/* last enqueue-to-run wait, us */
	u64 sq_ema;			/* service-quality EMA, ns */
	u32 sleep_var_ratio;		/* sleep variation ratio, FP_SHIFT fixed point */
	u32 pad;			/* explicit pad for 64-byte alignment */
	u32 gpu_submit;			/* gpu submissions quantised 0..4, FP_SHIFT steps */
	u32 pad2;			/* explicit pad for 64-byte alignment */
};

/*
 * One node of the serialized tree. threshold is the split point in
 * nsecs. left is the left child index, or the leaf prediction in nsecs
 * when right == 0. right is the right child index, 0 marking a leaf.
 * feature is the split feature id (0..8, indexing the walk's feat[]
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
 * publish. The meta commit is the last write of a publish, and the tree
 * contents it points at were fully written before it.
 *
 * The protocol is sound at the 60 s publish cadence: a reader could
 * only observe a torn tree if two publishes completed within one tree
 * walk, and each walk is a few dozen memory reads while a publish moves
 * up to 2048 nodes, so two consecutive publishes cannot complete inside
 * one walk. The consequence of the theoretical race (a reader that
 * loaded the meta between two back-to-back publishes and walks the
 * freshly overwritten buffer) is one mispredicted burst, which the
 * queue-band nets absorb. It is not a memory-safety issue because the
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
 * struct mlfq_tree_sample - One training sample for the daemon.
 *
 * Fact. the ring-buffer record is the atomic training unit.
 * Rule. 84 bytes packed aligned(4), field order is the shared ABI.
 *
 * Steps. pid/queue (8 bytes) + feats 64 bytes + label 8 bytes +
 * version 4 bytes = 84. The feats vector is the 64-byte form (sq_ema
 * at 40, sleep_var_ratio at 48, gpu_submit at 56). label_ns is clamped to
 * MLFQ_TREE_LABEL_MAX_NS, so the fitter's f64 sums never sum near-u64
 * values.
 *
 * Bound. version is MLFQ_TREE_SAMPLE_VERSION (4 for 1.3.11 ABI);
 * mismatch drops the record instead of misreading fields.
 *
 * reader helper: stopping path observes task state to emit this
 * record; daemon observes the ring buffer (reader) without shared
 * state.
 *
 * 84 bytes packed aligned(4); every field keeps its base offset.
 */
struct mlfq_tree_sample {
	u32 pid;
	u32 queue;
	struct mlfq_tree_feats feats;
	u64 label_ns;
	u32 version;			/* MLFQ_TREE_SAMPLE_VERSION */
} __attribute__((packed, aligned(4)));

/* ABI layout pins: compiled on every build, native and BPF. */
_Static_assert(sizeof(struct mlfq_tree_feats) == 64,
	       "mlfq_tree_feats must be 64 bytes (sq_ema at 40, var_ratio at 48, gpu_submit at 56)");
_Static_assert(sizeof(struct mlfq_tree_sample) == 84,
	       "mlfq_tree_sample must be 84 bytes (packed, aligned(4))");
_Static_assert(__builtin_offsetof(struct mlfq_tree_feats, sq_ema) == 40,
	       "sq_ema must sit at offset 40");
_Static_assert(__builtin_offsetof(struct mlfq_tree_feats, sleep_var_ratio) == 48,
	       "sleep_var_ratio must sit at offset 48");
_Static_assert(__builtin_offsetof(struct mlfq_tree_feats, gpu_submit) == 56,
	       "gpu_submit must sit at offset 56");
_Static_assert(__builtin_offsetof(struct mlfq_tree_sample, label_ns) == 72,
	       "label_ns must sit at offset 72 (pid 0, queue 4, feats 8+64)");
_Static_assert(__builtin_offsetof(struct mlfq_tree_sample, version) == 80,
	       "version must sit at offset 80");
_Static_assert(__builtin_offsetof(struct mlfq_tree_feats, prev_burst_ns) == 0,
	       "prev_burst_ns at 0");
_Static_assert(__builtin_offsetof(struct mlfq_tree_feats, wake_lat_us) == 32,
	       "wake_lat_us at 32");
_Static_assert(__builtin_offsetof(struct mlfq_tree_feats, queue_wait_us) == 36,
	       "queue_wait_us at 36");
/* Masking gap: BPF walk feat[16] uses &0xF (0..15) with feat[16]
 * holding nine split features 0..8 (gpu_submit at 8, quant 0..4),
 * sleep_var_ratio carry-along at 9, and 10..15 zeroed; Rust feat[16]
 * mirrors this with match 0..10 and _=>0. The plain < NR_FEATURES
 * check is authoritative (not &0xF<9 which is tautological) and is
 * unconditional, so 9..15 never indexes OOB. NR_FEATURES 9.
 */
_Static_assert(MLFQ_TREE_NR_FEATURES == 9,
	       "NR_FEATURES must be 9 for 1.3.11 ABI (feat[16] 0..8 split, gpu_submit quant 0..4, 9 carry-along)");

/*
 * Sentinel "no LLC owner" value for task_ctx.last_llc. Valid LLC domain
 * ids are 0..MLFQ_MAX_LLCS-1 (0..31), which fit in a u8; 0xFF marks a
 * task that is not counted in the per-LLC runnable gauges: it is not
 * runnable, or it is parked on the kernel-owned global DSQ where no LLC
 * owns it.
 */
#define MLFQ_LLC_UNOWNED 0xFFU

/*
 * struct task_ctx - Per-task state in BPF task storage.
 *
 * Fact. the task is the unit of EEVDF placement and MLFQ
 * classification. Rule. vruntime anchored to the queue average
 * via the signed bounded lag clamp, vlag in [-limit, limit].
 *
 * Steps. 96-byte classification/vtime block, 24-byte
 * enqueue-to-run measurement block, plus the 80-byte MLFQ tree sample
 * block (the 64-byte feature vector plus pending_queue and
 * pending_valid padded to 64-bit) plus 24-byte sleep cadence EMA
 * block (mean 8, var 8, ratio 4 + pad 4) plus 4-byte gpu_submit
 * plus 4-byte pad plus 8-byte gpu_submit dedup timestamp.
 * Total 240 bytes aligned for the 1.3.12 ABI, unchanged from 1.3.11
 * (232 before gpu_submit timestamp, 224 before gpu_submit, gpu_submit at 224,
 * last_gpu_submit_at at 232). The 64-byte vector keeps sq_ema at 40,
 * sleep_var_ratio at 48 and gpu_submit at 56 quantised 0..4.
 *
 * Bound. placement lag clamped to [-limit, limit] for bounded lag,
 * with lag inflation preserving the average across joins. Service EMAs
 * clamped to MAX to bound thresholds and f64 sums.
 * gpu_submit dedup window is MLFQ_TREE_PER_TASK_LIMIT_NS (10 ms),
 * the same per-task rate limit as the training-sample gate, so a
 * single logical GPU submission that fires 2-3 tracepoints
 * (amdgpu_cs, amdgpu_cs_ioctl, gpu_sched) is counted once.
 */

/*
 * struct mlfq_q1_occupancy - Per-CPU Q1 occupancy for SMT isolation.
 *
 * Fact. each CPU's Q1 occupancy is the soft SMT veto the selection
 * observes. Rule. one byte per CPU, padded to 8 bytes for array
 * map value alignment and to keep per-CPU slots on separate cache
 * lines from mlfq_stats (reader: select_cpu observes occupancy,
 * path: veto is direct via helper).
 *
 * Steps. occupied==1 when the CPU runs a Q1 task (set in
 * running(), cleared in stopping()), 0 otherwise. The 8-byte value
 * keeps array map values plainly aligned and avoids false sharing
 * with the BSS stats line; the map is BPF_MAP_TYPE_ARRAY, not BSS,
 * so no __sync_* on a shared line is needed and cross-CPU
 * bpf_map_lookup_elem returns the sibling's occupancy. Performance
 * review: no extra cache-line pad needed today — ARRAY already
 * isolates each CPU's slot from the BSS stats line; pad further only
 * if perf measurement shows sibling veto contention (documented, not
 * padded now).
 *
 * Split. keeping occupancy per-CPU avoids the word-bit
 * false sharing of a global q1_mask; sibling lookup is logical via
 * mlfq_cpu_sibling table, not bit arithmetic.
 *
 * 8 bytes.
 */
struct mlfq_q1_occupancy {
	u8 occupied;
	u8 pad[7];
};

struct task_ctx {
	u64 vruntime;			/* last placed virtual runtime */
	s64 vlag;			/* clamped virtual lag, in [-limit, limit] */
	u64 deadline;			/* last computed virtual deadline, absolute unless REL_DEADLINE */
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
	/*
	 * Runnable-ownership record, maintained by the accounting helpers
	 * (mlfq_runnable_enter/exit). last_llc is the LLC domain owning
	 * the task's current DSQ or running CPU, MLFQ_LLC_UNOWNED when
	 * the task is not runnable or is parked on the kernel-owned
	 * global DSQ; last_qid is the queue (1..3) of the last counted
	 * placement, 0 when unowned. The pair is the single source of
	 * truth for "is this task counted in the per-LLC/per-queue
	 * runnable gauges". The helpers treat last_llc == MLFQ_LLC_UNOWNED
	 * as not counted. The read-modify-write is lock-free. The kernel
	 * serializes enqueue/dequeue/stopping per task, so the counter
	 * RMWs stay exact in the absence of a cross-rq race; a torn read
	 * can only defer one release, recovered by the next episode
	 * entry.
	 */
	u8  last_llc;			/* owning LLC, MLFQ_LLC_UNOWNED if none */
	u8  last_qid;			/* queue of the last placement, 0 if none */
	u8  pad[2];
	/*
	 * Enqueue-to-run measurement block. enq_at is stamped at every
	 * DSQ insert (except the global park, whose wait is kernel-side)
	 * and the wait since it is measured at the first ops.running()
	 * of the episode: last_q_wait_ns for every episode, last_wake_lat_ns
	 * for wakeup episodes only (MLFQ_TF_ENQ_WAKEUP). sq_ema is the
	 * per-task saturating EMA of the wakeup latency, the service
	 * quality prior the tree can split on. The block is zeroed by
	 * mlfq_reset_task_ctx like every other field.
	 */
	u64 enq_at;			/* stamp of the current enqueue episode */
	u32 last_wake_lat_ns;		/* last wakeup-to-run latency, ns */
	u32 last_q_wait_ns;		/* last enqueue-to-run wait, ns */
	u64 sq_ema;			/* service-quality EMA [0, SQ_EMA_MAX] */
	u64 prev_burst_ns;		/* last completed run segment, tree feature */
	u64 last_sample_at;		/* scx_bpf_now() of the last emitted
					 * training sample, per-task rate limit */
	/*
	 * Sleep cadence EMA block for frame-loop regularity. mean/var are
	 * N=32 EWMA (α=8/256) over sleep intervals, ratio is var/mean² in
	 * FP_SHIFT=8 fixed point saturating 0..1024 (4*FP_ONE). The block
	 * is zeroed by mlfq_reset_task_ctx and updated in stopping(!runnable)
	 * with clamp and long-idle decay (>120ms) to avoid stale cadence
	 * carrying over a long idle.
	 */
	u64 sleep_mean_ema;		/* EMA of sleep intervals, ns */
	u64 sleep_var_ema;		/* EMA of sleep variance, ns² */
	u32 sleep_var_ratio;		/* var/mean² ratio, FP_SHIFT=8, 0..1024 */
	u32 pad2;
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
	u32 gpu_submit;			/* gpu submissions, quantised 0..4, decay on idle */
	u32 pad3;			/* pad to 8-byte alignment for the timestamp */
	u64 last_gpu_submit_at;		/* scx_bpf_now() of the last gpu_submit bump, per-task dedup window (10 ms) */
};

_Static_assert(sizeof(struct task_ctx) == 240,
	       "task_ctx must be 240 bytes for 1.3.12 ABI (64-byte feats + cadence + gpu_submit + dedup timestamp, 8-byte aligned; 224 before gpu, 232 last_gpu_submit_at)");
_Static_assert(__builtin_offsetof(struct task_ctx, pending_feats) == 144,
	       "pending_feats at 144");
_Static_assert(__builtin_offsetof(struct task_ctx, pending_queue) == 208,
	       "pending_queue at 208");
_Static_assert(__builtin_offsetof(struct task_ctx, pending_valid) == 216,
	       "pending_valid at 216");
_Static_assert(__builtin_offsetof(struct task_ctx, gpu_submit) == 224,
	       "gpu_submit must sit at offset 224");
_Static_assert(__builtin_offsetof(struct task_ctx, last_gpu_submit_at) == 232,
	       "last_gpu_submit_at must sit at offset 232");
_Static_assert(__builtin_offsetof(struct task_ctx, sleep_mean_ema) == 120,
	       "sleep_mean_ema at 120");
_Static_assert(__builtin_offsetof(struct task_ctx, sleep_var_ratio) == 136,
	       "sleep_var_ratio at 136");

/* wake_cpu_state bits */
#define MLFQ_WAKE_CPU_IDLE	0x01U
#define MLFQ_WAKE_CPU_VALID	0x02U

/*
 * Per-queue EEVDF runqueue. clock is the legacy monotone service point,
 * kept for observability and advanced alongside the average. The average
 * itself is the weighted mean of the queued vruntimes, tracked with the
 * relative sums below, plus the running task when it belongs to the queue.
 * Placement anchors lag to the average, eligibility tests against it, and
 * the zero point advances monotonically so stale reads stay eligible.
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
	s64 sum_w_vruntime;		/* sum of (vruntime - zero) * weight, queued only */
	s64 sum_weight;			/* sum of queued weights, scaled */
	u64 zero_vruntime;		/* base the relative sums are measured from */
	u32 sum_shift;			/* weight scale shift, 0 until overflow */
	u32 pad_shift;			/* explicit pad for 8 byte alignment */
	u64 pad[2];			/* keep the struct at 64 bytes, one cache line */
};

_Static_assert(sizeof(struct queue_ctx) == 64,
	       "queue_ctx must be 64 bytes, one cache line with sums and zero");

/*
 * Global idle tracking. mlfq_idle_count is the number of currently idle
 * CPUs, maintained by ops.update_idle() with atomic RMWs (a single u32;
 * the only consumer treats it as a zero/non-zero test). mlfq_idle_tracking
 * is a rodata gate written by the Rust front-end. It is 1 only when the
 * kernel keeps its built-in idle tracking alongside the callback (the
 * KEEP_BUILTIN_IDLE flag), 0 otherwise. Declared here so the modules and
 * the pure-math harness share the same contract.
 */
extern volatile u32 mlfq_idle_count;
extern const volatile u32 mlfq_idle_tracking;

/*
 * struct mlfq_cpu_state - Per-CPU occupancy and scheduling state.
 *
 * Fact. each CPU's running queue, deadline and EMA are the
 * observable state the dispatch and selection helpers observe.
 * Rule. one entry per CPU, 64 bytes, one cache line; array key
 * is cpu id.
 *
 * Steps. running_queue/pid/deadline track the current occupant
 * for same-queue preemption (mlfq_sameq_preempt_owed). cpu_ema is the
 * busy-ns EMA (MLFQ_BUDGET_MAX_NS ceiling, MLFQ_EMA_HALF_LIFE_NS
 * decay) used for cpuperf level (mlfq_cpuperf_from_ema). steal_scan_off
 * rotates the Tier-B steal scan (reader: dispatch observes this
 * state, path: scan order is a direct helper without indirect).
 *
 * Bound. cpu_ema clamped to [0, BUDGET_MAX] bounds the cpuperf
 * level to [0, SCX_CPUPERF_ONE] and bounds virtual-time math; deadline
 * 0 marks unknown and never preempts.
 *
 * 64 bytes, one cache line.
 */
struct mlfq_cpu_state {
	s32 running_queue;		/* queue of the running task, 0 none */
	u32 running_pid;
	u32 steal_scan_off;		/* rotating remote-scan start for Q2/Q3 */
	u32 pad0;			/* explicit pad for 8 byte alignment */
	u64 cpu_ema;			/* busy-ns EMA of this CPU's activity */
	u64 cpu_ema_at;			/* scx_bpf_now() of the last update */
	u64 running_deadline;		/* running task's deadline, 0 unknown */
	u64 run_start_at;		/* scx_bpf_now() at ops.running() */
	u32 running_gpu_submit;		/* gpu_submit 0..4 of the running task */
	u32 running_weight;		/* weight of the running task, for avg curr */
	u64 running_vruntime;		/* vruntime of the running task, for avg curr */
};

_Static_assert(sizeof(struct mlfq_cpu_state) == 64,
	       "mlfq_cpu_state must be 64 bytes, one cache line with curr vruntime");
_Static_assert(__builtin_offsetof(struct mlfq_cpu_state, running_vruntime) == 56,
	       "running_vruntime at 56");

/* Per-CPU realtime-occupancy flags. */
#define MLFQ_RTDL_OCCUPIED			(1U << 0)

/*
 * struct mlfq_rtdl_state - Per-CPU realtime occupancy.
 *
 * Fact. the RT occupancy flag is the gate the scheduler observes
 * before placing work. Rule. one entry per CPU, flags
 * MLFQ_RTDL_OCCUPIED when the last sched_switch saw RT/DL.
 *
 * Steps. sched_switch hook (rtdl.bpf.c) observes the switched-in
 * task class (reader) and sets flags; enqueue and select_cpu observe
 * flags to redirect or skip the CPU (path via helper predicates,
 * static inline, no indirect). last_drain_at rate-limits the evacuation
 * scan to MLFQ_RTDL_DRAIN_INTERVAL_NS, so a takeover blip cannot
 * thrash.
 *
 * Bound. flags is a single bit, checked under the 7.1-only
 * watchdog (30 s); drain interval clamps the churn to 1/ms per CPU,
 * bounding the DSQ moves under continuous RT preemption.
 *
 * 16 bytes, BPF_MAP_TYPE_ARRAY value.
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
 * healthy when its charges stay in the first few buckets; a regression
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
	/* EEVDF diagnostics (vtime, dispatch, lifecycle). */
	u64 eevdf_eligible;		/* eligible picks observed at dispatch */
	u64 eevdf_ineligible;		/* ineligible heads skipped at dispatch */
	u64 eevdf_deadline_miss;	/* vruntime past deadline at charge time */
	u64 eevdf_divergence;		/* lag spread beyond one bound at publish */
	/*
	 * The counter struct is 36 counters plus 4 pad words, 40 u64s or
	 * 320 bytes (five 64 byte lines). The counters before the pad are
	 * write-hammered by the hot paths, and the published tree meta
	 * line (mlfq_tree_ctrl) must not share a line with them. The
	 * isolation itself comes from the __aligned(64) on the
	 * mlfq_tree_ctrl instance in main.bpf.c, which pins that line to
	 * a dedicated cache line. The size stays a whole number of lines,
	 * so the two never land on the same line by layout accident. The
	 * pad keeps the multiple; adding any counter requires recomputing
	 * it.
	 */
	u64 pad[4];
};

/*
 * System-level wakeup gauges, the inputs of the threshold adaptation.
 * lat_ema is the average wakeup latency of the machine, an EMA over
 * the per-window average wait, so its equilibrium does not depend on
 * the wakeup rate. rate_ema is a wakeup-rate EMA in FP_SHIFT fixed
 * point, folded once per adaptation step. step_at gates the adaptation
 * cadence (the compare-and-swap single-winner step of the adaptation
 * layer). wait_total and wait_count accumulate the episode waits
 * between folds, and the fold derives the average from them. The
 * wakeup arrival counters live in the per-CPU map mlfq_wakeup_stats
 * (see mlfq_wakeup_counters below), not here, so the wakeup path never
 * touches this line. Each CPU owns its own map slot and the u64 totals
 * cannot wrap. The rate fold consumes the per-CPU window slots once
 * per step. The latency fold runs at the cadence even with the
 * adaptation disabled, so the latency gauge stays live, while the rate
 * fold stays gated and the rate EMA stays frozen. 48 bytes.
 */
struct mlfq_sys_gauge {
	u64 lat_ema;		/* average wakeup latency, ns, [0, SYS_LAT_MAX] */
	u64 rate_ema;		/* wakeup rate, wakeups/s in FP_SHIFT fixed point */
	u64 step_at;		/* scx_bpf_now() of the last adaptation step */
	u64 wait_total;		/* wakeup waits accumulated since the last fold */
	u64 wait_count;		/* wakeup episodes since the last fold */
	u32 adapt_steps;	/* lifetime adaptation steps */
	u32 pad;
};

/*
 * Per-CPU wakeup-arrival counters, one slot per CPU in the per-CPU
 * array map mlfq_wakeup_stats. Each CPU owns its own slot, so the
 * wakeup path needs no locked operation on a shared line. total is the
 * lifetime arrival count of the owning CPU, a u64 so it cannot wrap.
 * window counts the arrivals since the last rate fold, consumed and
 * zeroed by the adaptation step with an atomic exchange. The stats
 * read sums every CPU's total with atomic loads, so the counters stay
 * tear-free for the readers. While the adaptation is disabled the fold
 * never runs and the rate EMA stays frozen, but total still grows on
 * every wakeup (the observation-only contract).
 */
struct mlfq_wakeup_counters {
	u64 total;		/* lifetime wakeup arrivals of this CPU */
	u64 window;		/* arrivals since the last rate fold */
};

/*
 * Effective adaptation state, the values the classification predicates
 * consume. Every field is written only by the 1 Hz adaptation step and
 * by mlfq_init() (which copies the rodata bases in, so the bss-zeroed
 * state, which zero thresholds would map every task to Q1, can never be
 * observed). shift_fp is the slew-limited common relative shift of both
 * band pairs, in FP_SHIFT fixed point; the t_*_eff_ns fields are the
 * clamped effective band edges; guard_eff_ns is the same-queue
 * preemption residency guard, fixed at the base constant (the
 * adaptation no longer moves it). 48 bytes.
 */
struct mlfq_adapt_state {
	s64 shift_fp;		/* slew-limited relative shift, FP */
	u64 t_l_eff_ns;		/* effective EMA Q1/Q2 band edge */
	u64 t_h_eff_ns;		/* effective EMA Q2/Q3 band edge */
	u64 t_int_eff_ns;	/* effective tree Q1/Q2 band edge */
	u64 t_bnd_eff_ns;	/* effective tree Q2/Q3 band edge */
	u64 guard_eff_ns;	/* effective same-queue residency guard */
};

extern volatile struct mlfq_sys_gauge mlfq_sys_gauge;
extern volatile struct mlfq_adapt_state mlfq_adapt_state;
extern const volatile bool mlfq_adapt_enabled;

/*
 * GPU submit tracepoint state. mlfq_gpu_submit_total counts every
 * deduped quantised gpu_submit bump (the per-task 0..4 counter's
 * increments, one per MLFQ_TREE_PER_TASK_LIMIT_NS window, so a burst
 * of amdgpu_cs/amdgpu_cs_ioctl/gpu_sched for one job is a single
 * bump) and mlfq_gpu_trace_mask records which tracepoints attached
 * at load: bit0 amdgpu_cs, bit1 amdgpu_cs_ioctl, bit2 gpu_sched. Both
 * are gauges, not interval deltas, and are read by the web metrics.
 * The dedup window mirrors the sample per-task limiter, so the total
 * is not raw trace hits.
 */
#define MLFQ_GPU_TRACE_AMDGPU_CS	(1U << 0)
#define MLFQ_GPU_TRACE_AMDGPU_CS_IOCTL	(1U << 1)
#define MLFQ_GPU_TRACE_GPU_SCHED	(1U << 2)

extern volatile u64 mlfq_gpu_submit_total;
extern volatile u32 mlfq_gpu_trace_mask;

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
 * map. Written by the Rust front-end after load; the dispatch Tier-A
 * scan walks the consuming CPU's own-LLC entry as its same-LLC steal
 * window. 132 bytes per value (4 + 32 * 4), far under the ARRAY-map
 * value-size limit; the unpopulated map state means "feature off", and
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

/*
 * mlfq_bitmap_test_cpu - Test a CPU's bit in a bitmap.
 * @bm: The bitmap.
 * @cpu: The CPU id.
 *
 * Out-of-range CPUs never have their bit set.
 *
 * Gives True if @cpu's bit is set.
 */
static __always_inline bool mlfq_bitmap_test_cpu(const struct mlfq_bitmap *bm,
						 u32 cpu)
{
	if (cpu >= MLFQ_MAX_CPUS)
		return false;
	return bm->words[cpu >> 6] & (1ULL << (cpu & 63));
}

/*
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

/*
 * mlfq_time_before - Wrapping-safe u64 "before" comparison.
 * @a: First comparable as u64.
 * @b: Second comparable as u64.
 *
 * Same convention as fair.c vruntime_cmp()/time_before64(): the kernel
 * DSQ orders by min deadline with the same wrapping semantics.
 *
 * Gives true if @a is before @b.
 */
static __always_inline bool mlfq_time_before(u64 a, u64 b)
{
	return (s64)(b - a) > 0;
}

/*
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
 * Gives true if a new boost may be granted at @now.
 */
static __always_inline bool mlfq_ss_boost_allowed(u64 last_boost_at, u64 now,
						  u64 rate_limit)
{
	if (!last_boost_at)
		return true;
	return mlfq_time_before(last_boost_at + rate_limit, now);
}

/*
 * mlfq_boost_eligible - IPC boost eligibility at wakeup.
 * @sleep_ns: Sleep duration at wakeup (scx_bpf_now() delta, 0 = none).
 * @window_ns: Short-sleep window (MLFQ_SHORT_SLEEP_NS).
 * @io_wait: True when the wakeup is an I/O completion
 *	(task_struct::in_iowait).
 *
 * A wakeup is boost-eligible when it is an I/O wakeup regardless of the
 * sleep length, or when the sleep fell within the short-sleep window. The
 * I/O-wait case covers the other plain interactive wakeup source beside
 * the short-sleep window. The rate limit is applied separately by the
 * caller (mlfq_ss_boost_allowed()), so an I/O wakeup burst cannot chain
 * boosts.
 *
 * Gives true if the wakeup is boost-eligible.
 */
static __always_inline bool mlfq_boost_eligible(u64 sleep_ns, u64 window_ns,
						bool io_wait)
{
	if (io_wait)
		return true;
	return sleep_ns && sleep_ns <= window_ns;
}

/*
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
 * Gives true if the wakeup qualifies for the Q1 boost.
 */
static __always_inline bool mlfq_ss_boost_pending(const struct task_ctx *tctx,
						  u64 sleep_ns, bool io_wait,
						  u64 now, u64 short_sleep,
						  u64 rate_limit)
{
	return mlfq_boost_eligible(sleep_ns, short_sleep, io_wait) &&
	       mlfq_ss_boost_allowed(tctx->last_ss_boost_at, now, rate_limit);
}

/*
 * mlfq_cpuperf_from_ema - CPU performance level for a busy-ns gauge.
 * @ema: The per-CPU EMA of the recent run time.
 *
 * Maps the busy-ns gauge to the sched_ext cpuperf scale. A CPU that ran
 * tasks for the whole gauge window requests the maximum level and a
 * lightly loaded CPU requests a proportionally lower one. The gauge
 * ceiling is the per-task budget, so a CPU saturated over the gauge
 * window maps to the maximum.
 *
 * Gives The cpuperf level in [0, SCX_CPUPERF_ONE].
 */
static __always_inline u32 mlfq_cpuperf_from_ema(u64 ema)
{
	u64 perf = ema * MLFQ_CPUPERF_Q1 / MLFQ_BUDGET_MAX_NS;

	return perf > MLFQ_CPUPERF_Q1 ? MLFQ_CPUPERF_Q1 : (u32)perf;
}

/*
 * calc_delta_fair_bpf - Scale a runtime delta to virtual time.
 * @delta: Physical time in nsecs.
 * @weight: Task weight in scx scale (nice-0 = 100, min 1).
 *
 * EEVDF virtual time grows at rate w_i/NICE_0_LOAD while running. With
 * the scx weight scale this is delta * 100 / weight.
 *
 * Gives The virtual time delta.
 */
static __always_inline u64 calc_delta_fair_bpf(u64 delta, u32 weight)
{
	return delta * 100 / weight;
}

/*
 * mlfq_avg_weight - Scaled weight for the average sums.
 * @q: The queue holding the shift.
 * @weight: Task weight in scx scale.
 *
 * The sums use the scaled weight to keep the key times weight products
 * inside s64. The shift starts at zero and grows only on overflow, and
 * the scaled weight never drops below MLFQ_AVG_MIN_WEIGHT, so an idle
 * queue still carries a non-zero denominator. The scaling preserves
 * ordering, since every weight in one queue shares the same shift.
 *
 * Gives The scaled weight.
 */
static __always_inline u64 mlfq_avg_weight(const struct queue_ctx *q, u32 weight)
{
	u64 w = weight;

	if (q && q->sum_shift)
		w >>= q->sum_shift > MLFQ_SUM_SHIFT_MAX ? MLFQ_SUM_SHIFT_MAX : q->sum_shift;
	if (w < MLFQ_AVG_MIN_WEIGHT)
		w = MLFQ_AVG_MIN_WEIGHT;
	return w;
}

/*
 * mlfq_entity_key - Relative vruntime of a task against the queue base.
 * @q: The queue holding zero_vruntime.
 * @vruntime: Task vruntime.
 *
 * The relative form keeps the summed products small, since zero tracks
 * the service point and the deltas stay near one lag bound. The result
 * is signed, so tasks ahead of the base yield negative keys.
 *
 * Gives vruntime minus zero as s64.
 */
static __always_inline s64 mlfq_entity_key(const struct queue_ctx *q, u64 vruntime)
{
	return (s64)(vruntime - q->zero_vruntime);
}

/*
 * mlfq_lag_limit - Placement lag bound (fair.c entity_lag()).
 * @q: The queue.
 * @weight: Task weight.
 *
 * limit = calc_delta_fair(max_slice + TICK, weight). A task lag is kept
 * inside [-limit, limit], the bounded lag horizon of entity_lag() in
 * kernel/sched/fair.c. The limit uses the raw task weight, as fair.c
 * does; the sums use the scaled weight floored to MLFQ_AVG_MIN_WEIGHT
 * only to keep an empty queue's denominator non-zero. The two weights
 * differ only for weight 1 (floored to 2 in the sums), where the limit
 * stays conservative (twice the sums-implied bound), never tighter.
 *
 * Gives The lag bound in virtual-time nsecs.
 */
static __always_inline u64 mlfq_lag_limit(const struct queue_ctx *q, u32 weight)
{
	return calc_delta_fair_bpf(q->max_slice_ns + MLFQ_TICK_NS, weight);
}

/*
 * mlfq_entity_lag_raw - Signed lag of a vruntime against an average.
 * @avg: Queue average vruntime.
 * @vruntime: Task vruntime.
 * @limit: Lag bound from mlfq_lag_limit().
 *
 * lag = clamp(avg - vruntime, -limit, limit). Positive lag means owed
 * service, negative lag means ahead. The clamp bounds the steady state
 * spread to one request plus one tick either way.
 *
 * Gives The clamped signed lag.
 */
static __always_inline s64 mlfq_entity_lag_raw(u64 avg, u64 vruntime, u64 limit)
{
	s64 vlag = (s64)(avg - vruntime);
	s64 bound = (s64)limit;

	if (vlag > bound)
		vlag = bound;
	if (vlag < -bound)
		vlag = -bound;
	return vlag;
}

/*
 * mlfq_inflate_lag - Preserve lag across a queue join.
 * @lag: Stored virtual lag before placement.
 * @sum_weight: Queued weight sum, without the joining task.
 * @w: Scaled weight of the joining task.
 *
 * Joining moves the average, so the stored lag would evaporate without
 * compensation. The inflated lag is lag * (W + w) / W, which inverts the
 * averaging step and leaves the effective lag after placement equal to
 * the stored lag. A zero sum means an empty queue, where no inflation
 * is needed. Overflow saturates to the input sign, which the caller
 * clamps again.
 *
 * Gives The inflated lag.
 */
static __always_inline s64 mlfq_inflate_lag(s64 lag, s64 sum_weight, u64 w)
{
	s64 inflated;
	u64 mag;
	bool neg = false;

	if (!lag || sum_weight <= 0)
		return lag;
	if (lag < 0) {
		neg = true;
		mag = (u64)(-lag);
	} else {
		mag = (u64)lag;
	}
	/* Guard the multiply, saturate before it can wrap. */
	{
		u64 total = (u64)sum_weight + w;

		if (mag > (u64)0x7FFFFFFFFFFFFFFFULL / total)
			return neg ? (s64)-0x7FFFFFFFFFFFFFFFLL : (s64)0x7FFFFFFFFFFFFFFFLL;
		mag = mag * total / (u64)sum_weight;
	}
	if (mag > (u64)0x7FFFFFFFFFFFFFFFULL)
		mag = (u64)0x7FFFFFFFFFFFFFFFULL;
	inflated = (s64)mag;
	return neg ? -inflated : inflated;
}

/*
 * mlfq_avg_from_sums - Weighted average from the relative sums.
 * @sum_w: Sum of key times weight, queued only.
 * @sum_weight: Sum of weights, queued only.
 * @zero: Base vruntime.
 * @curr_key: Key of the running task, 0 when none.
 * @curr_w: Scaled weight of the running task, 0 when none.
 *
 * avg = zero + (sum_w + curr_key * curr_w) / (sum_weight + curr_w).
 * The division uses floor for positive sums and ceiling for negative
 * sums, the left bias that keeps avg plus zero eligible. An empty
 * queue with no running task yields zero, and a single running task
 * yields its vruntime directly.
 *
 * Gives The average vruntime.
 */
static __always_inline u64 mlfq_avg_from_sums(s64 sum_w, s64 sum_weight, u64 zero,
					      s64 curr_key, u64 curr_w)
{
	s64 runtime = sum_w;
	s64 weight = sum_weight;
	u64 mag, div;
	bool neg;

	if (curr_w) {
		runtime += curr_key * (s64)curr_w;
		weight += (s64)curr_w;
	}
	if (weight <= 0) {
		if (curr_w)
			return zero + (u64)curr_key;
		return zero;
	}
	/* BPF has no signed division, so divide the magnitude in u64. */
	neg = runtime < 0;
	mag = neg ? (u64)(-runtime) : (u64)runtime;
	if (neg)
		mag += (u64)weight - 1;
	div = mag / (u64)weight;
	if (neg)
		return zero - div;
	return zero + div;
}

/*
 * mlfq_vruntime_eligible_raw - Eligibility of a vruntime against sums.
 * @sum_w: Sum of key times weight, queued only.
 * @sum_weight: Sum of weights, queued only.
 * @zero: Base vruntime.
 * @vruntime: Vruntme under test.
 * @curr_key: Key of the running task, 0 when none.
 * @curr_w: Scaled weight of the running task, 0 when none.
 *
 * Eligible means owed service, lag >= 0, tested without division as
 * sum_w + curr >= (vruntime - zero) * (sum_weight + curr_w). A stale
 * or empty sum (weight <= 0) is eligible, so a torn read never starves
 * a task. The key is tested unclamped here; the BPF callers clamp it to
 * 32 bits before the call, so the product stays inside s64 for every
 * reachable vruntime and the overflow arm only fires on a corrupted
 * sum. Overflow of the right hand side yields eligible when the key
 * is behind and ineligible when ahead, the same sign rule as fair.c,
 * symmetric by lag sign, never by weight.
 *
 * Gives True when eligible.
 */
static __always_inline bool mlfq_vruntime_eligible_raw(s64 sum_w, s64 sum_weight, u64 zero,
						       u64 vruntime, s64 curr_key, u64 curr_w)
{
	s64 avg = sum_w;
	s64 load = sum_weight;
	s64 key = (s64)(vruntime - zero);
	u64 mag_key, mag_load, prod;
	bool neg;

	if (curr_w) {
		avg += curr_key * (s64)curr_w;
		load += (s64)curr_w;
	}
	if (load <= 0)
		return true;
	/* BPF has no signed overflow builtin, guard by magnitude. */
	neg = key < 0;
	mag_key = neg ? (u64)(-key) : (u64)key;
	mag_load = (u64)load;
	/* Overflow yields eligible when behind and ineligible when ahead. */
	if (mag_key && mag_load > (u64)0x7FFFFFFFFFFFFFFFULL / mag_key)
		return neg;
	prod = mag_key * mag_load;
	if (neg)
		return avg >= -(s64)prod;
	return avg >= (s64)prod;
}

/*
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

/*
 * mlfq_update_zero_raw - Advance the zero base by delta.
 * @sum_w: Pointer to the weighted sum, adjusted by -delta * sum_weight.
 * @zero: Pointer to the base, advanced by delta.
 * @sum_weight: Current weight sum.
 * @delta: Signed advance, as s64.
 *
 * Moving the base keeps the relative keys small, which keeps the key
 * times weight products inside s64. The update preserves the average,
 * since the sum is reduced by exactly the base movement times the
 * weight. Pure math for the harness, the BPF side wraps it in atomics.
 */
static __always_inline void mlfq_update_zero_raw(s64 *sum_w, u64 *zero,
						 s64 sum_weight, s64 delta)
{
	if (!delta)
		return;
	*sum_w -= sum_weight * delta;
	*zero += (u64)delta;
}

/*
 * mlfq_update_deadline_raw - Refresh a deadline after service.
 * @vruntime: Current vruntime after the charge.
 * @deadline: Pointer to the deadline, updated when expired.
 * @vslice: Virtual slice for one request.
 *
 * When vruntime has reached the deadline, the task consumed its request
 * and the deadline moves to vruntime plus one virtual slice. Otherwise
 * the deadline is unchanged. Pure math, no side effects beyond the
 * deadline store.
 *
 * Gives True when the deadline moved.
 */
static __always_inline bool mlfq_update_deadline_raw(u64 vruntime, u64 *deadline, u64 vslice)
{
	if ((s64)(vruntime - *deadline) < 0)
		return false;
	*deadline = vruntime + vslice;
	if (!*deadline)
		*deadline = 1;
	return true;
}

/*
 * mlfq_avg_queued - Queued-only average from a queue snapshot.
 * @q: The queue.
 *
 * avg = zero + sum_w / sum_weight, with the left bias for eligibility.
 * Stale reads stay monotone, since zero only moves forward and the sums
 * are adjusted with it. An empty queue yields zero, the same idle value
 * the BPF average publishes.
 *
 * Gives The queued-only average.
 */
static __always_inline u64 mlfq_avg_queued(const struct queue_ctx *q)
{
	s64 runtime = q->sum_w_vruntime;
	s64 weight = q->sum_weight;
	u64 mag, div;
	bool neg;

	if (weight <= 0)
		return q->zero_vruntime;
	neg = runtime < 0;
	mag = neg ? (u64)(-runtime) : (u64)runtime;
	if (neg)
		mag += (u64)weight - 1;
	div = mag / (u64)weight;
	if (neg)
		return q->zero_vruntime - div;
	return q->zero_vruntime + div;
}

/*
 * mlfq_avg_for_place - Placement average, with the running task included.
 * @q: The queue.
 * @curr_vr: Vruntme of the running task on the target CPU, 0 when none.
 * @curr_w: Weight of that task, 0 when none.
 * @curr_valid: True when the running task belongs to @q.
 *
 * The queued sums exclude the running task, but fair.c places against
 * the average including it. The helper folds the running task in
 * without side effects; an empty queue with only the running task
 * yields its vruntime, and no running task yields the queued average.
 *
 * Gives The average vruntime to place against.
 */
static __always_inline u64 mlfq_avg_for_place(const struct queue_ctx *q,
					      u64 curr_vr, u32 curr_w,
					      bool curr_valid)
{
	s64 curr_key = 0;
	u64 w = 0;

	if (!curr_valid || !curr_w)
		return mlfq_avg_queued(q);
	curr_key = (s64)(curr_vr - q->zero_vruntime);
	if (curr_key > (s64)(1LL << 32))
		curr_key = (s64)(1LL << 32);
	if (curr_key < -(s64)(1LL << 32))
		curr_key = -(s64)(1LL << 32);
	w = mlfq_avg_weight(q, curr_w);
	return mlfq_avg_from_sums(q->sum_w_vruntime, q->sum_weight,
				  q->zero_vruntime, curr_key, w);
}

/*
 * mlfq_place_vruntime_raw - Placement vruntime from an average and lag.
 * @avg: Queue average vruntime.
 * @lag: Inflated signed lag.
 * @is_initial: True for the first ever enqueue.
 *
 * A new task joins at the average with zero lag. Any other task is
 * placed at average minus lag, which preserves positive lag as owed
 * service and negative lag as ahead credit within the clamp.
 *
 * Gives The vruntime to commit.
 */
static __always_inline u64 mlfq_place_vruntime_raw(u64 avg, s64 lag, bool is_initial)
{
	if (is_initial)
		return avg;
	return avg - (u64)lag;
}

/*
 * mlfq_place_entity_deadline_with_curr - Placement deadline with running task.
 * @q: The queue being placed into.
 * @tctx: The task being placed.
 * @curr_vr: Vruntme of the running task on the target CPU, 0 when none.
 * @curr_w: Weight of that task, 0 when none.
 * @curr_valid: True when the running task belongs to @q.
 *
 * The placement formula of mlfq_place_entity() without the commit, but
 * against the average including the running task, the fair.c placement
 * average. The lag is the signed clamp in [-limit, limit] inflated by
 * (W + w) / W, and the deadline is the placed vruntime plus one virtual
 * slice, halved for FIRST_RUN. A task with INITIAL joins at the average.
 * A relative deadline adds vruntime back instead of recomputing the
 * slice. The wakeup preemption decision uses this to compare deadlines
 * before any placement is committed.
 *
 * Gives The deadline the placement would commit.
 */
static __always_inline u64
mlfq_place_entity_deadline_with_curr(const struct queue_ctx *q,
				     const struct task_ctx *tctx,
				     u64 curr_vr, u32 curr_w,
				     bool curr_valid)
{
	u32 w = tctx->weight ? tctx->weight : 1;
	u64 limit = mlfq_lag_limit(q, w);
	u64 avg = mlfq_avg_for_place(q, curr_vr, curr_w, curr_valid);
	u64 w_scaled = mlfq_avg_weight(q, w);
	u64 vslice, vruntime_new, deadline;
	s64 lag;

	if (tctx->flags & MLFQ_TF_INITIAL) {
		vruntime_new = avg;
	} else {
		lag = mlfq_entity_lag_raw(avg, tctx->vruntime, limit);
		lag = mlfq_inflate_lag(lag, q->sum_weight, w_scaled);
		/* Reclamp after inflation, the average moved under us. */
		if (lag > (s64)limit)
			lag = (s64)limit;
		if (lag < -(s64)limit)
			lag = -(s64)limit;
		vruntime_new = mlfq_place_vruntime_raw(avg, lag, false);
	}

	if (tctx->flags & MLFQ_TF_REL_DEADLINE) {
		deadline = vruntime_new + tctx->deadline;
		if (!deadline)
			deadline = 1;
		return deadline;
	}

	vslice = calc_delta_fair_bpf(q->max_slice_ns, w);
	/* New tasks ease into competition with half a slice. */
	if (tctx->flags & MLFQ_TF_FIRST_RUN)
		vslice /= 2;

	deadline = vruntime_new + vslice;
	/*
	 * A deadline that lands exactly on the wrap point computes to zero,
	 * zero is the sentinel for a failed placement, so move the wrapped
	 * deadline to one, which is positionally identical in the wrapping
	 * order the DSQ rbtree uses.
	 */
	if (!deadline)
		deadline = 1;
	return deadline;
}

/*
 * mlfq_place_entity_deadline - Compute a placement deadline, read-only.
 * @q: The queue being placed into.
 * @tctx: The task being placed.
 *
 * The placement formula of mlfq_place_entity() without the commit. The
 * average comes from the queued sums, the lag is the signed clamp in
 * [-limit, limit] inflated by (W + w) / W, and the deadline is the
 * placed vruntime plus one virtual slice, halved for FIRST_RUN. A task
 * with INITIAL joins at the average. A relative deadline adds vruntime
 * back instead of recomputing the slice. The wakeup preemption decision
 * uses this to compare deadlines before any placement is committed.
 *
 * Gives The deadline the placement would commit.
 */
static __always_inline u64
mlfq_place_entity_deadline(const struct queue_ctx *q,
			   const struct task_ctx *tctx)
{
	return mlfq_place_entity_deadline_with_curr(q, tctx, 0, 0, false);
}

/*
 * mlfq_place_entity_with_curr - Place with the running task included.
 * @q: The queue being placed into.
 * @tctx: The task being placed.
 * @curr_vr: Vruntme of the running task on the target CPU, 0 when none.
 * @curr_w: Weight of that task, 0 when none.
 * @curr_valid: True when the running task belongs to @q.
 *
 * Same as mlfq_place_entity() but against the average including the
 * running task, the fair.c placement average. The caller passes the
 * target CPU's running task when its queue matches, otherwise no curr.
 *
 * Gives The placement deadline, also stored in tctx->deadline.
 */
static __always_inline u64 mlfq_place_entity_with_curr(struct queue_ctx *q,
						       struct task_ctx *tctx,
						       u64 curr_vr, u32 curr_w,
						       bool curr_valid)
{
	u32 w = tctx->weight ? tctx->weight : 1;
	u64 limit = mlfq_lag_limit(q, w);
	u64 avg = mlfq_avg_for_place(q, curr_vr, curr_w, curr_valid);
	u64 w_scaled = mlfq_avg_weight(q, w);
	u64 vslice, vruntime_new, deadline;
	s64 lag;

	if (tctx->flags & MLFQ_TF_INITIAL) {
		vruntime_new = avg;
		lag = 0;
	} else {
		lag = mlfq_entity_lag_raw(avg, tctx->vruntime, limit);
		lag = mlfq_inflate_lag(lag, q->sum_weight, w_scaled);
		/* Reclamp after inflation, the average moved under us. */
		if (lag > (s64)limit)
			lag = (s64)limit;
		if (lag < -(s64)limit)
			lag = -(s64)limit;
		vruntime_new = mlfq_place_vruntime_raw(avg, lag, false);
	}

	if (tctx->flags & MLFQ_TF_REL_DEADLINE) {
		deadline = vruntime_new + tctx->deadline;
		if (!deadline)
			deadline = 1;
	} else {
		vslice = calc_delta_fair_bpf(q->max_slice_ns, w);
		/* New tasks ease into competition with half a slice. */
		if (tctx->flags & MLFQ_TF_FIRST_RUN)
			vslice /= 2;
		deadline = vruntime_new + vslice;
		/*
		 * A deadline that lands exactly on the wrap point computes
		 * to zero, zero is the sentinel for a failed placement, so
		 * move the wrapped deadline to one, which is positionally
		 * identical in the wrapping order the DSQ rbtree uses.
		 */
		if (!deadline)
			deadline = 1;
	}

	tctx->vruntime = vruntime_new;
	tctx->vlag = lag;
	tctx->deadline = deadline;
	tctx->flags &= ~(MLFQ_TF_INITIAL | MLFQ_TF_REL_DEADLINE);

	return deadline;
}

/*
 * mlfq_place_entity - Place a task on the virtual-time timeline.
 * @q: The queue being placed into.
 * @tctx: The task being placed.
 *
 * EEVDF placement against the queue average is this.
 *
 *   avg          = zero + sum_w / sum_weight
 *   limit        = calc_delta_fair(max_slice + TICK, weight)
 *   lag          = clamp(avg - vruntime, -limit, limit)
 *   lag          = lag * (W + w) / W
 *   vruntime_new = avg - lag (or avg when INITIAL)
 *   vslice       = calc_delta_fair(slice_q, weight)
 *   if (FIRST_RUN) vslice /= 2
 *   if (REL_DEADLINE) deadline = vruntime_new + rel
 *   else deadline = vruntime_new + vslice
 *
 * A task behind the average keeps owed lag within one bound, a task
 * ahead keeps negative lag within one bound, and a new task joins at
 * zero lag. The inflation preserves lag across the join, the heavy
 * task zero update is done by the caller, and eligibility is tested at
 * dispatch, so min deadline selection over eligible tasks is EEVDF.
 *
 * Updates tctx->vruntime, tctx->vlag in [-limit, limit] and
 * tctx->deadline. Clears INITIAL and REL_DEADLINE on commit.
 *
 * Gives The placement deadline, also stored in tctx->deadline.
 */
/* Placement keeps lag within one bound. */
static __always_inline u64 mlfq_place_entity(struct queue_ctx *q,
					     struct task_ctx *tctx)
{
	return mlfq_place_entity_with_curr(q, tctx, 0, 0, false);
}

/*
 * mlfq_eevdf_weight - EEVDF weight mapping for classification output.
 * @weight: Cached scx weight.
 *
 * The classifier works in scx weight scale, while the virtual time math
 * needs a non-zero weight. The mapping clamps to [1, 10000] and guards
 * zero, so a corrupted cache never divides by zero. Classification is
 * otherwise unchanged.
 *
 * Gives The weight the virtual time math must use.
 */
static __always_inline u32 mlfq_eevdf_weight(u32 weight)
{
	if (!weight)
		return 1;
	if (weight > 10000)
		return 10000;
	return weight;
}

/*
 * mlfq_clamp_qid - Clamp a queue id to the valid range.
 * @qid The queue id to check.
 *
 * An out of range id would alias another queue. Clamp to queue 2,
 * the neutral queue.
 *
 * Gives The queue id when 1 to 3, 2 otherwise.
 */
static __always_inline u8 mlfq_clamp_qid(u32 qid)
{
	if (qid < 1U)
		return 2;
	if (qid > 3U)
		return 2;
	return (u8)qid;
}

/*
 * mlfq_sums_present - Whether the task holds a sums entry.
 * @tctx: The task.
 *
 * Gives True when the task joined the sums and has not left.
 */
static __always_inline bool mlfq_sums_present(const struct task_ctx *tctx)
{
	return (tctx->flags & MLFQ_TF_IN_SUMS) != 0;
}

/*
 * mlfq_sums_qid - Queue the task's sums entry belongs to.
 * @tctx: The task.
 *
 * Decodes bits 6-7 as qid - 1. The value 4 never stores (only 0..2
 * for qid 1..3) and marks a corrupted entry the caller must not use.
 *
 * Gives The stored queue id in 1..4, 4 when corrupted.
 */
static __always_inline u8 mlfq_sums_qid(const struct task_ctx *tctx)
{
	return (u8)(((tctx->flags >> MLFQ_SUM_QID_SHIFT) & 0x3U) + 1);
}

/*
 * mlfq_sums_set - Record a sums join.
 * @tctx: The task.
 * @qid: Queue joined, clamped to 1..3.
 *
 * Encodes qid - 1 in bits 6-7 and sets IN_SUMS. The task size is
 * unchanged.
 */
static __always_inline void mlfq_sums_set(struct task_ctx *tctx, u8 qid)
{
	u8 c = mlfq_clamp_qid(qid);

	tctx->flags = (u8)((tctx->flags & (u8)~(MLFQ_TF_IN_SUMS | MLFQ_SUM_QID_MASK)) |
			  MLFQ_TF_IN_SUMS | (((c - 1) & 0x3U) << MLFQ_SUM_QID_SHIFT));
}

/*
 * mlfq_sums_clear - Record a sums leave.
 * @tctx: The task.
 *
 * Clears IN_SUMS and keeps the queue bits for debugging. A second
 * leave stays a no-op through mlfq_sums_present().
 */
static __always_inline void mlfq_sums_clear(struct task_ctx *tctx)
{
	tctx->flags &= (u8)~MLFQ_TF_IN_SUMS;
}

/*
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
 *   must have a known deadline; an unknown wakeup deadline (failed
 *   placement) never preempts.
 *
 * The residency is measured from the resident's ops.running(); an
 * unknown or future run start cannot prove the guard window, so the
 * elapsed time falls back to zero (which is conservative only when the
 * guard is non-zero).
 *
 * Gives true when the resident owes the wakeup its CPU.
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

/*
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
 * so a CPU-bound task converges to budget_max. The rate is 1/tau_climb
 * with tau_climb = budget_max * FP_ONE / alpha. alpha is fixed.
 *
 * Gives The updated gauge.
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

/*
 * mlfq_ema_decay - Decay the EMA gauge for a sleep.
 * @ema: Current gauge value.
 * @sleep_ns: Physical sleep time in nsecs.
 * @half_life: Gauge half-life (MLFQ_EMA_HALF_LIFE_NS).
 *
 * Shift decay with a 2nd-order Taylor residual for the sub-period. Whole
 * half-lives shift the gauge right. The fractional period is
 * approximated by 2^-x ~= 1 - x*ln2 + (x*ln2)^2/2 in FP_ONE fixed point
 * (relative error < 10% for x in [0,1)). The gauge is zeroed at or beyond
 * 64 half-lives.
 *
 * Gives The updated gauge.
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

/*
 * mlfq_sys_lat_fold - Fold the accumulated wakeup waits into the gauge.
 * @lat_ema: The gauge, average wakeup latency in nsecs.
 * @wait_total: Sum of the episode waits since the last fold.
 * @wait_count: Number of episodes since the last fold.
 * @elapsed: Wall time since the last fold, in nsecs.
 * @half_life: Gauge half-life (MLFQ_SYS_GAUGE_HALF_LIFE_NS).
 * @max_ns: Gauge ceiling (MLFQ_SYS_LAT_MAX_NS).
 *
 * The gauge is a first-order low-pass filter over the per-window
 * average wakeup wait, the wait_sum and nr_wakeups pattern of fair.c.
 * Episodes accumulate their wait, the fold derives the average, and
 * the gauge moves toward the average by the decayed fraction of the
 * gap. The time constant is the wall-clock half-life, so the
 * equilibrium is the average wait regardless of the episode rate, and
 * a busy desktop and a quiet server with the same per-episode wait
 * settle on the same gauge value. A fold with no episodes leaves the
 * gauge untouched, and the result is capped at the ceiling. A clock
 * wrap that makes the elapsed compute to zero also leaves the gauge
 * untouched, and the caller still resets the totals, the same
 * convention as the rate fold.
 *
 * Overflow: wait_count is bounded by the episodes of one window (the
 * caller resets the totals at every fold) and wait_total by the
 * count times max_ns, both far inside u64.
 *
 * Gives The updated gauge.
 */
static __always_inline u64 mlfq_sys_lat_fold(u64 lat_ema, u64 wait_total,
					     u64 wait_count, u64 elapsed,
					     u64 half_life, u64 max_ns)
{
	u64 avg, factor, decayed, rise, v;

	if (wait_count == 0)
		return lat_ema;

	avg = wait_total / wait_count;
	if (avg > max_ns)
		avg = max_ns;
	factor = mlfq_ema_decay(FP_ONE, elapsed, half_life);
	decayed = mlfq_ema_decay(lat_ema, elapsed, half_life);
	rise = avg * (FP_ONE - factor) / FP_ONE;
	v = decayed + rise;
	return v > max_ns ? max_ns : v;
}

/*
 * mlfq_sys_rate_step - Fold the wakeup-rate EMA at an adaptation step.
 * @rate_ema: The rate gauge, FP_SHIFT fixed point.
 * @wakeup_cnt: Wakeup arrivals since the last fold.
 * @elapsed: Wall time since the last fold, in nsecs.
 *
 * The instantaneous rate is the arrival count over the elapsed window,
 * clamped to MLFQ_SYS_RATE_MAX, and the EMA folds it at the same 1 s
 * half-life as the latency gauge. The elapsed window is clamped to
 * [MLFQ_ADAPT_MIN_INTERVAL_NS, MLFQ_SYS_RATE_WINDOW_MAX_NS]. The compare-and-swap gate lets
 * the winner through only when at least a full interval has passed
 * since the last step, so a sub-second window is reachable only on the
 * u64 clock wrap path, where the elapsed computes to about zero. The
 * upper clamp covers a multi-minute idle gap (the boot or a long idle
 * stretch before the first step).
 *
 * Overflow: the count argument is a u32, so the rate product is at
 * most 2^32 * 1e9 ~= 4.3e18, inside u64. The fold sums the per-CPU
 * window slots in u64 and truncates to the u32 count, and a one-second
 * arrival total cannot reach 2^32 on any machine, so the truncation
 * cannot clip a measured rate. rate_i is clamped below 1e6, so the
 * fixed-point EMA operands are at most 1e6 << 8 ~= 2.6e8 and the
 * products at most ~6.6e10, far inside u64.
 *
 * Gives The updated gauge.
 */
static __always_inline u64 mlfq_sys_rate_step(u64 rate_ema, u32 wakeup_cnt,
					      u64 elapsed)
{
	u64 rate_i, rate_i_fp, factor;

	if (elapsed < MLFQ_ADAPT_MIN_INTERVAL_NS)
		elapsed = MLFQ_ADAPT_MIN_INTERVAL_NS;
	if (elapsed > MLFQ_SYS_RATE_WINDOW_MAX_NS)
		elapsed = MLFQ_SYS_RATE_WINDOW_MAX_NS;

	rate_i = (u64)wakeup_cnt * NSEC_PER_SEC / elapsed;
	if (rate_i > MLFQ_SYS_RATE_MAX)
		rate_i = MLFQ_SYS_RATE_MAX;
	rate_i_fp = rate_i << FP_SHIFT;

	/* The EMA fold: rate_ema * factor + rate_i * (1 - factor). */
	factor = mlfq_ema_decay(FP_ONE, elapsed, MLFQ_SYS_GAUGE_HALF_LIFE_NS);
	rate_ema = rate_ema * factor / FP_ONE +
		   rate_i_fp * (FP_ONE - factor) / FP_ONE;
	return rate_ema;
}

/*
 * mlfq_adapt_shift_target - Shift target from the latency and rate gauges.
 * @lat_ema: The wakeup-latency gauge, nsecs.
 * @rate_ema: The wakeup-rate gauge, FP_SHIFT fixed point.
 *
 * The proportional control law of the adaptation is this.
 *
 *   shift = clamp((lat - target) * K / target, 0, +MAX_SHIFT)
 *
 * with K = FP_ONE/2, so a full-range gauge error moves the target by
 * half the shift range. The shift only widens the bands, for the
 * reason given at the control-law constants: a machine at or below
 * the target latency keeps the base bands. The wakeup-rate storm gate
 * caps the positive target at +FP_ONE/4 when the rate gauge exceeds
 * MLFQ_ADAPT_RATE_GATE_HIGH: under a wakeup storm the bands must not
 * chase the latency error as far as in the normal regime.
 *
 * Overflow: the error is at most 15 ms and K is 128, so the product
 * is at most ~1.9e9, inside u64; the division brings the target well
 * below the clamp range before the clamp applies.
 *
 * Gives The slew target, FP_SHIFT fixed point, in
 * [0, +MLFQ_ADAPT_MAX_SHIFT].
 */
static __always_inline s64 mlfq_adapt_shift_target(u64 lat_ema, u64 rate_ema)
{
	s64 err = (s64)lat_ema - (s64)MLFQ_ADAPT_TARGET_LAT_NS;
	u64 mag, scaled;
	s64 target;

	/*
	 * BPF has no signed division, so the magnitude is scaled in u64.
	 * A gauge at or below the target widens nothing; the error is at
	 * most 15 ms and K is 128, so the product is ~1.9e9, inside u64.
	 */
	mag = err < 0 ? 0 : (u64)err;
	scaled = mag * MLFQ_ADAPT_K / MLFQ_ADAPT_TARGET_LAT_NS;
	target = (s64)scaled;

	if (target > (s64)MLFQ_ADAPT_MAX_SHIFT)
		target = (s64)MLFQ_ADAPT_MAX_SHIFT;
	if (rate_ema > MLFQ_ADAPT_RATE_GATE_HIGH &&
	    target > (s64)MLFQ_ADAPT_RATE_GATE_SHIFT)
		target = (s64)MLFQ_ADAPT_RATE_GATE_SHIFT;
	return target;
}

/*
 * mlfq_adapt_slew - Slew-limited shift update.
 * @prev: The current shift, FP_SHIFT fixed point.
 * @target: The gauge-derived shift target.
 *
 * The shift moves by at most MLFQ_ADAPT_MAX_STEP (10% of the base)
 * per step. Together with the gauge's 1 s half-life this is a cascaded
 * first-order limit. A single bad latency sample moves the bands at
 * most one step, and a full regime flip converges over at least five
 * steps. The difference is bounded by twice the shift range, so the
 * arithmetic cannot overflow.
 *
 * Gives The updated shift.
 */
static __always_inline s64 mlfq_adapt_slew(s64 prev, s64 target)
{
	s64 step = target - prev;

	if (step > (s64)MLFQ_ADAPT_MAX_STEP)
		step = (s64)MLFQ_ADAPT_MAX_STEP;
	if (step < -(s64)MLFQ_ADAPT_MAX_STEP)
		step = -(s64)MLFQ_ADAPT_MAX_STEP;
	return prev + step;
}

/*
 * mlfq_adapt_band - Effective band edge from the base and the shift.
 * @base: The base (rodata) band edge, nsecs.
 * @shift_fp: The current shift, FP_SHIFT fixed point.
 * @floor: The band's hard floor, nsecs.
 * @ceil: The band's hard ceiling, nsecs.
 *
 * effective = clamp(base + base * shift / FP_ONE, floor, ceil). The
 * clamps apply to the result, not the input, so a shift at either
 * extreme can never push a band past its hard bound. With shift 0 the
 * effective value is exactly the base, which is what keeps the
 * disabled state (init copies the bases) identical to the fixed
 * thresholds.
 *
 * Overflow: the largest base is below 6 ms and the shift range is
 * +-128, so the product is at most ~7.7e8, inside s64.
 *
 * Gives The effective band edge, clamped to [@floor, @ceil].
 */
static __always_inline u64 mlfq_adapt_band(u64 base, s64 shift_fp,
					   u64 floor, u64 ceil)
{
	s64 v = (s64)base;
	u64 mag, scaled;

	/*
	 * BPF has no signed division, so the delta is scaled in u64
	 * (the shift magnitude) and subtracted or added by sign. The
	 * largest base is below 6 ms and the shift range is +-128, so
	 * the product is at most ~7.7e8, inside s64.
	 */
	mag = shift_fp < 0 ? (u64)(-shift_fp) : (u64)shift_fp;
	scaled = base * mag / FP_ONE;
	if (shift_fp < 0)
		v -= (s64)scaled;
	else
		v += (s64)scaled;

	if (v < (s64)floor)
		v = (s64)floor;
	if (v > (s64)ceil)
		v = (s64)ceil;
	return (u64)v;
}

/*
 * mlfq_queue_from_ema - Base queue mapping from the EMA gauge.
 * @ema: The gauge value.
 * @t_l: Interactive threshold (MLFQ_T_L_NS).
 * @t_h: CPU-bound threshold (MLFQ_T_H_NS).
 *
 * The base mapping is ema <= T_L -> Q1, ema >= T_H -> Q3, else Q2.
 *
 * Gives 1, 2 or 3.
 */
static __always_inline u8 mlfq_queue_from_ema(u64 ema, u64 t_l, u64 t_h)
{
	if (ema <= t_l)
		return 1;
	if (ema >= t_h)
		return 3;
	return 2;
}

/*
 * mlfq_promote_on_wakeup - Wakeup promotion state machine.
 * @tctx: The task.
 * @sleep_ns: Sleep duration at wakeup.
 * @t_l: Interactive threshold.
 * @t_h: CPU-bound threshold.
 * @short_sleep: A sleep at most this long counts toward wake_cnt.
 *
 * The hysteresis promotes Q2->Q1 when ema < T_L/2 and wake_cnt >= 2
 * consecutive short sleeps, and Q3->Q2 when ema < T_H/2 and wake_cnt >= 2.
 * wake_cnt is reset on a long sleep. reenq_cnt is left for the caller to
 * clear on the wakeup path.
 *
 * Gives true if the task was promoted.
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

/*
 * mlfq_demote_on_reenq - Slice-exhaustion demotion state machine.
 * @tctx: The task.
 * @t_h: CPU-bound threshold (the effective EMA Q2/Q3 edge).
 * @t_bound: Q2/Q3 tree band bound (the effective tree edge).
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
 * Demotion requires a sustained run without sleeping. Eight consecutive
 * exhaustions (about 8 ms at the interactive slice) must accumulate
 * while the task is CPU-bound. A task that sleeps between bursts is
 * re-boosted at its wakeup, which resets reenq_cnt, so a bursty
 * consumer of CPU such as a video decoder keeps its queue for the whole
 * burst. An impostor that never sleeps accumulates the counter and is
 * demoted after the same sustained window.
 *
 * Gives true if the task was demoted.
 */
static __always_inline bool mlfq_demote_on_reenq(struct task_ctx *tctx,
						 u64 t_h, u64 t_bound,
						 u64 pred)
{
	bool demoted = false;
	bool cpu_bound;

	tctx->reenq_cnt++;

	cpu_bound = pred ? pred >= t_bound : tctx->ema > t_h;

	if ((tctx->queue == 1 || tctx->queue == 2) &&
	    cpu_bound && tctx->reenq_cnt >= 8) {
		tctx->queue++;
		demoted = true;
	}

	if (demoted)
		tctx->reenq_cnt = 0;
	return demoted;
}

/*
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
 * Rule predicates. Compiled only under MLFQ_CHECK; the
 * BPF side reports violations via scx_bpf_error() at the base points.
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

static __always_inline bool mlfq_check_queued_vlag(s64 vlag, u64 limit)
{
	s64 bound = (s64)limit;

	return vlag >= -bound && vlag <= bound;
}

static __always_inline bool mlfq_check_tree_node_index(u32 idx)
{
	return idx < MLFQ_TREE_MAX_NODES;
}

static __always_inline bool mlfq_check_tree_feature(u8 feature)
{
	/*
	 * Fact. the split feature must be within the populated ABI.
	 * Steps. 1.3.11 ABI populates nine split features (0..8:
	 * prev_burst, sleep, ema, io_wait, wake_cnt, wake_lat,
	 * queue_wait, sq_ema, gpu_submit). The fitter caps splits to
	 * [0, MLFQ_TREE_NR_FEATURES), and sleep_var_ratio at id 9 is
	 * carry-along for the next ABI (zeroed until promoted; BPF walk
	 * feat[16] holds it at 9 with 10..15 zeroed, &0xF keeps 0..15
	 * in bounds). The bound check is unconditional, so feature 9..15
	 * never indexes OOB even with MLFQ_CHECK=0, and serialize_validate
	 * is extra check.
	 * Bound. plain < bound is authoritative, not masked tautology.
	 *
	 * path helper: the walk observes the feature vector
	 * (path pattern without indirect) via this predicate.
	 */
	return feature < MLFQ_TREE_NR_FEATURES;
}

static __always_inline bool mlfq_check_bands(u64 t_l, u64 t_h,
					     u64 t_int, u64 t_bnd)
{
	/*
	 * The effective band edges must keep the queue semantics of the
	 * fixed thresholds: each band sits within its hard floor/ceiling
	 * and the two edges of each pair stay strictly ordered (T_L <
	 * T_H, T_INT < T_BOUND), so no band can collapse to zero width.
	 */
	return t_l < t_h && t_int < t_bnd &&
	       t_l >= MLFQ_ADAPT_T_L_FLOOR_NS && t_l <= MLFQ_ADAPT_T_L_CEIL_NS &&
	       t_h >= MLFQ_ADAPT_T_H_FLOOR_NS && t_h <= MLFQ_ADAPT_T_H_CEIL_NS &&
	       t_int >= MLFQ_ADAPT_T_INT_FLOOR_NS && t_int <= MLFQ_ADAPT_T_INT_CEIL_NS &&
	       t_bnd >= MLFQ_ADAPT_T_BND_FLOOR_NS && t_bnd <= MLFQ_ADAPT_T_BND_CEIL_NS;
}
#endif /* MLFQ_CHECK */

/*
 * mlfq_tree_walk - Walk a tree buffer and predict the next CPU burst.
 * @store: The tree buffer (one entry of mlfq_tree_map).
 * @f: The feature vector.
 *
 * Fact. the walk is a bounded, masked descent over the 9-feature
 * tree (prev_burst, sleep, ema, io_wait, wake_cnt, wake_lat,
 * queue_wait, sq_ema, gpu_submit). Rule. depth <= MLFQ_TREE_MAX_DEPTH.
 *
 * Steps. every index is masked to the node budget
 * (MLFQ_TREE_MAX_NODES - 1), so a corrupted tree can never address
 * outside the buffer. feat[16] holds nine split features 0..8 plus
 * sleep_var_ratio carry-along at 9 and 10..15 zeroed; Rust mirrors
 * feat[16]. An out-of-range feature (>=9) is rejected unconditionally
 * before dereference, so serialize_validate is extra check and
 * MLFQ_CHECK=0 cannot compile out the bound. Walk past tail lands on
 * zeroed node predicting 0. The walk is the path observed via the
 * feature vector (reader) without a indirect.
 *
 * Bound. the 30 s watchdog bounds the dispatch stall, and the
 * 16 ms label clamp bounds the f64 sums; the unconditional feat bound
 * prevents OOB reads even when MLFQ_CHECK=0.
 *
 * Gives The predicted burst in nsecs.
 */
static __always_inline u64
mlfq_tree_walk(const struct mlfq_tree_store *store,
	       const struct mlfq_tree_feats *f)
{
	u64 feat[16] = { f->prev_burst_ns, f->sleep_ns, f->ema,
			f->io_wait, f->wake_cnt, f->wake_lat_us,
			f->queue_wait_us, f->sq_ema, f->gpu_submit,
			f->sleep_var_ratio, 0, 0, 0, 0, 0, 0 };
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

		/* BPF walk feat[16] with &0xF (0..15); 9 is sleep_var_ratio
		 * carry-along, 10..15 zeroed. Bound check is unconditional.
		 */
		feature = n->feature & 0xF;
		if (feature >= MLFQ_TREE_NR_FEATURES)
			return 0;
#if MLFQ_CHECK
		if (!mlfq_check_tree_feature(feature))
			return 0;
#endif
		idx = feat[feature] <= n->threshold ? n->left : n->right;
	}

	/*
	 * When the depth is exhausted, the last reachable node is returned as a leaf
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

/*
 * mlfq_tree_map_queue - Promotion-only queue mapping of a prediction.
 * @pred: The predicted next burst, 0 while untrained.
 * @cur: The task's current queue (1..3).
 * @t_int: The tree Q1/Q2 band edge (the effective value).
 * @t_bound: The tree Q2/Q3 band edge (the effective value).
 *
 * The wakeup path is promotion-only: a Q1-band prediction raises the
 * queue to 1, a Q2-band prediction raises a Q3 task to 2, and a
 * Q3-band or untrained prediction leaves the queue unchanged. Demotions
 * are the run-out gate's job (mlfq_demote_on_reenq), so a single wakeup
 * prediction can never demote a task and bypass the exhaustion
 * hysteresis, the plain MLFQ gap where the wakeup only
 * promotes and the run-out only demotes.
 *
 * Gives The new queue.
 */
static __always_inline u8 mlfq_tree_map_queue(u64 pred, u8 cur,
					      u64 t_int, u64 t_bound)
{
	/* 0 is the untrained sentinel: it never moves the queue. */
	if (pred && pred < t_int)
		return 1;
	if (pred && pred < t_bound && cur > 2)
		return 2;
	return cur;
}

#ifdef __VMLINUX_H__
/*
 * The published tree as a two-entry array map, defined in main.bpf.c.
 * The type and the extern are declared here so the BPF wrapper can look
 * up the active entry. Both are skipped outside the BPF build, where
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
 * slot, so the wakeup path needs no locked operation on a shared line,
 * and the fold (mlfq_adapt_step) iterates the slots with
 * bpf_map_lookup_percpu_elem.
 */
struct mlfq_wakeup_stats_map {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mlfq_wakeup_counters);
};

extern struct mlfq_wakeup_stats_map mlfq_wakeup_stats;

/*
 * mlfq_op_lat_bucket - Histogram bucket covering an elapsed time.
 * @delta_us: Elapsed microseconds.
 *
 * The eight buckets delimit [0, 2) [2, 5) [5, 10) [10, 20) [20, 50)
 * [50, 100) [100, 250) [250, inf) microseconds.
 *
 * Gives The bucket index in [0, MLFQ_OP_LAT_BUCKETS).
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

/*
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

/*
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
 * Gives The predicted burst in nsecs. 0 while untrained or on a
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

/*
 * The per-LLC and per-queue runnable gauges, defined in the main.bpf.c
 * bss block before mlfq_stats. The externs are declared here, outside
 * the BPF-only guard above, so the accounting helpers below can
 * reference them in every build. The BPF build links them against the
 * bss block, and the native harness supplies its own shadow storage.
 * The queue gauges are three separate counters, one per queue, so the
 * update path needs no array index and no range proof.
 */
extern volatile u32 mlfq_llc_runnable[MLFQ_MAX_LLCS];
extern volatile u32 mlfq_queue_runnable_q1;
extern volatile u32 mlfq_queue_runnable_q2;
extern volatile u32 mlfq_queue_runnable_q3;

/*
 * mlfq_llc_add - One atomic step on the per-LLC runnable gauge.
 * @llc The LLC domain id.
 * @delta Plus one to count, minus one to uncount.
 *
 * The index is checked against the hard array bound. An out of range
 * id is a no-op.
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

/*
 * mlfq_queue_add - One atomic step on the per-queue runnable gauge.
 * @qid The queue id, 1 to 3.
 * @delta Plus one to count, minus one to uncount.
 *
 * Each queue has its own counter, so the update is a plain branch
 * with no array index. The signed step adds modulo 2^32, so minus
 * one wraps the same as a subtract. An out of range id is a no-op.
 */
static __always_inline void mlfq_queue_add(u32 qid, s64 delta)
{
	u32 step = (u32)delta;

	if (qid == 1)
		__sync_fetch_and_add(&mlfq_queue_runnable_q1, step);
	else if (qid == 2)
		__sync_fetch_and_add(&mlfq_queue_runnable_q2, step);
	else if (qid == 3)
		__sync_fetch_and_add(&mlfq_queue_runnable_q3, step);
}

/*
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
	qid = mlfq_clamp_qid(qid);

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

/*
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

/*
 * mlfq_steer_pick_llc - Least-loaded eligible LLC selection.
 * @runnable: Per-LLC runnable gauge (advisory, stale-tolerant).
 * @idle: Per-LLC idle-CPU gate. A zero entry excludes the domain.
 * @nr_llcs: Number of populated LLC domains; domains at or above it are
 *	excluded (extra check on top of the idle gate, which already
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
 * Gives The chosen domain id, or MLFQ_MAX_LLCS when no domain is
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
