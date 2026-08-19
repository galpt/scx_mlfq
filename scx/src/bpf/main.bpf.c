/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multilevel Feedback Queue scheduling with per-queue EEVDF virtual time.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 */

/*
 * This file defines the BPF maps, volatiles, and ops dispatch table.
 * The scheduling logic is organized into separate modules included below
 * in dependency order.
 *   vtime.bpf.c      - EEVDF virtual-time substrate (virtual clock, placement)
 *   classify.bpf.c   - wakeup promotion and run-out demotion classification
 *   lifecycle.bpf.c  - task state, init_task/enable/running/stopping/exit_task
 *   rtdl.bpf.c       - realtime/DL takeover tracking, cpu_release/cpu_acquire, evacuation
 *   select_cpu.bpf.c - CPU selection
 *   enqueue.bpf.c    - enqueue routing, aging, wakeup preemption
 *   dispatch.bpf.c   - queue service with quotas, cross-CPU stealing, keep path
 */

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/user_exit_info.bpf.h>
#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * Per-task state, allocated in init_task()/enable() and freed in
 * exit_task() (BPF task storage is reclaimed on task exit regardless).
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Per-queue virtual-clock state, keyed by queue id 1..3 (slot 0 unused).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_NR_QUEUES + 1);
	__type(key, u32);
	__type(value, struct queue_ctx);
} queue_ctx_stor SEC(".maps");

/*
 * Per-CPU state, keyed by cpu id. Bounds are validated against
 * nr_cpu_ids (<= MLFQ_MAX_CPUS, checked in init()).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_MAX_CPUS);
	__type(key, u32);
	__type(value, struct mlfq_cpu_state);
} cpu_state_stor SEC(".maps");

/*
 * Per-CPU realtime-occupancy state, keyed by cpu id. The flags reflect
 * whether a realtime task currently holds the CPU (see rtdl.bpf.c). The
 * state is written by ops.cpu_release()/cpu_acquire() and read by the
 * enqueue redirect and the CPU selection.
 */
struct mlfq_rtdl_state_map rtdl_state_stor SEC(".maps");

/*
 * Op-latency histogram, keyed by op id (MLFQ_OP_LAT_* in intf.h). A
 * per-CPU array so the counters never contend, and each slot samples only
 * every MLFQ_OP_LAT_SAMPLE_N-th op so the wall-time read and bucket
 * store are not on the hot path. The Rust front-end sums the CPUs for the
 * stats output.
 */
struct mlfq_op_lat_map mlfq_op_lat SEC(".maps");

/*
 * Per-CPU wakeup-arrival counters (see mlfq_wakeup_stats_map in
 * intf.h). Each CPU owns its own slot, so the wakeup path bumps its
 * slot with no locked operation on a shared line and the u64 totals
 * cannot wrap. The Rust front-end sums the slots for the stats output.
 */
struct mlfq_wakeup_stats_map mlfq_wakeup_stats SEC(".maps");

/*
 * Scheduler-wide state in .bss. The stats counters are shared across
 * CPUs and updated with atomic RMWs. Volatile stops the compiler from
 * caching a value in a register across the atomic operations.
 * nr_cpu_ids is written once in init() before any other callback runs.
 */
volatile u64 nr_cpu_ids;
volatile u32 mlfq_steal_scan;
volatile u32 mlfq_idle_count;

/*
 * Per-LLC and per-queue runnable gauges, maintained by
 * mlfq_runnable_enter()/mlfq_runnable_exit() at every tracked insert
 * and leave-runnable event. mlfq_llc_runnable[llc] is the number of
 * tracked runnable tasks owned by each LLC domain, and
 * mlfq_queue_runnable is the same count split per queue (index 0
 * unused, 1..3 = Q1..Q3). mlfq_llc_idle[llc] mirrors mlfq_idle_count
 * per domain, the steering gate of the least-loaded-LLC placement
 * step. The counts are advisory. They cover tracked tasks only (the
 * drop paths never touch them) and drive placement heuristics, never
 * correctness. The gauges are zero-default, so the unpopulated state
 * (LLC awareness disabled) leaves them untouched by construction.
 */
volatile u32 mlfq_llc_runnable[MLFQ_MAX_LLCS];
volatile u32 mlfq_queue_runnable[MLFQ_NR_QUEUES + 1];
volatile u32 mlfq_llc_idle[MLFQ_MAX_LLCS];

/*
 * Scheduler counters, one slot per CPU. Each CPU bumps its own slot, so
 * the hot paths never contend on a shared cache line. The Rust front-end
 * sums the per-CPU slots for the stats output.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mlfq_stats);
} mlfq_stats SEC(".maps");

/*
 * Bump one mlfq_stats field on the calling CPU's slot. The lookup on a
 * PERCPU_ARRAY map returns the current CPU's value, so the increment is
 * a plain non-atomic store on a private cache line.
 */
#define mlfq_stat_add(field, delta)					\
	do {								\
		u32 __key = 0;						\
		struct mlfq_stats *__s =					\
			bpf_map_lookup_elem(&mlfq_stats, &__key);	\
		if (__s)						\
			__s->field += (delta);				\
	} while (0)

/*
 * The calling CPU's mlfq_stats slot, or NULL on a failed lookup. Used
 * where a counter needs a read-modify-write (the on_cpu clamp) rather
 * than a plain bump.
 */
static __always_inline struct mlfq_stats *mlfq_stats_slot(void)
{
	u32 key = 0;

	return bpf_map_lookup_elem(&mlfq_stats, &key);
}

/*
 * Placement bitmaps (see select_cpu.bpf.c).
 *
 * mlfq_primary_bitmap[0] holds the primary (big-core) CPU set.
 * mlfq_llc_bitmaps[llc_id] holds the CPU membership of one LLC domain.
 * Both are plain u64 bitmaps in ARRAY map values. The Rust front-end
 * writes them after load, and the CPU-selection path reads them directly
 * as map values, without any kernel cpumask kptr machinery or RCU
 * protection.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct mlfq_bitmap);
} mlfq_primary_bitmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_MAX_LLCS);
	__type(key, u32);
	__type(value, struct mlfq_bitmap);
} mlfq_llc_bitmaps SEC(".maps");

/*
 * Per-LLC CPU lists (see intf.h). mlfq_llc_cpus[llc_id] holds the CPUs
 * of one LLC domain, the Tier-A same-LLC steal window of the dispatch
 * path. The Rust front-end writes the values after load, and the
 * dispatch path reads them directly as map values. An
 * unpopulated map entry (write failed or LLC awareness disabled) reads
 * as nr == 0, which skips the Tier-A scan and keeps today's behavior.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_MAX_LLCS);
	__type(key, u32);
	__type(value, struct mlfq_llc_cpu_list);
} mlfq_llc_cpus SEC(".maps");

/*
 * Constants land in rodata. The declared defaults match the constants in
 * intf.h and are written by the Rust front-end before load. The section
 * is read-only afterwards, and the compiler must not fold them as
 * compile-time constants. The veristat configs supply the same values
 * as verification inputs.
 */
const volatile u64 mlfq_q1_slice_ns = MLFQ_Q1_SLICE_NS;
const volatile u64 mlfq_q2_slice_ns = MLFQ_Q2_SLICE_NS;
const volatile u64 mlfq_q3_slice_ns = MLFQ_Q3_SLICE_NS;
const volatile u64 mlfq_budget_max_ns = MLFQ_BUDGET_MAX_NS;
const volatile u64 mlfq_alpha = MLFQ_ALPHA;
const volatile u64 mlfq_ema_half_life_ns = MLFQ_EMA_HALF_LIFE_NS;
const volatile u64 mlfq_t_l_ns = MLFQ_T_L_NS;
const volatile u64 mlfq_t_h_ns = MLFQ_T_H_NS;
const volatile u64 mlfq_long_sleep_ns = MLFQ_LONG_SLEEP_NS;
const volatile u64 mlfq_aging_period_ns = MLFQ_AGING_PERIOD_NS;
const volatile u64 mlfq_short_sleep_ns = MLFQ_SHORT_SLEEP_NS;
const volatile u64 mlfq_short_sleep_rate_limit_ns = MLFQ_SHORT_SLEEP_RATE_LIMIT_NS;
const volatile u64 mlfq_hysteresis_sleep_ns = MLFQ_HYSTERESIS_SLEEP_NS;
const volatile u64 mlfq_sameq_preempt_min_run_ns = MLFQ_SAMEQ_PREEMPT_MIN_RUN_NS;
const volatile u64 mlfq_preempt_slice_ns = MLFQ_PREEMPT_SLICE_NS;
const volatile u32 mlfq_q1_quota = MLFQ_Q1_QUOTA;
const volatile u32 mlfq_q2_quota = MLFQ_Q2_QUOTA;
const volatile u32 mlfq_dispatch_max_batch = MLFQ_DISPATCH_MAX_BATCH;
const volatile u64 mlfq_rtdl_drain_interval_ns = MLFQ_RTDL_DRAIN_INTERVAL_NS;

/*
 * True when every CPU has the same capacity (uniform-capacity system). The
 * CPU-selection fast path skips all hybrid logic in that case. Written by
 * the Rust front-end from the discovered topology.
 */
const volatile bool mlfq_primary_all = true;

/*
 * Cache-domain data written by the Rust front-end before load. mlfq_nr_llcs
 * is the number of LLC domains with usable masks (0 disables the LLC step
 * entirely). mlfq_llc_has_primary marks LLCs that contain at least one
 * primary (big) core. mlfq_cpu_llc maps a CPU to its LLC domain
 * (MLFQ_MAX_LLCS, the sentinel, when the CPU is unknown or unmapped).
 */
const volatile u32 mlfq_nr_llcs;
const volatile u8 mlfq_llc_has_primary[MLFQ_MAX_LLCS];
const volatile u32 mlfq_cpu_llc[MLFQ_MAX_CPUS];

/*
 * Gates the saturation fast path in select_cpu() on the idle-CPU count
 * maintained by ops.update_idle(). Written by the Rust front-end before
 * load. It is 1 only when the kernel keeps its built-in idle tracking alongside
 * the callback (the KEEP_BUILTIN_IDLE flag). It is 0 on kernels without it, so
 * the lean path is dead and the behavior is unchanged.
 */
const volatile u32 mlfq_idle_tracking = 0;

/*
 * SMT sibling preference table, written by the Rust front-end
 * before load. mlfq_cpu_sibling[cpu] is the lowest-id other CPU sharing
 * cpu's physical core, or the CPU itself when the core is unpaired.
 * mlfq_smt_on is true only when at least one sibling differs from its
 * CPU, and it gates the sibling step. With SMT off or the table
 * unwritten (all-zero rodata can never fire it, and the write is
 * atomic pre-load) the step is dead and placement is unchanged.
 */
const volatile bool mlfq_smt_on = false;
const volatile u32 mlfq_cpu_sibling[MLFQ_MAX_CPUS];

/*
 * Largest-LLC domain id for the Q1 placement bias, written by the
 * Rust front-end before load. The sentinel MLFQ_MAX_LLCS means "no
 * bias. Discovery failed, the machine has fewer than two LLC domains,
 * or two domains tie for the largest cache size. The bias is Q1-only
 * and non-exclusive, trading clock speed for cache capacity. The
 * sentinel keeps the step dead unless a strictly-largest domain exists.
 */
const volatile u32 mlfq_llc_largest = MLFQ_MAX_LLCS;

static struct task_ctx *mlfq_lookup_task_ctx(const struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0, 0);
}

static struct task_ctx *mlfq_alloc_task_ctx(struct task_struct *p)
{
	return bpf_task_storage_get(&task_ctx_stor, (struct task_struct *)p, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

static __always_inline struct mlfq_cpu_state *mlfq_lookup_cpu_state(s32 cpu)
{
	u32 key;

	if (cpu < 0)
		return NULL;
	key = (u32)cpu;
	return bpf_map_lookup_elem(&cpu_state_stor, &key);
}

/*
 * mlfq_llc_of_cpu - LLC domain of a CPU, validated against the populated set.
 * @cpu: CPU id.
 *
 * Returns the rodata cpu->llc mapping when @cpu is in range and the
 * value is a populated domain id, MLFQ_MAX_LLCS (the hard bound of the
 * runnable gauges) otherwise. The sentinel turns every accounting
 * helper call into a no-op, so with LLC awareness disabled
 * (mlfq_nr_llcs == 0) every call yields it and the gauges never move.
 * The unpopulated state reproduces current behavior by construction.
 * The hard bound is checked as well as the populated count. An unmapped
 * CPU reads the MLFQ_MAX_LLCS sentinel from the front-end's default,
 * and a front-end bug writing mlfq_nr_llcs above MLFQ_MAX_LLCS must
 * not validate the sentinel (or a larger id) into a domain index.
 */
static __always_inline u32 mlfq_llc_of_cpu(u32 cpu)
{
	u32 llc;

	if (cpu >= MLFQ_MAX_CPUS)
		return MLFQ_MAX_LLCS;
	llc = mlfq_cpu_llc[cpu];
	return llc < MLFQ_MAX_LLCS && llc < mlfq_nr_llcs ? llc : MLFQ_MAX_LLCS;
}

#include "vtime.bpf.c"
#include "classify.bpf.c"
#include "lifecycle.bpf.c"
#include "rtdl.bpf.c"
#include "select_cpu.bpf.c"
#include "enqueue.bpf.c"
#include "dispatch.bpf.c"

s32 BPF_STRUCT_OPS_SLEEPABLE(mlfq_init)
{
	struct queue_ctx *q;
	u32 key, qid, nr_cpus;
	s32 cpu;
	s32 ret;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	if (nr_cpu_ids > MLFQ_MAX_CPUS) {
		scx_bpf_error("nr_cpu_ids (%llu) exceeds max supported (%llu)",
			      nr_cpu_ids, (u64)MLFQ_MAX_CPUS);
		return -E2BIG;
	}

	/*
	 * Snapshot the CPU count once. The DSQ creation loop and the
	 * id-space invariant below are keyed on it.
	 */
	nr_cpus = (u32)nr_cpu_ids;
	if (nr_cpus == 0) {
		scx_bpf_error("no possible CPUs");
		return -EINVAL;
	}

	/*
	 * Clamp the Q2/Q3 steal-scan window to the CPU count. On a machine
	 * with fewer CPUs than the cap, an unscaled window would re-peek
	 * the same remote DSQs multiple times per slot.
	 */
	mlfq_steal_scan = nr_cpus < MLFQ_STEAL_SCAN_MAX ?
			  nr_cpus : (u32)MLFQ_STEAL_SCAN_MAX;

	/*
	 * Create the per-CPU vtime-ordered queue DSQs. bpf_for() is an
	 * iterator-backed loop. The bound is a runtime value (the checked
	 * CPU count) and the iterator contract lets the verifier bound the
	 * iteration without unrolling it.
	 */
	bpf_for(cpu, 0, nr_cpus) {
		for (qid = 1; qid <= MLFQ_NR_QUEUES; qid++) {
			ret = scx_bpf_create_dsq(mlfq_dsq_id(qid, cpu), -1);
			if (ret < 0 && ret != -EEXIST) {
				scx_bpf_error("failed to create q%u cpu%d DSQ: %d",
					      qid, cpu, ret);
				return ret;
			}
		}
	}

	/*
	 * The dispatch batch is served as q1 + q2 + q3, with the Q3 share
	 * computed as the unsigned remainder of dispatch_max_batch (see
	 * dispatch.bpf.c). Quotas that cover the whole batch would wrap
	 * that remainder and unbind the Q3 service loop, so the
	 * configuration is rejected outright.
	 */
	if (mlfq_q1_quota + mlfq_q2_quota >= mlfq_dispatch_max_batch) {
		scx_bpf_error("Q1+Q2 quotas (%u+%u) must leave a Q3 share of "
			      "max batch %u",
			      mlfq_q1_quota, mlfq_q2_quota,
			      mlfq_dispatch_max_batch);
		return -EINVAL;
	}

	/*
	 * The classification thresholds must keep the queue semantics of
	 * the fixed bands. T_L must be strictly below T_H, and T_H
	 * strictly below the gauge ceiling, so the CPU-bound edge is
	 * reachable and the gauge can never saturate past it. A
	 * configuration that violates the order is rejected outright.
	 */
	if (mlfq_t_l_ns >= mlfq_t_h_ns || mlfq_t_h_ns >= mlfq_budget_max_ns) {
		scx_bpf_error("thresholds out of order: T_L=%llu T_H=%llu "
			      "B_MAX=%llu",
			      mlfq_t_l_ns, mlfq_t_h_ns, mlfq_budget_max_ns);
		return -EINVAL;
	}

	/*
	 * The queue DSQ id space must stay below the top bits the kernel
	 * reserves for the SCX_DSQ_LOCAL / SCX_DSQ_LOCAL_ON flags, so the
	 * mlfq_dsq_id() arithmetic never collides with the local DSQ
	 * range. With the per-CPU layout the highest id is owned by the
	 * last queue on the last CPU.
	 */
	if (mlfq_dsq_id(MLFQ_NR_QUEUES, (s32)(nr_cpus - 1)) >= SCX_DSQ_LOCAL_ON) {
		scx_bpf_error("queue DSQ id space overflows SCX_DSQ_LOCAL_ON");
		return -EINVAL;
	}

	/*
	 * Initialize the per-queue request slices. The queue state is
	 * bss-zeroed by default, which is the empty state, so the slice
	 * loop only writes the slice.
	 */
	for (key = 1; key <= MLFQ_NR_QUEUES; key++) {
		q = mlfq_lookup_queue(key);
		if (!q) {
			scx_bpf_error("queue %u map lookup failed", key);
			return -EINVAL;
		}
		q->max_slice_ns = mlfq_queue_slice(key);
	}

	return 0;
}

void BPF_STRUCT_OPS(mlfq_exit, struct scx_exit_info *info)
{
	UEI_RECORD(uei, info);
}

SCX_OPS_DEFINE(mlfq_ops,
	       .select_cpu		= (void *)mlfq_select_cpu,
	       .enqueue			= (void *)mlfq_enqueue,
	       .dispatch		= (void *)mlfq_dispatch,
	       .cpu_release		= (void *)mlfq_cpu_release,
	       .cpu_acquire		= (void *)mlfq_cpu_acquire,
	       .running			= (void *)mlfq_running,
	       .stopping		= (void *)mlfq_stopping,
	       /*
		* The runnable-accounting exit signal. The kernel
		* invokes ops.quiescent on every dequeue_task_scx()
		* regardless of the task's ops_state, gated only on
		* !task_on_rq_migrating (structurally unreachable for
		* sched-ext tasks), so it fires exactly once per
		* leave-runnable event. ops.dequeue is deliberately NOT
		* used. It fires only while ops_state is QUEUED, which the
		* dispatch moves leave set for same-rq moves and clear for
		* remote transfers, so it is not a complete signal on its
		* own. The callback releases the task's LLC/queue gauge
		* ownership.
		*/
	       .quiescent		= (void *)mlfq_quiescent,
	       .update_idle		= (void *)mlfq_update_idle,
	       .enable			= (void *)mlfq_enable,
	       .init			= (void *)mlfq_init,
	       .exit			= (void *)mlfq_exit,
	       .init_task		= (void *)mlfq_init_task,
	       .exit_task		= (void *)mlfq_exit_task,
	       .dispatch_max_batch	= MLFQ_DISPATCH_MAX_BATCH,
	       /*
		* The kernel's own default watchdog timeout. A shorter one
		* would trip on machines where real-time tasks saturate the
		* CPUs. The RT class is not throttled below its budget, so
		* the watchdog work can be starved for the whole burst, and
		* the scheduler would exit even though nothing in its own
		* queues stalled. The watchdog still fires on a genuinely
		* stalled queue within the kernel's maximum detection
		* latency.
		*/
	       .timeout_ms		= MLFQ_OPS_TIMEOUT_MS,
	       .name			= "mlfq");
