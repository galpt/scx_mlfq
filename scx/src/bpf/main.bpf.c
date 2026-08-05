/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Multilevel Feedback Queue scheduling with per-queue EEVDF virtual time.
 *
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * sched_ext sits below the fair class in sched_class precedence
 * (kernel/sched/core.c), so SCHED_FIFO/RR/DEADLINE are scheduled by the
 * rt/dl classes and never reach this scheduler. This file schedules
 * SCHED_NORMAL/BATCH/IDLE/EXT tasks only.
 */

/*
 * This file defines the BPF maps, volatiles, and ops dispatch table.
 * The scheduling logic is organized into separate modules included below:
 *   vtime.bpf.c      - EEVDF virtual-time substrate (aggregates, placement)
 *   classify.bpf.c   - EMA gauge, queue mapping, hysteresis
 *   select_cpu.bpf.c - per-queue CPU selection
 *   enqueue.bpf.c    - enqueue routing, aging, preemption kicks
 *   dispatch.bpf.c   - queue service with quotas
 *   lifecycle.bpf.c  - init_task/enable/running/stopping/exit_task/exit
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
 * Per-queue aggregate state, keyed by queue id 1..3 (slot 0 unused).
 * The per-queue spinlock guarding the scalars lives in queue_locks so
 * intf.h stays native/bindgen-safe.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_NR_QUEUES + 1);
	__type(key, u32);
	__type(value, struct queue_ctx);
} queue_ctx_stor SEC(".maps");

struct mlfq_queue_lock {
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MLFQ_NR_QUEUES + 1);
	__type(key, u32);
	__type(value, struct mlfq_queue_lock);
} queue_locks SEC(".maps");

/*
 * Per-CPU state, keyed by cpu id. Bounds are validated against
 * nr_cpu_ids (<= 1024, checked in init()).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct mlfq_cpu_state);
} cpu_state_stor SEC(".maps");

/* Scheduler-wide state. */
volatile u64 nr_cpu_ids;
volatile struct mlfq_stats mlfq_stats;

/*
 * Placement bitmaps (see select_cpu.bpf.c).
 *
 * mlfq_primary_bitmap[0] holds the primary (big-core) CPU set;
 * mlfq_llc_bitmaps[llc_id] holds the CPU membership of one LLC domain.
 * Both are plain u64 bitmaps in ARRAY map values, written by the Rust
 * front-end after load and read as map values by the CPU-selection path,
 * so no kernel cpumask kptrs and no RCU discipline are required.
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
 * Constants - rodata, materialized by cargo-veristat from the
 * veristat/9950x.json config. Compile-time defaults match the constants
 * in intf.h; the Rust front-end may override them before load.
 */
const volatile u64 mlfq_q1_slice_ns = MLFQ_Q1_SLICE_NS;
const volatile u64 mlfq_q2_slice_ns = MLFQ_Q2_SLICE_NS;
const volatile u64 mlfq_q3_slice_ns = MLFQ_Q3_SLICE_NS;
const volatile u64 mlfq_budget_max_ns = MLFQ_BUDGET_MAX_NS;
const volatile u64 mlfq_alpha = MLFQ_ALPHA;
const volatile u64 mlfq_t_l_ns = MLFQ_T_L_NS;
const volatile u64 mlfq_t_h_ns = MLFQ_T_H_NS;
const volatile u64 mlfq_ema_half_life_ns = MLFQ_EMA_HALF_LIFE_NS;
const volatile u64 mlfq_aging_period_ns = MLFQ_AGING_PERIOD_NS;
const volatile u64 mlfq_short_sleep_ns = MLFQ_SHORT_SLEEP_NS;
const volatile u64 mlfq_short_sleep_rate_limit_ns = MLFQ_SHORT_SLEEP_RATE_LIMIT_NS;
const volatile u64 mlfq_hysteresis_sleep_ns = MLFQ_HYSTERESIS_SLEEP_NS;
const volatile u64 mlfq_long_sleep_ns = MLFQ_LONG_SLEEP_NS;
const volatile u32 mlfq_q1_quota = MLFQ_Q1_QUOTA;
const volatile u32 mlfq_q2_quota = MLFQ_Q2_QUOTA;
const volatile u32 mlfq_dispatch_max_batch = MLFQ_DISPATCH_MAX_BATCH;

/*
 * True when every CPU has the same capacity (uniform-capacity system): the
 * CPU-selection fast path skips all hybrid logic in that case. Written by
 * the Rust front-end from the discovered topology.
 */
const volatile bool mlfq_primary_all = true;

/*
 * Cache-domain data written by the Rust front-end before load. mlfq_nr_llcs
 * is the number of LLC domains with usable masks (0 disables the LLC step
 * entirely); mlfq_llc_has_primary marks LLCs that contain at least one
 * primary (big) core; mlfq_cpu_llc maps a CPU to its LLC domain (0 when
 * unknown).
 */
const volatile u32 mlfq_nr_llcs = 0;
const volatile u8 mlfq_llc_has_primary[MLFQ_MAX_LLCS];
const volatile u32 mlfq_cpu_llc[MLFQ_MAX_CPUS];

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

#include "vtime.bpf.c"
#include "classify.bpf.c"
#include "select_cpu.bpf.c"
#include "enqueue.bpf.c"
#include "dispatch.bpf.c"
#include "lifecycle.bpf.c"

s32 BPF_STRUCT_OPS_SLEEPABLE(mlfq_init)
{
	struct queue_ctx *q;
	u32 key;
	s32 ret;

	nr_cpu_ids = scx_bpf_nr_cpu_ids();
	if (nr_cpu_ids > 1024) {
		scx_bpf_error("nr_cpu_ids (%llu) exceeds max supported (1024)",
			      nr_cpu_ids);
		return -E2BIG;
	}

	/* Create the three global vtime-ordered queue DSQs. */
	ret = scx_bpf_create_dsq(MLFQ_DSQ_Q1, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("failed to create Q1 DSQ: %d", ret);
		return ret;
	}
	ret = scx_bpf_create_dsq(MLFQ_DSQ_Q2, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("failed to create Q2 DSQ: %d", ret);
		return ret;
	}
	ret = scx_bpf_create_dsq(MLFQ_DSQ_Q3, -1);
	if (ret < 0 && ret != -EEXIST) {
		scx_bpf_error("failed to create Q3 DSQ: %d", ret);
		return ret;
	}

	/* Initialize the per-queue aggregates. */
	for (key = 1; key <= MLFQ_NR_QUEUES; key++) {
		q = mlfq_lookup_queue(key);
		if (!q) {
			scx_bpf_error("queue %u map lookup failed", key);
			return -EINVAL;
		}
		if (key == 1)
			q->max_slice_ns = mlfq_q1_slice_ns;
		else if (key == 2)
			q->max_slice_ns = mlfq_q2_slice_ns;
		else
			q->max_slice_ns = mlfq_q3_slice_ns;
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
	       .running			= (void *)mlfq_running,
	       .stopping		= (void *)mlfq_stopping,
	       .enable			= (void *)mlfq_enable,
	       .init			= (void *)mlfq_init,
	       .exit			= (void *)mlfq_exit,
	       .init_task		= (void *)mlfq_init_task,
	       .exit_task		= (void *)mlfq_exit_task,
	       .dispatch_max_batch	= MLFQ_DISPATCH_MAX_BATCH,
	       .timeout_ms		= 5000,
	       .name			= "scx_mlfq");
