/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Realtime/DL core avoidance, included by main.bpf.c via #include.
 *
 * The kernel schedules RT, DL and stop tasks outside sched_ext: when
 * one of them becomes runnable on a CPU running an SCX task, the kernel
 * switches the CPU to the higher-priority class and only hands it back
 * when the higher-priority queue empties. This module tracks which CPUs
 * a realtime task is running on through a sched_switch hook, drains the
 * DSQs of a CPU that is taken over so its tasks are not stranded, and
 * (in the placement modules) redirects wakeups away from occupied
 * cores. The occupancy flag is the scheduler's view of a CPU the SCX
 * classes cannot run on; it is updated on every real context switch,
 * so it always reflects the class of the last task that ran.
 */

/*
 * The kernel's RT priority cutoff (kernel/sched/sched.h): tasks with
 * prio < MAX_RT_PRIO are the realtime classes -- DL at prio -1, RT at
 * 0..99 and the stop task at 0 -- while fair, ext and idle tasks sit at
 * prio >= 100. The vmlinux.h type header does not expose the macro, so
 * it is stated here as the constant it is.
 */
#define MAX_RT_PRIO 100

/*
 * Look up the per-CPU realtime-occupancy state.
 *
 * Return: The state, or NULL for an invalid CPU or a failed lookup.
 */
static __always_inline struct mlfq_rtdl_state *mlfq_lookup_rtdl_state(s32 cpu)
{
	u32 key;

	if (cpu < 0)
		return NULL;
	key = (u32)cpu;
	return bpf_map_lookup_elem(&rtdl_state_stor, &key);
}

/*
 * Whether the last task that ran on @cpu belonged to a realtime class.
 * An invalid CPU or a failed lookup never reports occupied.
 */
static __always_inline bool mlfq_cpu_occupied(s32 cpu)
{
	struct mlfq_rtdl_state *rt;

	rt = mlfq_lookup_rtdl_state(cpu);
	if (!rt)
		return false;
	return rt->flags & MLFQ_RTDL_OCCUPIED;
}

/*
 * mlfq_rtdl_drain - Evacuation pass for a taken-over CPU.
 * @cpu: The CPU a realtime task took over.
 * @now: Current time (scx_bpf_now()).
 *
 * Rate-limited evacuation pass. The rate-limit gate is load-bearing:
 * the kernel reenqueues through the local DSQ on a takeover without a
 * repeat guard of its own, so the interval bounds the churn a takeover
 * can stir up. The pass is skipped entirely when every DSQ this CPU
 * owns is empty, which also keeps the gate from being consumed by the
 * takeover blips themselves.
 */
static __always_inline void mlfq_rtdl_drain(s32 cpu, u64 now)
{
	struct mlfq_rtdl_state *rt;

	rt = mlfq_lookup_rtdl_state(cpu);
	if (!rt)
		return;

	/*
	 * Rate-limited drain gate: at most one pass per CPU per
	 * mlfq_rtdl_drain_interval_ns, so a takeover storm cannot burn
	 * the CPU in the hook. The first pass is ungated (last_drain_at
	 * == 0).
	 */
	if (rt->last_drain_at &&
	    !mlfq_time_before(rt->last_drain_at + mlfq_rtdl_drain_interval_ns, now))
		return;

	/*
	 * Nonempty gate: when every DSQ this CPU owns is empty there is
	 * nothing to evacuate, so the pass is skipped without consuming
	 * the rate-limit window.
	 */
	if (!scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | (u64)cpu) &&
	    !scx_bpf_dsq_nr_queued(mlfq_dsq_id(1, cpu)) &&
	    !scx_bpf_dsq_nr_queued(mlfq_dsq_id(2, cpu)) &&
	    !scx_bpf_dsq_nr_queued(mlfq_dsq_id(3, cpu)))
		return;

	/*
	 * The evacuation action lands in a following change: it
	 * reenqueues the local DSQ and the three queue DSQs through the
	 * kernel's reenqueue kfuncs, version-gated. Until then the pass
	 * only consumes the gates and records the attempt, so this
	 * commit lands without moving any task.
	 */
	rt->last_drain_at = now;
	__sync_fetch_and_add(&mlfq_stats.rt_evacuations, 1);
}

/*
 * The sched_switch hook. The kernel fires this tracepoint on every real
 * context switch; the program reads next->prio to learn the class of
 * the task the CPU is about to run. A realtime next marks the CPU
 * occupied and attempts the takeover drain; any other next clears the
 * mark. Because the hook fires on every real switch, the flag always
 * reflects the class of the last task that ran on the CPU, which is
 * exactly the invariant the placement redirect needs. The program is
 * loaded on every kernel: the flag logic alone drives placement even
 * where the evacuation cannot run, and the evacuation branches inside
 * are ksym-gated so they self-prune on kernels without the reenqueue
 * kfuncs. The body is straight-line with at most a few bounded map
 * operations per switch; no loops.
 */
SEC("?tp_btf/sched_switch")
int BPF_PROG(mlfq_sched_switch, bool preempt,
	     struct task_struct *prev, struct task_struct *next,
	     unsigned int prev_state)
{
	s32 cpu = bpf_get_smp_processor_id();
	struct mlfq_rtdl_state *rt;
	u64 now;

	if (unlikely(next->prio < MAX_RT_PRIO)) {
		rt = mlfq_lookup_rtdl_state(cpu);
		if (!rt)
			return 0;
		if (!(rt->flags & MLFQ_RTDL_OCCUPIED)) {
			rt->flags |= MLFQ_RTDL_OCCUPIED;
			__sync_fetch_and_add(&mlfq_stats.rt_takeovers, 1);
		}
		now = scx_bpf_now();
		mlfq_rtdl_drain(cpu, now);
	} else {
		rt = mlfq_lookup_rtdl_state(cpu);
		if (!rt)
			return 0;
		if (rt->flags & MLFQ_RTDL_OCCUPIED)
			rt->flags &= ~MLFQ_RTDL_OCCUPIED;
	}
	return 0;
}
