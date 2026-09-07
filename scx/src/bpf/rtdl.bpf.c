/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Realtime/DL core avoidance, included by main.bpf.c via #include.
 *
 * The kernel schedules RT, DL and stop tasks outside sched_ext. When
 * one of them becomes runnable on a CPU running an SCX task, the kernel
 * switches the CPU to the higher-priority class and only hands it back
 * when the higher-priority queue empties. This module tracks which CPUs
 * a realtime task is running on through a sched_switch hook, drains the
 * local DSQ of a CPU that is taken over so its tasks are not stranded,
 * and (in the placement modules) redirects wakeups away from occupied
 * cores. The queue DSQs of a taken-over CPU are served by the steal
 * scans as the second channel. The occupancy flag is the scheduler's
 * view of a CPU the SCX classes cannot run on. It is updated on every
 * real context switch, so it always reflects the class of the last task
 * that ran.
 */

/*
 * The kernel's RT priority cutoff (kernel/sched/sched.h) is this.
 * Tasks with prio < MAX_RT_PRIO are the realtime classes, DL at prio -1,
 * RT at 0..99 and the stop task at 0, while fair, ext and idle tasks
 * sit at prio >= 100. The vmlinux.h type header does not expose the
 * macro, so it is stated here as the constant it is.
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
 * mlfq_local_insert_safe - Veto a FIFO local insert to a bad CPU.
 * @cpu: The CPU whose local DSQ would receive the task.
 *
 * A FIFO local insert bypasses the virtual-time order and shadows the
 * queue DSQs while it sits, so it is allowed only when the CPU can run
 * the task immediately: not occupied by a higher-priority class and with
 * an empty local DSQ. An occupied CPU would strand the task behind the
 * takeover until the drain, and a non-empty local would queue it behind
 * unrelated work. Both cases fall back to the owning queue DSQ, which
 * the steal scans serve. The idle claim itself is not tested here; the
 * caller holds it via test_and_clear.
 *
 * Return: true when the local insert may proceed.
 */
static __always_inline bool mlfq_local_insert_safe(s32 cpu)
{
	if (cpu < 0 || cpu >= (s32)nr_cpu_ids)
		return false;
	if (mlfq_cpu_occupied(cpu))
		return false;
	if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | (u64)cpu))
		return false;
	return true;
}

/*
 * mlfq_needs_shared_kick - Whether a queue-DSQ insert needs an idle kick.
 * @p: The task just queued.
 * @enq_flags: The enqueue flags of the insert.
 * @target_cpu: The CPU owning the queue DSQ.
 *
 * Local inserts never kick (the target runs its local DSQ without one).
 * A queue-DSQ insert kicks only when the target is another CPU, is not
 * occupied, and either the selection was skipped (no idle claim was made,
 * so nobody was woken to look) or the task is affinity-constrained (only
 * a few CPUs may serve its queue). A wakeup that already went through the
 * selection and may run anywhere needs no extra kick: the claim or the
 * fallback already woke the right CPU, and an extra kick is a redundant
 * inter-processor interrupt on the wakeup path.
 *
 * Return: true when the caller must kick @target_cpu idle.
 */
static __always_inline bool mlfq_needs_shared_kick(const struct task_struct *p,
						   u64 enq_flags, s32 target_cpu)
{
	if (target_cpu == bpf_get_smp_processor_id())
		return false;
	if (target_cpu < 0 || target_cpu >= (s32)nr_cpu_ids)
		return false;
	if (mlfq_cpu_occupied(target_cpu))
		return false;
	if (__COMPAT_is_enq_cpu_selected(enq_flags) &&
	    p->nr_cpus_allowed == (u32)nr_cpu_ids)
		return false;
	return true;
}

/*
 * Pick a non-occupied CPU out of a membership bitmap for @p. The same
 * word-major, bit-minor bounded walk the idle scan in select_cpu.bpf.c
 * uses, skipping occupied CPUs instead of busy ones. No idle marks are
 * touched. The caller has already decided the wakeup must not land on
 * an occupied core, and the kernel's idle accounting is unaffected.
 * When @strict_smt is true the same SMT-sibling Q1 predicate the
 * selection uses (is_smt_sibling_q1_busy) is also a veto; when false
 * only the realtime hard gate applies. No new heuristic: the predicate
 * is exactly the selection's.
 *
 * Return: The first non-occupied CPU @p may run on, or -ENOENT.
 */
static __always_inline s32
mlfq_pick_unoccupied_in_bitmap(const struct mlfq_bitmap *bm,
			       const struct task_struct *p, bool strict_smt)
{
	u32 word, bit;

	bpf_for(word, 0, MLFQ_BITMAP_WORDS) {
		bpf_for(bit, 0, 64) {
			u32 cand = word * 64 + bit;

			if (cand >= MLFQ_MAX_CPUS)
				break;
			if (!mlfq_bitmap_test_cpu(bm, cand))
				continue;
			if (!bpf_cpumask_test_cpu(cand, p->cpus_ptr))
				continue;
			if (mlfq_cpu_occupied((s32)cand))
				continue;
			if (strict_smt && is_smt_sibling_q1_busy((s32)cand))
				continue;
			return (s32)cand;
		}
	}

	return -ENOENT;
}

/*
 * Pick a non-occupied CPU for @p, preferring the cache domain of @origin
 * (the waker's CPU). The LLC pass walks the origin's membership bitmap.
 * When it finds nothing, a flat bounded scan takes any non-occupied CPU
 * @p may run on. An unpopulated LLC bitmap or an unknown LLC proceeds
 * to the flat scan. @strict_smt adds the selection's SMT-sibling Q1 veto
 * to both passes (same predicate, no new heuristic); false keeps the
 * realtime-only hard gate.
 *
 * Return: A non-occupied CPU @p may run on, or -ENOENT.
 */
static __always_inline s32
mlfq_pick_unoccupied_cpu(const struct task_struct *p, s32 origin,
			 bool strict_smt)
{
	const struct mlfq_bitmap *bm;
	s32 pick;
	u32 cand;

	if (origin >= 0 && (u32)origin < MLFQ_MAX_CPUS && mlfq_nr_llcs > 0) {
		u32 origin_llc = mlfq_cpu_llc[(u32)origin];

		if (origin_llc < MLFQ_MAX_LLCS && origin_llc < mlfq_nr_llcs) {
			bm = bpf_map_lookup_elem(&mlfq_llc_bitmaps, &origin_llc);
			if (bm) {
				pick = mlfq_pick_unoccupied_in_bitmap(bm, p,
								      strict_smt);
				if (pick >= 0)
					return pick;
			}
		}
	}

	/*
	 * The global fallback is any non-occupied CPU in a flat bounded
	 * scan. The LLC bitmaps partition the machine, but walking all of
	 * them would nest three loops. A single scan over the CPU id
	 * space reaches the same set in one bounded pass.
	 */
	bpf_for(cand, 0, MLFQ_MAX_CPUS) {
		if (cand >= nr_cpu_ids)
			break;
		if (!bpf_cpumask_test_cpu(cand, p->cpus_ptr))
			continue;
		if (mlfq_cpu_occupied((s32)cand))
			continue;
		if (strict_smt && is_smt_sibling_q1_busy((s32)cand))
			continue;
		return (s32)cand;
	}

	return -ENOENT;
}

/*
 * mlfq_rtdl_drain - Local-only evacuation pass for a taken-over CPU.
 * @cpu: The CPU a realtime task took over.
 * @now: Current time (scx_bpf_now()).
 *
 * Rate-limited, straight-line evacuation pass for the local DSQ only.
 * The kernel reenqueues the local DSQ on a takeover without a repeat
 * guard of its own, so the interval bounds the churn a takeover can
 * stir up, in particular the pinned-task reenqueue loop, which the
 * kernel lets run unthrottled. The pass is skipped entirely when the
 * local DSQ is empty, which also keeps the gate from being consumed by
 * the takeover blips themselves. The stop-class blips that interrupt a
 * takeover are safe for the same reason, because the drain they trigger
 * is rate-limited and a no-op when there is nothing to drain. The queue
 * DSQs are not drained here, and the steal scans serve them as the
 * second channel on every kernel.
 */
static __always_inline void mlfq_rtdl_drain(s32 cpu, u64 now)
{
	struct mlfq_rtdl_state *rt;
	bool evacuated = false;

	rt = mlfq_lookup_rtdl_state(cpu);
	if (!rt)
		return;

	/*
	 * The rate-limited drain gate allows at most one pass per CPU per
	 * mlfq_rtdl_drain_interval_ns, so a takeover storm cannot burn
	 * the CPU in the hook. The first pass is ungated (last_drain_at
	 * == 0). On kernels without the reenqueue kfuncs, the gate never
	 * closes. The pass is a no-op and last_drain_at does not advance,
	 * so every realtime-class switch pays the nonempty gate below.
	 * That is the documented 6.18 degradation.
	 */
	if (rt->last_drain_at &&
	    !mlfq_time_before(rt->last_drain_at + mlfq_rtdl_drain_interval_ns, now))
		return;

	/*
	 * Nonempty gate: when the local DSQ is empty there is nothing to
	 * evacuate, so the pass is skipped without consuming the
	 * rate-limit window. The queue DSQs are not gated here, since the
	 * steal scans drain them as the second channel.
	 */
	if (!scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | (u64)cpu))
		return;

	/*
	 * The local-only evacuation is version-gated. The local DSQ is
	 * reenqueued from anywhere only where the call-from-anywhere kfunc
	 * exists (v6.19+), as one straight-line call with no loop. The
	 * reenqueue itself re-anchors the tasks in the queue DSQs. The
	 * enqueue redirect then relocates them off the occupied CPU, so
	 * the drain plus the redirect is what actually evacuates. On 6.18
	 * the drain is a no-op by kernel limitation. The local DSQ is
	 * reenqueued by ops.cpu_release, whose reenqueue the redirect
	 * likewise relocates, and the queue DSQs are served by the steal
	 * scans on every kernel, which is the second channel. The probe
	 * is the compat layer's stable surface, and the call goes
	 * straight to the v2 kfunc, which is what the from-anywhere
	 * wrapper does internally. Spelling it out keeps the drain
	 * buildable against compat headers that predate the wrapper.
	 */
	if (__COMPAT_scx_bpf_reenqueue_local_from_anywhere()) {
		scx_bpf_reenqueue_local___v2___compat();
		evacuated = true;
	}

	/*
	 * The gate and the counter are consumed only when the pass
	 * actually ran. On kernels without the reenqueue kfuncs nothing
	 * was evacuated, so the rate-limit window stays open and no
	 * evacuation is counted.
	 */
	if (evacuated) {
		rt->last_drain_at = now;
		__sync_fetch_and_add(&mlfq_stats.rt_evacuations, 1);
	}
}

/*
 * The sched_switch hook. The kernel fires this tracepoint on every real
 * context switch. The program reads next->prio to learn the class of
 * the task the CPU is about to run. A realtime next marks the CPU
 * occupied and attempts the local-only takeover drain. Any other next
 * clears the mark. Because the hook fires on every real switch, the
 * flag always reflects the class of the last task that ran on the CPU,
 * which is exactly the invariant the placement redirect needs. The
 * program is loaded on every kernel. The flag logic alone drives
 * placement even where the evacuation cannot run, and the evacuation
 * branch inside is ksym-gated so it self-prunes on kernels without the
 * reenqueue kfunc. The body is straight-line with at most a few bounded
 * map operations per switch. There are no loops.
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
