/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Enqueue routing, included by main.bpf.c via #include.
 *
 * The MLFQ enqueue path:
 *   WAKEUP -> EMA decay + classification, then placement
 *   RUN-OUT (enq_flags == 0) -> demotion, then placement
 *   other (fork / SCX_ENQ_LAST / class switch) -> counter reset, placement
 *   wall-clock aging check for Q2/Q3 stays, then placement
 * and the queue-preemptive wakeup kicks.
 *
 * Enqueue flag taxonomy (which ops.enqueue() call sites produce which
 * flags; verified against kernel/sched/ext/ext.c, 6.13 and 7.2-rc6):
 *
 *   - Wakeup: ttwu_do_activate() -> activate_task() passes ENQUEUE_WAKEUP
 *     (== SCX_ENQ_WAKEUP), plus ENQUEUE_NOCLOCK and, when select_task_rq()
 *     ran, ENQUEUE_RQ_SELECTED (== SCX_ENQ_CPU_SELECTED).
 *   - Fork: wake_up_new_task() -> activate_task() passes
 *     ENQUEUE_NOCLOCK | ENQUEUE_INITIAL (no SCX_ENQ_WAKEUP bit).
 *   - Run-out (slice exhaustion): put_prev_task_scx() re-enqueues the
 *     runnable task with do_enqueue_task(rq, p, 0, -1) -- flags == 0 --
 *     or with SCX_ENQ_LAST when leaving for a higher sched class.
 *   - SCX_ENQ_REENQ is set only for SCX_ENQ_IMMED re-enqueues
 *     (put_prev_task_scx(), ext.c:3102) and for
 *     scx_bpf_reenqueue_local()/scx_bpf_dsq_reenq() (ext.c:4165, 4280);
 *     this scheduler never uses IMMED or those kfuncs, so SCX_ENQ_REENQ
 *     never reaches ops.enqueue() here and is not tested.
 *   - SCX-internal DSQ migrations (dispatch_to_local_dsq()) keep the task
 *     SCX_TASK_QUEUED and never call ops.enqueue(); generic rq migrations
 *     (move_queued_task()) only move CFS-queued tasks, which SCX tasks
 *     never are. Hence the only flags == 0 enqueue is the run-out above.
 */

static __always_inline bool mlfq_task_is_migration_disabled(const struct task_struct *p)
{
	return p->nr_cpus_allowed == 1 || is_migration_disabled(p);
}

static __always_inline u64 mlfq_queue_slice(u8 qid)
{
	if (qid == 1)
		return mlfq_q1_slice_ns;
	if (qid == 2)
		return mlfq_q2_slice_ns;
	return mlfq_q3_slice_ns;
}

static __always_inline u64 mlfq_dsq_id(u8 qid)
{
	return MLFQ_DSQ_Q1 + (u64)(qid - 1);
}

static __always_inline void mlfq_stat_placement(u8 qid)
{
	if (qid == 1)
		__sync_fetch_and_add(&mlfq_stats.q1_placements, 1);
	else if (qid == 2)
		__sync_fetch_and_add(&mlfq_stats.q2_placements, 1);
	else
		__sync_fetch_and_add(&mlfq_stats.q3_placements, 1);
}

void BPF_STRUCT_OPS(mlfq_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct task_ctx *tctx;
	struct mlfq_cpu_state *cpu;
	u64 now, deadline;
	u32 weight, qid;
	u8 old_queue;
	bool wakeup, runout, inflate, local_fast_path, migration_disabled;
	bool sched_idle;
	s32 prev_cpu = scx_bpf_task_cpu(p);

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx)
		return;

	/* Refresh the weight cache; the kernel clamps p->scx.weight to [1, 10000]. */
	weight = p->scx.weight;
	if (weight < 1) {
		scx_bpf_error("pid %d has invalid weight %u", p->pid, weight);
		return;
	}
	tctx->weight = weight;

	now = scx_bpf_now();
	wakeup = enq_flags & SCX_ENQ_WAKEUP;
	/* See the file header for the flags == 0 call-site table. */
	runout = enq_flags == 0;
	old_queue = tctx->queue;

	if (wakeup) {
		mlfq_wakeup_classify(p, tctx, now);
	} else if (runout) {
		/*
		 * Slice-exhaustion re-enqueue from put_prev_task_scx().
		 * The consecutive-exhaustion demotion state machine runs
		 * here and only here.
		 */
		mlfq_runout_classify(p, tctx);
	} else {
		/* fork, SCX_ENQ_LAST or class switch: reset the counters. */
		tctx->wake_cnt = 0;
		tctx->reenq_cnt = 0;
	}

	/*
	 * SCHED_IDLE is always Q3 and never ages.
	 */
	sched_idle = mlfq_apply_sched_idle(p, tctx);

	/*
	 * Stay bookkeeping: a wakeup ends the previous stay (sleeping resets
	 * it) and a queue change starts a fresh one, both refreshed only at
	 * the enqueues that begin a residency -- never at run-out
	 * re-enqueues. A queue change also clears the consecutive
	 * slice-exhaustion counter (band semantics). Only Q2/Q3 stays carry
	 * a non-zero queued_at.
	 */
	if (tctx->queue != old_queue) {
		tctx->queued_at = tctx->queue >= 2 ? now : 0;
		tctx->reenq_cnt = 0;
	} else if (wakeup) {
		tctx->queued_at = tctx->queue >= 2 ? now : 0;
	}

	/*
	 * Aging: a stay of >= MLFQ_AGING_PERIOD_NS of continuous Q2/Q3
	 * wall-clock time (queued_at is refreshed only at wakeup/queue
	 * change, never at run-out) is elevated to a Q1 placement. A task
	 * that sleeps between placements resets its stay at the wakeup, so
	 * wall-clock time spent asleep never counts toward aging.
	 */
	qid = tctx->queue;
	if (tctx->queue >= 2 && !sched_idle &&
	    !(tctx->flags & MLFQ_TF_AGING_BOOSTED) &&
	    tctx->queued_at &&
	    !mlfq_time_before(now, tctx->queued_at + mlfq_aging_period_ns)) {
		tctx->queue = 1;
		tctx->reenq_cnt = 0;
		tctx->flags |= MLFQ_TF_AGING_BOOSTED;
		__sync_fetch_and_add(&mlfq_stats.aging_boosts, 1);
	}

	qid = tctx->queue;
	/*
	 * The enqueue runs on the rq the task is being enqueued to, so its
	 * cpu_state is the local-curr fold input (fair.c folds the
	 * enqueueing cfs_rq's curr; see mlfq_queue_fold_local()).
	 */
	cpu = mlfq_lookup_cpu_state(bpf_get_smp_processor_id());
	inflate = wakeup || runout;

#if MLFQ_CHECK
	if (!mlfq_check_queue(tctx->queue) || !mlfq_check_weight(tctx->weight))
		scx_bpf_error("pid %d invalid queue %u weight %u", p->pid,
			      tctx->queue, tctx->weight);
#endif

	/*
	 * Migration-disabled and single-CPU tasks never enter the shared
	 * DSQs: they are pinned to their allowed CPU with the
	 * queue slice as their runtime grant. They are placed (for a
	 * consistent vruntime/deadline) but not accounted.
	 */
	migration_disabled = mlfq_task_is_migration_disabled(p);
	if (migration_disabled) {
		if (prev_cpu < 0) {
			scx_bpf_error("pid %d pinned task without a CPU", p->pid);
			return;
		}
		deadline = mlfq_place_task(qid, tctx, inflate, cpu, p->pid,
					   false);
		if (!deadline)
			return;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)prev_cpu,
				   mlfq_queue_slice(qid), enq_flags);
		if (cpu)
			cpu->migration_disabled_placements++;
		mlfq_stat_placement(qid);
		tctx->wake_cpu_state = 0;
		goto done;
	}

	/*
	 * Idle-CPU fast path: select_cpu() found an idle CPU and returned it,
	 * so the wakeup can be served on that CPU's local DSQ immediately.
	 * Correct because the CPU is idle -- no runnable task is displaced.
	 */
	local_fast_path = __COMPAT_is_enq_cpu_selected(enq_flags) &&
			  (tctx->wake_cpu_state & MLFQ_WAKE_CPU_VALID) &&
			  (tctx->wake_cpu_state & MLFQ_WAKE_CPU_IDLE);
	if (local_fast_path) {
		deadline = mlfq_place_task(qid, tctx, inflate, cpu, p->pid,
					   false);
		if (!deadline)
			return;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, mlfq_queue_slice(qid),
				   enq_flags);
		if (cpu)
			cpu->fast_path_dispatches++;
		mlfq_stat_placement(qid);
		tctx->wake_cpu_state = 0;
		goto done;
	}

	/* Regular path: into the queue's global vtime DSQ. */
	deadline = mlfq_place_task(qid, tctx, inflate, cpu, p->pid, true);
	if (!deadline)
		return;
	scx_bpf_dsq_insert_vtime(p, mlfq_dsq_id(qid), mlfq_queue_slice(qid),
				 deadline, enq_flags);
	mlfq_stat_placement(qid);

	/* Keep the fast-path state from leaking into the next enqueue. */
	tctx->wake_cpu_state = 0;

done:
	/*
	 * Wakeup preemption: a higher-priority arrival
	 * preempts the lower-priority task running on prev_cpu. The kick is
	 * restricted to genuine promotions, into Q1 from Q2 or Q3 and into
	 * Q2 from Q3, which keeps borderline-promotion IPI storms out. Never
	 * kick the wakee itself and never kick the local CPU.
	 */
	if (wakeup && !migration_disabled) {
		struct mlfq_cpu_state *prev_state = mlfq_lookup_cpu_state(prev_cpu);
		bool promoted = (qid == 1 && old_queue >= 2) ||
				(qid == 2 && old_queue == 3);

		if (promoted && prev_state && prev_state->running_queue > (s32)qid &&
		    prev_state->running_pid != p->pid &&
		    prev_cpu != bpf_get_smp_processor_id()) {
			scx_bpf_kick_cpu(prev_cpu, SCX_KICK_PREEMPT);
			prev_state->preemption_kicks++;
		}
	}
}
