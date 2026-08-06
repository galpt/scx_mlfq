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
 * and the wakeup preemption decision: a higher queue, or the same queue
 * with an earlier EEVDF deadline, preempts the running task.
 *
 * The demotion path keys on the flags == 0 run-out re-enqueue, which only
 * slice exhaustion produces: put_prev_task_scx() re-enqueues the runnable
 * task with do_enqueue_task(rq, p, 0, -1), or with SCX_ENQ_LAST when
 * leaving for a higher sched class. SCX_ENQ_REENQ appears only on
 * SCX_ENQ_IMMED re-enqueues (put_prev_task_scx(), ext.c:3102) and
 * scx_bpf_reenqueue_local()/scx_bpf_dsq_reenq() (ext.c:4165, 4280), and
 * neither DSQ migrations nor generic rq migrations call ops.enqueue() for
 * queued SCX tasks, so no other path produces an enqueue without flag
 * bits.
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
	s32 target_cpu;

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx) {
		/*
		 * init_task() normally pre-allocates the task storage, but a
		 * task can reach enqueue() without it (for example a task
		 * that was runnable when this scheduler attached). Allocate
		 * on demand instead of dropping the task from scheduling: a
		 * runnable task without state would otherwise stay stranded
		 * until its next enqueue. If the allocation still fails (out
		 * of memory), the error path exits the scheduler and the
		 * kernel's bypass mode then guarantees every runnable task
		 * makes progress, so a task is never silently stranded.
		 */
		tctx = mlfq_alloc_task_ctx(p);
		if (!tctx) {
			__sync_fetch_and_add(&mlfq_stats.enq_no_tctx, 1);
			scx_bpf_error("pid %d task state allocation failed in enqueue",
				      p->pid);
			return;
		}
		mlfq_reset_task_ctx(tctx, p, scx_bpf_now());
	}

	/* Refresh the weight cache; the kernel clamps p->scx.weight to [1, 10000]. */
	weight = p->scx.weight;
	if (weight < 1) {
		__sync_fetch_and_add(&mlfq_stats.enq_bad_weight, 1);
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

	migration_disabled = mlfq_task_is_migration_disabled(p);
	if (migration_disabled) {
		if (prev_cpu < 0) {
			scx_bpf_error("pid %d pinned task without a CPU", p->pid);
			return;
		}

		/*
		 * The allowed CPU set may have changed since the last
		 * placement; the pinned CPU is prev_cpu only when the task
		 * may still run there. A task whose affinity no longer
		 * includes prev_cpu is parked on the global DSQ, which the
		 * kernel drains on every dispatch cycle without this
		 * scheduler's involvement.
		 */
		if (!bpf_cpumask_test_cpu((u32)prev_cpu, p->cpus_ptr)) {
			__sync_fetch_and_add(&mlfq_stats.enq_pinned_global, 1);
			scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL,
					   mlfq_queue_slice(qid), enq_flags);
			mlfq_stat_placement(qid);
			tctx->wake_cpu_state = 0;
			goto done;
		}

		if (scx_bpf_test_and_clear_cpu_idle(prev_cpu)) {
			/*
			 * The pinned CPU is idle, so the local DSQ is
			 * empty. The task runs on the next scheduling
			 * cycle and the local DSQ drains immediately after,
			 * which keeps balance_one() from skipping
			 * ops.dispatch() for the tasks queued behind it.
			 */
			deadline = mlfq_place_task(qid, tctx, inflate, cpu,
						   p->pid, false);
			if (!deadline)
				return;
			__sync_fetch_and_add(&mlfq_stats.enq_pinned_idle, 1);
			tctx->dsq_id = 0;
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)prev_cpu,
					   mlfq_queue_slice(qid), enq_flags);
			if (cpu)
				cpu->migration_disabled_placements++;
			mlfq_stat_placement(qid);
			tctx->wake_cpu_state = 0;
			goto done;
		}

		/*
		 * The pinned CPU is busy. The task is placed into the
		 * CPU's queue DSQ and shares the CPU by virtual time
		 * order; the owning CPU drains the queue at every slice
		 * boundary, so the task is served without ever parking in
		 * the local DSQ, which would shadow every other runnable
		 * task on the CPU until the stall watchdog fires.
		 *
		 * The task is added to the queue aggregate because it now
		 * participates in the queue DSQ, and the aggregate must
		 * mirror DSQ membership for the virtual-time average to
		 * stay exact.
		 */
		deadline = mlfq_place_task(qid, tctx, inflate, cpu, p->pid, true);
		if (!deadline)
			return;
		__sync_fetch_and_add(&mlfq_stats.enq_pinned_busy, 1);
		tctx->dsq_id = mlfq_dsq_id(qid, prev_cpu);
		scx_bpf_dsq_insert_vtime(p, mlfq_dsq_id(qid, prev_cpu),
					 mlfq_queue_slice(qid), deadline,
					 enq_flags);
		if (cpu)
			cpu->migration_disabled_placements++;
		mlfq_stat_placement(qid);
		tctx->wake_cpu_state = 0;

		/*
		 * A placement into another CPU's queue needs that CPU to
		 * run one more scheduling cycle; the idle kick is a cheap
		 * flag that is consumed when the CPU next goes idle, and
		 * it guarantees the queued task is not stranded on a
		 * nohz-idle CPU. The enqueueing CPU needs no kick: its own
		 * dispatch drains the queue in the same scheduling cycle.
		 */
		if (prev_cpu != bpf_get_smp_processor_id())
			scx_bpf_kick_cpu(prev_cpu, SCX_KICK_IDLE);
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
		/*
		 * The idle-CPU fast path places the task on the local DSQ,
		 * not in a queue DSQ, so dsq_id is cleared.
		 */
		tctx->dsq_id = 0;
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, mlfq_queue_slice(qid),
				   enq_flags);
		__sync_fetch_and_add(&mlfq_stats.enq_fastpath, 1);
		if (cpu)
			cpu->fast_path_dispatches++;
		mlfq_stat_placement(qid);
		tctx->wake_cpu_state = 0;
		goto done;
	}

	/*
	 * The queue DSQ a task is placed in is owned by the CPU it is
	 * enqueued to: a wakeup lands on prev_cpu, the CPU the task was
	 * last running on, while run-out re-enqueues and fork/class-switch
	 * placements run on the rq the task is being enqueued to, which is
	 * the enqueueing CPU. Each CPU drains only its own three queue
	 * DSQs (see dispatch.bpf.c), so the insert must target the owning
	 * CPU's queue.
	 */
	if (wakeup)
		target_cpu = prev_cpu;
	else
		target_cpu = bpf_get_smp_processor_id();

	/*
	 * Compute the placement before the preemption decision so the
	 * wakeup's EEVDF deadline is available to it. The task is not
	 * accounted yet: the preemption branch dispatches it to a local
	 * DSQ, which never carries aggregate membership, so the accounting
	 * step that mirrors mlfq_place_task()'s tail runs only when the
	 * task actually enters a queue DSQ.
	 */
	deadline = mlfq_place_task(qid, tctx, inflate, cpu, p->pid, false);
	if (!deadline) {
		__sync_fetch_and_add(&mlfq_stats.enq_no_deadline, 1);
		return;
	}

	/*
	 * Wakeup preemption: a wakeup outranks the task running on the CPU
	 * it was last running on when it belongs to a higher queue, or to
	 * the same queue with an earlier EEVDF deadline -- the
	 * check_preempt_wakeup semantics of the fair scheduler, where the
	 * higher-priority arrival preempts. The wakee is dispatched to
	 * that CPU's local DSQ with SCX_ENQ_PREEMPT, which the kernel
	 * resolves into a preemption on the next scheduling event. The
	 * local-DSQ insert is never accounted, matching the idle-CPU fast
	 * path. The decision is confined to wakeups of migratable tasks
	 * (migration-disabled tasks are routed above); a wakeup without a
	 * previous CPU fails the cpu_state lookup and falls through.
	 */
	if (wakeup && !migration_disabled) {
		struct mlfq_cpu_state *prev_state = mlfq_lookup_cpu_state(prev_cpu);
		bool preempt = false;

		if (prev_state && prev_state->running_pid &&
		    prev_state->running_pid != p->pid &&
		    prev_state->running_queue > 0) {
			if ((s32)qid < prev_state->running_queue)
				preempt = true;	/* higher queue than the running task */
			else if ((s32)qid == prev_state->running_queue &&
				 mlfq_time_before(deadline, prev_state->running_deadline))
				preempt = true;	/* earlier deadline on the same queue */
		}

		if (preempt) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)prev_cpu,
					   mlfq_queue_slice(qid),
					   enq_flags | SCX_ENQ_PREEMPT);
			__sync_fetch_and_add(&mlfq_stats.preemption_kicks, 1);
			/*
			 * The task is on the local DSQ, not in a queue DSQ,
			 * so dsq_id is cleared like on the idle-CPU fast
			 * path.
			 */
			tctx->dsq_id = 0;
			tctx->wake_cpu_state = 0;
			goto done;
		}
	}

	/* Regular path: into the owning CPU's queue vtime DSQ. */
	__sync_fetch_and_add(&mlfq_stats.enq_regular, 1);
	if (!mlfq_queue_account_only(qid, tctx)) {
		__sync_fetch_and_add(&mlfq_stats.enq_no_deadline, 1);
		return;
	}
	tctx->dsq_id = mlfq_dsq_id(qid, target_cpu);
	scx_bpf_dsq_insert_vtime(p, mlfq_dsq_id(qid, target_cpu),
				 mlfq_queue_slice(qid), deadline, enq_flags);
	mlfq_stat_placement(qid);

	/* Keep the fast-path state from leaking into the next enqueue. */
	tctx->wake_cpu_state = 0;

	/*
	 * A placement into another CPU's queue needs that CPU to run one
	 * more scheduling cycle so a queued task is not stranded on a
	 * nohz-idle CPU; the idle kick is a cheap flag that is consumed
	 * when the CPU next goes idle. The enqueueing CPU needs no kick:
	 * its own dispatch drains the queue in the same scheduling cycle.
	 */
	if (target_cpu != bpf_get_smp_processor_id())
		scx_bpf_kick_cpu(target_cpu, SCX_KICK_IDLE);

done:
	;
}
