/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Dispatch: queue service with quotas and cross-CPU stealing, included by
 * main.bpf.c via #include.
 *
 * The kernel serves SCX_DSQ_LOCAL before ops.dispatch() (the dispatch
 * loop in ext.c), so this callback only fills the local DSQ from the
 * per-CPU queue DSQs. Each CPU serves its own three queue DSQs in Q1..Q3
 * priority order, each queue bounded by dispatch_max_batch. Every slot
 * picks the earliest EEVDF deadline among the queue's own head and the
 * heads of remote CPUs' same-queue DSQs (affinity-prechecked), so an idle
 * CPU drains the most-owed task in the system for that queue, not only
 * its own. The kernel enforces affinity on the move itself:
 * consume_dispatch_q() in ext.c skips heads that cannot run on the
 * consuming CPU, so the BPF pre-check only prefers the earliest eligible
 * head and avoids wasted moves.
 *
 * The three quotas are served by bounded loops: Q1 scans every candidate
 * CPU, Q2/Q3 scan a rotating window of at most MLFQ_STEAL_SCAN_MAX
 * candidates. Each slot is a constant number of peeks and one move, so
 * the loop bodies stay flat and the verifier state small.
 *
 * The keep path runs first, before the slot loops: when the CPU's queue
 * DSQs are empty and the outgoing task is still queued, the task is the
 * only runnable work this CPU can take, so it is kept with a fresh queue
 * slice instead of the CPU idling with runnable work. Resolving the keep
 * up front reads the queue state once, before the slot loops churn it,
 * and keeps the loop bodies to a single job each.
 */

/*
 * mlfq_dispatch_queue - Serve one queue for up to @quota slots.
 * @cpu: CPU running dispatch.
 * @qid: Queue being served (1..3), a constant at each call site.
 * @quota: Number of slots granted to this queue; zero yields no slots.
 * @cpu_state: Per-CPU state of @cpu, may be NULL.
 * @nr_cpus: Snapshot of nr_cpu_ids.
 *
 * Each slot peeks the queue's own head and the heads of the candidate
 * CPUs' same-queue DSQs, affinity-checks each (migration-disabled tasks
 * fail this automatically), and moves the earliest-deadline candidate to
 * the local DSQ. Q1 scans every candidate CPU; Q2/Q3 scan a rotating
 * window of at most MLFQ_STEAL_SCAN_MAX candidates starting at the
 * per-CPU offset, so the bounded window is fair across the system.
 *
 * Return: The number of tasks moved.
 */
static __always_inline u32
mlfq_dispatch_queue(s32 cpu, u8 qid, u32 quota,
		    struct mlfq_cpu_state *cpu_state, u64 nr_cpus)
{
	u64 own_dsq = mlfq_dsq_id(qid, cpu);
	u32 slot, moved = 0;

	bpf_for(slot, 0, quota) {
		struct task_struct *best = NULL;
		u64 best_dsq = 0;
		s32 best_cpu = cpu;
		u32 cand;
		u32 off = cpu_state ? cpu_state->steal_scan_off % (u32)nr_cpus : 0;
		u32 i;

		/* the queue's own head, affinity-prechecked */
		best = __COMPAT_scx_bpf_dsq_peek(own_dsq);
		if (best && !bpf_cpumask_test_cpu((u32)cpu, best->cpus_ptr))
			best = NULL;
		best_dsq = own_dsq;

		/*
		 * Q1 scans every candidate CPU; the lower queues scan a
		 * bounded rotating window. The bound folds to a constant
		 * at each call site.
		 */
		bpf_for(i, 0, qid == 1 ? nr_cpus : MLFQ_STEAL_SCAN_MAX) {
			struct task_struct *t;

			cand = (off + i) % (u32)nr_cpus;
			if (cand == (u32)cpu)
				continue;
			t = __COMPAT_scx_bpf_dsq_peek(mlfq_dsq_id(qid, cand));
			if (!t || !bpf_cpumask_test_cpu((u32)cpu, t->cpus_ptr))
				continue;
			/*
			 * Prefer the earlier deadline, the same
			 * time_before64() order the kernel's priq
			 * uses (scx_dsq_priq_less()).
			 */
			if (!best || mlfq_time_before(t->scx.dsq_vtime,
						    best->scx.dsq_vtime)) {
				best = t;
				best_dsq = mlfq_dsq_id(qid, cand);
				best_cpu = (s32)cand;
			}
		}

		/* nothing eligible anywhere: this queue has no work */
		if (!best)
			break;

		scx_bpf_dsq_move_to_local(best_dsq, 0);
		moved++;
		if (cpu_state) {
			if (qid == 1)
				cpu_state->q1_dispatches++;
			else if (qid == 2)
				cpu_state->q2_dispatches++;
			else
				cpu_state->q3_dispatches++;
			if (best_cpu != cpu)
				cpu_state->steal_dispatches++;
		}
		if (best_cpu != cpu)
			__sync_fetch_and_add(&mlfq_stats.steals, 1);
	}

	return moved;
}

void BPF_STRUCT_OPS(mlfq_dispatch, s32 cpu, struct task_struct *prev)
{
	struct mlfq_cpu_state *cpu_state = mlfq_lookup_cpu_state(cpu);
	u64 nr_cpus = nr_cpu_ids;
	u32 remaining = mlfq_dispatch_max_batch;

	if (nr_cpus == 0)
		return;

	/*
	 * Advance the rotating scan start once per dispatch call. Q1
	 * always scans every candidate, so only the bounded Q2/Q3 windows
	 * consume the offset; per-call rotation keeps the window fair
	 * across CPUs without a per-slot cost.
	 */
	if (cpu_state)
		cpu_state->steal_scan_off++;

	/*
	 * Keep the outgoing task when nothing else is dispatchable here.
	 * If @prev is still queued and all three of the CPU's queue DSQs
	 * are empty, @prev is the only runnable work this CPU can take;
	 * the alternative is switching to idle with runnable work, which
	 * leaves the CPU parked until an external wakeup. Replenish the
	 * queue slice and place @prev on the local DSQ; the pick path then
	 * runs it without a context switch. Spurious inserts are safe
	 * because the kernel claims the task again in finish_dispatch()
	 * (ext.c), dropping the insert if @prev was concurrently dequeued.
	 *
	 * The kernel's automatic keep path (balance_one() setting
	 * SCX_RQ_BAL_KEEP) is available only while SCX_OPS_ENQ_LAST is
	 * clear. This scheduler sets SCX_OPS_ENQ_LAST, so ops.dispatch()
	 * itself must make the keep effective.
	 */
	if (prev && (prev->scx.flags & SCX_TASK_QUEUED) &&
	    !scx_bpf_dsq_nr_queued(mlfq_dsq_id(1, cpu)) &&
	    !scx_bpf_dsq_nr_queued(mlfq_dsq_id(2, cpu)) &&
	    !scx_bpf_dsq_nr_queued(mlfq_dsq_id(3, cpu))) {
		struct task_ctx *tctx = mlfq_lookup_task_ctx(prev);
		u8 qid;

		if (tctx) {
			qid = tctx->queue;
			if (qid >= 1 && qid <= MLFQ_NR_QUEUES) {
				u64 slice = mlfq_queue_slice(qid);

				scx_bpf_task_set_slice(prev, slice);
				scx_bpf_dsq_insert(prev, SCX_DSQ_LOCAL, slice, 0);
				__sync_fetch_and_add(&mlfq_stats.keep_running, 1);
			}
		}
		return;
	}

	/*
	 * Q1 then Q2 then Q3, each bounded by the dispatch batch. The
	 * quotas need no clamping: init() rejects configurations with
	 * Q1+Q2 >= dispatch_max_batch, so each fixed quota always fits in
	 * the batch remainder, and a zero remainder yields an empty slot
	 * loop.
	 */
	remaining -= mlfq_dispatch_queue(cpu, 1, mlfq_q1_quota,
					 cpu_state, nr_cpus);
	remaining -= mlfq_dispatch_queue(cpu, 2, mlfq_q2_quota,
					 cpu_state, nr_cpus);
	remaining -= mlfq_dispatch_queue(cpu, 3, remaining,
					 cpu_state, nr_cpus);
}
