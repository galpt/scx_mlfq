/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Classification, the wakeup promotion and run-out demotion paths.
 *
 * The burst gauge is the classification input. It climbs per run
 * segment in stopping() and decays per sleep at wakeup by the CBS
 * period step (see mlfq_gauge_decay() in intf.h). Queue changes are
 * asymmetric. The wakeup path is promotion-only. The short-sleep and
 * I/O boost and the gauge-gated hysteresis raise the queue, and no
 * wakeup can ever demote a task. Demotions flow through the run-out
 * gate, whose consecutive-exhaustion counter (mlfq_demote_on_reenq in
 * intf.h) implements the demotion hysteresis.
 */

#include <bpf/bpf_core_read.h>

/*
 * in_iowait guard. task_struct::in_iowait is a 1-bit bitfield read with
 * BPF_CORE_READ_BITFIELD. Define MLFQ_HAVE_IN_IOWAIT to 0 when the
 * kernel type header does not expose the field.
 */
#ifndef MLFQ_HAVE_IN_IOWAIT
#define MLFQ_HAVE_IN_IOWAIT 1
#endif

/*
 * uclamp_min guard. task_struct::uclamp_req only exists with
 * CONFIG_UCLAMP_TASK. The kernel type header used for this build does
 * not expose it, so the guard is compiled out. Define
 * MLFQ_HAVE_TASK_UCLAMP_MIN to 1 when the kernel type header provides
 * the field.
 */
#ifndef MLFQ_HAVE_TASK_UCLAMP_MIN
#define MLFQ_HAVE_TASK_UCLAMP_MIN 0
#endif

static __always_inline bool mlfq_demotion_blocked(const struct task_struct *p)
{
#if MLFQ_HAVE_TASK_UCLAMP_MIN
	/* UCLAMP_MIN > 0 marks a latency-sensitive task. Keep its queue. */
	return BPF_CORE_READ(p, uclamp_req[0].value) > 0;
#else
	(void)p;
	return false;
#endif
}

/*
 * The task is waking from I/O when task_struct::in_iowait is set. The
 * bitfield is read with the CO-RE bitfield macro (direct memory read is
 * fine for the trusted task pointer ops.enqueue receives). The parameter
 * is intentionally not named p, because BPF_CORE_READ_BITFIELD() declares
 * its own local named p and would shadow it.
 *
 * Return: true if @task is an I/O waiter.
 */
static __always_inline bool mlfq_task_io_wait(const struct task_struct *task)
{
#if MLFQ_HAVE_IN_IOWAIT
	return BPF_CORE_READ_BITFIELD(task, in_iowait);
#else
	(void)task;
	return false;
#endif
}

/*
 * SCHED_IDLE tasks always run in Q3.
 *
 * Return: true if @p is SCHED_IDLE.
 */
static __always_inline bool mlfq_apply_sched_idle(const struct task_struct *p,
						  struct task_ctx *tctx)
{
	if (p->policy == MLFQ_SCHED_IDLE) {
		tctx->queue = 3;
		return true;
	}
	return false;
}

/*
 * mlfq_wakeup_classify - Wakeup classification.
 * @p: The task.
 * @tctx: The task context.
 * @now: Current time (scx_bpf_now()).
 *
 * Applies, in order, the gauge decay over the sleep, the rate-limited
 * short-sleep and I/O boost, and the gauge-gated hysteresis promotion.
 * It updates the boost and promotion stats.
 *
 * The wakeup path is promotion-only. The boost and the hysteresis are
 * the only queue moves, so a single wakeup can never demote a task and
 * bypass the exhaustion hysteresis. The base band mapping
 * (mlfq_queue_from_gauge) is deliberately not applied here. A task
 * that qualifies for neither the boost nor the hysteresis keeps its
 * current queue.
 */
static __always_inline void mlfq_wakeup_classify(const struct task_struct *p,
						 struct task_ctx *tctx, u64 now)
{
	u64 sleep_ns = 0;
	bool io_wait = mlfq_task_io_wait(p);

	/*
	 * Decay the gauge by the CBS period step of the task's current
	 * queue. The queue is the pre-wakeup queue, so the decay uses the
	 * server the task was last served by. A wrap-guarded sleep delta
	 * computes to zero and leaves the gauge untouched, which is
	 * directionally conservative toward CPU-bound.
	 */
	if (tctx->last_sleep_at && mlfq_time_before(tctx->last_sleep_at, now)) {
		struct queue_ctx *q = mlfq_lookup_queue(tctx->queue);

		sleep_ns = now - tctx->last_sleep_at;
		if (q && q->max_slice_ns) {
			u64 q_i = q->max_slice_ns;
			u64 p_i = q_i * MLFQ_CBS_PERIOD_MULT;

			tctx->g = mlfq_gauge_decay(tctx->g, sleep_ns, q_i, p_i);
#if MLFQ_CHECK
			if (!mlfq_check_gauge_bounds(tctx->g, mlfq_gauge_max_ns))
				scx_bpf_error("pid %d gauge %llu out of bounds "
					      "after decay", p->pid, tctx->g);
#endif
		}
	}
	tctx->last_sleep_at = 0;
	tctx->reenq_cnt = 0;

	/*
	 * The IPC boost. A wakeup from I/O or a short sleep is treated as
	 * interactive and placed in Q1, rate-limited per task (the
	 * stand-in for the kernel's futex/IPC wakeup fast paths). The
	 * rate limit is part of mlfq_ss_boost_pending(), which the CPU
	 * selection also consults so the two paths agree on whether the
	 * wakeup will be treated as interactive. The boost is
	 * unconditional, so a task with a saturated gauge still gets it.
	 * SCHED_IDLE tasks are forced to Q3 by mlfq_apply_sched_idle, so
	 * a boost would burn the rate-limit budget to no effect. It is
	 * gated on the task policy.
	 */
	if (p->policy != MLFQ_SCHED_IDLE &&
	    mlfq_ss_boost_pending(tctx, sleep_ns, io_wait, now,
				  mlfq_short_sleep_ns, mlfq_short_sleep_rate_limit_ns)) {
		tctx->queue = 1;
		tctx->last_ss_boost_at = now;
		__sync_fetch_and_add(&mlfq_stats.short_sleep_boosts, 1);
	}

	/*
	 * The hysteresis promotion. Two consecutive short sleeps with a
	 * decayed gauge below half the band edge raise the queue one
	 * step. The boost above already moved the task to Q1, so the
	 * hysteresis only fires for tasks the boost did not cover.
	 */
	if (mlfq_promote_on_wakeup(tctx, sleep_ns,
				   mlfq_t_l_ns, mlfq_t_h_ns,
				   mlfq_hysteresis_sleep_ns))
		__sync_fetch_and_add(&mlfq_stats.promotions, 1);
}

/*
 * mlfq_runout_classify - Slice-exhaustion demotion.
 * @p: The task.
 * @tctx: The task context.
 *
 * The run-out re-enqueue arrives through ops.enqueue() with flags == 0,
 * delivered by put_prev_task_scx()'s do_enqueue_task(rq, p, 0, -1), and is
 * the scx equivalent of the tick/demotion path. It is the only enqueue
 * without flag bits, which identifies it at the routing in enqueue(). The
 * consecutive-exhaustion counter saturates at MLFQ_DEMOTE_EXHAUSTIONS
 * and gates the band crossing, the gauge test g >= T_H is the CPU-bound
 * test, and uclamp_min tasks keep their queue.
 */
static __always_inline void mlfq_runout_classify(const struct task_struct *p,
						 struct task_ctx *tctx)
{
	tctx->wake_cnt = 0;

	/*
	 * A uclamp_min task keeps its queue. The early return also
	 * freezes the exhaustion counter, so a blocked task never
	 * accumulates history it did not earn.
	 */
	if (mlfq_demotion_blocked(p))
		return;
	if (mlfq_demote_on_reenq(tctx, mlfq_t_h_ns))
		__sync_fetch_and_add(&mlfq_stats.demotions, 1);
}