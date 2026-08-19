/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Classification, the wakeup promotion and run-out demotion paths.
 *
 * The EMA interactivity gauge is the classification input. It climbs
 * per run segment in stopping() and decays per sleep at wakeup by the
 * half-life step (see mlfq_ema_climb()/mlfq_ema_decay() in intf.h).
 * The decay is sampled per task: it runs at most once per
 * MLFQ_CLASSIFY_INTERVAL_NS, so a wakeup burst pays only the boost and
 * hysteresis on the interleaved wakeups. Queue changes are asymmetric.
 * The wakeup path is promotion-only. The short-sleep and I/O boost and
 * the gauge-gated hysteresis raise the queue, and no wakeup can ever
 * demote a task. Demotions flow through the run-out gate, whose
 * consecutive-exhaustion counter (mlfq_demote_on_reenq in intf.h)
 * implements the demotion hysteresis.
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
 * Climb the EMA gauge for a run segment (stopping path). The delta is
 * clamped by mlfq_ema_climb(), so a CPU-bound task saturates the gauge
 * and the classification thresholds keep it out of Q1.
 */
static __always_inline void mlfq_ema_climb_task(struct task_ctx *tctx,
						u64 delta_ns)
{
	tctx->ema = mlfq_ema_climb(tctx->ema, delta_ns, mlfq_budget_max_ns,
				   mlfq_alpha);
#if MLFQ_CHECK
	if (!mlfq_check_ema_bounds(tctx->ema, mlfq_budget_max_ns))
		scx_bpf_error("ema %llu exceeds budget max after climb",
			      tctx->ema);
#endif
}

/*
 * mlfq_wakeup_classify - Wakeup classification.
 * @p: The task.
 * @tctx: The task context.
 * @now: Current time (scx_bpf_now()).
 *
 * The wakeup path is promotion-only. The boost and the hysteresis are
 * the only queue moves, so a single wakeup can never demote a task and
 * bypass the exhaustion hysteresis. The base band mapping
 * (mlfq_queue_from_ema) is deliberately not applied here except after a
 * long sleep, which collapses the gauge and re-adopts the base mapping
 * so an interactive task cannot be stuck in Q3. A task that qualifies
 * for neither the boost nor the hysteresis keeps its current queue.
 *
 * The EMA decay runs at most once per MLFQ_CLASSIFY_INTERVAL_NS per
 * task. The interleaved wakeups pay only the boost and hysteresis
 * comparisons. The decay is deferred until the window elapses and is
 * then applied to the whole sleep that accumulated since the last
 * decay, so the band edge is reached on the same total sleep; only the
 * division is amortized. A wrap-guarded sleep delta computes to zero
 * and leaves the gauge untouched, which is directionally conservative
 * toward CPU-bound.
 */
static __always_inline void mlfq_wakeup_classify(const struct task_struct *p,
						 struct task_ctx *tctx, u64 now)
{
	u64 sleep_ns = 0, base_q;
	bool io_wait = mlfq_task_io_wait(p);

	if (mlfq_time_before(tctx->last_sleep_at, now))
		sleep_ns = now - tctx->last_sleep_at;

	if (mlfq_time_before(now, tctx->next_classify_at))
		goto samples;

	if (tctx->last_sleep_at && mlfq_time_before(tctx->last_sleep_at, now)) {
		tctx->ema = mlfq_ema_decay(tctx->ema, sleep_ns,
					   mlfq_ema_half_life_ns);
#if MLFQ_CHECK
		if (!mlfq_check_ema_bounds(tctx->ema, mlfq_budget_max_ns))
			scx_bpf_error("pid %d ema %llu out of bounds after decay",
				      p->pid, tctx->ema);
#endif
	}
	tctx->last_sleep_at = 0;
	tctx->reenq_cnt = 0;
	tctx->next_classify_at = now + MLFQ_CLASSIFY_INTERVAL_NS;

samples:
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
		mlfq_stat_add(short_sleep_boosts, 1);
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
		mlfq_stat_add(promotions, 1);

	/*
	 * A long sleep collapses the gauge; re-adopt the base mapping so
	 * an interactive task cannot be stuck in Q3.
	 */
	if (sleep_ns > mlfq_long_sleep_ns) {
		base_q = mlfq_queue_from_ema(tctx->ema, mlfq_t_l_ns,
					     mlfq_t_h_ns);
		if (base_q < tctx->queue) {
			tctx->queue = base_q;
			mlfq_stat_add(promotions, 1);
		}
	}
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
 * and gates the band crossing, the gauge test ema >= T_H is the
 * CPU-bound test, and uclamp_min tasks keep their queue.
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
		mlfq_stat_add(demotions, 1);
}
