/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * EEVDF virtual-time substrate, included by main.bpf.c via #include.
 *
 * The pure math lives in intf.h so the native harness compiles it
 * directly. This module wires that math to the per-queue sums with
 * lock-free atomics only. No spinlocks, no allocations, all loops use
 * bpf_for with static bounds. The queued sums exclude the running task;
 * placement, eligibility and the publish fold it back in when its queue
 * matches, the fair.c including-curr average, so service advances the
 * average without waiting for the next enqueue. The zero base moves
 * forward only, and stale reads stay eligible.
 */

static __always_inline struct queue_ctx *mlfq_lookup_queue(u32 qid)
{
	return bpf_map_lookup_elem(&queue_ctx_stor, &qid);
}

/*
 * Scaled weight for one update, with the queue shift applied. The shift
 * is usually zero, so this is the raw weight bounded below. The bound
 * keeps the denominator non-zero for empty queues.
 */
static __always_inline u64 mlfq_bpf_weight(struct queue_ctx *q, u32 weight)
{
	u64 w = weight ? weight : 1;

	if (w > 10000)
		w = 10000;
	if (q && q->sum_shift) {
		u32 s = q->sum_shift > MLFQ_SUM_SHIFT_MAX ? MLFQ_SUM_SHIFT_MAX : q->sum_shift;

		w >>= s;
	}
	if (w < MLFQ_AVG_MIN_WEIGHT)
		w = MLFQ_AVG_MIN_WEIGHT;
	return w;
}

/*
 * Add one queued task to the sums. The key is clamped to 32 bits either
 * way, so the product stays inside s64 even for a far vruntime. The two
 * adds are separate atomics, so a concurrent reader may see a torn pair.
 * The eligibility and average helpers treat a torn or stale pair as
 * eligible and monotone, so the tear heals on the next update.
 */
/* Sums join with the stored queue id. */
static __always_inline void mlfq_sum_add(struct queue_ctx *q, u64 vruntime, u32 weight)
{
	s64 key = (s64)(vruntime - q->zero_vruntime);
	u64 w;

	if (key > (s64)(1LL << 32))
		key = (s64)(1LL << 32);
	if (key < -(s64)(1LL << 32))
		key = -(s64)(1LL << 32);
	w = mlfq_bpf_weight(q, weight);
	__sync_fetch_and_add(&q->sum_w_vruntime, key * (s64)w);
	__sync_fetch_and_add(&q->sum_weight, (s64)w);
}

/*
 * Remove one queued task from the sums. The key is recomputed against
 * the current zero, so zero movement since the add is accounted for.
 * A missing entry (weight already zero) is a no-op for the average,
 * since the eligibility helper treats empty sums as eligible.
 */
static __always_inline void mlfq_sum_sub(struct queue_ctx *q, u64 vruntime, u32 weight)
{
	s64 key = (s64)(vruntime - q->zero_vruntime);
	u64 w;

	if (key > (s64)(1LL << 32))
		key = (s64)(1LL << 32);
	if (key < -(s64)(1LL << 32))
		key = -(s64)(1LL << 32);
	w = mlfq_bpf_weight(q, weight);
	__sync_fetch_and_add(&q->sum_w_vruntime, -(key * (s64)w));
	__sync_fetch_and_add(&q->sum_weight, -(s64)w);
}

/*
 * Leave the sums for a task that holds an entry. The subtract uses the
 * stored queue, the queue the task joined, not the queue it is about
 * to rejoin, so a queue change between the join and the leave cannot
 * corrupt the per-queue sums. A task with no entry (local DSQ or
 * running) is a no-op, so a local re-enqueue never double subtracts.
 * A corrupted stored queue clears the record without touching a sum.
 */
static __always_inline void mlfq_sums_leave(struct task_ctx *tctx)
{
	u8 sqid;
	struct queue_ctx *sq;

	if (!mlfq_sums_present(tctx))
		return;
	sqid = mlfq_sums_qid(tctx);
	if (sqid < 1 || sqid > MLFQ_NR_QUEUES) {
		mlfq_sums_clear(tctx);
		return;
	}
	sq = mlfq_lookup_queue(sqid);
	if (sq)
		mlfq_sum_sub(sq, tctx->vruntime, tctx->weight ? tctx->weight : 1);
	mlfq_sums_clear(tctx);
}

/*
 * Advance the zero base by delta and keep the sums consistent. Only a
 * forward delta moves the base, in wrapping order, so a heavy joiner
 * that is behind never pulls zero backward. The store is a single
 * compare and swap, so contention degrades to a stale base, never to
 * a convoy. The sum adjustment uses a stale weight read, so a
 * concurrent add or sub may shift the average by one entry, and the
 * next average publish heals it.
 */
/* Zero moves forward by one swap only. */
static __always_inline void mlfq_bpf_update_zero(struct queue_ctx *q, s64 delta)
{
	u64 zero;
	s64 w;

	if (!delta)
		return;
	if (delta < 0)
		return;
	zero = q->zero_vruntime;
	if (!mlfq_time_before(zero, zero + (u64)delta))
		return;
	w = q->sum_weight;
	if (__sync_val_compare_and_swap(&q->zero_vruntime, zero, zero + (u64)delta) == zero)
		__sync_fetch_and_add(&q->sum_w_vruntime, -(w * delta));
}

/*
 * Weighted average of the queue including the running task when it
 * belongs here. The caller passes the running vruntime and weight when
 * its queue matches, otherwise zero weight for queued only. The zero
 * base is advanced forward only with a single compare and swap, so
 * contention degrades to a stale average, never to a convoy. A stale
 * average stays eligible by construction in the eligibility helper.
 * The legacy clock is advanced alongside for observability.
 */
static __always_inline u64 mlfq_avg_bpf(struct queue_ctx *q, u64 curr_vruntime,
					u32 curr_weight, bool curr_valid)
{
	s64 sum_w = q->sum_w_vruntime;
	s64 sum_weight = q->sum_weight;
	u64 zero = q->zero_vruntime;
	s64 curr_key = 0;
	u64 curr_w = 0;
	u64 avg;

	if (curr_valid && curr_weight) {
		curr_key = (s64)(curr_vruntime - zero);
		if (curr_key > (s64)(1LL << 32))
			curr_key = (s64)(1LL << 32);
		if (curr_key < -(s64)(1LL << 32))
			curr_key = -(s64)(1LL << 32);
		curr_w = mlfq_bpf_weight(q, curr_weight);
	}
	avg = mlfq_avg_from_sums(sum_w, sum_weight, zero, curr_key, curr_w);
	/* Monotone gate, forward only in wrapping order. */
	if (avg != zero && mlfq_time_before(zero, avg)) {
		s64 delta = (s64)(avg - zero);

		if (__sync_val_compare_and_swap(&q->zero_vruntime, zero, avg) == zero)
			__sync_fetch_and_add(&q->sum_w_vruntime, -(sum_weight * delta));
	}
	if (mlfq_time_before(q->clock, avg))
		__sync_val_compare_and_swap(&q->clock, q->clock, avg);
	return avg;
}

/*
 * Eligibility of a vruntime against the queue sums, with the running
 * task included when it belongs here. Stale sums yield eligible, so a
 * torn read never starves a task. The 32 bit key clamp keeps the
 * product inside s64, and the helper in intf.h guards the residual
 * overflow by sign.
 */
static __always_inline bool mlfq_eligible_bpf(struct queue_ctx *q, u64 vruntime,
					      u64 curr_vruntime, u32 curr_weight,
					      bool curr_valid)
{
	s64 sum_w = q->sum_w_vruntime;
	s64 sum_weight = q->sum_weight;
	u64 zero = q->zero_vruntime;
	s64 curr_key = 0;
	u64 curr_w = 0;

	if (curr_valid && curr_weight) {
		curr_key = (s64)(curr_vruntime - zero);
		if (curr_key > (s64)(1LL << 32))
			curr_key = (s64)(1LL << 32);
		if (curr_key < -(s64)(1LL << 32))
			curr_key = -(s64)(1LL << 32);
		curr_w = mlfq_bpf_weight(q, curr_weight);
	}
	return mlfq_vruntime_eligible_raw(sum_w, sum_weight, zero, vruntime, curr_key, curr_w);
}

/*
 * Place @tctx into queue @qid against the queue average including the
 * running task on @target_cpu when it belongs here. No lock is taken.
 * The average is read stale, the lag is clamped signed and inflated,
 * and the sums are joined after the commit. A heavy joiner that is
 * ahead pulls zero forward so the next average does not overflow; a
 * joiner behind never moves zero backward. The placement clamp bounds
 * any error a stale average introduces. The queue id is clamped before
 * any lookup, so a corrupted queue cannot alias another CPU's DSQ.
 *
 * Gives the placement deadline, or 0 on lookup failure.
 */
static __always_inline u64 mlfq_place_task(u32 qid, struct task_ctx *tctx,
					   s32 pid, s32 target_cpu)
{
	u8 cqid = mlfq_clamp_qid(qid);
	u32 key = cqid;
	struct queue_ctx *q = mlfq_lookup_queue(key);
	u64 deadline;
	u64 limit;
	u64 w;
	u64 curr_vr = 0;
	u32 curr_w = 0;
	bool curr_valid = false;

	if (!q) {
		scx_bpf_error("pid %d queue %u lookup failed", pid, key);
		return 0;
	}

	if (target_cpu >= 0) {
		struct mlfq_cpu_state *st = mlfq_lookup_cpu_state(target_cpu);

		if (st && st->running_queue == cqid && st->running_weight) {
			curr_vr = st->running_vruntime;
			curr_w = st->running_weight;
			curr_valid = true;
		}
	}

	w = mlfq_bpf_weight(q, tctx->weight);
	deadline = mlfq_place_entity_with_curr(q, tctx, curr_vr, curr_w,
					       curr_valid);
	limit = mlfq_lag_limit(q, tctx->weight ? tctx->weight : 1);
#if MLFQ_CHECK
	if (!mlfq_check_queued_vlag(tctx->vlag, limit))
		scx_bpf_error("pid %d queue %u vlag %lld outside bound %llu", pid, key,
			      tctx->vlag, limit);
#endif
	/* Test the weight before the join, after it the test never fires. */
	{
		s64 old_sum = q->sum_weight;
		bool heavy = old_sum >= 0 ? w > (u64)old_sum : false;

		/* Join the sums after the commit, so the average excluded us. */
		mlfq_sum_add(q, tctx->vruntime, tctx->weight ? tctx->weight : 1);
		mlfq_sums_set(tctx, cqid);
		/* A heavy joiner ahead pulls zero forward to keep keys small. */
		if (heavy && tctx->vlag < 0)
			mlfq_bpf_update_zero(q, -(s64)tctx->vlag / 2);
	}
	(void)limit;
	return deadline;
}

/*
 * mlfq_update_vruntime - Advance a task's virtual runtime for a run segment.
 * @tctx: The task.
 * @delta_ns: Physical run time in nsecs.
 *
 * vruntime grows by the weighted delta. The weight mapping guards zero,
 * so a corrupted cache never divides by zero.
 */
static __always_inline void mlfq_update_vruntime(struct task_ctx *tctx,
						 u64 delta_ns)
{
	u32 w = mlfq_eevdf_weight(tctx->weight);

	tctx->vruntime += calc_delta_fair_bpf(delta_ns, w);
}

/*
 * Publish the average after service. Called after the charge and the
 * deadline refresh, in that order. The running task is included when it
 * belongs to this queue, so the average tracks service without waiting
 * for the next enqueue. The update is monotone and single shot.
 */
static __always_inline void mlfq_publish_avg(struct queue_ctx *q, struct task_ctx *tctx)
{
	bool is_curr = false;
	u64 curr_vr = 0;
	u32 curr_w = 0;

	if (tctx) {
		curr_vr = tctx->vruntime;
		curr_w = tctx->weight ? tctx->weight : 1;
		is_curr = true;
	}
	mlfq_avg_bpf(q, curr_vr, curr_w, is_curr);
}
