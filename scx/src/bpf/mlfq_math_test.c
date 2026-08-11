/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Native unit tests for the scx_mlfq pure-logic layer (intf.h). Compiles
 * the same header the BPF code and the Rust bindings use, with MLFQ_CHECK
 * forced on so the invariant predicates are exercised too. Runs on the
 * host with no kernel, BTF or BPF privileges, driven by the Rust unit
 * test in main.rs.
 */

#define MLFQ_CHECK 1
#include "intf.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static int nr_failed;

#define TEST_OK(cond, fmt, ...)						\
	do {								\
		if (cond) {						\
			printf("PASS: " fmt "\n", ##__VA_ARGS__);	\
		} else {						\
			printf("FAIL: " fmt "\n", ##__VA_ARGS__);	\
			nr_failed++;					\
		}							\
	} while (0)

/* Virtual time scales as delta * 100 / weight. */
static void test_calc_delta_fair(void)
{
	TEST_OK(calc_delta_fair_bpf(1000000, 100) == 1000000,
		"delta 1ms weight 100 -> 1ms virtual");
	TEST_OK(calc_delta_fair_bpf(1000000, 200) == 500000,
		"delta 1ms weight 200 -> 0.5ms virtual");
	TEST_OK(calc_delta_fair_bpf(1000000, 1) == 100000000,
		"delta 1ms weight 1 -> 100ms virtual");
	TEST_OK(calc_delta_fair_bpf(1000000, 10000) == 10000,
		"delta 1ms weight 10000 -> 10us virtual");
}

static struct queue_ctx make_q(u64 clock, u64 max_slice_ns)
{
	struct queue_ctx q = {
		.clock = clock,
		.max_slice_ns = max_slice_ns,
	};

	return q;
}

static void test_place_entity(void)
{
	struct queue_ctx q;
	struct task_ctx t;

	/* Empty clock at 0, weight 100, Q2 slice: deadline == vslice == 2ms. */
	q = make_q(0, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	TEST_OK(mlfq_place_entity(&q, &t) == 2000000 &&
		t.vruntime == 0 && t.vlag == 0 && t.deadline == 2000000,
		"first placement: vruntime 0, vlag 0, deadline 2ms");

	/*
	 * A task far behind the clock is clamped to clock - limit, the
	 * fair.c bounded-lag property: lag saturates at limit and the
	 * placed vruntime never falls more than one lag bound behind the
	 * service point. limit = 3ms virtual at weight 100.
	 */
	q = make_q(1ULL << 40, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.vruntime = 0;
	TEST_OK(mlfq_place_entity(&q, &t) == (1ULL << 40) - 1000000 &&
		t.vruntime == (1ULL << 40) - 3000000 && t.vlag == 3000000,
		"behind task clamped to clock - limit, lag at the bound");

	/*
	 * An ahead task is placed at the clock (fair.c DELAY_ZERO):
	 * leading credit is not carried, so the negative lag case is
	 * collapsed to zero.
	 */
	q = make_q(1000, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.vruntime = 1ULL << 40;
	TEST_OK(mlfq_place_entity(&q, &t) == 2001000 &&
		t.vruntime == 1000 && t.vlag == 0,
		"ahead task placed at the clock, vlag 0");

	/*
	 * An in-band task (within one lag limit behind the clock) keeps
	 * its vruntime; its lag and deadline follow the placement formulas.
	 */
	q = make_q(1000000, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.vruntime = 800000;
	TEST_OK(mlfq_place_entity(&q, &t) == 2800000 &&
		t.vruntime == 800000 && t.vlag == 200000 &&
		t.deadline == 2800000,
		"in-band task keeps its vruntime, deadline = vruntime + vslice");

	/* deadline = vruntime_new + vslice, with FIRST_RUN halving once. */
	q = make_q(0, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.flags = MLFQ_TF_FIRST_RUN;
	TEST_OK(mlfq_place_entity(&q, &t) == 1000000,
		"FIRST_RUN deadline is half vslice (1ms)");
	t.flags &= ~MLFQ_TF_FIRST_RUN;
	TEST_OK(mlfq_place_entity(&q, &t) == 2000000,
		"after FIRST_RUN clears the full vslice applies");

	/*
	 * A wrapped deadline that would compute to zero is bumped to one
	 * (the sentinel for a failed placement); the position is identical
	 * in the wrapping order the DSQ rbtree uses.
	 */
	q = make_q(0ULL - 1000000ULL, 1000000);	/* clock one slice before wrap */
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.vruntime = q.clock;	/* task exactly at the clock, lag 0 */
	TEST_OK(mlfq_place_entity(&q, &t) == 1 && t.deadline == 1,
		"wrapped deadline that would be zero is bumped to 1");
}

/*
 * The lag bound scales with the weight: a weight-1 task may lag up to
 * 100x the request size behind the clock, a weight-10000 task only
 * 1% of it. The clamp holds at both extremes.
 */
static void test_place_entity_weight_edges(void)
{
	struct queue_ctx q;
	struct task_ctx t;

	q = make_q(1ULL << 40, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 1;
	t.vruntime = 0;
	TEST_OK(mlfq_place_entity(&q, &t) == (1ULL << 40) - 100000000ULL &&
		t.vruntime == (1ULL << 40) - 300000000ULL &&
		t.vlag == 300000000ULL,
		"weight 1: lag clamped to 100x the request size");

	q = make_q(1ULL << 40, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 10000;
	t.vruntime = 0;
	TEST_OK(mlfq_place_entity(&q, &t) == (1ULL << 40) - 30000ULL + 20000ULL &&
		t.vruntime == (1ULL << 40) - 30000ULL && t.vlag == 30000ULL,
		"weight 10000: lag clamped to 1/100 of the request size");
}

/*
 * Placement, charge and re-placement form the per-queue service loop:
 * the clock advances to the vruntime just charged, and the next
 * placement of the same task measures its lag from the fresh clock.
 */
static void test_place_charge_replacement(void)
{
	struct queue_ctx q;
	struct task_ctx t;

	q = make_q(1ULL << 40, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.vruntime = q.clock - 1000000;	/* one ms behind the clock */
	mlfq_place_entity(&q, &t);
	TEST_OK(t.vruntime == q.clock - 1000000 && t.vlag == 1000000,
		"in-band task placed with its lag preserved");

	mlfq_queue_advance_clock(&q, t.vruntime);
	TEST_OK(q.clock == (1ULL << 40),
		"a task behind the clock does not advance it");

	/*
	 * The task runs a full slice: the charge is its vruntime plus
	 * the slice's virtual time, which lands ahead of the clock.
	 */
	t.vruntime += 2000000;
	mlfq_queue_advance_clock(&q, t.vruntime);
	TEST_OK(q.clock == t.vruntime,
		"clock advances to the vruntime charged for a full slice");

	t.vruntime = q.clock - 500000;	/* now only 0.5 ms behind */
	mlfq_place_entity(&q, &t);
	TEST_OK(t.vruntime == q.clock - 500000 && t.vlag == 500000,
		"re-placement measures the lag from the advanced clock");
}

/*
 * The read-only deadline form must agree with the committed placement on
 * the same pre-placement state, and must not mutate the task state: the
 * wakeup-preemption path compares the fresh deadline before any placement
 * is committed.
 */
static void test_place_entity_deadline_pure(void)
{
	struct queue_ctx q;
	struct task_ctx t, before;

	q = make_q(1ULL << 40, 2000000);
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.vruntime = 0;

	before = t;
	mlfq_place_entity_deadline(&q, &t);
	TEST_OK(t.vruntime == before.vruntime && t.vlag == before.vlag &&
		t.deadline == before.deadline,
		"pure deadline does not mutate the task state");
	TEST_OK(mlfq_place_entity_deadline(&q, &t) ==
		mlfq_place_entity(&q, &t),
		"pure deadline equals the committed placement deadline");

	/* FIRST_RUN halves the vslice in both forms. */
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.flags = MLFQ_TF_FIRST_RUN;
	TEST_OK(mlfq_place_entity_deadline(&q, &t) ==
		mlfq_place_entity(&q, &t),
		"pure deadline matches the committed placement with FIRST_RUN");

	/* The wrap-to-one deadline handling is shared. */
	q = make_q(0ULL - 1000000ULL, 1000000);	/* clock one slice before wrap */
	memset(&t, 0, sizeof(t));
	t.weight = 100;
	t.vruntime = q.clock;	/* task exactly at the clock, lag 0 */
	TEST_OK(mlfq_place_entity_deadline(&q, &t) == 1 &&
		mlfq_place_entity(&q, &t) == 1,
		"pure deadline shares the wrap-to-one deadline handling");
}

static void test_sameq_preempt_owed(void)
{
	u64 now = 1000000000;

	/*
	 * Interactive (Q1 onto Q1): the residency guard alone decides, with
	 * no deadline comparison.
	 */
	TEST_OK(mlfq_sameq_preempt_owed(1, 1, 0, 0, now - 500000, now, 50000),
		"Q1 wakeup preempts an interactive resident past the guard");
	TEST_OK(!mlfq_sameq_preempt_owed(1, 1, 0, 0, now - 40000, now, 50000),
		"Q1 wakeup below the guard does not preempt");
	TEST_OK(mlfq_sameq_preempt_owed(1, 1, 2000000, 1000000, now - 500000,
				       now, 50000),
		"Q1 preempts even with a later wakeup deadline (guard only)");
	TEST_OK(mlfq_sameq_preempt_owed(1, 1, 0, 0, now - 500000, now, 50000),
		"Q1 preemption does not depend on the resident deadline");

	/* Q1 with an unknown run start is conservative: blocked past zero. */
	TEST_OK(!mlfq_sameq_preempt_owed(1, 1, 0, 0, 0, now, 50000),
		"Q1 with unknown run start is blocked past a zero guard");
	TEST_OK(mlfq_sameq_preempt_owed(1, 1, 0, 0, 0, now, 0),
		"Q1 with guard 0 preempts despite the unknown run start");

	/*
	 * Non-interactive (Q2/Q3) same-queue: the guard gates the deadline
	 * rule, the conservative EEVDF test.
	 */
	TEST_OK(mlfq_sameq_preempt_owed(2, 2, 500000, 1000000, now - 5000000,
				       now, 0),
		"Q2 earlier wakeup deadline preempts (guard 0)");
	TEST_OK(!mlfq_sameq_preempt_owed(2, 2, 1500000, 1000000, now - 5000000,
					now, 0),
		"Q2 later wakeup deadline does not preempt (guard 0)");
	TEST_OK(!mlfq_sameq_preempt_owed(3, 3, 1000000, 1000000, now - 5000000,
					now, 0),
		"Q3 equal deadlines do not preempt");
	TEST_OK(!mlfq_sameq_preempt_owed(2, 2, 500000, 1000000, now - 100000,
					now, 200000),
		"Q2 residency below the guard blocks an earlier deadline");
	TEST_OK(mlfq_sameq_preempt_owed(2, 2, 500000, 1000000, now - 500000,
				       now, 200000),
		"Q2 residency above the guard allows an earlier deadline");
	TEST_OK(!mlfq_sameq_preempt_owed(2, 2, 500000, 0, now - 5000000, now, 0),
		"Q2 unknown resident deadline never owes");
	TEST_OK(!mlfq_sameq_preempt_owed(2, 2, 0, 1000000, now - 5000000, now, 0),
		"Q2 unknown wakeup deadline (failed placement) never owes");
	TEST_OK(!mlfq_sameq_preempt_owed(3, 3, 500000, 1000000, 0, now, 200000),
		"Q3 unknown run start cannot prove a non-zero guard");

	/*
	 * Wrapping: a wakeup deadline just before the u64 epoch boundary
	 * is earlier than a resident deadline just after it.
	 */
	TEST_OK(mlfq_sameq_preempt_owed(2, 2, 0ULL - 100ULL, 1000,
					now - 5000000, now, 0),
		"wrapped wakeup deadline is earlier across the epoch");
	TEST_OK(!mlfq_sameq_preempt_owed(2, 2, 1000, 0ULL - 100ULL,
					 now - 5000000, now, 0),
		"wrapped resident deadline is earlier (wakeup later)");
}

static void test_clock_advance(void)
{
	struct queue_ctx q = make_q(1000, 2000000);

	mlfq_queue_advance_clock(&q, 5000);
	TEST_OK(q.clock == 5000,
		"advance to a larger vruntime advances the clock");
	mlfq_queue_advance_clock(&q, 100);
	TEST_OK(q.clock == 5000,
		"advance to a smaller vruntime is ignored (monotone)");
	mlfq_queue_advance_clock(&q, 5000);
	TEST_OK(q.clock == 5000,
		"equal vruntime leaves the clock unchanged");

	q = make_q(0ULL - 100ULL, 2000000);
	mlfq_queue_advance_clock(&q, 10);
	TEST_OK(q.clock == 10,
		"wrapped advance across the u64 boundary is followed");
}

static void test_ema_climb(void)
{
	TEST_OK(mlfq_ema_climb(0, 250000, 6000000, 3072) == 3000000,
		"0 + 250us run -> half the gauge");
	TEST_OK(mlfq_ema_climb(0, 1000000, 6000000, 3072) == 6000000,
		"0 + 1ms run saturates the gauge (step clamped)");
	TEST_OK(mlfq_ema_climb(3000000, 250000, 6000000, 3072) == 4500000,
		"half gauge + 250us -> three quarters");
	TEST_OK(mlfq_ema_climb(6000000, 1000000, 6000000, 3072) == 6000000,
		"gauge never exceeds budget max");
}

static void test_ema_decay(void)
{
	u64 d;

	TEST_OK(mlfq_ema_decay(6000000, 24000000, 24000000) == 3000000,
		"one half-life halves the gauge");
	TEST_OK(mlfq_ema_decay(6000000, 120000000, 24000000) == 187500,
		"five half-lives divide by 32");
	TEST_OK(mlfq_ema_decay(6000000, 24ULL * 64 * 1000000, 24000000) == 0,
		"64 periods zero the gauge");

	d = mlfq_ema_decay(6000000, 36000000, 24000000); /* 1.5 periods */
	TEST_OK(d < 3000000 && d >= 1500000,
		"1.5-period decay lands between one and two periods");
	TEST_OK(mlfq_ema_decay(6000000, 1000000, 24000000) < 6000000,
		"sub-period Taylor residual decays strictly");
}

static void test_queue_mapping(void)
{
	TEST_OK(mlfq_queue_from_ema(0, 250000, 2000000) == 1,
		"ema 0 -> Q1");
	TEST_OK(mlfq_queue_from_ema(250000, 250000, 2000000) == 1,
		"ema == T_L -> Q1");
	TEST_OK(mlfq_queue_from_ema(250001, 250000, 2000000) == 2,
		"ema just above T_L -> Q2");
	TEST_OK(mlfq_queue_from_ema(1000000, 250000, 2000000) == 2,
		"ema 1ms -> Q2");
	TEST_OK(mlfq_queue_from_ema(2000000, 250000, 2000000) == 3,
		"ema == T_H -> Q3");
	TEST_OK(mlfq_queue_from_ema(5000000, 250000, 2000000) == 3,
		"ema 5ms -> Q3");
}

static void test_promote_hysteresis(void)
{
	struct task_ctx t = { .queue = 2, .ema = 0 };

	TEST_OK(!mlfq_promote_on_wakeup(&t, 1000000, 250000, 2000000, 4000000) &&
		t.wake_cnt == 1 && t.queue == 2,
		"single short sleep does not promote Q2->Q1");
	TEST_OK(mlfq_promote_on_wakeup(&t, 1000000, 250000, 2000000, 4000000) &&
		t.queue == 1 && t.wake_cnt == 0,
		"two short sleeps promote Q2->Q1 and reset wake_cnt");
	mlfq_promote_on_wakeup(&t, 10000000, 250000, 2000000, 4000000);
	TEST_OK(t.wake_cnt == 0 && t.queue == 1,
		"long sleep resets wake_cnt, Q1 stays");

	t.queue = 3;
	t.ema = 0;
	t.wake_cnt = 0;
	mlfq_promote_on_wakeup(&t, 1000000, 250000, 2000000, 4000000);
	TEST_OK(mlfq_promote_on_wakeup(&t, 1000000, 250000, 2000000, 4000000) &&
		t.queue == 2,
		"two short sleeps promote Q3->Q2");

	t.queue = 3;
	t.ema = 1000000;	/* not < T_H/2 */
	t.wake_cnt = 0;
	mlfq_promote_on_wakeup(&t, 1000000, 250000, 2000000, 4000000);
	TEST_OK(!mlfq_promote_on_wakeup(&t, 1000000, 250000, 2000000, 4000000) &&
		t.queue == 3,
		"ema above T_H/2 blocks Q3->Q2 despite two short sleeps");
}

/*
 * The demotion gate switches on the predictor: pred == 0 is the
 * untrained fallback (the plain EMA-gauge test), and a
 * trained prediction gates the CPU-bound test on the band bound
 * instead, with the consecutive-exhaustion and queue <= 2 gates shared.
 */
static void test_demote_hysteresis(void)
{
	struct task_ctx t = { .queue = 1, .ema = 500000 };

	mlfq_demote_on_reenq(&t, 2000000, 0);
	TEST_OK(t.reenq_cnt == 1 && t.queue == 1,
		"untrained: single run-out with ema > T_L does not demote Q1->Q2");
	mlfq_demote_on_reenq(&t, 2000000, 0);
	TEST_OK(t.reenq_cnt == 2 && t.queue == 1,
		"untrained: two run-outs with ema below T_H do not demote Q1->Q2");

	t.queue = 1;
	t.ema = 3000000;	/* > T_H */
	t.reenq_cnt = 0;
	for (int i = 0; i < 7; i++)
		mlfq_demote_on_reenq(&t, 2000000, 0);
	TEST_OK(t.reenq_cnt == 7 && t.queue == 1,
		"untrained: seven run-outs with ema > T_H do not demote Q1->Q2");
	TEST_OK(mlfq_demote_on_reenq(&t, 2000000, 0) &&
		t.queue == 2 && t.reenq_cnt == 0,
		"untrained: eight run-outs demote Q1->Q2 and reset reenq_cnt");

	t.queue = 2;
	t.ema = 3000000;	/* > T_H */
	t.reenq_cnt = 0;
	for (int i = 0; i < 7; i++)
		mlfq_demote_on_reenq(&t, 2000000, 0);
	TEST_OK(t.reenq_cnt == 7 && t.queue == 2,
		"untrained: seven run-outs with ema > T_H do not demote Q2->Q3");
	TEST_OK(mlfq_demote_on_reenq(&t, 2000000, 0) &&
		t.queue == 3 && t.reenq_cnt == 0,
		"untrained: eight run-outs demote Q2->Q3 and reset reenq_cnt");

	/*
	 * Trained path: the prediction gates the CPU-bound test, so a
	 * low prediction never demotes regardless of the gauge, and a
	 * Q3-bound prediction demotes on the same exhaustion count.
	 */
	t.queue = 1;
	t.ema = 3000000;	/* > T_H, but pred is the gate now */
	t.reenq_cnt = 0;
	for (int i = 0; i < 8; i++)
		mlfq_demote_on_reenq(&t, 2000000, 1000000);	/* < T_BOUND */
	TEST_OK(t.queue == 1 && t.reenq_cnt == 8,
		"trained: a sub-band prediction never demotes, even with ema > T_H");

	t.queue = 1;
	t.ema = 0;		/* gauge idle, pred is the gate now */
	t.reenq_cnt = 0;
	for (int i = 0; i < 7; i++)
		mlfq_demote_on_reenq(&t, 2000000, MLFQ_TREE_T_BOUND_NS);
	TEST_OK(t.reenq_cnt == 7 && t.queue == 1,
		"trained: seven Q3-bound predictions do not demote Q1->Q2");
	TEST_OK(mlfq_demote_on_reenq(&t, 2000000, MLFQ_TREE_T_BOUND_NS) &&
		t.queue == 2 && t.reenq_cnt == 0,
		"trained: eight Q3-bound predictions demote Q1->Q2");

	/* Q3 (queue 3) is never demoted by the exhaustion gate. */
	t.queue = 3;
	t.ema = 3000000;
	t.reenq_cnt = 0;
	for (int i = 0; i < 8; i++)
		mlfq_demote_on_reenq(&t, 2000000, MLFQ_TREE_T_BOUND_NS);
	TEST_OK(t.queue == 3,
		"trained: Q3 is never demoted by the exhaustion gate");
}

static void test_mlfq_check_predicates(void)
{
	TEST_OK(mlfq_check_ema_bounds(6000000, 6000000),
		"ema == budget max is in bounds");
	TEST_OK(!mlfq_check_ema_bounds(6000001, 6000000),
		"ema above budget max is out of bounds");
	TEST_OK(mlfq_check_queue(1) && mlfq_check_queue(3),
		"queues 1 and 3 are valid");
	TEST_OK(!mlfq_check_queue(0) && !mlfq_check_queue(4),
		"queues 0 and 4 are invalid");
	TEST_OK(mlfq_check_weight(1) && !mlfq_check_weight(0),
		"weight >= 1 invariant");
	TEST_OK(mlfq_check_queued_vlag(0) && !mlfq_check_queued_vlag(-1),
		"queued lag >= 0 invariant");
}

static void test_bitmap(void)
{
	struct mlfq_bitmap bm;

	memset(&bm, 0, sizeof(bm));

	mlfq_bitmap_set_cpu(&bm, 0);
	mlfq_bitmap_set_cpu(&bm, 1);
	mlfq_bitmap_set_cpu(&bm, 64);
	mlfq_bitmap_set_cpu(&bm, 1023);
	mlfq_bitmap_set_cpu(&bm, 1024);	/* out of range, ignored */

	TEST_OK(mlfq_bitmap_test_cpu(&bm, 0) && mlfq_bitmap_test_cpu(&bm, 1),
		"bits 0 and 1 set in word 0");
	TEST_OK(mlfq_bitmap_test_cpu(&bm, 64),
		"bit 64 set in word 1");
	TEST_OK(mlfq_bitmap_test_cpu(&bm, 1023),
		"bit 1023 set in word 15");
	TEST_OK(!mlfq_bitmap_test_cpu(&bm, 2),
		"bit 2 not set");
	TEST_OK(!mlfq_bitmap_test_cpu(&bm, 63),
		"bit 63 not set");
	TEST_OK(!mlfq_bitmap_test_cpu(&bm, 1024),
		"out-of-range CPU never tests set");
	TEST_OK(bm.words[0] == 0x3ULL && bm.words[1] == 0x1ULL &&
		bm.words[15] == (1ULL << 63),
		"word layout matches cpu >> 6 / (cpu & 63)");
	TEST_OK(MLFQ_BITMAP_WORDS == (MLFQ_MAX_CPUS + 63) / 64,
		"bitmap word count matches the CPU bound");
}

static void test_ss_boost_allowed(void)
{
	u64 limit = 2000000;	/* MLFQ_SHORT_SLEEP_RATE_LIMIT_NS */
	u64 now = 1000000000;

	TEST_OK(mlfq_ss_boost_allowed(0, now, limit),
		"first boost is always allowed");
	TEST_OK(!mlfq_ss_boost_allowed(now, now, limit),
		"boost at the same instant as the last one is blocked");
	TEST_OK(!mlfq_ss_boost_allowed(now, now + limit - 1, limit),
		"boost within the rate-limit window is blocked");
	TEST_OK(!mlfq_ss_boost_allowed(now, now + limit, limit),
		"boost exactly at the window edge is still blocked");
	TEST_OK(mlfq_ss_boost_allowed(now, now + limit + 1, limit),
		"boost after the window has elapsed is allowed");
	TEST_OK(mlfq_ss_boost_allowed(now - 100000000, now, limit),
		"ancient boost (100ms ago) is allowed");
	TEST_OK(!mlfq_ss_boost_allowed(1000, 2000, limit),
		"tiny offset with a large limit is blocked");
	TEST_OK(!mlfq_ss_boost_allowed(2000, 1000, limit),
		"wrap-around clock: a future boost timestamp blocks");
}

/*
 * The combined boost decision must agree with its two parts, and it is
 * what the CPU selection consults to treat a wakeup as interactive
 * before the classification runs.
 */
static void test_ss_boost_pending(void)
{
	struct task_ctx t = { .ema = 0, .last_ss_boost_at = 0 };
	u64 now = 1000000000;

	TEST_OK(mlfq_ss_boost_pending(&t, 10000, false, now, 32000000, 2000000),
		"short sleep within the window qualifies");
	TEST_OK(!mlfq_ss_boost_pending(&t, 0, false, now, 32000000, 2000000),
		"zero sleep without I/O does not qualify");
	TEST_OK(mlfq_ss_boost_pending(&t, 0, true, now, 32000000, 2000000),
		"I/O wakeup qualifies regardless of the sleep length");
	TEST_OK(!mlfq_ss_boost_pending(&t, 100000000, false, now, 32000000, 2000000),
		"long sleep without I/O does not qualify");

	t.last_ss_boost_at = now;
	TEST_OK(!mlfq_ss_boost_pending(&t, 10000, false, now + 1000000, 32000000, 2000000),
		"rate limit blocks a second boost inside the window");
	TEST_OK(mlfq_ss_boost_pending(&t, 10000, false, now + 3000000, 32000000, 2000000),
		"rate limit expires and the boost qualifies again");
}

static void test_cpuperf_mapping(void)
{
	u32 one = MLFQ_CPUPERF_Q1;
	u64 budget = MLFQ_BUDGET_MAX_NS;

	TEST_OK(mlfq_cpuperf_from_ema(0) == 0,
		"an idle gauge requests the minimum level");
	TEST_OK(mlfq_cpuperf_from_ema(budget) == one,
		"a saturated gauge requests the maximum level");
	TEST_OK(mlfq_cpuperf_from_ema(budget / 2) == one / 2,
		"half the gauge requests half the level");
	TEST_OK(mlfq_cpuperf_from_ema(budget * 2) == one,
		"an over-saturated gauge clamps to the maximum");
}

static void test_boost_eligible(void)
{
	u64 win = 1000000;	/* MLFQ_SHORT_SLEEP_NS */

	TEST_OK(mlfq_boost_eligible(0, win, true),
		"I/O wakeup with no sleep is eligible");
	TEST_OK(mlfq_boost_eligible(5000000, win, true),
		"I/O wakeup after a long sleep is eligible");
	TEST_OK(!mlfq_boost_eligible(0, win, false),
		"no sleep and not I/O is not eligible");
	TEST_OK(mlfq_boost_eligible(500000, win, false),
		"short sleep is eligible");
	TEST_OK(!mlfq_boost_eligible(2000000, win, false),
		"long sleep without I/O is not eligible");
	TEST_OK(!mlfq_boost_eligible(win + 1, win, false),
		"sleep just past the window is not eligible");
	TEST_OK(mlfq_boost_eligible(win, win, false),
		"sleep exactly at the window is eligible");
}

/* --- MLFQ regression tree -------------------------------------------- */

static void tree_store_reset(struct mlfq_tree_store *store)
{
	memset(store, 0, sizeof(*store));
}

static void tree_node(struct mlfq_tree_store *store, u32 idx, u8 feature,
		      u64 threshold, u32 left, u32 right)
{
	struct mlfq_tree_node n = {
		.threshold = threshold,
		.left = left,
		.right = right,
		.feature = feature,
	};

	store->nodes[idx] = n;
}

static void test_mlfq_tree_layout(void)
{
	TEST_OK(sizeof(struct mlfq_tree_feats) == 32,
		"tree feats is 32 bytes");
	TEST_OK(sizeof(struct mlfq_tree_node) == 24,
		"tree node is 24 bytes");
	TEST_OK(sizeof(struct mlfq_tree_sample) == 48,
		"tree sample is 48 bytes");
	TEST_OK(offsetof(struct mlfq_tree_sample, pid) == 0 &&
		offsetof(struct mlfq_tree_sample, queue) == 4 &&
		offsetof(struct mlfq_tree_sample, feats) == 8 &&
		offsetof(struct mlfq_tree_sample, label_ns) == 40,
		"tree sample offsets match the shared ABI");
	TEST_OK(offsetof(struct mlfq_tree_node, threshold) == 0 &&
		offsetof(struct mlfq_tree_node, left) == 8 &&
		offsetof(struct mlfq_tree_node, right) == 12 &&
		offsetof(struct mlfq_tree_node, feature) == 16 &&
		offsetof(struct mlfq_tree_node, pad) == 17,
		"tree node offsets match the shared ABI, pad at 17");
	TEST_OK(sizeof(struct mlfq_tree_store) ==
		MLFQ_TREE_MAX_NODES * sizeof(struct mlfq_tree_node),
		"tree store is one 2048-node buffer (the map value type)");
	TEST_OK(sizeof(struct task_ctx) == 144,
		"task_ctx grows to 144 bytes with the per-task limiter and the pending queue snapshot");
	TEST_OK(sizeof(struct mlfq_tree_ctrl) == 64 &&
		offsetof(struct mlfq_tree_ctrl, meta) == 0 &&
		offsetof(struct mlfq_tree_ctrl, sample_last_at) == 8,
		"tree ctrl state is one dedicated 64-byte cache line");
	TEST_OK(sizeof(struct mlfq_stats) % 64 == 0 &&
		sizeof(struct mlfq_stats) == 256,
		"mlfq_stats is padded to a 64-byte multiple (256 bytes)");
	TEST_OK(MLFQ_TREE_PER_TASK_LIMIT_NS == 10ULL * NSEC_PER_MSEC,
		"per-task sample limit is 10ms");
	TEST_OK(MLFQ_TREE_LABEL_MAX_NS == MLFQ_TREE_T_BOUND_NS * 64,
		"label clamp is 64x the Q2/Q3 split bound (192ms)");
}

static void test_tree_meta_layout(void)
{
	u64 meta = MLFQ_TREE_META_TRAINED | MLFQ_TREE_META_ACTIVE |
		   ((u64)MLFQ_TREE_MAX_NODES << MLFQ_TREE_META_NR_NODES_SHIFT) |
		   (3ULL << MLFQ_TREE_META_GENERATION_SHIFT);

	TEST_OK(MLFQ_TREE_META_TRAINED == 1 && MLFQ_TREE_META_ACTIVE == 2,
		"trained and active are meta bits 0 and 1");
	TEST_OK((meta & MLFQ_TREE_META_TRAINED) &&
		(meta & MLFQ_TREE_META_ACTIVE),
		"trained and active bits are set");
	TEST_OK(((meta & MLFQ_TREE_META_NR_NODES_MASK) >>
		 MLFQ_TREE_META_NR_NODES_SHIFT) == MLFQ_TREE_MAX_NODES,
		"nr_nodes decodes from meta bits 8..31");
	TEST_OK((meta >> MLFQ_TREE_META_GENERATION_SHIFT) == 3,
		"generation decodes from meta bits 32..63");
	TEST_OK(!(MLFQ_TREE_META_NR_NODES_MASK & MLFQ_TREE_META_GENERATION_MASK) &&
		!(MLFQ_TREE_META_NR_NODES_MASK &
		  (MLFQ_TREE_META_TRAINED | MLFQ_TREE_META_ACTIVE)),
		"meta bit fields do not overlap");
}

/*
 * The walk is exercised directly on a local store, the buffer the BPF
 * wrapper would look up. The wrapper itself (mlfq_tree_predict) needs
 * the BPF map machinery and is not available here: its untrained gate
 * is a pure meta check (trained bit clear -> 0, verified above at the
 * bit level) and its NULL-store path guards a failed map lookup, both
 * exercised at the BPF side.
 */
static void test_tree_predict_walk(void)
{
	struct mlfq_tree_store store;
	struct mlfq_tree_feats f = { .prev_burst_ns = 0, .sleep_ns = 0,
				     .ema = 0, .io_wait = 0, .wake_cnt = 0 };

	/* Leaf at the root: the stored prediction is returned directly. */
	tree_store_reset(&store);
	tree_node(&store, 0, 0, 0, 123456, 0);
	TEST_OK(mlfq_tree_walk(&store, &f) == 123456,
		"leaf at the root returns the stored prediction");

	/* Single split on prev_burst_ns at the 1ms threshold. */
	tree_store_reset(&store);
	tree_node(&store, 0, 0, 1000000, 1, 2);
	tree_node(&store, 1, 0, 0, 50000, 0);
	tree_node(&store, 2, 0, 0, 3000000, 0);
	f.prev_burst_ns = 900000;
	TEST_OK(mlfq_tree_walk(&store, &f) == 50000,
		"below-threshold burst routes to the left leaf");
	f.prev_burst_ns = 1000000;	/* <= threshold: left */
	TEST_OK(mlfq_tree_walk(&store, &f) == 50000,
		"burst equal to the threshold routes left");
	f.prev_burst_ns = 1000001;
	TEST_OK(mlfq_tree_walk(&store, &f) == 3000000,
		"above-threshold burst routes to the right leaf");

	/*
	 * A chain of MLFQ_TREE_MAX_DEPTH internal nodes followed by one
	 * leaf: the constant-depth loop runs to its bound and the depth-12
	 * leaf is reached as "the last node", whose left is the prediction.
	 */
	tree_store_reset(&store);
	for (int i = 0; i < MLFQ_TREE_MAX_DEPTH; i++)
		tree_node(&store, i, 0, 0, i + 1, i + 1);
	tree_node(&store, MLFQ_TREE_MAX_DEPTH, 0, 0, 777777, 0);
	f.prev_burst_ns = 0;
	TEST_OK(mlfq_tree_walk(&store, &f) == 777777,
		"depth-12 chain exhausts the walk and returns the leaf");

	/*
	 * Deeper than the bound: the walk is cut and the last reachable
	 * node is returned as a leaf only when it really is one. The node
	 * at depth 12 here is internal, so the prediction is 0 -- a child
	 * index must never leak out as a burst.
	 */
	tree_store_reset(&store);
	for (int i = 0; i <= MLFQ_TREE_MAX_DEPTH; i++)
		tree_node(&store, i, 0, 0, i + 1, i + 1);
	TEST_OK(mlfq_tree_walk(&store, &f) == 0,
		"a deeper-than-12 chain is cut at the depth bound and yields 0, not a child index");

	/*
	 * Out-of-range feature id: 0x87 masks to 7, the first zeroed
	 * feat[] slot. Under MLFQ_CHECK the invariant predicate bails to
	 * the untrained result; without the check the walk would route on
	 * feat[7] == 0 and still stay in bounds.
	 */
	tree_store_reset(&store);
	tree_node(&store, 0, 0x87, 0, 1, 2);
	tree_node(&store, 1, 0, 0, 50000, 0);
	tree_node(&store, 2, 0, 0, 3000000, 0);
	TEST_OK(mlfq_tree_walk(&store, &f) == 0,
		"out-of-range feature id bails under MLFQ_CHECK, no OOB");

	/*
	 * Masked index: a child index of 0xFFFFFFFF must land on node
	 * 2047 (the mask is MLFQ_TREE_MAX_NODES - 1), never outside the
	 * buffer. The zeroed node at 2047 is a leaf predicting 0; a
	 * planted leaf there proves the landing index exactly.
	 */
	tree_store_reset(&store);
	tree_node(&store, 0, 0, 0, 0xFFFFFFFF, 0xFFFFFFFF);
	tree_node(&store, MLFQ_TREE_MAX_NODES - 1, 0, 0, 424242, 0);
	TEST_OK(mlfq_tree_walk(&store, &f) == 424242,
		"0xFFFFFFFF child index is masked into [0, 2047]");

	/*
	 * Double buffer: the two map entries hold the two generations and
	 * the wrapper picks the active entry from the meta bit; each entry
	 * is walked independently here.
	 */
	tree_store_reset(&store);
	tree_node(&store, 0, 0, 0, 111111, 0);
	TEST_OK(mlfq_tree_walk(&store, &f) == 111111,
		"entry 0 walks its own tree");
	tree_store_reset(&store);
	tree_node(&store, 0, 0, 0, 222222, 0);
	TEST_OK(mlfq_tree_walk(&store, &f) == 222222,
		"entry 1 walks its own tree");
}

/*
 * The shared crafted tree also walked by the Rust side
 * (golden_tree_predict_matches_shared_spec in mlfq_tree.rs): a chain on
 * prev_burst_ns, mixed leaves, and a node whose raw feature id is out of
 * the populated range but masks in-bounds (0x84 -> 4 = wake_cnt). Both
 * sides must produce identical outputs.
 */
static void test_tree_golden_shared(void)
{
	struct mlfq_tree_store store;
	struct mlfq_tree_feats f;

	tree_store_reset(&store);
	tree_node(&store, 0, 0, 1000000, 1, 8);
	tree_node(&store, 1, 0, 1000000, 2, 8);
	tree_node(&store, 2, 0, 1000000, 3, 8);
	tree_node(&store, 3, 1, 500000, 4, 5);
	tree_node(&store, 4, 0, 0, 1111111, 0);
	tree_node(&store, 5, 0x84, 1, 6, 7);
	tree_node(&store, 6, 0, 0, 2222222, 0);
	tree_node(&store, 7, 0, 0, 3333333, 0);
	tree_node(&store, 8, 0, 0, 8888888, 0);

	f = (struct mlfq_tree_feats){ .prev_burst_ns = 0, .sleep_ns = 400000,
				      .ema = 0, .io_wait = 0, .wake_cnt = 0 };
	TEST_OK(mlfq_tree_walk(&store, &f) == 1111111,
		"golden: chain left, sleep <= 500us -> 1111111");
	f.sleep_ns = 600000;
	TEST_OK(mlfq_tree_walk(&store, &f) == 2222222,
		"golden: wake_cnt 0 <= 1 -> 2222222");
	f.wake_cnt = 5;
	TEST_OK(mlfq_tree_walk(&store, &f) == 3333333,
		"golden: wake_cnt 5 > 1 -> 3333333");
	f.prev_burst_ns = 2000000;
	f.sleep_ns = 0;
	f.wake_cnt = 0;
	TEST_OK(mlfq_tree_walk(&store, &f) == 8888888,
		"golden: prev_burst above 1ms -> 8888888");
	f.prev_burst_ns = 0;
	f.sleep_ns = 400000;
	f.wake_cnt = 9;
	TEST_OK(mlfq_tree_walk(&store, &f) == 1111111,
		"golden: wake_cnt is irrelevant on the sleep-split left");
}

/*
 * The promotion-only wakeup mapping (mlfq_tree_map_queue): the tree can
 * only raise the queue at the wakeup; demotions are the run-out gate's
 * job, so a single prediction can never demote a task.
 */
static void test_tree_map_queue(void)
{
	u8 q;

	/* pred < T_INT raises to Q1 regardless of the current queue. */
	for (q = 1; q <= MLFQ_NR_QUEUES; q++)
		TEST_OK(mlfq_tree_map_queue(MLFQ_TREE_T_INT_NS - 1, q) == 1,
			"Q1-band prediction raises queue %u to 1", q);

	/* pred in [T_INT, T_BOUND): Q3 -> Q2, Q1/Q2 stay. */
	TEST_OK(mlfq_tree_map_queue(MLFQ_TREE_T_INT_NS, 1) == 1 &&
		mlfq_tree_map_queue(MLFQ_TREE_T_BOUND_NS - 1, 1) == 1,
		"Q2-band prediction leaves Q1 alone");
	TEST_OK(mlfq_tree_map_queue(MLFQ_TREE_T_INT_NS, 2) == 2 &&
		mlfq_tree_map_queue(MLFQ_TREE_T_BOUND_NS - 1, 2) == 2,
		"Q2-band prediction leaves Q2 alone");
	TEST_OK(mlfq_tree_map_queue(MLFQ_TREE_T_INT_NS, 3) == 2 &&
		mlfq_tree_map_queue(MLFQ_TREE_T_BOUND_NS - 1, 3) == 2,
		"Q2-band prediction raises Q3 to Q2");

	/* pred >= T_BOUND leaves the queue unchanged: no wakeup demotion. */
	TEST_OK(mlfq_tree_map_queue(MLFQ_TREE_T_BOUND_NS, 1) == 1 &&
		mlfq_tree_map_queue(MLFQ_TREE_T_BOUND_NS, 2) == 2 &&
		mlfq_tree_map_queue(MLFQ_TREE_T_BOUND_NS, 3) == 3,
		"Q3-band prediction never changes the queue");

	/* Untrained (pred 0) leaves the queue unchanged. */
	TEST_OK(mlfq_tree_map_queue(0, 1) == 1 &&
		mlfq_tree_map_queue(0, 2) == 2 &&
		mlfq_tree_map_queue(0, 3) == 3,
		"untrained prediction never changes the queue");
}

static void test_mlfq_check_tree_predicates(void)
{
	TEST_OK(mlfq_check_tree_node_index(0) &&
		mlfq_check_tree_node_index(MLFQ_TREE_MAX_NODES - 1),
		"node indices 0 and 2047 are in bounds");
	TEST_OK(!mlfq_check_tree_node_index(MLFQ_TREE_MAX_NODES),
		"node index 2048 is out of bounds");
	TEST_OK(mlfq_check_tree_feature(0) && mlfq_check_tree_feature(4),
		"feature ids 0 and 4 are in bounds");
	TEST_OK(!mlfq_check_tree_feature(5) && !mlfq_check_tree_feature(7),
		"feature ids 5 and 7 are out of bounds");
	TEST_OK(mlfq_check_tree_feature(0x80) &&
		!mlfq_check_tree_feature(0x85),
		"the feature id masks to 0..7 before the bound check");
}

int main(void)
{
	test_calc_delta_fair();
	test_place_entity();
	test_place_entity_weight_edges();
	test_place_charge_replacement();
	test_place_entity_deadline_pure();
	test_sameq_preempt_owed();
	test_clock_advance();
	test_ema_climb();
	test_ema_decay();
	test_queue_mapping();
	test_promote_hysteresis();
	test_demote_hysteresis();
	test_ss_boost_allowed();
	test_ss_boost_pending();
	test_cpuperf_mapping();
	test_boost_eligible();
	test_mlfq_check_predicates();
	test_bitmap();
	test_mlfq_tree_layout();
	test_tree_meta_layout();
	test_tree_predict_walk();
	test_tree_golden_shared();
	test_tree_map_queue();
	test_mlfq_check_tree_predicates();

	if (nr_failed) {
		printf("%d test(s) FAILED\n", nr_failed);
		return 1;
	}

	printf("All tests passed\n");
	return 0;
}
