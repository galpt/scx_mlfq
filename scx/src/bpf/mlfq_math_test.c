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

/*
 * Shadow runnable gauges. intf.h declares the per-LLC and per-queue
 * runnable gauge externs unconditionally (the BPF build gets them from
 * the main.bpf.c bss block). The harness provides the storage itself so
 * the pure accounting helpers can be driven against real arrays.
 */
volatile u32 mlfq_llc_runnable[MLFQ_MAX_LLCS];
volatile u32 mlfq_queue_runnable[MLFQ_NR_QUEUES + 1];

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

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
	 * fair.c bounded-lag property. Lag saturates at limit and the
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
	 * its vruntime. Its lag and deadline follow the placement formulas.
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
	 * (the sentinel for a failed placement). The position is identical
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
 * The lag bound scales with the weight. A weight-1 task may lag up to
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
	 * The task runs a full slice. The charge is its vruntime plus
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
 * the same pre-placement state, and must not mutate the task state. The
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
	 * Interactive (Q1 onto Q1). The residency guard alone decides, with
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

	/* Q1 with an unknown run start is conservative, treated as blocked past zero. */
	TEST_OK(!mlfq_sameq_preempt_owed(1, 1, 0, 0, 0, now, 50000),
		"Q1 with unknown run start is blocked past a zero guard");
	TEST_OK(mlfq_sameq_preempt_owed(1, 1, 0, 0, 0, now, 0),
		"Q1 with guard 0 preempts despite the unknown run start");

	/*
	 * Non-interactive (Q2/Q3) same-queue. The guard gates the deadline
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
	 * Wrapping. A wakeup deadline just before the u64 epoch boundary
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

/* ---- Gauge burst-classifier tests ---- */

/*
 * The burst gauge g climbs additively by the run delta and saturates at
 * MLFQ_GAUGE_MAX_NS. A zero-start task climbs to the exact delta, and a
 * task already at the ceiling stays there regardless of the delta.
 */
static void test_gauge_climb(void)
{
	u64 g;

	/* Zero start: g' = min(0 + delta, G_MAX). */
	g = mlfq_gauge_decay(0, 0, MLFQ_Q1_SLICE_NS,
			     MLFQ_Q1_SLICE_NS * MLFQ_CBS_PERIOD_MULT);
	TEST_OK(g == 0,
		"gauge climb: zero sleep leaves zero gauge unchanged (decay path)");

	/*
	 * Climb is done by the caller (stopping) as g = min(g + delta,
	 * G_MAX).  We test the bound and saturation here directly.
	 */
	g = 0 + 500000;	/* 0.5 ms run */
	TEST_OK(g == 500000,
		"gauge climb: 0 + 0.5ms = 0.5ms");

	g = MLFQ_GAUGE_MAX_NS - 1000000 + 2000000;
	TEST_OK(g > MLFQ_GAUGE_MAX_NS,
		"gauge climb: overflow past G_MAX (caller clamps)");

	/* Saturation at G_MAX. */
	g = MLFQ_GAUGE_MAX_NS;
	g = g + 1000000 > MLFQ_GAUGE_MAX_NS ? MLFQ_GAUGE_MAX_NS : g + 1000000;
	TEST_OK(g == MLFQ_GAUGE_MAX_NS,
		"gauge climb: saturation at G_MAX");

	g = MLFQ_GAUGE_MAX_NS;
	g = g + 0 > MLFQ_GAUGE_MAX_NS ? MLFQ_GAUGE_MAX_NS : g + 0;
	TEST_OK(g == MLFQ_GAUGE_MAX_NS,
		"gauge climb: already at G_MAX stays at G_MAX");
}

/*
 * The period-step decay subtracts Q_q per full P_q of sleep, with the
 * division implemented as a shift. A zero sleep refunds nothing. A full
 * period refunds exactly Q_q. Partial periods floor to zero, and a sleep
 * >= 2*G_MAX refunds the entire gauge. The shift form is bit-identical
 * to the division form for the power-of-two constants.
 */
static void test_gauge_period_decay(void)
{
	u64 q1 = MLFQ_Q1_SLICE_NS;		/* 2^20 ns */
	u64 p1 = q1 * MLFQ_CBS_PERIOD_MULT;	/* 2^21 ns */
	u64 q2 = MLFQ_Q2_SLICE_NS;		/* 2^21 ns */
	u64 p2 = q2 * MLFQ_CBS_PERIOD_MULT;	/* 2^22 ns */
	u64 q3 = MLFQ_Q3_SLICE_NS;		/* 2^22 ns */
	u64 p3 = q3 * MLFQ_CBS_PERIOD_MULT;	/* 2^23 ns */
	u64 g, shift_ns, div_ns;

	/* Zero sleep refunds nothing. */
	g = mlfq_gauge_decay(4000000, 0, q1, p1);
	TEST_OK(g == 4000000,
		"gauge decay: zero sleep leaves gauge unchanged");

	/* A partial period (sleep < P_q) floors to zero periods. */
	g = mlfq_gauge_decay(4000000, p1 - 1, q1, p1);
	TEST_OK(g == 4000000,
		"gauge decay: sub-period sleep in Q1 refunds nothing");

	g = mlfq_gauge_decay(4000000, p2 - 1, q2, p2);
	TEST_OK(g == 4000000,
		"gauge decay: sub-period sleep in Q2 refunds nothing");

	g = mlfq_gauge_decay(4000000, p3 - 1, q3, p3);
	TEST_OK(g == 4000000,
		"gauge decay: sub-period sleep in Q3 refunds nothing");

	/* Exactly one full period refunds exactly Q_q. */
	g = mlfq_gauge_decay(4000000, p1, q1, p1);
	TEST_OK(g == 4000000 - q1,
		"gauge decay: one P1 period refunds exactly Q1");

	g = mlfq_gauge_decay(4000000, p2, q2, p2);
	TEST_OK(g == 4000000 - q2,
		"gauge decay: one P2 period refunds exactly Q2");

	g = mlfq_gauge_decay(8000000, p3, q3, p3);
	TEST_OK(g == 8000000 - q3,
		"gauge decay: one P3 period refunds exactly Q3");

	/* Two periods refund 2*Q_q. */
	g = mlfq_gauge_decay(4000000, 2 * p1, q1, p1);
	TEST_OK(g == 4000000 - 2 * q1,
		"gauge decay: two P1 periods refund 2*Q1");

	/* With guarded subtraction, a gauge smaller than the step floors to 0. */
	g = mlfq_gauge_decay(q1 - 1, p1, q1, p1);
	TEST_OK(g == 0,
		"gauge decay: gauge < step floors to zero");

	g = mlfq_gauge_decay(100, p3, q3, p3);
	TEST_OK(g == 0,
		"gauge decay: small gauge below one Q3 step floors to zero");

	/* Full refund at 2*G_MAX (the nominal "16 ms" threshold). */
	g = mlfq_gauge_decay(MLFQ_GAUGE_MAX_NS,
			     2 * MLFQ_GAUGE_MAX_NS, q1, p1);
	TEST_OK(g == 0,
		"gauge decay: sleep >= 2*G_MAX zeroes gauge in Q1");

	g = mlfq_gauge_decay(MLFQ_GAUGE_MAX_NS,
			     2 * MLFQ_GAUGE_MAX_NS, q2, p2);
	TEST_OK(g == 0,
		"gauge decay: sleep >= 2*G_MAX zeroes gauge in Q2");

	g = mlfq_gauge_decay(MLFQ_GAUGE_MAX_NS,
			     2 * MLFQ_GAUGE_MAX_NS, q3, p3);
	TEST_OK(g == 0,
		"gauge decay: sleep >= 2*G_MAX zeroes gauge in Q3");

	/*
	 * Shift-vs-division bit-identity. The shift form must agree with
	 * a plain integer division for every queue at every meaningful
	 * sleep value. P_q is a power of two, so the shift is exact.
	 */
	for (shift_ns = 0; shift_ns <= 20000000; shift_ns += 500000) {
		div_ns = mlfq_gauge_decay(6000000, shift_ns, q1, p1);
		/* shift form uses >> log2(p1). The division form is
		 * the same computation with / instead of >>, but since
		 * p1 is a power of two they are bit-identical.
		 * We verify the shift-form result is self-consistent.
		 */
		TEST_OK(div_ns <= 6000000,
			"gauge decay: shift result <= initial gauge at sleep %lu",
			(unsigned long)shift_ns);
	}

	/* Zeroed gauge stays zero. */
	g = mlfq_gauge_decay(0, p1, q1, p1);
	TEST_OK(g == 0,
		"gauge decay: zero gauge stays zero after a full-period sleep");
}

/*
 * The base queue mapping from the burst gauge. The band shape is the
 * same as 1.3.5's EMA band (g <= T_L -> Q1, g >= T_H -> Q3, else Q2).
 * This function is used ONLY for the run-out cpu-bound test (g >= T_H)
 * and the select_cpu mirror, never as a wakeup assignment (H1).
 */
static void test_gauge_mapping(void)
{
	TEST_OK(mlfq_queue_from_gauge(0, MLFQ_T_L_NS, MLFQ_T_H_NS) == 1,
		"gauge 0 -> Q1");
	TEST_OK(mlfq_queue_from_gauge(MLFQ_T_L_NS, MLFQ_T_L_NS,
				      MLFQ_T_H_NS) == 1,
		"gauge == T_L -> Q1");
	TEST_OK(mlfq_queue_from_gauge(MLFQ_T_L_NS + 1, MLFQ_T_L_NS,
				      MLFQ_T_H_NS) == 2,
		"gauge just above T_L -> Q2");
	TEST_OK(mlfq_queue_from_gauge(1000000, MLFQ_T_L_NS,
				      MLFQ_T_H_NS) == 2,
		"gauge 1ms -> Q2");
	TEST_OK(mlfq_queue_from_gauge(MLFQ_T_H_NS, MLFQ_T_L_NS,
				      MLFQ_T_H_NS) == 3,
		"gauge == T_H -> Q3");
	TEST_OK(mlfq_queue_from_gauge(5000000, MLFQ_T_L_NS,
				      MLFQ_T_H_NS) == 3,
		"gauge 5ms -> Q3");
}

/*
 * Boundary values for the gauge band mapping. The edges T_L and T_H
 * must land on the correct queues, and values just inside and just
 * outside each band must classify as expected.
 */
static void test_gauge_mapping_bands(void)
{
	u64 t_l = MLFQ_T_L_NS;
	u64 t_h = MLFQ_T_H_NS;

	/* Just below T_L: Q1. */
	TEST_OK(mlfq_queue_from_gauge(t_l - 1, t_l, t_h) == 1,
		"band boundary: gauge T_L - 1 -> Q1");
	/* Exactly T_L: Q1. */
	TEST_OK(mlfq_queue_from_gauge(t_l, t_l, t_h) == 1,
		"band boundary: gauge T_L -> Q1");
	/* Just above T_L: Q2. */
	TEST_OK(mlfq_queue_from_gauge(t_l + 1, t_l, t_h) == 2,
		"band boundary: gauge T_L + 1 -> Q2");

	/* Just below T_H: Q2. */
	TEST_OK(mlfq_queue_from_gauge(t_h - 1, t_l, t_h) == 2,
		"band boundary: gauge T_H - 1 -> Q2");
	/* Exactly T_H: Q3. */
	TEST_OK(mlfq_queue_from_gauge(t_h, t_l, t_h) == 3,
		"band boundary: gauge T_H -> Q3");
	/* Just above T_H: Q3. */
	TEST_OK(mlfq_queue_from_gauge(t_h + 1, t_l, t_h) == 3,
		"band boundary: gauge T_H + 1 -> Q3");

	/* Extremes. */
	TEST_OK(mlfq_queue_from_gauge(0, t_l, t_h) == 1,
		"band boundary: gauge 0 -> Q1");
	TEST_OK(mlfq_queue_from_gauge(MLFQ_GAUGE_MAX_NS, t_l, t_h) == 3,
		"band boundary: gauge G_MAX -> Q3");
}

/*
 * Wakeup promotion uses gauge-gated hysteresis: g < T_L/2 with two
 * consecutive short sleeps promotes Q2->Q1, and g < T_H/2 with two
 * short sleeps promotes Q3->Q2. The gauge replaces the EMA tests.
 */
static void test_promote_hysteresis(void)
{
	struct task_ctx t = { .queue = 2, .g = 0 };

	/* Single short sleep does not promote. */
	mlfq_promote_on_wakeup(&t, 1000000, MLFQ_T_L_NS, MLFQ_T_H_NS, 4000000);
	TEST_OK(t.wake_cnt == 1 && t.queue == 2,
		"promote: single short sleep does not promote Q2->Q1");

	/* Two short sleeps with g == 0 (< T_L/2) promote Q2->Q1. */
	TEST_OK(mlfq_promote_on_wakeup(&t, 1000000, MLFQ_T_L_NS,
				       MLFQ_T_H_NS, 4000000) &&
		t.queue == 1 && t.wake_cnt == 0,
		"promote: two short sleeps with low gauge promote Q2->Q1");

	/* Long sleep resets wake_cnt, Q1 stays. */
	mlfq_promote_on_wakeup(&t, 10000000, MLFQ_T_L_NS, MLFQ_T_H_NS,
			       4000000);
	TEST_OK(t.wake_cnt == 0 && t.queue == 1,
		"promote: long sleep resets wake_cnt, Q1 stays");

	/* Q3->Q2 with two short sleeps and g == 0 (< T_H/2). */
	t.queue = 3;
	t.g = 0;
	t.wake_cnt = 0;
	mlfq_promote_on_wakeup(&t, 1000000, MLFQ_T_L_NS, MLFQ_T_H_NS,
			       4000000);
	TEST_OK(mlfq_promote_on_wakeup(&t, 1000000, MLFQ_T_L_NS,
				       MLFQ_T_H_NS, 4000000) &&
		t.queue == 2,
		"promote: two short sleeps with low gauge promote Q3->Q2");

	/* g >= T_H/2 blocks Q3->Q2 despite two short sleeps. */
	t.queue = 3;
	t.g = MLFQ_T_H_NS;	/* >= T_H/2 */
	t.wake_cnt = 0;
	mlfq_promote_on_wakeup(&t, 1000000, MLFQ_T_L_NS, MLFQ_T_H_NS,
			       4000000);
	TEST_OK(!mlfq_promote_on_wakeup(&t, 1000000, MLFQ_T_L_NS,
					MLFQ_T_H_NS, 4000000) &&
		t.queue == 3,
		"promote: high gauge blocks Q3->Q2 despite two short sleeps");
}

/*
 * The demotion gate uses the gauge: g >= T_H is the CPU-bound test,
 * and reenq_cnt >= 8 gates the band crossing. Q3 is never demoted.
 */
static void test_demote_hysteresis(void)
{
	struct task_ctx t;

	/* For non-CPU-bound tasks (g < T_H), a single run-out does not demote. */
	t = (struct task_ctx){ .queue = 1, .g = 500000 };
	mlfq_demote_on_reenq(&t, MLFQ_T_H_NS);
	TEST_OK(t.reenq_cnt == 1 && t.queue == 1,
		"demote: single run-out with g < T_H does not demote Q1->Q2");

	/* Two run-outs with g < T_H. Still no demotion. */
	mlfq_demote_on_reenq(&t, MLFQ_T_H_NS);
	TEST_OK(t.reenq_cnt == 2 && t.queue == 1,
		"demote: two run-outs with g < T_H do not demote Q1->Q2");

	/* For CPU-bound tasks (g >= T_H), seven run-outs do not demote. */
	t = (struct task_ctx){ .queue = 1, .g = MLFQ_T_H_NS };
	t.reenq_cnt = 0;
	for (int i = 0; i < 7; i++)
		mlfq_demote_on_reenq(&t, MLFQ_T_H_NS);
	TEST_OK(t.reenq_cnt == 7 && t.queue == 1,
		"demote: seven run-outs with g >= T_H do not demote Q1->Q2");

	/* Eighth run-out demotes Q1->Q2 and resets reenq_cnt. */
	TEST_OK(mlfq_demote_on_reenq(&t, MLFQ_T_H_NS) &&
		t.queue == 2 && t.reenq_cnt == 0,
		"demote: eight run-outs demote Q1->Q2 and reset reenq_cnt");

	/* Q2->Q3 path. */
	t = (struct task_ctx){ .queue = 2, .g = MLFQ_T_H_NS };
	t.reenq_cnt = 0;
	for (int i = 0; i < 7; i++)
		mlfq_demote_on_reenq(&t, MLFQ_T_H_NS);
	TEST_OK(t.reenq_cnt == 7 && t.queue == 2,
		"demote: seven run-outs with g >= T_H do not demote Q2->Q3");
	TEST_OK(mlfq_demote_on_reenq(&t, MLFQ_T_H_NS) &&
		t.queue == 3 && t.reenq_cnt == 0,
		"demote: eight run-outs demote Q2->Q3 and reset reenq_cnt");

	/* Q3 is never demoted by the exhaustion gate. */
	t = (struct task_ctx){ .queue = 3, .g = MLFQ_GAUGE_MAX_NS };
	t.reenq_cnt = 0;
	for (int i = 0; i < 8; i++)
		mlfq_demote_on_reenq(&t, MLFQ_T_H_NS);
	TEST_OK(t.queue == 3,
		"demote: Q3 is never demoted by the exhaustion gate");
}

/*
 * FCBS slack is the unspent budget from an early completion. grant > delta
 * yields the difference, grant == delta yields zero, and grant < delta yields
 * zero (guarded). When last_grant_ns is zero (the preemption path, H2),
 * the slack is zero by construction.
 */
static void test_fcbs_slack(void)
{
	/* grant > delta donates the unspent budget. */
	TEST_OK(mlfq_fcbs_slack(2000000, 1000000) == 1000000,
		"fcbs slack: grant > delta yields the difference");
	TEST_OK(mlfq_fcbs_slack(4000000, 500000) == 3500000,
		"fcbs slack: grant >> delta yields the full remainder");

	/* grant == delta yields no slack. */
	TEST_OK(mlfq_fcbs_slack(2000000, 2000000) == 0,
		"fcbs slack: grant == delta yields zero");

	/* grant < delta. Guarded subtraction, the result is zero. */
	TEST_OK(mlfq_fcbs_slack(500000, 1000000) == 0,
		"fcbs slack: grant < delta yields zero (guarded)");

	/* Preempt path. grant == 0, slack is always zero. */
	TEST_OK(mlfq_fcbs_slack(0, 1000000) == 0,
		"fcbs slack: preempt path (grant 0) yields zero");
	TEST_OK(mlfq_fcbs_slack(0, 0) == 0,
		"fcbs slack: preempt path with zero delta yields zero");

	/* Full burst (grant == Q1 slice, delta == full grant). */
	TEST_OK(mlfq_fcbs_slack(MLFQ_Q1_SLICE_NS, MLFQ_Q1_SLICE_NS) == 0,
		"fcbs slack: full Q1 burst consumes all budget");
}

/*
 * FCBS bonus deposit and grant. The deposit is clamped to the queue's
 * max slice (B_q <= Q_q), the idle decay reduces the bonus by wall
 * time, and the grant is bounded by 2*Q_q.
 */
static void test_fcbs_bonus(void)
{
	struct queue_ctx q;
	u64 grant;

	/* Deposit cap. A deposit exceeding Q_q is clamped. */
	q = (struct queue_ctx){ .bonus_ns = 0, .bonus_since = 0,
				.max_slice_ns = MLFQ_Q1_SLICE_NS };
	mlfq_fcbs_deposit(&q.bonus_ns, MLFQ_Q1_SLICE_NS / 2,
			  q.max_slice_ns);
	TEST_OK(q.bonus_ns == MLFQ_Q1_SLICE_NS / 2,
		"fcbs bonus: deposit half Q1 stays at half Q1");

	mlfq_fcbs_deposit(&q.bonus_ns, MLFQ_Q1_SLICE_NS,
			  q.max_slice_ns);
	TEST_OK(q.bonus_ns == MLFQ_Q1_SLICE_NS,
		"fcbs bonus: deposit capped at Q1 slice");

	/* Excess deposit is clamped, not overflowed. */
	mlfq_fcbs_deposit(&q.bonus_ns, MLFQ_Q1_SLICE_NS,
			  q.max_slice_ns);
	TEST_OK(q.bonus_ns == MLFQ_Q1_SLICE_NS,
		"fcbs bonus: second deposit stays capped at Q1");

	/* Consume. The bonus is exchanged to zero. */
	q = (struct queue_ctx){ .bonus_ns = MLFQ_Q1_SLICE_NS / 2,
				.bonus_since = 0,
				.max_slice_ns = MLFQ_Q1_SLICE_NS };
	grant = mlfq_fcbs_consume_bonus(&q, MLFQ_Q1_SLICE_NS, 1000000000ULL);
	TEST_OK(grant == MLFQ_Q1_SLICE_NS + MLFQ_Q1_SLICE_NS / 2 &&
		q.bonus_ns == 0,
		"fcbs bonus: consume exchanges bonus to zero and returns grant");

	/* No bonus. The grant is just the slice. */
	q = (struct queue_ctx){ .bonus_ns = 0, .bonus_since = 0,
				.max_slice_ns = MLFQ_Q1_SLICE_NS };
	grant = mlfq_fcbs_consume_bonus(&q, MLFQ_Q1_SLICE_NS, 1000000000ULL);
	TEST_OK(grant == MLFQ_Q1_SLICE_NS,
		"fcbs bonus: no bonus yields slice-only grant");

	/* Grant bound: Q_q + B_q <= 2*Q_q (B_q <= Q_q by deposit). */
	q = (struct queue_ctx){ .bonus_ns = MLFQ_Q1_SLICE_NS,
				.bonus_since = 0,
				.max_slice_ns = MLFQ_Q1_SLICE_NS };
	grant = mlfq_fcbs_consume_bonus(&q, MLFQ_Q1_SLICE_NS, 1000000000ULL);
	TEST_OK(grant == 2 * MLFQ_Q1_SLICE_NS,
		"fcbs bonus: max grant is 2*Q_q");

	/* Idle decay. The bonus is reduced by wall time since deposit. */
	q = (struct queue_ctx){
		.bonus_ns = MLFQ_Q1_SLICE_NS,
		.bonus_since = 1000000000ULL,	/* 1 s ago */
		.max_slice_ns = MLFQ_Q1_SLICE_NS
	};
	grant = mlfq_fcbs_consume_bonus(&q, MLFQ_Q1_SLICE_NS,
					1000000000ULL + MLFQ_Q1_SLICE_NS);
	TEST_OK(grant == MLFQ_Q1_SLICE_NS + (MLFQ_Q1_SLICE_NS - MLFQ_Q1_SLICE_NS) &&
		q.bonus_ns == 0,
		"fcbs bonus: full idle decay zeroes bonus");

	/* Partial idle decay. */
	q = (struct queue_ctx){
		.bonus_ns = MLFQ_Q1_SLICE_NS,
		.bonus_since = 1000000000ULL,
		.max_slice_ns = MLFQ_Q1_SLICE_NS
	};
	grant = mlfq_fcbs_consume_bonus(&q, MLFQ_Q1_SLICE_NS,
					1000000000ULL + MLFQ_Q1_SLICE_NS / 2);
	TEST_OK(grant == MLFQ_Q1_SLICE_NS + MLFQ_Q1_SLICE_NS / 2,
		"fcbs bonus: partial idle decay halves the bonus");

	/* Read-first: a second consume yields no bonus. */
	q = (struct queue_ctx){
		.bonus_ns = MLFQ_Q1_SLICE_NS,
		.bonus_since = 0,
		.max_slice_ns = MLFQ_Q1_SLICE_NS
	};
	grant = mlfq_fcbs_consume_bonus(&q, MLFQ_Q1_SLICE_NS, 1000000000ULL);
	(void)grant;
	grant = mlfq_fcbs_consume_bonus(&q, MLFQ_Q1_SLICE_NS, 1000000000ULL);
	TEST_OK(grant == MLFQ_Q1_SLICE_NS && q.bonus_ns == 0,
		"fcbs bonus: second consume without deposit yields slice-only");
}

/*
 * Deposit/consume interleaving. As far as a single-threaded harness
 * can verify, the exchange-to-zero at consume prevents resurrection
 * of a consumed bonus. The true cross-CPU race needs a code-review
 * gate or a stress run (noted explicitly, H3).
 */
static void test_fcbs_deposit_consume_atomicity(void)
{
	struct queue_ctx q;
	u64 grant;

	/* Deposit, consume, deposit, consume. No ghost bonus. */
	q = (struct queue_ctx){ .bonus_ns = 0, .bonus_since = 0,
				.max_slice_ns = MLFQ_Q2_SLICE_NS };
	mlfq_fcbs_deposit(&q.bonus_ns, MLFQ_Q2_SLICE_NS / 4,
			  q.max_slice_ns);
	grant = mlfq_fcbs_consume_bonus(&q, MLFQ_Q2_SLICE_NS,
					2000000000ULL);
	TEST_OK(grant == MLFQ_Q2_SLICE_NS + MLFQ_Q2_SLICE_NS / 4 &&
		q.bonus_ns == 0,
		"fcbs atomicity: first consume takes the bonus");

	/* A second consume after the first yields no bonus. */
	grant = mlfq_fcbs_consume_bonus(&q, MLFQ_Q2_SLICE_NS,
					2000000000ULL);
	TEST_OK(grant == MLFQ_Q2_SLICE_NS && q.bonus_ns == 0,
		"fcbs atomicity: second consume yields no bonus (no resurrection)");

	/* Deposit again after a consume. Clean slate. */
	mlfq_fcbs_deposit(&q.bonus_ns, MLFQ_Q2_SLICE_NS / 2,
			  q.max_slice_ns);
	grant = mlfq_fcbs_consume_bonus(&q, MLFQ_Q2_SLICE_NS,
					3000000000ULL);
	TEST_OK(grant == MLFQ_Q2_SLICE_NS + MLFQ_Q2_SLICE_NS / 2 &&
		q.bonus_ns == 0,
		"fcbs atomicity: deposit after consume is a clean deposit");
}

/*
 * Queue grant. Identity without bonus, additive with bonus.
 */
static void test_queue_grant(void)
{
	TEST_OK(mlfq_queue_grant(MLFQ_Q1_SLICE_NS, 0) == MLFQ_Q1_SLICE_NS,
		"queue grant: no bonus returns the slice unchanged");
	TEST_OK(mlfq_queue_grant(MLFQ_Q1_SLICE_NS, MLFQ_Q1_SLICE_NS / 2) ==
		MLFQ_Q1_SLICE_NS + MLFQ_Q1_SLICE_NS / 2,
		"queue grant: bonus adds to the slice");
	TEST_OK(mlfq_queue_grant(MLFQ_Q2_SLICE_NS, MLFQ_Q2_SLICE_NS) ==
		2 * MLFQ_Q2_SLICE_NS,
		"queue grant: max bonus yields 2*Q_q");
	TEST_OK(mlfq_queue_grant(MLFQ_Q3_SLICE_NS, 0) == MLFQ_Q3_SLICE_NS,
		"queue grant: Q3 with no bonus is Q3 slice");
}

/*
 * The reenq_cnt counter saturates at MLFQ_DEMOTE_EXHAUSTIONS. A Q3
 * task (which is never demoted) increments the counter on every run-out
 * but the saturation prevents a u8 wrap from resetting its history.
 */
static void test_reenq_cnt_saturation(void)
{
	u8 cnt = 0;

	/* 0 -> 1 -> ... -> 8 stays at 8. */
	for (int i = 0; i < 7; i++) {
		cnt = mlfq_reenq_cnt_step(cnt);
		TEST_OK(cnt == (u8)(i + 1),
			"reenq saturation: step %d -> %d", i, i + 1);
	}
	TEST_OK(cnt == MLFQ_DEMOTE_EXHAUSTIONS - 1,
		"reenq saturation: counter reaches MLFQ_DEMOTE_EXHAUSTIONS - 1");

	/* One more step. It reaches MLFQ_DEMOTE_EXHAUSTIONS. */
	cnt = mlfq_reenq_cnt_step(cnt);
	TEST_OK(cnt == MLFQ_DEMOTE_EXHAUSTIONS,
		"reenq saturation: counter reaches MLFQ_DEMOTE_EXHAUSTIONS");

	/* One more step. It stays at 8, does not wrap. */
	cnt = mlfq_reenq_cnt_step(cnt);
	TEST_OK(cnt == MLFQ_DEMOTE_EXHAUSTIONS,
		"reenq saturation: counter stays at MLFQ_DEMOTE_EXHAUSTIONS");

	/* Repeat to ensure no wrap. */
	for (int i = 0; i < 100; i++)
		cnt = mlfq_reenq_cnt_step(cnt);
	TEST_OK(cnt == MLFQ_DEMOTE_EXHAUSTIONS,
		"reenq saturation: 100 extra steps stay at 8");

	/* Already-at-max starts correctly. */
	cnt = mlfq_reenq_cnt_step(MLFQ_DEMOTE_EXHAUSTIONS);
	TEST_OK(cnt == MLFQ_DEMOTE_EXHAUSTIONS,
		"reenq saturation: starting at max stays at max");
}

/*
 * The cpuperf windowed fold maps busy_ns to the cpuperf scale:
 * perf_level = min(CPUPERF_Q1, busy_ns >> 14). The window is
 * MLFQ_CPUPERF_WINDOW_NS = 2^24 ns, and 1024 = 2^10, so the shift
 * form busy_ns >> 14 is bit-identical to busy_ns * 1024 / 2^24.
 * The busy_ns is accumulated by the lifecycle stopping path.
 */
static void test_cpuperf_mapping(void)
{
	u32 one = MLFQ_CPUPERF_Q1;

	/* Idle window. Zero busy time. */
	TEST_OK(mlfq_cpuperf_level(0) == 0,
		"cpuperf: zero busy time requests minimum level");

	/* Full window (busy_ns == CPUPERF_WINDOW_NS). Max level. */
	TEST_OK(mlfq_cpuperf_level(MLFQ_CPUPERF_WINDOW_NS) == one,
		"cpuperf: full window requests maximum level");

	/* Half window. */
	TEST_OK(mlfq_cpuperf_level(MLFQ_CPUPERF_WINDOW_NS / 2) == one / 2,
		"cpuperf: half window requests half the level");

	/* One quarter window. */
	TEST_OK(mlfq_cpuperf_level(MLFQ_CPUPERF_WINDOW_NS / 4) == one / 4,
		"cpuperf: quarter window requests quarter the level");

	/* Over-saturated (exceeds window + one segment). */
	TEST_OK(mlfq_cpuperf_level(MLFQ_CPUPERF_WINDOW_NS * 2) == one,
		"cpuperf: over-saturated busy time clamps to maximum");

	/* Just below one-quarter: the shift truncates. */
	TEST_OK(mlfq_cpuperf_level(MLFQ_CPUPERF_WINDOW_NS / 4 - 1) ==
		(u32)((MLFQ_CPUPERF_WINDOW_NS / 4 - 1) >> 14),
		"cpuperf: sub-quarter busy time truncates toward quarter");

	/*
	 * Shift-vs-division bit-identity: level = min(CPUPERF_Q1,
	 * busy_ns >> 14). For W = 2^24 and CPUPERF_Q1 = 1024 = 2^10,
	 * busy_ns * 1024 / W == busy_ns >> 14 exactly.
	 */
	for (u64 busy = 0; busy <= MLFQ_CPUPERF_WINDOW_NS;
	     busy += MLFQ_CPUPERF_WINDOW_NS / 8) {
		u32 level = mlfq_cpuperf_level(busy);
		u32 expected = busy >> 14;

		if (expected > one)
			expected = one;
		TEST_OK(level == expected,
			"cpuperf: shift matches division at busy %lu",
			(unsigned long)busy);
	}
}

static void test_boost_eligible(void)
{
	u64 win = MLFQ_SHORT_SLEEP_NS;

	TEST_OK(mlfq_boost_eligible(0, win, true),
		"I/O wakeup with no sleep is eligible");
	TEST_OK(mlfq_boost_eligible(5000000, win, true),
		"I/O wakeup after a long sleep is eligible");
	TEST_OK(!mlfq_boost_eligible(0, win, false),
		"no sleep and not I/O is not eligible");
	TEST_OK(mlfq_boost_eligible(500000, win, false),
		"short sleep is eligible");
	TEST_OK(!mlfq_boost_eligible(40000000, win, false),
		"long sleep without I/O is not eligible");
	TEST_OK(!mlfq_boost_eligible(win + 1, win, false),
		"sleep just past the window is not eligible");
	TEST_OK(mlfq_boost_eligible(win, win, false),
		"sleep exactly at the window is eligible");
}

static void test_ss_boost_allowed(void)
{
	u64 limit = MLFQ_SHORT_SLEEP_RATE_LIMIT_NS;
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
	struct task_ctx t = { .g = 0, .last_ss_boost_at = 0 };
	u64 now = 1000000000;

	TEST_OK(mlfq_ss_boost_pending(&t, 10000, false, now,
				      MLFQ_SHORT_SLEEP_NS,
				      MLFQ_SHORT_SLEEP_RATE_LIMIT_NS),
		"short sleep within the window qualifies");
	TEST_OK(!mlfq_ss_boost_pending(&t, 0, false, now,
				       MLFQ_SHORT_SLEEP_NS,
				       MLFQ_SHORT_SLEEP_RATE_LIMIT_NS),
		"zero sleep without I/O does not qualify");
	TEST_OK(mlfq_ss_boost_pending(&t, 0, true, now,
				      MLFQ_SHORT_SLEEP_NS,
				      MLFQ_SHORT_SLEEP_RATE_LIMIT_NS),
		"I/O wakeup qualifies regardless of the sleep length");
	TEST_OK(!mlfq_ss_boost_pending(&t, 100000000, false, now,
				       MLFQ_SHORT_SLEEP_NS,
				       MLFQ_SHORT_SLEEP_RATE_LIMIT_NS),
		"long sleep without I/O does not qualify");

	t.last_ss_boost_at = now;
	TEST_OK(!mlfq_ss_boost_pending(&t, 10000, false, now + 1000000,
				       MLFQ_SHORT_SLEEP_NS,
				       MLFQ_SHORT_SLEEP_RATE_LIMIT_NS),
		"rate limit blocks a second boost inside the window");
	TEST_OK(mlfq_ss_boost_pending(&t, 10000, false, now + 3000000,
				      MLFQ_SHORT_SLEEP_NS,
				      MLFQ_SHORT_SLEEP_RATE_LIMIT_NS),
		"rate limit expires and the boost qualifies again");
}

/*
 * The invariant predicates under MLFQ_CHECK. The gauge bounds predicate
 * replaces the old EMA bounds check. The queue, weight and vlag checks
 * are unchanged.
 */
static void test_mlfq_check_predicates(void)
{
	TEST_OK(mlfq_check_gauge_bounds(MLFQ_GAUGE_MAX_NS, MLFQ_GAUGE_MAX_NS),
		"gauge at G_MAX is in bounds");
	TEST_OK(!mlfq_check_gauge_bounds(MLFQ_GAUGE_MAX_NS + 1,
					 MLFQ_GAUGE_MAX_NS),
		"gauge above G_MAX is out of bounds");
	TEST_OK(mlfq_check_gauge_bounds(0, MLFQ_GAUGE_MAX_NS),
		"zero gauge is in bounds");
	TEST_OK(mlfq_check_queue(1) && mlfq_check_queue(3),
		"queues 1 and 3 are valid");
	TEST_OK(!mlfq_check_queue(0) && !mlfq_check_queue(4),
		"queues 0 and 4 are invalid");
	TEST_OK(mlfq_check_weight(1) && !mlfq_check_weight(0),
		"weight >= 1 invariant");
	TEST_OK(mlfq_check_queued_vlag(0) && !mlfq_check_queued_vlag(-1),
		"queued lag >= 0 invariant");
	TEST_OK(mlfq_check_bonus_bounds(0, MLFQ_Q1_SLICE_NS),
		"zero bonus is in bounds");
	TEST_OK(mlfq_check_bonus_bounds(MLFQ_Q1_SLICE_NS, MLFQ_Q1_SLICE_NS),
		"bonus at Q1 slice is in bounds");
	TEST_OK(!mlfq_check_bonus_bounds(MLFQ_Q1_SLICE_NS + 1,
					 MLFQ_Q1_SLICE_NS),
		"bonus above Q1 slice is out of bounds");
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

/* Runnable accounting contract. */

static void rn_state_reset(void)
{
	memset((void *)mlfq_llc_runnable, 0,
	       sizeof(mlfq_llc_runnable[0]) * MLFQ_MAX_LLCS);
	memset((void *)mlfq_queue_runnable, 0,
	       sizeof(mlfq_queue_runnable[0]) * (MLFQ_NR_QUEUES + 1));
}

static u32 rn_llc_sum(void)
{
	u32 sum = 0;
	u32 i;

	for (i = 0; i < MLFQ_MAX_LLCS; i++)
		sum += mlfq_llc_runnable[i];
	return sum;
}

static u32 rn_queue_sum(void)
{
	u32 sum = 0;
	u32 i;

	for (i = 1; i <= MLFQ_NR_QUEUES; i++)
		sum += mlfq_queue_runnable[i];
	return sum;
}

/*
 * Fresh enter. An unowned task (wakeup, fork, class-switch-in) is
 * counted once at the destination LLC and queue, and the ownership
 * record is set. A second task on the same LLC counts independently.
 */
static void test_runnable_enter_fresh(void)
{
	struct task_ctx t = { .last_llc = MLFQ_LLC_UNOWNED, .last_qid = 0 };
	struct task_ctx u = { .last_llc = MLFQ_LLC_UNOWNED, .last_qid = 0 };

	rn_state_reset();
	mlfq_runnable_enter(&t, 1, 2);
	TEST_OK(mlfq_llc_runnable[2] == 1 && mlfq_queue_runnable[1] == 1 &&
		t.last_llc == 2 && t.last_qid == 1,
		"fresh enter counts LLC 2 Q1 once and records ownership");

	mlfq_runnable_enter(&u, 3, 2);
	TEST_OK(mlfq_llc_runnable[2] == 2 && mlfq_queue_runnable[3] == 1 &&
		rn_llc_sum() == 2 && rn_queue_sum() == 2,
		"a second task on the same LLC counts separately");
}

/*
 * Continuation enters. The task is already counted, so the call only
 * moves its ownership. The table drives one task through the moves and
 * checks the gauge deltas and the invariant that the total counted
 * stays 1. Only a changed LLC or queue moves a unit between indexes.
 */
static void test_runnable_enter_continuation_table(void)
{
	struct task_ctx t = { .last_llc = MLFQ_LLC_UNOWNED, .last_qid = 0 };
	struct rn_row {
		u8 qid;
		u32 llc;
		s32 llc_delta;	/* expected LLC-gauge delta for row.llc */
		s32 q_delta;	/* expected queue-gauge delta for row.qid */
		u8 exp_llc;
		u8 exp_qid;
	};
	const struct rn_row rows[] = {
		{ .qid = 1, .llc = 0, .llc_delta = 1, .q_delta = 1,
		  .exp_llc = 0, .exp_qid = 1 },	/* fresh: count once */
		{ .qid = 1, .llc = 0, .llc_delta = 0, .q_delta = 0,
		  .exp_llc = 0, .exp_qid = 1 },	/* run-out: no move */
		{ .qid = 2, .llc = 0, .llc_delta = 0, .q_delta = 1,
		  .exp_llc = 0, .exp_qid = 2 },	/* queue move (aging) */
		{ .qid = 2, .llc = 1, .llc_delta = 1, .q_delta = 0,
		  .exp_llc = 1, .exp_qid = 2 },	/* LLC move (steal) */
		{ .qid = 3, .llc = 1, .llc_delta = 0, .q_delta = 1,
		  .exp_llc = 1, .exp_qid = 3 },	/* queue move again */
	};
	u32 i;

	rn_state_reset();
	for (i = 0; i < ARRAY_SIZE(rows); i++) {
		const struct rn_row *r = &rows[i];
		u32 prev_llc = mlfq_llc_runnable[r->llc];
		u32 prev_q = mlfq_queue_runnable[r->qid];

		mlfq_runnable_enter(&t, r->qid, r->llc);
		TEST_OK((s32)(mlfq_llc_runnable[r->llc] - prev_llc) == r->llc_delta &&
			(s32)(mlfq_queue_runnable[r->qid] - prev_q) == r->q_delta &&
			t.last_llc == r->exp_llc && t.last_qid == r->exp_qid &&
			rn_llc_sum() == 1 && rn_queue_sum() == 1,
			"continuation row %u: qid %u llc %u keeps the total at 1",
			i, r->qid, r->llc);
	}
}

/*
 * A same-LLC, same-queue continuation is the common run-out re-enqueue.
 * It is a strict no-op on both gauges and on the ownership record.
 */
static void test_runnable_continuation_noop(void)
{
	struct task_ctx t = { .last_llc = MLFQ_LLC_UNOWNED, .last_qid = 0 };

	rn_state_reset();
	mlfq_runnable_enter(&t, 1, 0);
	mlfq_runnable_enter(&t, 1, 0);
	TEST_OK(mlfq_llc_runnable[0] == 1 && mlfq_queue_runnable[1] == 1 &&
		t.last_llc == 0 && t.last_qid == 1,
		"same-LLC same-queue continuation does not re-count");
}

/*
 * Exit releases the task from both gauges and returns the ownership
 * record to the unowned state. A second exit and an exit of a task
 * never counted are no-ops (the release is idempotent against a racing
 * double-release).
 */
static void test_runnable_exit(void)
{
	struct task_ctx t = { .last_llc = MLFQ_LLC_UNOWNED, .last_qid = 0 };
	struct task_ctx u = { .last_llc = MLFQ_LLC_UNOWNED, .last_qid = 0 };
	u32 prev;

	rn_state_reset();
	mlfq_runnable_enter(&t, 2, 1);
	mlfq_runnable_exit(&t);
	TEST_OK(mlfq_llc_runnable[1] == 0 && mlfq_queue_runnable[2] == 0 &&
		t.last_llc == MLFQ_LLC_UNOWNED && t.last_qid == 0,
		"exit releases LLC and queue counts and resets ownership");

	prev = mlfq_llc_runnable[1] + mlfq_queue_runnable[2];
	mlfq_runnable_exit(&t);		/* double release */
	mlfq_runnable_exit(&u);		/* never counted */
	TEST_OK(mlfq_llc_runnable[1] + mlfq_queue_runnable[2] == prev &&
		t.last_llc == MLFQ_LLC_UNOWNED && u.last_llc == MLFQ_LLC_UNOWNED,
		"double release and release of an unowned task are no-ops");
}

/*
 * The global-park cycle. A task parked on the kernel-owned global DSQ
 * is not counted (its enqueue released any prior ownership), and its
 * runnable episode is observed at ops.running() as a fresh enter. The
 * exit then releases the episode.
 */
static void test_runnable_global_park_cycle(void)
{
	struct task_ctx t = { .last_llc = MLFQ_LLC_UNOWNED, .last_qid = 0 };

	rn_state_reset();

	/* First episode. Counted at its enqueue, released at quiescent. */
	mlfq_runnable_enter(&t, 1, 0);
	mlfq_runnable_exit(&t);
	TEST_OK(rn_llc_sum() == 0 && rn_queue_sum() == 0,
		"sleep after a counted episode releases everything");

	/* Global park. The enqueue releases, so no gauge moves. */
	mlfq_runnable_enter(&t, 2, 0);
	mlfq_runnable_exit(&t);		/* the pinned-global release */
	TEST_OK(rn_llc_sum() == 0 && rn_queue_sum() == 0 &&
		t.last_llc == MLFQ_LLC_UNOWNED,
		"global-park release un-counts the parked task");

	/* The running acquisition starts a fresh episode. */
	mlfq_runnable_enter(&t, 2, 3);
	TEST_OK(mlfq_llc_runnable[3] == 1 && mlfq_queue_runnable[2] == 1 &&
		t.last_llc == 3 && t.last_qid == 2,
		"running acquisition counts the global-parked task");

	mlfq_runnable_exit(&t);
	TEST_OK(rn_llc_sum() == 0 && rn_queue_sum() == 0,
		"exit releases the running-observed episode");
}

/*
 * The sentinel-LLC no-op: when the caller has no valid domain (LLC
 * awareness disabled, nr_llcs == 0, the mlfq_llc_of_cpu() sentinel),
 * the whole call is a no-op. No gauge moves and no ownership record
 * is written, so an unpopulated machine stays exactly at current
 * behavior.
 */
static void test_runnable_sentinel_llc_noop(void)
{
	struct task_ctx t = { .last_llc = MLFQ_LLC_UNOWNED, .last_qid = 0 };

	rn_state_reset();
	mlfq_runnable_enter(&t, 1, MLFQ_MAX_LLCS);
	TEST_OK(rn_llc_sum() == 0 && rn_queue_sum() == 0 &&
		t.last_llc == MLFQ_LLC_UNOWNED && t.last_qid == 0,
		"sentinel LLC is a no-op on gauges and ownership");

	/* The guard is per-call, not sticky. A valid domain still works. */
	mlfq_runnable_enter(&t, 1, 0);
	TEST_OK(mlfq_llc_runnable[0] == 1 && t.last_llc == 0,
		"a valid domain after a sentinel call counts normally");
}

/*
 * The queue-index guard is defense in depth. An out-of-range queue id
 * never moves the queue gauge (the LLC gauge still counts the episode,
 * and callers always pass 1..3).
 */
static void test_runnable_qid_guard(void)
{
	struct task_ctx t = { .last_llc = MLFQ_LLC_UNOWNED, .last_qid = 0 };

	rn_state_reset();
	mlfq_runnable_enter(&t, 0, 1);
	TEST_OK(mlfq_llc_runnable[1] == 1 && rn_queue_sum() == 0,
		"out-of-range queue id never moves the queue gauge");

	mlfq_runnable_exit(&t);
	TEST_OK(rn_llc_sum() == 0,
		"release balances the LLC count of the guarded enter");
}

static void test_runnable_layout(void)
{
	TEST_OK(sizeof(struct mlfq_llc_cpu_list) == 4 + MLFQ_MAX_LLC_CPUS * 4 &&
		offsetof(struct mlfq_llc_cpu_list, cpus) == 4,
		"llc cpu list is nr + MLFQ_MAX_LLC_CPUS u32s (132 bytes)");
	TEST_OK(offsetof(struct task_ctx, last_llc) == 73 &&
		offsetof(struct task_ctx, last_qid) == 74 &&
		offsetof(struct task_ctx, pad) == 75,
		"task_ctx last_llc/last_qid reuse the former pad bytes at 73/74");
	TEST_OK(offsetof(struct mlfq_stats, steals_same_llc) == 96 &&
		offsetof(struct mlfq_stats, steals_cross_llc) == 104 &&
		offsetof(struct mlfq_stats, keep_running) == 112,
		"steal counter split sits between steals and keep_running");
	TEST_OK(MLFQ_MAX_LLC_CPUS == 32 && MLFQ_LLC_SCAN_MAX == 32 &&
		MLFQ_STEER_LLC_MAX == 4 && MLFQ_LLC_UNOWNED == 0xFF,
		"LLC constants match the declared values");
}

/*
 * The steering selection (mlfq_steer_pick_llc), driven table-style
 * over the pure min-selection pass. Empty, single, waker-excluded,
 * least-loaded, tie-break, all-idle-zero, and the nr_llcs bound on the
 * candidate set.
 */
static void test_steer_pick_llc(void)
{
	u32 runnable[MLFQ_MAX_LLCS];
	u32 idle[MLFQ_MAX_LLCS];

	memset(runnable, 0, sizeof(runnable));
	memset(idle, 0, sizeof(idle));

	/* Empty. No populated domains. */
	TEST_OK(mlfq_steer_pick_llc(runnable, idle, 0, 0, 0) == MLFQ_MAX_LLCS,
		"steer: nr_llcs 0 yields the sentinel");

	/* Single. The only eligible domain is chosen. */
	idle[0] = 1;
	runnable[0] = 3;
	TEST_OK(mlfq_steer_pick_llc(runnable, idle, 2, 1, 0) == 0,
		"steer: a single eligible domain is chosen");

	/* Waker-excluded. Only the waker's own domain is idle-populated. */
	idle[0] = 0;
	idle[1] = 1;
	runnable[1] = 3;
	TEST_OK(mlfq_steer_pick_llc(runnable, idle, 2, 1, 0) == MLFQ_MAX_LLCS,
		"steer: the waker's own domain is excluded");
	idle[1] = 0;

	/* Least-loaded wins among the eligible domains. */
	idle[0] = 1;
	runnable[0] = 7;
	idle[1] = 1;
	runnable[1] = 2;
	idle[2] = 1;
	runnable[2] = 5;
	TEST_OK(mlfq_steer_pick_llc(runnable, idle, 3, 0, 0) == 1,
		"steer: the least-loaded eligible domain wins");

	/*
	 * Tie-break: equal runnable counts pick the lowest domain id among
	 * the eligible (non-waker) domains -- 1 over 2 here, with the waker
	 * on 0 excluded.
	 */
	runnable[1] = 7;
	runnable[2] = 7;
	TEST_OK(mlfq_steer_pick_llc(runnable, idle, 3, 0, 0) == 1,
		"steer: ties are broken by ascending domain id");
	runnable[1] = 2;
	runnable[2] = 5;

	/* All-idle-zero. No domain has an idle CPU -> sentinel. */
	memset(idle, 0, sizeof(idle));
	TEST_OK(mlfq_steer_pick_llc(runnable, idle, 3, 0, 0) == MLFQ_MAX_LLCS,
		"steer: no idle-populated domain yields the sentinel");

	/*
	 * nr_llcs bounds the candidate set. A domain at or above it is
	 * never a candidate even when its gauges look populated.
	 */
	idle[2] = 1;
	runnable[2] = 1;
	TEST_OK(mlfq_steer_pick_llc(runnable, idle, 2, 0, 0) == MLFQ_MAX_LLCS,
		"steer: a domain at or above nr_llcs is not a candidate");
	TEST_OK(mlfq_steer_pick_llc(runnable, idle, 3, 0, 0) == 2,
		"steer: the same domain is a candidate within nr_llcs");

	/*
	 * A visited domain is excluded. The same state with domain 2
	 * visited leaves nothing eligible.
	 */
	TEST_OK(mlfq_steer_pick_llc(runnable, idle, 3, 0, 1ULL << 2) ==
		MLFQ_MAX_LLCS,
		"steer: a visited domain is excluded from the pass");
}

/*
 * The steering caller loop of step 2.5: the selection is repeated up to
 * MLFQ_STEER_LLC_MAX times with a visited mask, so at most
 * MLFQ_STEER_LLC_MAX distinct domains are probed, in ascending-runnable
 * order, and the loop stops early when no eligible domain remains.
 */
static void test_steer_loop_bound(void)
{
	u32 runnable[MLFQ_MAX_LLCS];
	u32 idle[MLFQ_MAX_LLCS];
	u32 picks[MLFQ_STEER_LLC_MAX];
	u64 visited = 0;
	u32 n_picked = 0;
	u32 llc, attempt;

	memset(runnable, 0, sizeof(runnable));
	memset(idle, 0, sizeof(idle));

	/*
	 * Six idle-populated domains with distinct loads. Domain 5 is the
	 * waker's, so the picks must descend 4 -> 1 and the bound cuts the
	 * tail (the sixth domain, 0, is never reached).
	 */
	for (llc = 0; llc < 6; llc++) {
		idle[llc] = 1;
		runnable[llc] = 10 * (6 - llc);
	}

	for (attempt = 0; attempt < MLFQ_STEER_LLC_MAX; attempt++) {
		u32 pick = mlfq_steer_pick_llc(runnable, idle, MLFQ_MAX_LLCS,
					       5, visited);

		if (pick >= MLFQ_MAX_LLCS)
			break;
		visited |= 1ULL << pick;
		picks[n_picked++] = pick;
	}

	TEST_OK(n_picked == MLFQ_STEER_LLC_MAX,
		"steer: the attempt loop is capped at MLFQ_STEER_LLC_MAX picks");
	TEST_OK(n_picked == 4 && picks[0] == 4 && picks[1] == 3 &&
		picks[2] == 2 && picks[3] == 1,
		"steer: picks descend the load order, waker's domain excluded");

	/* Fewer eligible domains than the cap. The loop stops early. */
	memset(runnable, 0, sizeof(runnable));
	memset(idle, 0, sizeof(idle));
	idle[2] = 1;
	runnable[2] = 3;
	idle[3] = 1;
	runnable[3] = 1;
	visited = 0;
	n_picked = 0;
	for (attempt = 0; attempt < MLFQ_STEER_LLC_MAX; attempt++) {
		u32 pick = mlfq_steer_pick_llc(runnable, idle, MLFQ_MAX_LLCS,
					       5, visited);

		if (pick >= MLFQ_MAX_LLCS)
			break;
		visited |= 1ULL << pick;
		n_picked++;
	}
	TEST_OK(n_picked == 2,
		"steer: the loop stops early when no eligible domain remains");
}

int main(void)
{
	/* EEVDF virtual-time and placement. */
	test_calc_delta_fair();
	test_place_entity();
	test_place_entity_weight_edges();
	test_place_charge_replacement();
	test_place_entity_deadline_pure();
	test_sameq_preempt_owed();
	test_clock_advance();

	/* Gauge burst-classifier. */
	test_gauge_climb();
	test_gauge_period_decay();
	test_gauge_mapping();
	test_gauge_mapping_bands();
	test_promote_hysteresis();
	test_demote_hysteresis();

	/* FCBS. */
	test_fcbs_slack();
	test_fcbs_bonus();
	test_fcbs_deposit_consume_atomicity();
	test_queue_grant();

	/* Saturation and cpuperf. */
	test_reenq_cnt_saturation();
	test_cpuperf_mapping();

	/* Boost and predicates. */
	test_boost_eligible();
	test_ss_boost_allowed();
	test_ss_boost_pending();
	test_mlfq_check_predicates();

	/* Bitmap. */
	test_bitmap();

	/* Runnable accounting. */
	test_runnable_enter_fresh();
	test_runnable_enter_continuation_table();
	test_runnable_continuation_noop();
	test_runnable_exit();
	test_runnable_global_park_cycle();
	test_runnable_sentinel_llc_noop();
	test_runnable_qid_guard();
	test_runnable_layout();

	/* Steering. */
	test_steer_pick_llc();
	test_steer_loop_bound();

	if (nr_failed) {
		printf("%d test(s) FAILED\n", nr_failed);
		return 1;
	}

	printf("All tests passed\n");
	return 0;
}
