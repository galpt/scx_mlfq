/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Dispatch: queue service with quotas, included by main.bpf.c via
 * #include.
 *
 * The kernel serves SCX_DSQ_LOCAL before ops.dispatch() (ext.c dispatch
 * loop), so this callback only consumes the per-CPU queue DSQs: each CPU
 * drains its own three queues, Q1 up to its quota, then Q2 up to its
 * quota, then the Q3 remainder, bounded by dispatch_max_batch. Each
 * dispatch() call moves at most MLFQ_Q1_QUOTA + MLFQ_Q2_QUOTA +
 * (MLFQ_DISPATCH_MAX_BATCH - quotas) tasks, so a Q3 task waits at most
 * one bounded batch of Q1+Q2 service.
 *
 * The three quotas are served by three independent, tightly bounded loops.
 * Each iteration is a queue-nonempty check, one move and one stat
 * increment, so the loop bodies stay flat and the verifier state small.
 */

void BPF_STRUCT_OPS(mlfq_dispatch, s32 cpu, struct task_struct *prev)
{
	struct mlfq_cpu_state *cpu_state = mlfq_lookup_cpu_state(cpu);
	u32 q1_quota = mlfq_q1_quota;
	u32 q2_quota = mlfq_q2_quota;
	u32 q3_quota = mlfq_dispatch_max_batch - q1_quota - q2_quota;
	u32 i;

	for (i = 0; i < q1_quota && scx_bpf_dsq_nr_queued(mlfq_dsq_id(1, cpu)); i++) {
		scx_bpf_dsq_move_to_local(mlfq_dsq_id(1, cpu), 0);
		if (cpu_state)
			cpu_state->q1_dispatches++;
	}

	for (i = 0; i < q2_quota && scx_bpf_dsq_nr_queued(mlfq_dsq_id(2, cpu)); i++) {
		scx_bpf_dsq_move_to_local(mlfq_dsq_id(2, cpu), 0);
		if (cpu_state)
			cpu_state->q2_dispatches++;
	}

	for (i = 0; i < q3_quota && scx_bpf_dsq_nr_queued(mlfq_dsq_id(3, cpu)); i++) {
		scx_bpf_dsq_move_to_local(mlfq_dsq_id(3, cpu), 0);
		if (cpu_state)
			cpu_state->q3_dispatches++;
	}
}
