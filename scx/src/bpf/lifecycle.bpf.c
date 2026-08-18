/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Task lifecycle, included by main.bpf.c via #include.
 *
 * init_task and enable initialize the task context. running() records
 * the running task's queue, pid, deadline and run start, the
 * wakeup-preemption inputs, and sets the cpuperf target. stopping()
 * charges vruntime, climbs the burst gauge, folds the per-CPU busy
 * window for cpuperf, and advances the owning queue's virtual clock
 * with the virtual time just charged. update_idle() maintains the
 * scheduler's idle-CPU count and per-CPU idle timestamps. exit_task()
 * deletes the task storage. cpu_release() re-enqueues local-DSQ
 * leftovers when a CPU leaves the scheduler.
 *
 * Runnable accounting. The per-LLC/per-queue gauges are entered at the
 * enqueue inserts (enqueue.bpf.c) and released exactly once per
 * leave-runnable event by ops.quiescent (see below), which the kernel
 * fires on every dequeue_task_scx(). The global-park ownership
 * acquisition is observed at ops.running().
 */

static __always_inline void mlfq_reset_task_ctx(struct task_ctx *tctx,
						const struct task_struct *p,
						u64 now)
{
	tctx->vruntime = 0;
	tctx->vlag = 0;
	tctx->deadline = 0;
	tctx->last_run_at = 0;
	tctx->last_sleep_at = scx_bpf_task_running(p) ? 0 : now;
	tctx->queued_at = 0;
	tctx->weight = p->scx.weight;
	if (!tctx->weight)
		tctx->weight = 1;
	tctx->flags = MLFQ_TF_FIRST_RUN;
	tctx->wake_cpu_state = 0;
	/*
	 * The runnable-ownership record starts unowned. A fresh task is
	 * not counted in the per-LLC/per-queue gauges until its first
	 * tracked enqueue, and the accounting helpers key their
	 * "not counted" branch on last_llc == MLFQ_LLC_UNOWNED.
	 */
	tctx->last_llc = MLFQ_LLC_UNOWNED;
	tctx->last_qid = 0;
	tctx->g = 0;
	tctx->last_grant_ns = 0;
	mlfq_reset_classification(tctx);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(mlfq_init_task, struct task_struct *p,
			     struct scx_init_task_args *args)
{
	struct task_ctx *tctx;

	tctx = mlfq_alloc_task_ctx(p);
	if (!tctx)
		return -ENOMEM;

	mlfq_reset_task_ctx(tctx, p, scx_bpf_now());
	return 0;
}

void BPF_STRUCT_OPS(mlfq_enable, struct task_struct *p)
{
	struct task_ctx *tctx;

	/* init_task() is called for every task first. Be defensive here. */
	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx)
		return;

	mlfq_reset_task_ctx(tctx, p, scx_bpf_now());
}

void BPF_STRUCT_OPS(mlfq_running, struct task_struct *p)
{
	struct task_ctx *tctx;
	struct mlfq_cpu_state *cpu;
	s32 cpu_id = bpf_get_smp_processor_id();
	u64 now;

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx)
		return;

	/*
	 * Record the running task's queue, pid, deadline and run start.
	 * The wakeup-preemption decision in enqueue() compares a wakeup's
	 * queue against the queue of the task running on the CPU it was
	 * last running on, and a same-queue wakeup against the resident's
	 * deadline and residency, so the record is refreshed on every
	 * context switch. The deadline is the task's last placement
	 * deadline, zero for a task that started running without a
	 * placement (the FIFO local-DSQ paths and the keep path defer
	 * placement), which the enqueue path treats as unknown.
	 */
	now = scx_bpf_now();
	cpu = mlfq_lookup_cpu_state(cpu_id);
	if (cpu) {
		cpu->running_queue = tctx->queue;
		cpu->running_pid = p->pid;
		cpu->running_deadline = tctx->deadline;
		cpu->run_start_at = now;
	}

	/*
	 * Runnable-ownership acquisition for global-parked tasks. The
	 * kernel consumes SCX_DSQ_GLOBAL into a local DSQ on the CPU the
	 * task lands on, invisible to this BPF program, so the ownership
	 * cannot be acquired at the enqueue (the pinned path releases any
	 * prior ownership there). It is observed here instead. A task
	 * arriving on a CPU with no recorded ownership was parked
	 * globally and starts its counted episode now. A task that was
	 * already counted at its tracked enqueue is left alone. The
	 * llc_of_cpu() sentinel makes the call a no-op when LLC
	 * awareness is disabled.
	 */
	if (tctx->last_llc == MLFQ_LLC_UNOWNED)
		mlfq_runnable_enter(tctx, tctx->queue,
				    mlfq_llc_of_cpu((u32)cpu_id));

	tctx->last_run_at = now;
	tctx->flags &= ~MLFQ_TF_FIRST_RUN;

	__sync_fetch_and_add(&mlfq_stats.on_cpu, 1);

	/*
	 * cpufreq interaction. The interactive queue requests the maximum
	 * performance level through the sched_ext cpuperf API, and the
	 * other queues use the level folded at the last stopping event
	 * (cpu->perf_level, the windowed busy-window fold). The kernel
	 * stores the target per CPU and schedutil follows it on every
	 * update, so setting it on every ops.running() makes the frequency
	 * track the task now on the CPU. With the scheduler in switch-all
	 * mode the target is the only utilization signal schedutil sees,
	 * so a stale maximum would keep the CPU at top frequency for the
	 * background work that follows an interactive task. The counter
	 * reports the interactive boosts.
	 */
	if (tctx->queue == 1) {
		scx_bpf_cpuperf_set(scx_bpf_task_cpu(p), MLFQ_CPUPERF_Q1);
		__sync_fetch_and_add(&mlfq_stats.cpuperf_boosts, 1);
	} else if (cpu) {
		scx_bpf_cpuperf_set(scx_bpf_task_cpu(p), cpu->perf_level);
	}
}

void BPF_STRUCT_OPS(mlfq_stopping, struct task_struct *p, bool runnable)
{
	struct task_ctx *tctx;
	struct mlfq_cpu_state *cpu;
	struct queue_ctx *q;
	u64 now, delta = 0;
	u64 op_lat_start = scx_bpf_now();

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx) {
		mlfq_op_lat_charge(MLFQ_OP_LAT_STOPPING, op_lat_start);
		return;
	}

	now = scx_bpf_now();
	if (tctx->last_run_at && mlfq_time_before(tctx->last_run_at, now))
		delta = now - tctx->last_run_at;
	tctx->last_run_at = 0;

	if (delta) {
		/* vruntime advance for this run segment. */
		mlfq_update_vruntime(tctx, delta);

		/*
		 * Burst gauge climb. The segment delta adds to the gauge,
		 * which saturates at G_MAX. The gauge is the sole
		 * classification input, and the saturation prevents overflow
		 * under any segment length.
		 */
		tctx->g += delta;
		if (tctx->g > MLFQ_GAUGE_MAX_NS)
			tctx->g = MLFQ_GAUGE_MAX_NS;

		/*
		 * Per-CPU busy-window fold. The window rolls when the
		 * elapsed time since busy_win_start passes the window
		 * length. The level is then folded from the accumulated
		 * busy time and applied on the next ops.running() for
		 * non-interactive queues. A CPU with no stopping events
		 * for a long time keeps the old level. The kernel's
		 * schedutil decays the actual frequency in the meantime.
		 */
		cpu = mlfq_lookup_cpu_state(bpf_get_smp_processor_id());
		if (cpu) {
			if (!cpu->busy_win_start ||
			    !mlfq_time_before(now,
					      cpu->busy_win_start +
					      MLFQ_CPUPERF_WINDOW_NS)) {
				cpu->busy_win_ns = 0;
				cpu->busy_win_start = now;
			}
			cpu->busy_win_ns += delta;
			cpu->perf_level = mlfq_cpuperf_level(cpu->busy_win_ns);
		}

		/*
		 * FCBS within-queue reclaim. When the task stops
		 * without being runnable (early completion or sleep),
		 * the unspent budget of its last grant is donated to
		 * the queue's bonus. The preempt path writes
		 * last_grant_ns = 0, so slack is zero by construction
		 * (H2). A preempt burst is not full-service budget
		 * and must not generate bonus.
		 */
		if (!runnable) {
			u64 slack = mlfq_fcbs_slack(tctx->last_grant_ns,
						    delta);

			if (slack > 0) {
				q = mlfq_lookup_queue(tctx->queue);
				if (q) {
					mlfq_fcbs_deposit(&q->bonus_ns,
							  slack,
							  q->max_slice_ns);
					if (!q->bonus_since)
						q->bonus_since = now;
					__sync_fetch_and_add(
						&mlfq_stats.fcbs_slack_events,
						1);
				}
			}
		}

		/*
		 * Advance the owning queue's virtual clock with the
		 * virtual time just charged. The clock follows the
		 * service given to the queue, and placement anchors new
		 * arrivals to it. The queue lookup can fail when the
		 * task's queue state was not carried over, which is
		 * tolerated. The clock only needs to be near the service
		 * point and the placement clamp bounds the staleness.
		 */
		q = mlfq_lookup_queue(tctx->queue);
		if (q)
			mlfq_queue_advance_clock(q, tctx->vruntime);
		__sync_fetch_and_add(&mlfq_stats.total_runtime, delta);
	}

	if (!runnable)
		tctx->last_sleep_at = now;

	/*
	 * Keep the running-task record while the task remains runnable
	 * (preempted). Clear it when the task goes to sleep so the
	 * wakeup-preemption decision never compares against a stale
	 * record. The deadline and run start clear with the rest of the
	 * record.
	 */
	cpu = mlfq_lookup_cpu_state(bpf_get_smp_processor_id());
	if (cpu && !runnable) {
		cpu->running_queue = 0;
		cpu->running_pid = 0;
		cpu->running_deadline = 0;
		cpu->run_start_at = 0;
	}

	/* Diagnostic runnable count. Guard against wrap-around. */
	if (__sync_fetch_and_sub(&mlfq_stats.on_cpu, 1) == 0)
		__sync_fetch_and_add(&mlfq_stats.on_cpu, 1);

	mlfq_op_lat_charge(MLFQ_OP_LAT_STOPPING, op_lat_start);
}

/*
 * Leave-runnable accounting. This is the single release of the per-LLC
 * and per-queue ownership. The kernel calls
 * ops.quiescent on every dequeue_task_scx() (ext.c in 6.18 and 7.2,
 * identical semantics), regardless of the task's ops_state, gated only
 * on !task_on_rq_migrating, which sched-ext tasks structurally never
 * hit, because transfers mark MIGRATING and exclude dequeue. The
 * callback therefore fires exactly once per task leaving the runnable
 * set, whether it leaves from a queue DSQ (sleep, exit, property or
 * class change) or from running (sleep). ops.dequeue is NOT a usable
 * exit signal for this accounting because it fires only while ops_state
 * is QUEUED, which the dispatch moves leave set for same-rq moves and
 * clear for remote transfers. A release of a task with no recorded
 * ownership is a no-op (idempotent against a racing transfer).
 */
void BPF_STRUCT_OPS(mlfq_quiescent, struct task_struct *p, u64 deq_flags)
{
	struct task_ctx *tctx;

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx)
		return;

	mlfq_runnable_exit(tctx);
}

/*
 * Idle-state tracking. The kernel invokes this on every idle transition
 * of a CPU when the scheduler keeps the kernel's built-in idle tracking
 * (the KEEP_BUILTIN_IDLE flag). The callback is left unregistered when
 * the flag is unavailable, and mlfq_idle_tracking gates the consumer.
 * The count mirrors the number of currently idle CPUs, so the CPU
 * selection can skip its idle scans entirely when the system is
 * saturated, which is the common case for a wake-all storm. idle_since
 * records when the CPU went idle (0 = not idle, or never observed).
 * The per-LLC mirror (mlfq_llc_idle) is the steering gate. It tells
 * which LLC domains still have an idle CPU. The gate is the
 * nr_llcs-validated rodata mapping (plus the MLFQ_MAX_LLCS hard array
 * bound, so a front-end bug cannot index the bss array out of bounds).
 * An unpopulated domain map leaves the per-LLC counter untouched.
 */
void BPF_STRUCT_OPS(mlfq_update_idle, s32 cpu, bool idle)
{
	struct mlfq_cpu_state *cpu_state = mlfq_lookup_cpu_state(cpu);

	if (!cpu_state)
		return;

	if (idle) {
		__sync_fetch_and_add(&mlfq_idle_count, 1);
	} else {
		__sync_fetch_and_sub(&mlfq_idle_count, 1);
	}

	if (cpu >= 0 && cpu < (s32)MLFQ_MAX_CPUS) {
		u32 llc = mlfq_cpu_llc[cpu];

		/*
		 * The per-LLC RMW is bounded by the hard array bound as
		 * well as the populated-domain count. mlfq_llc_idle has
		 * MLFQ_MAX_LLCS entries, so a front-end bug writing
		 * mlfq_nr_llcs above 32 must not index it out of bounds.
		 * An unmapped CPU reads the MLFQ_MAX_LLCS sentinel (the
		 * front-end's default), which fails both gates.
		 */
		if (llc < MLFQ_MAX_LLCS && llc < mlfq_nr_llcs) {
			if (idle)
				__sync_fetch_and_add(&mlfq_llc_idle[llc], 1);
			else
				__sync_fetch_and_sub(&mlfq_llc_idle[llc], 1);
		}
	}
}

void BPF_STRUCT_OPS(mlfq_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct task_ctx *tctx;

	tctx = mlfq_lookup_task_ctx(p);
	if (!tctx)
		return;

	bpf_task_storage_delete(&task_ctx_stor, p);
}

/*
 * CPU release, on hotplug offline, exit drain and higher-priority class
 * takeover, pushes any leftover local-DSQ tasks back through
 * ops.enqueue() so they re-enter the queue DSQs instead of being
 * stranded on the released CPU.
 * Normally a no-op. By discipline the local DSQ depth is at most one task,
 * and a queued leftover is exactly the runnable task the CPU is leaving
 * behind. The re-enqueued leftovers land in the releasing CPU's queue
 * DSQs and are served by other CPUs' steal scans. The kernel's reenqueue
 * guard and the stall watchdog cap the pathological loop.
 * scx_bpf_reenqueue_local() is restricted to this callback (ext.c).
 *
 * On kernels with the call-from-anywhere reenqueue
 * (scx_bpf_reenqueue_local___v2, v6.19+), the sched_switch hook in
 * rtdl.bpf.c evacuates the local DSQ on a higher-priority-class
 * takeover, so this callback has nothing left to drain there and stays
 * out of the way. On 6.18 it is the only local-DSQ evacuation path and
 * does the drain. The gate is the compat layer's ksym probe on the v2
 * kfunc, dead-folded to the drain on 6.18. The ops slot is registered on
 * every kernel (the ops initializer cannot fold the probe), so on newer
 * kernels the callback still engages the cpu_acquire/cpu_release
 * takeover path but does no work.
 */
void BPF_STRUCT_OPS(mlfq_cpu_release, s32 cpu, struct scx_cpu_release_args *args)
{
	u64 op_lat_start = scx_bpf_now();

	if (__COMPAT_scx_bpf_reenqueue_local_from_anywhere()) {
		mlfq_op_lat_charge(MLFQ_OP_LAT_CPU_RELEASE, op_lat_start);
		return;
	}
	scx_bpf_reenqueue_local();
	mlfq_op_lat_charge(MLFQ_OP_LAT_CPU_RELEASE, op_lat_start);
}
