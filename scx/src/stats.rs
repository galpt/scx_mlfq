// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

//! Stats server, `#[derive(Stats)]` metrics and monitor loop.
//!
//! `Metrics` corresponds to the BPF-side `struct mlfq_stats`: the type is
//! defined in `src/bpf/intf.h` and lives in a per-CPU map in
//! `src/bpf/main.bpf.c` (the front-end sums the per-CPU slots), plus a
//! userspace uptime gauge. Field names match the BPF struct 1:1. The
//! `top` stats op reports deltas over the poll interval.

use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;
use serde::Deserialize;
use serde::Serialize;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Tasks currently executing on a CPU")]
    pub on_cpu: u64,
    #[stat(desc = "Total CPU runtime in ns")]
    pub total_runtime: u64,
    #[stat(desc = "Scheduler uptime (wall clock since attach)")]
    pub uptime_ns: u64,
    #[stat(desc = "Tasks placed in Q1")]
    pub q1_placements: u64,
    #[stat(desc = "Tasks placed in Q2")]
    pub q2_placements: u64,
    #[stat(desc = "Tasks placed in Q3")]
    pub q3_placements: u64,
    #[stat(desc = "Queue promotions")]
    pub promotions: u64,
    #[stat(desc = "Queue demotions")]
    pub demotions: u64,
    #[stat(desc = "Aging boosts to Q1")]
    pub aging_boosts: u64,
    #[stat(desc = "Short-sleep and I/O wakeup boosts")]
    pub short_sleep_boosts: u64,
    #[stat(desc = "Wakeup preemption kicks")]
    pub preemption_kicks: u64,
    #[stat(desc = "Q1 cpuperf target boosts set on running")]
    pub cpuperf_boosts: u64,
    #[stat(desc = "Dispatch moves from remote queue DSQs")]
    pub steals: u64,
    #[stat(desc = "Dispatch moves from remote queue DSQs within the same LLC")]
    pub steals_same_llc: u64,
    #[stat(desc = "Dispatch moves from remote queue DSQs across LLC domains")]
    pub steals_cross_llc: u64,
    #[stat(desc = "Solo-task keep-running grants on empty dispatch")]
    pub keep_running: u64,
    #[stat(desc = "Enqueues dropped when task state cannot be allocated")]
    pub enq_no_tctx: u64,
    #[stat(desc = "Enqueues dropped for bad weight")]
    pub enq_bad_weight: u64,
    #[stat(desc = "Enqueues dropped for missing placement")]
    pub enq_no_deadline: u64,
    #[stat(desc = "Fast-path enqueues")]
    pub enq_fastpath: u64,
    #[stat(desc = "Regular-path enqueues")]
    pub enq_regular: u64,
    #[stat(desc = "Pinned enqueues to idle CPUs")]
    pub enq_pinned_idle: u64,
    #[stat(desc = "Pinned enqueues to busy CPUs")]
    pub enq_pinned_busy: u64,
    #[stat(desc = "Pinned enqueues to the global DSQ")]
    pub enq_pinned_global: u64,
    #[stat(desc = "Realtime/DL/stop takeovers of SCX CPUs observed via ops.cpu_release()")]
    pub rt_takeovers: u64,
    #[stat(desc = "DSQ evacuation passes that ran on realtime takeovers")]
    pub rt_evacuations: u64,
    #[stat(desc = "Placements redirected off realtime-occupied CPUs")]
    pub rt_redirects: u64,
    #[stat(desc = "SCX_ENQ_REENQ re-enqueues counted at enqueue")]
    pub rt_reenqs: u64,
    #[stat(
        desc = "Per-op callback latency histogram, 4 ops x 8 buckets in microseconds (stopping, dispatch, enqueue, cpu_release)"
    )]
    pub op_lat: Vec<u64>,
    #[stat(desc = "Wakeup arrivals (interval delta)")]
    pub wakeup_total: u64,
}

/// One entry of the web UI's per-CPU card grid.
///
/// The static fields (`freq_khz`, `llc_id`, `smt`) are seeded once at
/// attach from the host topology (`topology::web_cpu_static`). The
/// dynamic fields (`running_queue`, `running_pid`, `rt_occupied`) are
/// refreshed from the BPF per-CPU maps on every web-metrics poll. The
/// carriers do not take part in the stats server's `delta()` accounting.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PerCpuMetrics {
    /// CPU id.
    pub id: u32,
    /// Maximum operating frequency of the CPU, in kHz.
    pub freq_khz: u64,
    /// Current operating frequency of the CPU, in kHz, refreshed from
    /// sysfs at most once per second while the web UI serves stats. 0
    /// when the cpufreq driver exposes no current frequency.
    pub cur_freq_khz: u64,
    /// LLC domain id of the CPU (0 when the domain is unknown).
    pub llc_id: u32,
    /// True when the CPU is the non-primary thread of an SMT core, the
    /// virtual sibling. Display-only, see `topology::web_cpu_static`.
    pub smt: bool,
    /// Queue of the currently running task (0 = idle, 1..3).
    pub running_queue: i32,
    /// PID of the currently running task, 0 when idle.
    pub running_pid: u32,
    /// True when a realtime-class task currently occupies the CPU.
    pub rt_occupied: bool,
}

/// Snapshot served by the web UI's `/api/stats` endpoint.
///
/// The run loop pushes one of these every iteration (both the stats
/// request and the idle-timeout branches). The webui thread keeps the
/// newest snapshot behind a mutex for the HTTP handlers. All fields are
/// instantaneous gauges, not interval deltas: the gauges bypass the
/// stats server's `delta()` entirely.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WebMetrics {
    /// The scheduler-wide counters, raw (no delta applied).
    pub stats: Metrics,
    /// One entry per online CPU.
    pub per_cpu: Vec<PerCpuMetrics>,
    /// Tracked runnable tasks per queue. Index 0 unused, 1..3 = Q1..Q3.
    pub queue_runnable: Vec<u64>,
    /// Tracked runnable tasks per LLC domain.
    pub llc_runnable: Vec<u64>,
}

/// Bucket edges of the op-latency histogram, matching `enum
/// mlfq_op_lat_consts` in `src/bpf/intf.h`, in microseconds.
const OP_LAT_EDGES_US: [u64; 7] = [
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_2 as u64,
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_5 as u64,
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_10 as u64,
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_20 as u64,
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_50 as u64,
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_100 as u64,
    crate::bpf_intf::mlfq_op_lat_consts_MLFQ_OP_LAT_EDGE_250 as u64,
];

/// Format one op's eight bucket counts with their microsecond edges as
/// "low-high=count" pairs. A histogram shorter than eight buckets (the
/// untracked default) formats as "n/a".
fn fmt_op_lat(op: &[u64]) -> String {
    if op.len() < 8 {
        return "n/a".to_string();
    }
    let mut parts = Vec::new();
    parts.push(format!("0-{}={}", OP_LAT_EDGES_US[0], op[0]));
    for (i, edge) in OP_LAT_EDGES_US.iter().enumerate().skip(1) {
        parts.push(format!("{}-{}={}", OP_LAT_EDGES_US[i - 1], edge, op[i]));
    }
    parts.push(format!("{}+={}", OP_LAT_EDGES_US[6], op[7]));
    parts.join(" ")
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] run={} runtime_ns={} uptime_ns={} \
             placements: Q1={} Q2={} Q3={} \
             promotions={} demotions={} aging_boosts={} short_sleep_boosts={} \
             preemption_kicks={} cpuperf_boosts={} wakeups={}",
            crate::SCHEDULER_NAME,
            self.on_cpu,
            self.total_runtime,
            self.uptime_ns,
            self.q1_placements,
            self.q2_placements,
            self.q3_placements,
            self.promotions,
            self.demotions,
            self.aging_boosts,
            self.short_sleep_boosts,
            self.preemption_kicks,
            self.cpuperf_boosts,
            self.wakeup_total,
        )?;
        writeln!(
            w,
            "[{}] op_lat_us: stopping[{}] dispatch[{}]",
            crate::SCHEDULER_NAME,
            fmt_op_lat(self.op_lat.get(0..8).unwrap_or(&[])),
            fmt_op_lat(self.op_lat.get(8..16).unwrap_or(&[])),
        )?;
        writeln!(
            w,
            "[{}] op_lat_us: enqueue[{}] cpu_release[{}]",
            crate::SCHEDULER_NAME,
            fmt_op_lat(self.op_lat.get(16..24).unwrap_or(&[])),
            fmt_op_lat(self.op_lat.get(24..32).unwrap_or(&[])),
        )?;
        Ok(())
    }

    /// Interval delta. Counters are wrapping deltas over the poll interval.
    /// Gauges (`on_cpu`, `uptime_ns`) pass through as instantaneous values.
    pub fn delta(&self, rhs: &Self) -> Self {
        Self {
            on_cpu: self.on_cpu,
            total_runtime: self.total_runtime.wrapping_sub(rhs.total_runtime),
            uptime_ns: self.uptime_ns,
            q1_placements: self.q1_placements.wrapping_sub(rhs.q1_placements),
            q2_placements: self.q2_placements.wrapping_sub(rhs.q2_placements),
            q3_placements: self.q3_placements.wrapping_sub(rhs.q3_placements),
            promotions: self.promotions.wrapping_sub(rhs.promotions),
            demotions: self.demotions.wrapping_sub(rhs.demotions),
            aging_boosts: self.aging_boosts.wrapping_sub(rhs.aging_boosts),
            short_sleep_boosts: self.short_sleep_boosts.wrapping_sub(rhs.short_sleep_boosts),
            preemption_kicks: self.preemption_kicks.wrapping_sub(rhs.preemption_kicks),
            cpuperf_boosts: self.cpuperf_boosts.wrapping_sub(rhs.cpuperf_boosts),
            steals: self.steals.wrapping_sub(rhs.steals),
            steals_same_llc: self.steals_same_llc.wrapping_sub(rhs.steals_same_llc),
            steals_cross_llc: self.steals_cross_llc.wrapping_sub(rhs.steals_cross_llc),
            keep_running: self.keep_running.wrapping_sub(rhs.keep_running),
            enq_no_tctx: self.enq_no_tctx.wrapping_sub(rhs.enq_no_tctx),
            enq_bad_weight: self.enq_bad_weight.wrapping_sub(rhs.enq_bad_weight),
            enq_no_deadline: self.enq_no_deadline.wrapping_sub(rhs.enq_no_deadline),
            enq_fastpath: self.enq_fastpath.wrapping_sub(rhs.enq_fastpath),
            enq_regular: self.enq_regular.wrapping_sub(rhs.enq_regular),
            enq_pinned_idle: self.enq_pinned_idle.wrapping_sub(rhs.enq_pinned_idle),
            enq_pinned_busy: self.enq_pinned_busy.wrapping_sub(rhs.enq_pinned_busy),
            enq_pinned_global: self.enq_pinned_global.wrapping_sub(rhs.enq_pinned_global),
            rt_takeovers: self.rt_takeovers.wrapping_sub(rhs.rt_takeovers),
            rt_evacuations: self.rt_evacuations.wrapping_sub(rhs.rt_evacuations),
            rt_redirects: self.rt_redirects.wrapping_sub(rhs.rt_redirects),
            rt_reenqs: self.rt_reenqs.wrapping_sub(rhs.rt_reenqs),
            op_lat: self
                .op_lat
                .iter()
                .zip(rhs.op_lat.iter())
                .map(|(lhs, rhs)| lhs.wrapping_sub(*rhs))
                .collect(),
            wakeup_total: self.wakeup_total.wrapping_sub(rhs.wakeup_total),
        }
    }
}

/// The stats server definition. A single `top` op reporting interval deltas.
pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });

        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

/// The monitor loop. It periodically polls the stats server and prints a
/// one-line summary. It runs in its own thread (see `main.rs`) and exits
/// on shutdown.
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
