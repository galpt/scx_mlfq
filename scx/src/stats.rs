// SPDX-License-Identifier: GPL-2.0
//
// Copyright (c) 2026 Galih Tama <galpt@v.recipes>
//
// This software may be used and distributed according to the terms of the GNU
// General Public License version 2.

//! Stats server, `#[derive(Stats)]` metrics and monitor loop.
//!
//! `Metrics` corresponds to the BPF-side `struct mlfq_stats` (a `volatile` global
//! declared in `src/bpf/intf.h`, defined in `src/bpf/main.bpf.c`) plus a
//! userspace uptime gauge. Field names match the BPF struct 1:1; the `top`
//! stats op reports deltas over the poll interval.

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
}

impl Metrics {
    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(
            w,
            "[{}] run={} runtime_ns={} uptime_ns={} \
             placements: Q1={} Q2={} Q3={} \
             promotions={} demotions={} aging_boosts={} short_sleep_boosts={} \
             preemption_kicks={} cpuperf_boosts={}",
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
        )?;
        Ok(())
    }

    /// Interval delta: counters are wrapping deltas over the poll interval;
    /// gauges (`on_cpu`, `uptime_ns`) pass through as instantaneous values.
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
        }
    }
}

/// Stats server definition: a single `top` op reporting interval deltas.
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

/// Monitor loop: periodically poll the stats server and print a one-line
/// summary. Runs in its own thread (see `main.rs`); exits on shutdown.
pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}
