# scx_mlfq

scx_mlfq is a sched ext scheduler in Rust with a BPF core.
It implements a multilevel feedback queue on virtual time.
The design follows per queue bounded lag with fixed constants.

## Overview

Tasks enter three per CPU queues. The first holds interactive
tasks. The second holds unclassified tasks. The third holds
CPU bound tasks. Slices are one, two and four milliseconds.
Service follows virtual deadline order in a bounded batch.
Classification uses a regression tree that predicts the next
burst from recent behavior. The tree is trained in user space
on local samples and republished each minute. An EMA gauge
serves as fallback until the first model is published. Tasks
with recent GPU submissions are treated as interactive.

Wakeup promotion, run out demotion, aging and a Q3 share
provide balance across load. Each placement keeps lag within
one bound of the queue clock, which gives per queue bounded lag.

## Configuration

Constants are fixed at compile time. Reporting is controlled
by three options, namely statistical output, monitor mode and
disabled web interface. Adaptation of band edges is enabled
by default and follows system latency and rate gauges. A
topology banner reports CPU count, capacity split, cache
domains and SMT state at startup. A ten microsecond PM QoS
constraint is held for the run to limit idle exit latency.

## Web Interface

The interface serves loopback port 50005 with a unix fallback.
It presents summary gauges, per CPU state and system counters.
No authentication is provided as loopback is the boundary.
The disabled flag turns the thread off entirely. When TCP is
denied, service continues on the unix socket and a per boot
drop in under run lifts the filter for the next start. Run is
tmpfs, so an unclean exit is clean at reboot.

## Realtime Avoidance

Realtime tasks preempt sched ext CPUs by class order. The
scheduler tracks occupancy on context switch, drains taken
CPUs and avoids occupied cores at placement. Evacuation uses
the queue reenqueue path. A thirty second watchdog exits to
the base scheduler when a callback stalls.

## Limitations

Lag is bounded per queue only. Queues are per CPU, and idle
CPUs take owed work from peers. Gauges cover tracked tasks
and remain advisory.
