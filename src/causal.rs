//! MODULE B — Causal Inference Engine
//!
//! Formalism note (this is the part the memo got conceptually right and
//! terminologically wrong): a *pure DFA* cannot model an asynchronous,
//! multi-clock cell. What actually solves the "no synchronized clock"
//! requirement is a **single-observer happens-before relation** plus
//! **per-edge WCET windows**:
//!
//!   * One capture point => one total temporal order `tap_ts_ns`. Trustworthy.
//!   * Causal dependencies between events are NOT inferred from timing; they
//!     are declared in a per-cell `DependencyManifest` (the proprietary moat).
//!     Each declared edge A->B carries a WCET budget W.
//!   * A *violation* is an observed edge instance where Δt = ts(B)-ts(A) > W.
//!   * Root-cause attribution = walk the dependency DAG backward from the trip
//!     event and return the violation with the largest normalized magnitude
//!     (Δt - W)/W. If no edge on the path is violated, we return *no
//!     attributable cause* rather than inventing one.
//!
//! This is attribution under passive observation. It is correlational w.r.t.
//! formal causality (no interventions). We name the output
//! `CandidateCatalyst`, ranked, with magnitudes — not "the true cause".

use crate::ingest::{DecodedFieldbusFrame, IndustrialProtocol};
use std::collections::HashMap;

/// A node in the cell's dependency graph: a logical participant whose timing we
/// reason about (e.g. "AMR_cmd_vel", "Fanuc_predock", "PLC_interlock").
pub type NodeId = u32;

/// How an observed frame maps onto a logical node. Built from the manifest.
#[derive(Debug, Clone)]
pub enum NodeMatcher {
    /// Match a PROFINET frame by FrameID, and read the interlock bit from a
    /// specified (byte, bit) of the IO data. `byte_index` is relative to the
    /// start of IO data (i.e. the raw_status_byte is byte 0 in our parser; the
    /// manifest can extend this once the full IO image is plumbed).
    ProfinetFrame {
        frame_id: u16,
        bit_index: u8, // which bit of raw_status_byte is the interlock
    },
    /// Match ROS2/DDS arrival on a UDP port (logical topic).
    Ros2Port { topic_port: u16 },
    /// Match Fanuc pose stream (single logical node).
    FanucPose,
}

impl NodeMatcher {
    /// Does this matcher claim the frame? Returns the interlock level for
    /// interlock-bearing nodes (Some(true/false)); None means "matched, no
    /// interlock semantics" (a pure arrival signal).
    fn matches(&self, f: &DecodedFieldbusFrame) -> Option<Option<bool>> {
        match (self, &f.proto) {
            (
                NodeMatcher::ProfinetFrame { frame_id, bit_index },
                IndustrialProtocol::ProfinetIrt {
                    frame_id: fid,
                    raw_status_byte,
                    ..
                },
            ) if frame_id == fid => {
                let bit = (raw_status_byte >> *bit_index) & 0x01 != 0;
                Some(Some(bit))
            }
            (
                NodeMatcher::Ros2Port { topic_port },
                IndustrialProtocol::Ros2Udp { topic_port: p, .. },
            ) if topic_port == p => Some(None),
            (NodeMatcher::FanucPose, IndustrialProtocol::FanucUdp { .. }) => Some(None),
            _ => None,
        }
    }
}

/// A declared causal dependency A -> B with a WCET budget in nanoseconds.
/// "B must occur within `wcet_ns` of its triggering A, else B's timing contract
/// is violated."
#[derive(Debug, Clone, Copy)]
pub struct DependencyEdge {
    pub from: NodeId,
    pub to: NodeId,
    pub wcet_ns: u64,
}

/// The per-cell manifest. THIS is the proprietary asset. Without it the packets
/// are uninterpretable; the algorithm is generic, the manifest is the moat.
#[derive(Debug, Clone)]
pub struct DependencyManifest {
    pub nodes: HashMap<NodeId, NodeMatcher>,
    pub edges: Vec<DependencyEdge>,
    /// The node whose interlock going false (true->false) defines a "trip".
    pub trip_node: NodeId,
    /// Reverse adjacency for backward walk: to -> [edges ending at to].
    rev_adj: HashMap<NodeId, Vec<DependencyEdge>>,
}

impl DependencyManifest {
    pub fn new(
        nodes: HashMap<NodeId, NodeMatcher>,
        edges: Vec<DependencyEdge>,
        trip_node: NodeId,
    ) -> Self {
        let mut rev_adj: HashMap<NodeId, Vec<DependencyEdge>> = HashMap::new();
        for e in &edges {
            rev_adj.entry(e.to).or_default().push(*e);
        }
        Self {
            nodes,
            edges,
            trip_node,
            rev_adj,
        }
    }

    fn classify(&self, f: &DecodedFieldbusFrame) -> Option<(NodeId, Option<bool>)> {
        for (id, m) in &self.nodes {
            if let Some(interlock) = m.matches(f) {
                return Some((*id, interlock));
            }
        }
        None
    }
}

/// One recorded state transition in the ring buffer. Fixed-size, Copy, so the
/// ring is a flat preallocated array with no per-event allocation.
#[derive(Debug, Clone, Copy)]
pub struct StateTransition {
    pub seq: u64, // monotonically increasing global sequence
    pub node: NodeId,
    pub ts_ns: u64,
    /// Last-known interlock level for interlock nodes; None for arrival-only.
    pub interlock: Option<bool>,
}

/// A ranked candidate for the upstream catalyst of a trip.
#[derive(Debug, Clone)]
pub struct CandidateCatalyst {
    pub edge: DependencyEdge,
    pub observed_dt_ns: u64,
    pub wcet_ns: u64,
    /// (Δt - W) / W. >0 means budget exceeded. We rank by this.
    pub normalized_overrun: f64,
    pub trigger: StateTransition,  // the A event
    pub effect: StateTransition,   // the B event
}

/// A completed trip analysis: the trip plus the ranked catalyst chain.
#[derive(Debug, Clone)]
pub struct TripAnalysis {
    pub trip_event: StateTransition,
    /// Ranked most-severe-first. Empty => trip occurred with no WCET violation
    /// on any dependency path (an honest "no attributable cause" — likely a
    /// genuine fault, not a timing-induced nuisance trip).
    pub ranked_catalysts: Vec<CandidateCatalyst>,
}

/// Fixed-capacity ring buffer of the last `CAP` transitions. No reallocation,
/// O(1) push, O(CAP) worst-case backward scan.
pub struct RingBuffer<const CAP: usize> {
    buf: Box<[Option<StateTransition>; CAP]>,
    head: usize, // index of next write
    len: usize,
}

impl<const CAP: usize> RingBuffer<CAP> {
    pub fn new() -> Self {
        Self {
            buf: Box::new([None; CAP]),
            head: 0,
            len: 0,
        }
    }

    #[inline]
    fn push(&mut self, t: StateTransition) {
        self.buf[self.head] = Some(t);
        self.head = (self.head + 1) % CAP;
        if self.len < CAP {
            self.len += 1;
        }
    }

    /// Iterate transitions newest -> oldest.
    fn iter_rev(&self) -> impl Iterator<Item = &StateTransition> {
        let head = self.head;
        let len = self.len;
        (0..len).map(move |i| {
            // newest is at head-1
            let idx = (head + CAP - 1 - i) % CAP;
            self.buf[idx].as_ref().expect("len invariant")
        })
    }

    /// Most recent transition for `node` strictly before `before_ts`.
    fn last_for_node_before(&self, node: NodeId, before_ts: u64) -> Option<StateTransition> {
        self.iter_rev()
            .find(|t| t.node == node && t.ts_ns < before_ts)
            .copied()
    }
}

/// The engine. Generic over ring capacity; the memo asked for 10_000.
pub struct CausalGraphObserver<const CAP: usize = 10_000> {
    manifest: DependencyManifest,
    ring: RingBuffer<CAP>,
    seq: u64,
    /// Last interlock level seen per node, to detect true->false edges (trips).
    last_interlock: HashMap<NodeId, bool>,
}

impl<const CAP: usize> CausalGraphObserver<CAP> {
    pub fn new(manifest: DependencyManifest) -> Self {
        Self {
            manifest,
            ring: RingBuffer::new(),
            seq: 0,
            last_interlock: HashMap::new(),
        }
    }

    /// Feed one decoded frame. Returns `Some(TripAnalysis)` iff this frame is
    /// the trip node transitioning interlock true->false. Hot path: classify,
    /// push, and (only on trip) backtrack.
    pub fn observe(&mut self, f: &DecodedFieldbusFrame) -> Option<TripAnalysis> {
        let (node, interlock) = self.manifest.classify(f)?;

        let transition = StateTransition {
            seq: self.seq,
            node,
            ts_ns: f.tap_ts_ns,
            interlock,
        };
        self.seq += 1;

        // Detect a trip edge: trip_node going true -> false.
        let mut trip = false;
        if node == self.manifest.trip_node {
            if let Some(level) = interlock {
                let prev = self.last_interlock.get(&node).copied();
                if prev == Some(true) && !level {
                    trip = true;
                }
                self.last_interlock.insert(node, level);
            }
        } else if let Some(level) = interlock {
            self.last_interlock.insert(node, level);
        }

        self.ring.push(transition);

        if trip {
            Some(self.backtrack(transition))
        } else {
            None
        }
    }

    /// Backward attribution. From the trip event, walk the reverse dependency
    /// DAG. For each edge (A->B) whose effect node B has a recent instance at
    /// or before the trip, find the matching trigger A instance and measure
    /// Δt against W. Collect violations, rank by normalized overrun.
    ///
    /// Complexity: O(E * CAP) worst case (each edge does one backward scan).
    /// With E small (a cell is tens of edges) and CAP=10_000, this is a few
    /// hundred thousand comparisons — sub-millisecond, and it runs only on the
    /// rare trip event, never on the steady-state ingest path.
    ///
    /// Cycle safety: we do a bounded BFS over the reverse graph with a visited
    /// set, so a manifest containing a dependency cycle cannot loop forever.
    fn backtrack(&self, trip: StateTransition) -> TripAnalysis {
        use std::collections::HashSet;
        let mut candidates: Vec<CandidateCatalyst> = Vec::new();
        let mut visited: HashSet<NodeId> = HashSet::new();
        let mut frontier: Vec<(NodeId, u64)> = vec![(trip.node, trip.ts_ns)];

        while let Some((effect_node, effect_ts)) = frontier.pop() {
            if !visited.insert(effect_node) {
                continue;
            }
            let Some(incoming) = self.manifest.rev_adj.get(&effect_node) else {
                continue;
            };
            for edge in incoming {
                // The effect instance: the latest `effect_node` transition at
                // or before effect_ts. For the trip node itself this is the
                // trip; for intermediate nodes it's their last update.
                let effect_instance = if effect_node == trip.node && effect_ts == trip.ts_ns {
                    trip
                } else {
                    match self.ring.last_for_node_before(effect_node, effect_ts + 1) {
                        Some(t) => t,
                        None => continue,
                    }
                };
                // The trigger instance: latest `from` transition strictly before
                // the effect instance.
                let Some(trigger) = self
                    .ring
                    .last_for_node_before(edge.from, effect_instance.ts_ns)
                else {
                    continue;
                };

                let dt = effect_instance.ts_ns.saturating_sub(trigger.ts_ns);
                if dt > edge.wcet_ns {
                    let overrun = (dt as f64 - edge.wcet_ns as f64) / (edge.wcet_ns as f64);
                    candidates.push(CandidateCatalyst {
                        edge: *edge,
                        observed_dt_ns: dt,
                        wcet_ns: edge.wcet_ns,
                        normalized_overrun: overrun,
                        trigger,
                        effect: effect_instance,
                    });
                }
                // Continue walking upstream from the trigger regardless of
                // whether THIS edge violated — the catalyst may be two hops up.
                frontier.push((edge.from, trigger.ts_ns));
            }
        }

        // Rank most-severe first. NaN-safe: overruns are finite positives here.
        candidates.sort_by(|a, b| {
            b.normalized_overrun
                .partial_cmp(&a.normalized_overrun)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        TripAnalysis {
            trip_event: trip,
            ranked_catalysts: candidates,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::{DecodedFieldbusFrame, IndustrialProtocol};

    // Node ids
    const N_AMR: NodeId = 1;
    const N_FANUC: NodeId = 2;
    const N_PLC: NodeId = 3;

    fn manifest() -> DependencyManifest {
        let mut nodes = HashMap::new();
        nodes.insert(N_AMR, NodeMatcher::Ros2Port { topic_port: 7400 });
        nodes.insert(N_FANUC, NodeMatcher::FanucPose);
        nodes.insert(
            N_PLC,
            NodeMatcher::ProfinetFrame {
                frame_id: 0x0002,
                bit_index: 0,
            },
        );
        // Dependency chain: AMR arrival -> Fanuc pose -> PLC interlock.
        // WCET budgets: AMR->Fanuc must be within 3ms; Fanuc->PLC within 4ms.
        let edges = vec![
            DependencyEdge {
                from: N_AMR,
                to: N_FANUC,
                wcet_ns: 3_000_000,
            },
            DependencyEdge {
                from: N_FANUC,
                to: N_PLC,
                wcet_ns: 4_000_000,
            },
        ];
        DependencyManifest::new(nodes, edges, N_PLC)
    }

    fn ros2(ts: u64) -> DecodedFieldbusFrame<'static> {
        DecodedFieldbusFrame {
            tap_ts_ns: ts,
            proto: IndustrialProtocol::Ros2Udp {
                topic_port: 7400,
                payload_len: 32,
            },
            raw: &[],
        }
    }
    fn fanuc(ts: u64) -> DecodedFieldbusFrame<'static> {
        DecodedFieldbusFrame {
            tap_ts_ns: ts,
            proto: IndustrialProtocol::FanucUdp {
                x_mm: 0.0,
                y_mm: 0.0,
                z_mm: 0.0,
            },
            raw: &[],
        }
    }
    fn plc(ts: u64, interlock: bool) -> DecodedFieldbusFrame<'static> {
        let status = if interlock { 0x01 } else { 0x00 };
        DecodedFieldbusFrame {
            tap_ts_ns: ts,
            proto: IndustrialProtocol::ProfinetIrt {
                frame_id: 0x0002,
                interlock_bit: interlock,
                raw_status_byte: status,
            },
            raw: &[],
        }
    }

    #[test]
    fn attributes_trip_to_amr_jitter() {
        let mut eng: CausalGraphObserver<10_000> = CausalGraphObserver::new(manifest());

        // Normal cycle: AMR@0, Fanuc@2ms (within 3ms), PLC interlock high@4ms.
        assert!(eng.observe(&ros2(0)).is_none());
        assert!(eng.observe(&fanuc(2_000_000)).is_none());
        assert!(eng.observe(&plc(4_000_000, true)).is_none());

        // Bad cycle: AMR@10ms, but Fanuc pose arrives @20ms (10ms gap >> 3ms
        // budget — the jitter). PLC then trips low @22ms (within its own 4ms
        // budget from Fanuc, so the PLC->edge is NOT the culprit).
        assert!(eng.observe(&ros2(10_000_000)).is_none());
        assert!(eng.observe(&fanuc(20_000_000)).is_none());
        let analysis = eng
            .observe(&plc(22_000_000, false))
            .expect("trip should fire on true->false");

        assert!(!analysis.ranked_catalysts.is_empty());
        let top = &analysis.ranked_catalysts[0];
        // The AMR->Fanuc edge is the violated one (10ms vs 3ms budget).
        assert_eq!(top.edge.from, N_AMR);
        assert_eq!(top.edge.to, N_FANUC);
        assert_eq!(top.observed_dt_ns, 10_000_000);
        // overrun = (10-3)/3 ≈ 2.33
        assert!((top.normalized_overrun - 7.0 / 3.0).abs() < 1e-9);
    }

    #[test]
    fn clean_trip_yields_no_false_catalyst() {
        let mut eng: CausalGraphObserver<10_000> = CausalGraphObserver::new(manifest());
        // Everything within budget, but PLC trips anyway (genuine non-timing
        // fault). Engine must NOT fabricate a catalyst.
        eng.observe(&ros2(0));
        eng.observe(&fanuc(1_000_000)); // 1ms < 3ms ok
        eng.observe(&plc(2_000_000, true)); // 1ms < 4ms ok
        eng.observe(&ros2(100_000_000));
        eng.observe(&fanuc(101_000_000));
        let analysis = eng.observe(&plc(102_000_000, false)).unwrap();
        assert!(
            analysis.ranked_catalysts.is_empty(),
            "no WCET violation => no attributable catalyst"
        );
    }
}
