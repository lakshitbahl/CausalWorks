//! JSON manifest loader + validation.
//!
//! Moves the cell topology out of hardcoded harness constants into an
//! authorable config file. The on-disk schema is deliberately explicit and
//! flat so an SI engineer can read and edit it without knowing Rust.
//!
//! WCET budgets are ABSOLUTE NANOSECONDS, by deliberate decision: relative
//! budgets (e.g. "3x nominal cycle") would silently expand if the line's
//! cyclic rate changed, which is disqualifying for a functional-safety budget.
//! The discovery histograms inform the absolute numbers the SI commits to;
//! the schema itself stays stateless and absolute.
//!
//! Validation rejects manifests that would produce garbage attributions:
//!   * dangling edge endpoints (edge references an undeclared node)
//!   * duplicate node ids
//!   * zero or absurd WCET budgets
//!   * a trip_node that isn't a Profinet/interlock-bearing node
//!   * dependency CYCLES (the backtracker tolerates them via a visited-set, but
//!     a cycle in a *causal dependency* graph is almost always an authoring
//!     error and we surface it rather than silently accept it)
//!
//! Validation is fail-CLOSED: an invalid manifest is an error, never a
//! best-effort partial load. Wrong topology silently accepted is the
//! credibility-killing failure mode.

use crate::causal::{DependencyEdge, DependencyManifest, NodeId, NodeMatcher};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("json parse: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("duplicate node id {0}")]
    DuplicateNode(NodeId),
    #[error("edge references undeclared node id {0}")]
    DanglingNode(NodeId),
    #[error("edge {from}->{to} has zero or absurd WCET budget {wcet_ns} ns")]
    BadBudget { from: NodeId, to: NodeId, wcet_ns: u64 },
    #[error("trip_node {0} is not declared")]
    TripNodeUndeclared(NodeId),
    #[error("trip_node {0} is not an interlock-bearing Profinet node")]
    TripNodeNotInterlock(NodeId),
    #[error("dependency cycle detected involving node {0}")]
    DependencyCycle(NodeId),
    #[error("manifest declares no nodes")]
    Empty,
}

/// Non-fatal lint findings. Surfaced to the operator but do not block a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestWarning {
    /// No edge leads into the trip node — every trip will be unattributed.
    TripNodeUnreachable(NodeId),
    /// A declared node has no edges in or out (likely forgotten wiring).
    OrphanNode(NodeId),
    /// A WCET budget below ~1µs — below the jitter floor of replay/software
    /// timestamps, so violations of it are likely noise unless the capture is
    /// characterized NIC-hardware-stamped.
    SuspiciouslyTightBudget { from: NodeId, to: NodeId, wcet_ns: u64 },
}

impl std::fmt::Display for ManifestWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ManifestWarning::TripNodeUnreachable(id) => write!(
                f,
                "trip_node {id} has no incoming dependency edges — all trips will be UNATTRIBUTED (did you forget to wire edges into it?)"
            ),
            ManifestWarning::OrphanNode(id) => write!(
                f,
                "node {id} has no edges in or out — it is declared but never used"
            ),
            ManifestWarning::SuspiciouslyTightBudget { from, to, wcet_ns } => write!(
                f,
                "edge {from}->{to} budget {wcet_ns}ns is sub-µs — below replay/software timestamp jitter; violations may be noise unless the capture is hardware-stamped"
            ),
        }
    }
}

/// On-disk node matcher. Tagged enum for readable JSON, e.g.
/// `{ "type": "profinet", "frame_id": 2, "bit_index": 0 }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeMatcherCfg {
    Profinet { frame_id: u16, bit_index: u8 },
    Ros2Port { topic_port: u16 },
    FanucPose,
}

impl From<&NodeMatcherCfg> for NodeMatcher {
    fn from(c: &NodeMatcherCfg) -> Self {
        match *c {
            NodeMatcherCfg::Profinet { frame_id, bit_index } => {
                NodeMatcher::ProfinetFrame { frame_id, bit_index }
            }
            NodeMatcherCfg::Ros2Port { topic_port } => NodeMatcher::Ros2Port { topic_port },
            NodeMatcherCfg::FanucPose => NodeMatcher::FanucPose,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCfg {
    pub id: NodeId,
    /// Human label for reports (not used in matching).
    #[serde(default)]
    pub label: String,
    #[serde(flatten)]
    pub matcher: NodeMatcherCfg,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdgeCfg {
    pub from: NodeId,
    pub to: NodeId,
    /// Absolute WCET budget in nanoseconds. Authored from the SI's stated
    /// cyclic specs, informed by (but not equal to) discovery percentiles.
    pub wcet_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestCfg {
    #[serde(default)]
    pub cell_name: String,
    pub nodes: Vec<NodeCfg>,
    pub edges: Vec<EdgeCfg>,
    pub trip_node: NodeId,
}

/// Upper sanity bound on a WCET budget: 60 seconds. A cyclic safety budget
/// larger than this is almost certainly a units error (ms entered as ns, etc.).
const MAX_SANE_WCET_NS: u64 = 60_000_000_000;

impl ManifestCfg {
    pub fn from_json_str(s: &str) -> Result<Self, ManifestError> {
        Ok(serde_json::from_str(s)?)
    }

    pub fn from_path(path: &str) -> Result<Self, ManifestError> {
        let s = std::fs::read_to_string(path)?;
        Self::from_json_str(&s)
    }

    /// Validate and convert into the runtime `DependencyManifest`. Fail-closed.
    pub fn build(&self) -> Result<DependencyManifest, ManifestError> {
        if self.nodes.is_empty() {
            return Err(ManifestError::Empty);
        }

        // Node table + duplicate detection.
        let mut nodes: HashMap<NodeId, NodeMatcher> = HashMap::new();
        for n in &self.nodes {
            if nodes.contains_key(&n.id) {
                return Err(ManifestError::DuplicateNode(n.id));
            }
            nodes.insert(n.id, (&n.matcher).into());
        }

        // Trip node must exist and be interlock-bearing (Profinet).
        match nodes.get(&self.trip_node) {
            None => return Err(ManifestError::TripNodeUndeclared(self.trip_node)),
            Some(NodeMatcher::ProfinetFrame { .. }) => {}
            Some(_) => return Err(ManifestError::TripNodeNotInterlock(self.trip_node)),
        }

        // Edge validation: endpoints declared, budgets sane.
        let mut edges = Vec::with_capacity(self.edges.len());
        for e in &self.edges {
            if !nodes.contains_key(&e.from) {
                return Err(ManifestError::DanglingNode(e.from));
            }
            if !nodes.contains_key(&e.to) {
                return Err(ManifestError::DanglingNode(e.to));
            }
            if e.wcet_ns == 0 || e.wcet_ns > MAX_SANE_WCET_NS {
                return Err(ManifestError::BadBudget {
                    from: e.from,
                    to: e.to,
                    wcet_ns: e.wcet_ns,
                });
            }
            edges.push(DependencyEdge {
                from: e.from,
                to: e.to,
                wcet_ns: e.wcet_ns,
            });
        }

        // Cycle detection over the directed dependency graph (DFS, 3-color).
        Self::detect_cycle(&edges)?;

        Ok(DependencyManifest::new(nodes, edges, self.trip_node))
    }

    /// Non-fatal lints: a manifest can be structurally valid (passes `build`)
    /// yet analytically useless or suspicious. These do NOT block the run but
    /// MUST be surfaced — they are the mistakes an SI makes that produce
    /// "everything is unattributed" or attribution on noise.
    ///
    /// Returns the warnings; an empty vec means a clean lint. Call after a
    /// successful `build()` (assumes structural validity).
    pub fn lint(&self) -> Vec<ManifestWarning> {
        let mut w = Vec::new();

        let node_ids: HashSet<NodeId> = self.nodes.iter().map(|n| n.id).collect();

        // Build adjacency (forward) and reverse-reachability to the trip node.
        let mut fwd: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        let mut indeg: HashMap<NodeId, usize> = HashMap::new();
        let mut outdeg: HashMap<NodeId, usize> = HashMap::new();
        for e in &self.edges {
            fwd.entry(e.from).or_default().push(e.to);
            *outdeg.entry(e.from).or_insert(0) += 1;
            *indeg.entry(e.to).or_insert(0) += 1;
        }

        // 1. Trip node reachability: is there ANY path from some node into the
        //    trip node? If indeg(trip)==0 the backtracker has nothing to walk.
        if indeg.get(&self.trip_node).copied().unwrap_or(0) == 0 {
            w.push(ManifestWarning::TripNodeUnreachable(self.trip_node));
        }

        // 2. Orphan nodes: declared but no edges in or out.
        for id in &node_ids {
            let has_in = indeg.get(id).copied().unwrap_or(0) > 0;
            let has_out = outdeg.get(id).copied().unwrap_or(0) > 0;
            if !has_in && !has_out {
                w.push(ManifestWarning::OrphanNode(*id));
            }
        }

        // 3. Suspiciously tight budgets. A sub-microsecond WCET on any edge is
        //    below the jitter floor of every timestamp source except a
        //    characterized NIC hardware stamp; on a replay/software-stamped
        //    capture such a "violation" is noise. We warn, not error, because a
        //    genuine hardware-stamped wired Profinet edge *could* legitimately
        //    be sub-µs.
        const TIGHT_BUDGET_NS: u64 = 1_000; // 1µs
        for e in &self.edges {
            if e.wcet_ns < TIGHT_BUDGET_NS {
                w.push(ManifestWarning::SuspiciouslyTightBudget {
                    from: e.from,
                    to: e.to,
                    wcet_ns: e.wcet_ns,
                });
            }
        }

        w
    }

    /// Classic white/gray/black DFS cycle detection. Returns the first node
    /// found on a back-edge.
    fn detect_cycle(edges: &[DependencyEdge]) -> Result<(), ManifestError> {
        let mut adj: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
        let mut all: HashSet<NodeId> = HashSet::new();
        for e in edges {
            adj.entry(e.from).or_default().push(e.to);
            all.insert(e.from);
            all.insert(e.to);
        }
        // 0 = white (unvisited), 1 = gray (on stack), 2 = black (done)
        let mut color: HashMap<NodeId, u8> = HashMap::new();

        // Iterative DFS to avoid stack overflow on large graphs.
        for &start in &all {
            if color.get(&start).copied().unwrap_or(0) != 0 {
                continue;
            }
            // stack holds (node, child-iterator-index)
            let mut stack: Vec<(NodeId, usize)> = vec![(start, 0)];
            color.insert(start, 1);
            while let Some(&mut (node, ref mut idx)) = stack.last_mut() {
                let children = adj.get(&node);
                let next = children.and_then(|c| c.get(*idx)).copied();
                match next {
                    Some(child) => {
                        *idx += 1;
                        match color.get(&child).copied().unwrap_or(0) {
                            1 => return Err(ManifestError::DependencyCycle(child)), // back-edge
                            0 => {
                                color.insert(child, 1);
                                stack.push((child, 0));
                            }
                            _ => {}
                        }
                    }
                    None => {
                        color.insert(node, 2);
                        stack.pop();
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_json() -> &'static str {
        r#"{
          "cell_name": "demo",
          "nodes": [
            { "id": 1, "label": "amr",   "type": "ros2_port", "topic_port": 7400 },
            { "id": 2, "label": "fanuc", "type": "fanuc_pose" },
            { "id": 3, "label": "plc",   "type": "profinet", "frame_id": 2, "bit_index": 0 }
          ],
          "edges": [
            { "from": 1, "to": 2, "wcet_ns": 3000000 },
            { "from": 2, "to": 3, "wcet_ns": 4000000 }
          ],
          "trip_node": 3
        }"#
    }

    #[test]
    fn valid_manifest_builds() {
        let cfg = ManifestCfg::from_json_str(base_json()).unwrap();
        let m = cfg.build().unwrap();
        assert_eq!(m.trip_node, 3);
        assert_eq!(m.edges.len(), 2);
    }

    #[test]
    fn rejects_dangling_edge() {
        let j = base_json().replace("\"from\": 1, \"to\": 2", "\"from\": 99, \"to\": 2");
        let cfg = ManifestCfg::from_json_str(&j).unwrap();
        assert!(matches!(cfg.build(), Err(ManifestError::DanglingNode(99))));
    }

    #[test]
    fn rejects_zero_budget() {
        let j = base_json().replace("\"wcet_ns\": 3000000", "\"wcet_ns\": 0");
        let cfg = ManifestCfg::from_json_str(&j).unwrap();
        assert!(matches!(
            cfg.build(),
            Err(ManifestError::BadBudget { wcet_ns: 0, .. })
        ));
    }

    #[test]
    fn rejects_units_error_budget() {
        // 120 seconds in ns — likely ms entered as ns.
        let j = base_json().replace("\"wcet_ns\": 3000000", "\"wcet_ns\": 120000000000");
        let cfg = ManifestCfg::from_json_str(&j).unwrap();
        assert!(matches!(cfg.build(), Err(ManifestError::BadBudget { .. })));
    }

    #[test]
    fn rejects_non_interlock_trip_node() {
        let j = base_json().replace("\"trip_node\": 3", "\"trip_node\": 1");
        let cfg = ManifestCfg::from_json_str(&j).unwrap();
        assert!(matches!(
            cfg.build(),
            Err(ManifestError::TripNodeNotInterlock(1))
        ));
    }

    #[test]
    fn detects_cycle() {
        // Add an edge 3->1 to close a cycle 1->2->3->1.
        let j = base_json().replace(
            "{ \"from\": 2, \"to\": 3, \"wcet_ns\": 4000000 }",
            "{ \"from\": 2, \"to\": 3, \"wcet_ns\": 4000000 }, { \"from\": 3, \"to\": 1, \"wcet_ns\": 1000000 }",
        );
        let cfg = ManifestCfg::from_json_str(&j).unwrap();
        assert!(matches!(cfg.build(), Err(ManifestError::DependencyCycle(_))));
    }

    #[test]
    fn rejects_duplicate_node() {
        let j = base_json().replace(
            "{ \"id\": 2, \"label\": \"fanuc\", \"type\": \"fanuc_pose\" }",
            "{ \"id\": 1, \"label\": \"dup\", \"type\": \"fanuc_pose\" }",
        );
        let cfg = ManifestCfg::from_json_str(&j).unwrap();
        assert!(matches!(cfg.build(), Err(ManifestError::DuplicateNode(1))));
    }

    #[test]
    fn clean_manifest_lints_clean() {
        let cfg = ManifestCfg::from_json_str(base_json()).unwrap();
        cfg.build().unwrap();
        assert!(cfg.lint().is_empty(), "demo manifest should have no warnings");
    }

    #[test]
    fn lints_unreachable_trip_node() {
        // Remove the edge into the trip node (2->3), leaving trip_node 3 with
        // no incoming edges. Structurally valid, analytically dead.
        let j = base_json().replace(
            ",\n            { \"from\": 2, \"to\": 3, \"wcet_ns\": 4000000 }",
            "",
        );
        let cfg = ManifestCfg::from_json_str(&j).unwrap();
        cfg.build().unwrap(); // passes structural validation
        let w = cfg.lint();
        assert!(
            w.iter().any(|x| matches!(x, ManifestWarning::TripNodeUnreachable(3)))
                && w.iter().any(|x| matches!(x, ManifestWarning::OrphanNode(3))),
            "unreachable trip node 3 must warn; got {:?}",
            w
        );
    }

    #[test]
    fn lints_tight_budget() {
        let j = base_json().replace("\"wcet_ns\": 3000000", "\"wcet_ns\": 500");
        let cfg = ManifestCfg::from_json_str(&j).unwrap();
        cfg.build().unwrap();
        let w = cfg.lint();
        assert!(w
            .iter()
            .any(|x| matches!(x, ManifestWarning::SuspiciouslyTightBudget { wcet_ns: 500, .. })));
    }
}
