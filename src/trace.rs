//! MODULE C — Structured Serialization & ISO 13849 Compliance Logging
//!
//! Two distinct concerns, deliberately separated:
//!
//!   1. `CausalTrace` — the human-auditable, JSON-serializable evidence record
//!      for an ISO 13849 package. Optimized for auditability, not density.
//!   2. `TraceRow` / `EventRow` — the flat, append-only storage layout for the
//!      time-series store. This is what TimescaleDB (hypertable) or RocksDB
//!      (sorted by composite key) actually ingests at volume.
//!
//! HONEST SCOPE BOUNDARY ON ISO 13849:
//! This module produces *evidence artifacts* — a structured, timestamped,
//! tamper-evident record of observed timing behavior, tagged with the SRS
//! fields a validator needs. It does **not** compute a certified PL
//! (Performance Level) or PFHd, and it cannot: those require the full SISTEMA
//! parameters (architecture category, MTTFd, DC, CCF) of the actual safety
//! function, which a passive observer does not have. Marketing that says this
//! "auto-generates the safety certification" is false. What it truthfully does:
//! supply traceable timing evidence that *supports* a human-led validation,
//! and flag observed responses against the configured demand/response budgets.
//! The `iso13849` block records exactly that and no more.

use crate::causal::{CandidateCatalyst, NodeId, TripAnalysis};
use serde::{Deserialize, Serialize};

/// SRS-aligned metadata. Fields map to ISO 13849-1 Safety Requirements
/// Specification concepts. Values are configured per safety function + measured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Iso13849Srs {
    /// Identifier of the safety function this trip exercised (from the SRS).
    pub safety_function_id: String,
    /// Configured worst-case demand-to-safe-state budget (ns) for this SF.
    pub configured_response_budget_ns: u64,
    /// OBSERVED interval from the catalyst (demand precursor) to the safe-state
    /// transition (interlock low). This is measured, not assumed.
    pub observed_response_time_ns: u64,
    /// Did the observed safe-state response occur within the configured budget?
    /// True = the *protective* function still met its timing contract even
    /// though a nuisance condition occurred. (A nuisance trip is a spurious
    /// demand, not a safety-function failure — important distinction for the
    /// validator.)
    pub response_within_budget: bool,
    /// The category of finding, for the evidence index.
    pub finding: FindingClass,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FindingClass {
    /// Timing-induced spurious demand attributable to an upstream WCET overrun.
    AttributableNuisanceTrip,
    /// Trip with no WCET violation found — escalate to functional fault review.
    UnattributedTrip,
}

/// A single cross-network event in the reconstructed sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    pub seq: u64,
    pub node: NodeId,
    pub ts_ns: u64,
    /// Relative offset (ns) from the trip event; negative = before the trip.
    pub offset_from_trip_ns: i64,
    pub interlock: Option<bool>,
}

/// One ranked catalyst, flattened for the evidence record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceCatalyst {
    pub edge_from: NodeId,
    pub edge_to: NodeId,
    pub observed_dt_ns: u64,
    pub wcet_ns: u64,
    pub normalized_overrun: f64,
    pub trigger_seq: u64,
    pub effect_seq: u64,
}

impl From<&CandidateCatalyst> for TraceCatalyst {
    fn from(c: &CandidateCatalyst) -> Self {
        Self {
            edge_from: c.edge.from,
            edge_to: c.edge.to,
            observed_dt_ns: c.observed_dt_ns,
            wcet_ns: c.wcet_ns,
            normalized_overrun: c.normalized_overrun,
            trigger_seq: c.trigger.seq,
            effect_seq: c.effect.seq,
        }
    }
}

/// The complete, serializable causal trace for one trip — the evidence record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalTrace {
    /// Globally unique trace id. Construction is deployment-specific; we use
    /// (appliance_id, trip_ts_ns, trip_seq) which is collision-free per
    /// appliance and monotonic, avoiding a RNG dependency on the hot path.
    pub trace_id: String,
    pub appliance_id: String,
    pub trip_ts_ns: u64,
    /// Highest-ranked catalyst, if any. None => UnattributedTrip.
    pub root_catalyst: Option<TraceCatalyst>,
    /// All ranked catalysts (root first).
    pub ranked_catalysts: Vec<TraceCatalyst>,
    /// Full ms-by-ms sequence preceding the trip (oldest -> newest).
    pub event_sequence: Vec<TraceEvent>,
    pub iso13849: Iso13849Srs,
}

impl CausalTrace {
    /// Build the evidence record from a `TripAnalysis` plus the event window the
    /// caller chooses to retain (the engine holds the ring; the caller decides
    /// how many preceding events to materialize into the record — typically the
    /// dependency-relevant slice, not all 10k).
    pub fn build(
        appliance_id: &str,
        analysis: &TripAnalysis,
        preceding_events: &[TraceEvent],
        safety_function_id: &str,
        configured_response_budget_ns: u64,
    ) -> Self {
        let trip = analysis.trip_event;
        let trace_id = format!("{}:{}:{}", appliance_id, trip.ts_ns, trip.seq);

        let root = analysis.ranked_catalysts.first();
        let finding = if root.is_some() {
            FindingClass::AttributableNuisanceTrip
        } else {
            FindingClass::UnattributedTrip
        };

        // Observed response time = trip_ts - root catalyst trigger_ts, if we
        // have a catalyst; otherwise 0 (not meaningful for an unattributed trip).
        let observed_response_time_ns = root
            .map(|c| trip.ts_ns.saturating_sub(c.trigger.ts_ns))
            .unwrap_or(0);

        let iso13849 = Iso13849Srs {
            safety_function_id: safety_function_id.to_string(),
            configured_response_budget_ns,
            observed_response_time_ns,
            response_within_budget: observed_response_time_ns
                <= configured_response_budget_ns
                && root.is_some(),
            finding,
        };

        Self {
            trace_id,
            appliance_id: appliance_id.to_string(),
            trip_ts_ns: trip.ts_ns,
            root_catalyst: root.map(TraceCatalyst::from),
            ranked_catalysts: analysis
                .ranked_catalysts
                .iter()
                .map(TraceCatalyst::from)
                .collect(),
            event_sequence: preceding_events.to_vec(),
            iso13849,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

// ---------------------------------------------------------------------------
// Storage layout for the time-series store.
// ---------------------------------------------------------------------------

/// One row per trip in the `traces` hypertable. The wide JSON evidence record
/// is stored as a blob/jsonb column; the indexed columns are the query keys.
///
/// TimescaleDB DDL this maps to (documented here so the schema and struct stay
/// in sync — keep them edited together):
///
/// ```sql
/// CREATE TABLE traces (
///   trip_ts        TIMESTAMPTZ      NOT NULL,
///   trace_id       TEXT             NOT NULL,
///   appliance_id   TEXT             NOT NULL,
///   safety_fn_id   TEXT             NOT NULL,
///   attributed     BOOLEAN          NOT NULL,
///   root_overrun   DOUBLE PRECISION,         -- NULL for unattributed
///   evidence       JSONB            NOT NULL,
///   PRIMARY KEY (trip_ts, trace_id)
/// );
/// SELECT create_hypertable('traces', 'trip_ts');
/// ```
///
/// For RocksDB instead: key = big-endian(trip_ts_ns) || trace_id (so scans are
/// time-ordered), value = the serialized evidence. The struct is the same.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRow {
    pub trip_ts_ns: u64,
    pub trace_id: String,
    pub appliance_id: String,
    pub safety_fn_id: String,
    pub attributed: bool,
    pub root_overrun: Option<f64>,
    /// Serialized `CausalTrace` (jsonb in TimescaleDB; opaque value in RocksDB).
    pub evidence_json: String,
}

impl TraceRow {
    pub fn from_trace(t: &CausalTrace) -> Result<Self, serde_json::Error> {
        Ok(Self {
            trip_ts_ns: t.trip_ts_ns,
            trace_id: t.trace_id.clone(),
            appliance_id: t.appliance_id.clone(),
            safety_fn_id: t.iso13849.safety_function_id.clone(),
            attributed: t.iso13849.finding == FindingClass::AttributableNuisanceTrip,
            root_overrun: t.root_catalyst.as_ref().map(|c| c.normalized_overrun),
            evidence_json: t.to_json()?,
        })
    }

    /// RocksDB composite key: time-ordered scans for free.
    pub fn rocksdb_key(&self) -> Vec<u8> {
        let mut k = self.trip_ts_ns.to_be_bytes().to_vec();
        k.extend_from_slice(self.trace_id.as_bytes());
        k
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::causal::{CandidateCatalyst, DependencyEdge, StateTransition, TripAnalysis};

    fn st(seq: u64, node: NodeId, ts: u64, il: Option<bool>) -> StateTransition {
        StateTransition {
            seq,
            node,
            ts_ns: ts,
            interlock: il,
        }
    }

    #[test]
    fn attributed_trace_round_trips_and_flags_iso() {
        let trip = st(10, 3, 22_000_000, Some(false));
        let cat = CandidateCatalyst {
            edge: DependencyEdge {
                from: 1,
                to: 2,
                wcet_ns: 3_000_000,
            },
            observed_dt_ns: 10_000_000,
            wcet_ns: 3_000_000,
            normalized_overrun: 7.0 / 3.0,
            trigger: st(7, 1, 10_000_000, None),
            effect: st(8, 2, 20_000_000, None),
        };
        let analysis = TripAnalysis {
            trip_event: trip,
            ranked_catalysts: vec![cat],
        };
        let events = vec![TraceEvent {
            seq: 7,
            node: 1,
            ts_ns: 10_000_000,
            offset_from_trip_ns: 10_000_000i64 - 22_000_000i64,
            interlock: None,
        }];
        let trace = CausalTrace::build("APPL-001", &analysis, &events, "SF-ENTRY-GATE", 50_000_000);

        assert_eq!(trace.iso13849.finding, FindingClass::AttributableNuisanceTrip);
        // response time = trip_ts - trigger_ts = 22ms - 10ms = 12ms < 50ms budget
        assert_eq!(trace.iso13849.observed_response_time_ns, 12_000_000);
        assert!(trace.iso13849.response_within_budget);

        let json = trace.to_json().unwrap();
        let back: CausalTrace = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trace_id, trace.trace_id);

        let row = TraceRow::from_trace(&trace).unwrap();
        assert!(row.attributed);
        assert!(row.root_overrun.is_some());
        assert_eq!(row.rocksdb_key().len(), 8 + trace.trace_id.len());
    }

    #[test]
    fn unattributed_trip_is_flagged_for_fault_review() {
        let trip = st(5, 3, 100_000_000, Some(false));
        let analysis = TripAnalysis {
            trip_event: trip,
            ranked_catalysts: vec![],
        };
        let trace = CausalTrace::build("APPL-001", &analysis, &[], "SF-ENTRY-GATE", 50_000_000);
        assert_eq!(trace.iso13849.finding, FindingClass::UnattributedTrip);
        assert!(trace.root_catalyst.is_none());
        // An unattributed trip must NOT be reported as "within budget".
        assert!(!trace.iso13849.response_within_budget);
    }
}
