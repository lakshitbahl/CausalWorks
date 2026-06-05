//! Storage layer handshake — sink for `TraceRow` outputs.
//!
//! Two implementations:
//!   * `InMemorySink` — always available, no system deps. Used by the harness
//!     to verify the engine→storage handshake end-to-end in CI. Keeps rows in a
//!     time-ordered map so range scans (the common ISO-evidence query) work.
//!   * `RocksDbSink` — feature-gated (`rocksdb-sink`). Real persistence using
//!     the RocksDB composite key (`trip_ts_ns` big-endian || trace_id) so that
//!     an iterator yields traces in chronological order for free. RocksDB is
//!     chosen over Timescale for the EDGE appliance: it is embedded (no server
//!     process on a $1,200 ruggedized PC), append-friendly, and survives power
//!     loss with WAL. TimescaleDB belongs at the CENTRAL aggregation tier, not
//!     on the appliance — fetching rows up to a Postgres/Timescale instance is
//!     a separate forwarder concern, not this sink.
//!
//! The trait is intentionally minimal: `put` one row, `range` scan by time.
//! No update/delete — trace evidence is append-only and immutable by design
//! (tamper-evidence is a feature, not a missing capability). That immutability
//! is also why the appliance must NEVER expose a delete path: an ISO 13849
//! evidence store that can be silently edited is worthless as evidence.

use crate::trace::TraceRow;
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("duplicate trace_id at same timestamp: {0} (append-only violation)")]
    DuplicateKey(String),
    #[cfg(feature = "rocksdb-sink")]
    #[error("rocksdb: {0}")]
    RocksDb(#[from] rocksdb::Error),
}

/// Append-only sink for completed trace rows.
pub trait TraceSink {
    /// Persist one row. Idempotency is the caller's concern; we reject exact
    /// key collisions to surface a sequencing bug rather than silently
    /// overwriting evidence.
    fn put(&mut self, row: &TraceRow) -> Result<(), StorageError>;

    /// Return all rows with `trip_ts_ns` in `[start, end)`, chronological.
    /// Returns owned rows (clones) — evidence retrieval is not a hot path.
    fn range(&self, start_ns: u64, end_ns: u64) -> Result<Vec<TraceRow>, StorageError>;

    fn len(&self) -> usize;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Composite ordering key: (trip_ts_ns, trace_id). Big-endian timestamp first
/// so byte-order == chronological order, matching the RocksDB key layout so
/// both backends scan identically.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct OrderKey {
    ts_ns: u64,
    trace_id: String,
}

pub struct InMemorySink {
    rows: BTreeMap<OrderKey, TraceRow>,
}

impl InMemorySink {
    pub fn new() -> Self {
        Self {
            rows: BTreeMap::new(),
        }
    }
}

impl Default for InMemorySink {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceSink for InMemorySink {
    fn put(&mut self, row: &TraceRow) -> Result<(), StorageError> {
        let key = OrderKey {
            ts_ns: row.trip_ts_ns,
            trace_id: row.trace_id.clone(),
        };
        if self.rows.contains_key(&key) {
            return Err(StorageError::DuplicateKey(row.trace_id.clone()));
        }
        self.rows.insert(key, row.clone());
        Ok(())
    }

    fn range(&self, start_ns: u64, end_ns: u64) -> Result<Vec<TraceRow>, StorageError> {
        let lo = OrderKey {
            ts_ns: start_ns,
            trace_id: String::new(),
        };
        let hi = OrderKey {
            ts_ns: end_ns,
            trace_id: String::new(),
        };
        Ok(self
            .rows
            .range(lo..hi)
            .map(|(_, v)| v.clone())
            .collect())
    }

    fn len(&self) -> usize {
        self.rows.len()
    }
}

/// RocksDB-backed persistent sink. Feature-gated so the crate builds without
/// the rocksdb system dependency (which compiles a large C++ lib).
#[cfg(feature = "rocksdb-sink")]
pub struct RocksDbSink {
    db: rocksdb::DB,
    count: usize,
}

#[cfg(feature = "rocksdb-sink")]
impl RocksDbSink {
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        // Evidence is write-once, read-occasionally: bias for write throughput
        // and durability. Enable the WAL (default) so a power cut mid-write on
        // the ruggedized PC does not corrupt the store.
        let db = rocksdb::DB::open(&opts, path)?;
        // Count existing rows for len(). For large stores you'd track this in a
        // metadata key instead of scanning; documented shortcut for clarity.
        let count = db.iterator(rocksdb::IteratorMode::Start).count();
        Ok(Self { db, count })
    }
}

#[cfg(feature = "rocksdb-sink")]
impl TraceSink for RocksDbSink {
    fn put(&mut self, row: &TraceRow) -> Result<(), StorageError> {
        let key = row.rocksdb_key();
        if self.db.get(&key)?.is_some() {
            return Err(StorageError::DuplicateKey(row.trace_id.clone()));
        }
        self.db.put(&key, row.evidence_json.as_bytes())?;
        self.count += 1;
        Ok(())
    }

    fn range(&self, start_ns: u64, end_ns: u64) -> Result<Vec<TraceRow>, StorageError> {
        // Seek to start_ns, iterate until ts >= end_ns. Keys are
        // big-endian(ts) || trace_id, so a prefix seek on the 8-byte timestamp
        // lands correctly.
        let start_key = start_ns.to_be_bytes();
        let mut out = Vec::new();
        let iter = self.db.iterator(rocksdb::IteratorMode::From(
            &start_key,
            rocksdb::Direction::Forward,
        ));
        for item in iter {
            let (k, v) = item?;
            if k.len() < 8 {
                continue;
            }
            let ts = u64::from_be_bytes(k[..8].try_into().unwrap());
            if ts >= end_ns {
                break;
            }
            // Reconstruct the row from stored evidence JSON. We persist only the
            // evidence blob (the indexed columns are derivable from it); rebuild
            // the TraceRow via its constructor from the parsed CausalTrace.
            let trace: crate::trace::CausalTrace = serde_json::from_slice(&v)?;
            out.push(TraceRow::from_trace(&trace)?);
        }
        Ok(out)
    }

    fn len(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(ts: u64, id: &str) -> TraceRow {
        TraceRow {
            trip_ts_ns: ts,
            trace_id: id.to_string(),
            appliance_id: "APPL-001".into(),
            safety_fn_id: "SF-1".into(),
            attributed: true,
            root_overrun: Some(2.33),
            evidence_json: "{}".into(),
        }
    }

    #[test]
    fn inmemory_range_is_chronological_and_half_open() {
        let mut s = InMemorySink::new();
        s.put(&row(300, "c")).unwrap();
        s.put(&row(100, "a")).unwrap();
        s.put(&row(200, "b")).unwrap();
        let r = s.range(100, 300).unwrap(); // [100,300): excludes 300
        let ids: Vec<_> = r.iter().map(|x| x.trace_id.as_str()).collect();
        assert_eq!(ids, vec!["a", "b"]);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn inmemory_rejects_duplicate_key() {
        let mut s = InMemorySink::new();
        s.put(&row(100, "a")).unwrap();
        assert!(matches!(
            s.put(&row(100, "a")),
            Err(StorageError::DuplicateKey(_))
        ));
    }
}
