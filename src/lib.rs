//! CausalWorks core backend.
//!
//! Pipeline shape (single-cell appliance):
//!
//! ```text
//!  TAP/SPAN ──> CaptureSource ──> parse_frame ──> CausalGraphObserver
//!   (HW ts)      (ingest.rs)       (zero-copy)        (causal.rs)
//!                                                         │ on trip
//!                                                         ▼
//!                                                   TripAnalysis
//!                                                         │
//!                                                   CausalTrace ──> TraceRow
//!                                                    (trace.rs)      ──> store
//! ```
//!
//! Threading model for production (NOT implemented here — it is deployment
//! policy, and over-specifying it now would be premature):
//!   * One capture thread, CPU-pinned, real-time priority, doing only
//!     capture+parse+`observe`. Keep it allocation-free (it is).
//!   * `observe` returns `Some(TripAnalysis)` rarely (only on a trip). Hand that
//!     off over a bounded SPSC channel to a separate serialization/storage
//!     thread so the DB write (which CAN block/allocate) never stalls capture.
//!   * If the channel is full, drop-newest with a counter, never block the
//!     capture thread — a passive diagnostic must never become backpressure on
//!     its own observation.
//!
//! What is deliberately NOT here, and why:
//!   * AF_XDP capture backend — needs a target NIC + kernel to be real, not a
//!     mock. The `CaptureSource` trait is the seam.
//!   * Full RTPS/DDS submessage parsing — a module of its own; arrival timing
//!     suffices for the causal layer.
//!   * Certified PL/PFHd computation — out of scope for a passive observer
//!     (see trace.rs scope note).

pub use causal::{
    CausalGraphObserver, DependencyEdge, DependencyManifest, NodeId, NodeMatcher, StateTransition,
    TripAnalysis,
};
pub use discovery::{
    DiscoveryEngine, LogHistogram, StreamKey, StreamProfile, UnclassifiedTally,
};
pub use ingest::{
    parse_frame, CaptureSource, DecodedFieldbusFrame, IndustrialProtocol, ParseError,
    TimestampSource,
};
pub use manifest::{ManifestCfg, ManifestError, ManifestWarning};
pub use replay::{PcapError, PcapReplaySource};
pub use stream::{StreamPcapError, StreamingPcapSource};
pub use storage::{InMemorySink, StorageError, TraceSink};
pub use trace::{CausalTrace, FindingClass, Iso13849Srs, TraceEvent, TraceRow};

pub mod causal;
pub mod discovery;
pub mod hwcapture;
pub mod ingest;
pub mod manifest;
pub mod replay;
pub mod stream;
pub mod storage;
pub mod trace;
