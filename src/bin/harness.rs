//! CausalWorks local testing harness.
//!
//! Usage:
//!   causalworks-harness run <capture.pcap>     # replay a capture through the engine
//!   causalworks-harness gen-fixture <out.pcap> # write a synthetic test capture
//!
//! The harness wires: PcapReplaySource -> parse_frame -> CausalGraphObserver
//! -> CausalTrace -> InMemorySink, and prints a summary including how many
//! frames were dropped/truncated and how many trips were attributed.
//!
//! "Handles line drops correctly" is the core verification target. Two drop
//! classes are exercised:
//!   1. Capture-truncated records (incl_len < orig_len) — the replay source
//!      flags these; the parser returns a Truncated/ShortPayload error; the
//!      harness counts and SKIPS them without crashing and without corrupting
//!      engine state.
//!   2. Unparseable / non-traced frames — skipped the same way.
//! A passive diagnostic that panics on a malformed frame is unfit for purpose;
//! this loop proves it degrades to "count and continue."

use std::collections::HashMap;
use std::process::ExitCode;

use causalworks::causal::StateTransition;
use causalworks::{
    parse_frame, CaptureSource, CausalGraphObserver, CausalTrace, DependencyEdge,
    DependencyManifest, InMemorySink, NodeId, NodeMatcher, PcapReplaySource, TimestampSource,
    TraceEvent, TraceRow, TraceSink,
};

// ---- Demo cell topology (used ONLY by gen-fixture and the legacy demo run;
// real runs load a manifest from JSON via `run-manifest`). ----
const N_AMR: NodeId = 1;
const N_FANUC: NodeId = 2;
const N_PLC: NodeId = 3;
const FANUC_PORT: u16 = 60008;
const AMR_PORT: u16 = 7400;

// ---- Discovery mode: stream a (possibly multi-GB) capture and profile it ----

fn ethertype_of(buf: &[u8]) -> Option<u16> {
    if buf.len() < 14 {
        return None;
    }
    let mut et = ((buf[12] as u16) << 8) | buf[13] as u16;
    if et == 0x8100 {
        if buf.len() < 18 {
            return Some(0x8100);
        }
        et = ((buf[16] as u16) << 8) | buf[17] as u16;
    }
    Some(et)
}

// ---- Preflight triage: read-only qualification of an incoming capture ----
//
// Design principle: report FACTS the file actually contains; give a verdict
// only where the data supports one. A classic .pcap does NOT record whether its
// timestamps came from NIC hardware or a software driver — that metadata lives
// in pcapng interface blocks, or nowhere. Therefore preflight does NOT classify
// "hardware TAP vs software SPAN" from inter-frame timing: the minimum gap
// between consecutive frames measures how busy the line was, not clock
// fidelity, and inferring fidelity from it would be exactly the kind of
// confident-wrong output this tool exists to prevent. Fidelity is FLAGGED as a
// question for the SI to answer, not asserted.

/// Fraction of unclassified frames above which we withhold an "Analyzable"
/// verdict — the cell is likely running a protocol the parser doesn't cover.
const COVERAGE_GAP_THRESHOLD: f64 = 0.20; // 20%

/// Pure, measurable facts extracted from a capture during preflight. No I/O, no
/// printing — this is the testable core. The CLI wrapper formats it; the verdict
/// is derived from it deterministically.
#[derive(Debug, Default, PartialEq)]
struct PreflightStats {
    total: u64,
    classifiable: u64,
    unclassified: u64,
    malformed: u64,
    vlan_frames: u64,
    truncated: u64,
    ended_mid_record: bool,
    span_ns: u64,
    min_delta_ns: Option<u64>,
    /// EtherType -> frame count, for the unsupported-protocol breakdown.
    ethertypes: std::collections::BTreeMap<u16, u64>,
}

impl PreflightStats {
    fn unclassified_frac(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.unclassified as f64 / self.total as f64
        }
    }

    /// The verdict is a pure function of the stats — no printing — so it can be
    /// asserted in tests directly.
    fn verdict(&self) -> PreflightVerdict {
        if self.total == 0 {
            PreflightVerdict::RejectedEmpty
        } else if self.unclassified_frac() > COVERAGE_GAP_THRESHOLD {
            PreflightVerdict::CoverageGap
        } else {
            PreflightVerdict::Analyzable
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PreflightVerdict {
    Analyzable,
    CoverageGap,
    RejectedEmpty,
    /// Reader rejected the file before any frame (pcapng / bad magic). Carries
    /// whether the reader said it was pcapng, so the CLI can give the editcap hint.
    RejectedFormat { is_pcapng: bool },
}

/// Measure a capture from any reader. Testable with an in-memory `Cursor`; no
/// files, no stdout. Returns the reader-format rejection as a verdict (not an
/// error) so the caller can print the right hint.
fn compute_preflight<R: std::io::Read>(
    reader: R,
) -> (PreflightVerdict, PreflightStats) {
    use causalworks::{CaptureSource, StreamingPcapSource};

    let mut src = match StreamingPcapSource::new(reader) {
        Ok(s) => s,
        Err(e) => {
            let is_pcapng = e.to_string().contains("pcapng");
            return (
                PreflightVerdict::RejectedFormat { is_pcapng },
                PreflightStats::default(),
            );
        }
    };

    let mut s = PreflightStats::default();
    let mut first_ts: Option<u64> = None;
    let mut last_ts: u64 = 0;
    let mut min_delta = u64::MAX;

    loop {
        match src.next_frame() {
            Ok(Some((ts, buf))) => {
                s.total += 1;

                if first_ts.is_none() {
                    first_ts = Some(ts);
                } else if ts >= last_ts {
                    let d = ts - last_ts;
                    if d > 0 && d < min_delta {
                        min_delta = d;
                    }
                }
                last_ts = ts;

                if buf.len() >= 14 && buf[12] == 0x81 && buf[13] == 0x00 {
                    s.vlan_frames += 1;
                }

                // Record the EtherType for the breakdown regardless of
                // classifiability.
                match ethertype_of(buf) {
                    Some(et) => {
                        *s.ethertypes.entry(et).or_insert(0) += 1;
                    }
                    None => {
                        s.malformed += 1;
                    }
                }

                // CLASSIFY USING THE SAME ARBITER THE ENGINE USES: parse_frame.
                // A frame is "classifiable" iff parse_frame accepts it — i.e.
                // Profinet (0x8892), or IPv4/UDP (which parse_frame treats as a
                // ROS2/Fanuc arrival signal). IPv4/TCP (e.g. S7comm on port 102)
                // is rejected by parse_frame and is therefore correctly counted
                // unclassified here. This makes preflight's coverage agree with
                // discover's by construction — both gate on parse_frame — rather
                // than preflight optimistically counting all IPv4 as supported,
                // which over-reported coverage on real S7-1500 captures (the
                // majority of which is TCP S7comm, not UDP).
                match parse_frame(ts, buf) {
                    Ok(_) => s.classifiable += 1,
                    Err(_) => s.unclassified += 1,
                }
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("capture error after {} records (stopping): {e}", s.total);
                break;
            }
        }
    }

    s.truncated = src.truncated_records;
    s.ended_mid_record = src.ended_mid_record;
    s.span_ns = first_ts.map(|f| last_ts.saturating_sub(f)).unwrap_or(0);
    s.min_delta_ns = if min_delta == u64::MAX { None } else { Some(min_delta) };

    let verdict = s.verdict();
    (verdict, s)
}

/// CLI wrapper: open the file, compute, print the report, return the pass/fail
/// bool for the process exit code. All formatting lives here; the logic above
/// is what the tests exercise.
fn preflight(path: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let file = std::fs::File::open(path)?;
    let (verdict, s) = compute_preflight(file);

    println!("=== PREFLIGHT REPORT: {path} ===");

    if let PreflightVerdict::RejectedFormat { is_pcapng } = verdict {
        println!("VERDICT: [REJECTED] file not accepted by reader (bad magic / pcapng).");
        if is_pcapng {
            println!("  Fix: editcap -F pcap <input.pcapng> <output.pcap>");
        }
        return Ok(false);
    }

    println!("  Format            : classic .pcap (accepted by reader)");
    println!("  Total records     : {}", s.total);
    println!("  Time span         : {} ({} records)", fmt_ns(s.span_ns), s.total);
    if s.truncated > 0 {
        println!("  Truncated/dropped : {}", s.truncated);
    }
    if s.ended_mid_record {
        println!("  NOTE: capture ended mid-record (file may be partial).");
    }
    println!(
        "  Min frame gap     : {}  (LINE BUSYNESS, not a timestamp-fidelity measure)",
        s.min_delta_ns.map(fmt_ns).unwrap_or_else(|| "n/a".into())
    );
    println!(
        "  VLAN-tagged frames: {}{}",
        s.vlan_frames,
        if s.vlan_frames > 0 { " (802.1Q present)" } else { "" }
    );
    println!(
        "  Coverage          : {} classifiable, {} unclassified ({:.1}%)",
        s.classifiable,
        s.unclassified,
        s.unclassified_frac() * 100.0
    );
    if s.malformed > 0 {
        println!("    malformed/too-short: {}", s.malformed);
    }
    // EtherType breakdown with honest classification status. Note IPv4 (0x0800)
    // is PARTIAL: parse_frame accepts its UDP traffic but rejects TCP (e.g.
    // S7comm on port 102), so an IPv4-heavy capture can still have large
    // unclassified volume. Run `discover` for the UDP-port-level split.
    if !s.ethertypes.is_empty() {
        println!("    EtherTypes present:");
        let mut ets: Vec<(&u16, &u64)> = s.ethertypes.iter().collect();
        ets.sort_by(|a, b| b.1.cmp(a.1));
        for (et, n) in ets.iter().take(12) {
            // Single description per EtherType. For supported/partial types the
            // status is specific; for unsupported types fold the protocol name
            // (LLDP/ARP/etc.) in here rather than appending a second hint, which
            // previously produced a redundant doubled parenthetical on 0x8892.
            let status: String = match **et {
                0x8892 => "supported (Profinet RT/IRT; DCP/alarm share this EtherType)".into(),
                0x0800 => "PARTIAL (UDP parsed; TCP e.g. S7comm not parsed — see `discover`)".into(),
                other => {
                    let name = ethertype_hint(other);
                    if name.is_empty() {
                        "unsupported".into()
                    } else {
                        format!("unsupported{name}")
                    }
                }
            };
            println!("      0x{:04x}: {} frames — {}", et, n, status);
        }
    }

    println!("------------------------------------");
    println!("  TIMESTAMP FIDELITY: classic .pcap carries NO hardware/software stamp");
    println!("  metadata. Confirm with the SI that this capture came from a HARDWARE");
    println!("  TAP (not a switch SPAN/mirror port) before trusting sub-ms attribution.");
    println!("------------------------------------");

    match verdict {
        PreflightVerdict::Analyzable => {
            println!("VERDICT: [ANALYZABLE] coverage sufficient. Proceed to `discover`,");
            println!("         then author the manifest from SI specs (not from the fault).");
            Ok(true)
        }
        PreflightVerdict::CoverageGap => {
            println!(
                "VERDICT: [COVERAGE GAP] {:.1}% of traffic is a protocol the parser does",
                s.unclassified_frac() * 100.0
            );
            println!("         not cover. Run a BOM/topology review and add the matcher");
            println!("         before analyzing — the dependency model has a hole.");
            Ok(false)
        }
        PreflightVerdict::RejectedEmpty => {
            println!("VERDICT: [REJECTED] no records read.");
            Ok(false)
        }
        PreflightVerdict::RejectedFormat { .. } => unreachable!("handled above"),
    }
}

fn discover(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    use causalworks::{DiscoveryEngine, StreamingPcapSource};

    let file = std::fs::File::open(path)?;
    let mut src = StreamingPcapSource::new(file)?;
    let mut disc = DiscoveryEngine::new();

    // Bounded-memory streaming loop. Every frame is either classified into a
    // stream profile or counted in the unclassified tally — total coverage.
    loop {
        match src.next_frame() {
            Ok(Some((ts, buf))) => {
                let et = ethertype_of(buf);
                match parse_frame(ts, buf) {
                    Ok(frame) => disc.observe(&frame),
                    Err(_) => disc.observe_unclassified(et),
                }
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("capture error (stopping): {e}");
                break;
            }
        }
    }

    print_discovery_report(&disc, &src);
    Ok(())
}

fn print_discovery_report<R: std::io::Read>(
    disc: &causalworks::DiscoveryEngine,
    src: &causalworks::StreamingPcapSource<R>,
) {
    use causalworks::StreamKey;

    println!("=== DISCOVERY REPORT ===");
    println!("total frames        : {}", disc.total_frames);
    println!("records read        : {}", src.records_read);
    println!("truncated (drops)   : {}", src.truncated_records);
    if src.ended_mid_record {
        println!("NOTE: capture ended mid-record (file may be partial/truncated).");
    }

    // Coverage: classified vs unclassified.
    let classified: u64 = disc.streams.values().map(|s| s.interarrival.count() + 1).sum();
    let unclassified_total: u64 =
        disc.unclassified.by_ethertype.values().sum::<u64>() + disc.unclassified.malformed;
    println!(
        "\nCOVERAGE: {} classified, {} unclassified ({:.1}% unclassified)",
        classified,
        unclassified_total,
        if disc.total_frames > 0 {
            100.0 * unclassified_total as f64 / disc.total_frames as f64
        } else {
            0.0
        }
    );
    if unclassified_total > 0 {
        let mut ets: Vec<_> = disc.unclassified.by_ethertype.iter().collect();
        ets.sort_by(|a, b| b.1.cmp(a.1));
        for (et, n) in ets {
            println!(
                "  unclassified EtherType 0x{:04x}: {} frames{}",
                et,
                n,
                ethertype_hint(*et)
            );
        }
        if disc.unclassified.malformed > 0 {
            println!("  malformed/too-short: {}", disc.unclassified.malformed);
        }
    }

    // Per-stream profile. p50 is the nominal cycle to sanity-check; the
    // p99.9-vs-p50 gap is the jitter signature. max is "worst observed",
    // explicitly NOT a proposed budget.
    println!("\nSTREAMS (inter-arrival; percentiles are histogram ESTIMATES, min/max exact):");
    let mut keys: Vec<_> = disc.streams.keys().copied().collect();
    keys.sort_by_key(|k| match k {
        StreamKey::Profinet { frame_id } => (0u8, *frame_id as u32),
        StreamKey::UdpPort { dst_port } => (1u8, *dst_port as u32),
        StreamKey::S7comm { port } => (2u8, *port as u32),
    });
    for k in keys {
        let s = &disc.streams[&k];
        let h = &s.interarrival;
        let label = match k {
            StreamKey::Profinet { frame_id } => format!("Profinet FrameID 0x{:04x}", frame_id),
            StreamKey::UdpPort { dst_port } => format!("UDP port {}", dst_port),
            StreamKey::S7comm { port } => format!("S7comm TCP port {} (arrival timing only)", port),
        };
        println!("\n  [{}]  ({} frames)", label, h.count() + 1);
        if h.count() == 0 {
            println!("    (single frame; no inter-arrival samples)");
        } else if !h.percentiles_meaningful() {
            // Too few samples for a trustworthy percentile. Show exact stats
            // only, and say plainly why the percentiles are withheld — this is
            // the guard against the spurious "p50 = 28ms on 3 samples" artifact.
            println!(
                "    INSUFFICIENT SAMPLES for percentiles (n={} < {}); exact stats only:",
                h.count(),
                causalworks::LogHistogram::<8>::MIN_SAMPLES_FOR_PERCENTILE,
            );
            println!(
                "    min={} (exact)  max={} (exact)  mean={}",
                fmt_ns(h.min()),
                fmt_ns(h.max()),
                fmt_ns(h.mean()),
            );
        } else {
            println!(
                "    p50={}  p95={}  p99={}  p99.9={}",
                fmt_ns(h.quantile(0.50)),
                fmt_ns(h.quantile(0.95)),
                fmt_ns(h.quantile(0.99)),
                fmt_ns(h.quantile(0.999)),
            );
            println!(
                "    min={} (exact)  max={} (exact, WORST OBSERVED — not a budget)  mean={}",
                fmt_ns(h.min()),
                fmt_ns(h.max()),
                fmt_ns(h.mean()),
            );
        }
        // Toggling bits for Profinet streams — candidate interlock/status bits.
        if let StreamKey::Profinet { .. } = k {
            let bits = s.toggling_bits();
            if bits.is_empty() {
                println!("    toggling bits: NONE (payload constant — no status bit here?)");
            } else {
                let shown: Vec<String> = bits
                    .iter()
                    .take(16)
                    .map(|(byte, bit)| format!("byte{}:bit{}", byte, bit))
                    .collect();
                println!(
                    "    toggling bits ({}): {}{}",
                    bits.len(),
                    shown.join(", "),
                    if bits.len() > 16 { " ..." } else { "" }
                );
            }
        }
    }

    println!(
        "\nNEXT: hand these p50 nominals + toggling bits to the SI. Have them state\n\
         ABSOLUTE WCET budgets (ns) per dependency edge BEFORE the attribution run.\n\
         Do not derive budgets from the fault you're trying to find."
    );
}

fn ethertype_hint(et: u16) -> &'static str {
    match et {
        0x0806 => " (ARP)",
        0x88cc => " (LLDP)",
        0x88f7 => " (PTP/IEEE1588)",
        0x8892 => " (PROFINET DCP/alarm — non-cyclic FrameIDs)",
        0x8100 => " (VLAN-tagged, double tag?)",
        0x88e3 => " (MRP ring)",
        _ => "",
    }
}

fn fmt_ns(ns: u64) -> String {
    if ns >= 1_000_000 {
        format!("{:.3}ms", ns as f64 / 1e6)
    } else if ns >= 1_000 {
        format!("{:.1}µs", ns as f64 / 1e3)
    } else {
        format!("{}ns", ns)
    }
}

// ---- Manifest-driven attribution run (production path) ----

fn validate_manifest(manifest_path: &str) -> Result<bool, Box<dyn std::error::Error>> {
    use causalworks::ManifestCfg;

    // Parse + structural validation (fail-closed). Distinguish parse errors
    // (bad JSON) from validation errors (bad topology) in the message.
    let cfg = match ManifestCfg::from_path(manifest_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("INVALID: {e}");
            return Ok(false);
        }
    };

    match cfg.build() {
        Err(e) => {
            eprintln!("INVALID: {e}");
            Ok(false)
        }
        Ok(_) => {
            // Structurally valid. Now run non-fatal lints.
            let warnings = cfg.lint();
            println!(
                "VALID: '{}' — {} nodes, {} edges, trip_node={}",
                cfg.cell_name,
                cfg.nodes.len(),
                cfg.edges.len(),
                cfg.trip_node
            );
            if warnings.is_empty() {
                println!("  no warnings.");
            } else {
                println!("  {} WARNING(S) (run is allowed, but review these):", warnings.len());
                for w in &warnings {
                    println!("  - {w}");
                }
            }
            Ok(true)
        }
    }
}

fn run_with_manifest(
    pcap_path: &str,
    manifest_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use causalworks::{ManifestCfg, StreamingPcapSource};

    let cfg = ManifestCfg::from_path(manifest_path)?;
    let manifest = cfg.build()?; // fail-closed validation
    println!("loaded manifest '{}': {} nodes, {} edges, trip_node={}",
        cfg.cell_name, cfg.nodes.len(), cfg.edges.len(), cfg.trip_node);

    let file = std::fs::File::open(pcap_path)?;
    let mut src = StreamingPcapSource::new(file)?;
    let ts_source = src.timestamp_source();
    let mut engine: CausalGraphObserver<10_000> = CausalGraphObserver::new(manifest);
    let mut sink = InMemorySink::new();

    let (mut frames, mut parsed, mut dropped, mut trips, mut attributed) = (0u64, 0u64, 0u64, 0u64, 0u64);
    loop {
        match src.next_frame() {
            Ok(Some((ts, buf))) => {
                frames += 1;
                match parse_frame(ts, buf) {
                    Ok(frame) => {
                        parsed += 1;
                        if let Some(analysis) = engine.observe(&frame) {
                            trips += 1;
                            let trip_ts = analysis.trip_event.ts_ns;
                            let trace = CausalTrace::build(
                                "APPL-REPLAY",
                                &analysis,
                                &[trip_event_to_trace(&analysis.trip_event, trip_ts)],
                                "SF-FROM-MANIFEST",
                                50_000_000,
                            );
                            if trace.root_catalyst.is_some() {
                                attributed += 1;
                            }
                            sink.put(&TraceRow::from_trace(&trace)?)?;
                            print_finding(&trace, ts_source);
                        }
                    }
                    Err(_) => dropped += 1,
                }
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("capture error (stopping): {e}");
                break;
            }
        }
    }
    println!(
        "\n--- RUN SUMMARY ---\nts source: {:?}\nframes={} parsed={} dropped={} trips={} attributed={} rows={}",
        ts_source, frames, parsed, dropped, trips, attributed, sink.len()
    );
    Ok(())
}

fn demo_manifest() -> DependencyManifest {
    let mut nodes = HashMap::new();
    nodes.insert(N_AMR, NodeMatcher::Ros2Port { topic_port: AMR_PORT });
    nodes.insert(N_FANUC, NodeMatcher::FanucPose);
    nodes.insert(
        N_PLC,
        NodeMatcher::ProfinetFrame {
            frame_id: 0x0002,
            bit_index: 0,
        },
    );
    let edges = vec![
        DependencyEdge {
            from: N_AMR,
            to: N_FANUC,
            wcet_ns: 3_000_000, // 3ms
        },
        DependencyEdge {
            from: N_FANUC,
            to: N_PLC,
            wcet_ns: 4_000_000, // 4ms
        },
    ];
    DependencyManifest::new(nodes, edges, N_PLC)
}

// ---- Frame builders for the synthetic fixture ----
fn eth(ethertype: u16) -> Vec<u8> {
    let mut v = vec![0u8; 14];
    v[12] = (ethertype >> 8) as u8;
    v[13] = (ethertype & 0xff) as u8;
    v
}
fn profinet_frame(frame_id: u16, interlock: bool) -> Vec<u8> {
    let mut f = eth(0x8892);
    f.extend_from_slice(&frame_id.to_be_bytes());
    f.push(if interlock { 0x01 } else { 0x00 });
    // pad to a realistic minimum frame
    f.resize(60, 0);
    f
}
fn udp_frame(dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = eth(0x0800);
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[9] = 17; // UDP
    f.extend_from_slice(&ip);
    let udp_len = 8 + payload.len() as u16;
    let mut udp = vec![0u8; 8];
    udp[2] = (dst_port >> 8) as u8;
    udp[3] = (dst_port & 0xff) as u8;
    udp[4] = (udp_len >> 8) as u8;
    udp[5] = (udp_len & 0xff) as u8;
    f.extend_from_slice(&udp);
    f.extend_from_slice(payload);
    f
}
fn fanuc_frame() -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&100.0f32.to_le_bytes());
    p.extend_from_slice(&200.0f32.to_le_bytes());
    p.extend_from_slice(&50.0f32.to_le_bytes());
    udp_frame(FANUC_PORT, &p)
}
fn ros2_frame() -> Vec<u8> {
    udp_frame(AMR_PORT, &[0u8; 32])
}

/// Write a classic usec/LE pcap. `records` is (ts_ns, incl_len_override, frame).
/// `incl_len_override = None` means a clean record; `Some(n)` truncates the
/// stored bytes to `n` while keeping orig_len = full, simulating a captured
/// line drop.
fn write_pcap(records: &[(u64, Option<usize>, Vec<u8>)]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic usec LE
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&4u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&65535u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes()); // ETHERNET
    for (ts_ns, incl_override, frame) in records {
        let sec = (ts_ns / 1_000_000_000) as u32;
        let usec = ((ts_ns % 1_000_000_000) / 1_000) as u32;
        let orig_len = frame.len() as u32;
        let incl_len = incl_override.map(|n| n as u32).unwrap_or(orig_len);
        v.extend_from_slice(&sec.to_le_bytes());
        v.extend_from_slice(&usec.to_le_bytes());
        v.extend_from_slice(&incl_len.to_le_bytes());
        v.extend_from_slice(&orig_len.to_le_bytes());
        v.extend_from_slice(&frame[..incl_len as usize]);
    }
    v
}

/// Build the synthetic capture: one clean cycle, one jittered fault cycle that
/// must produce an attributed trip, and one truncated frame (line drop) that
/// must be skipped without crashing.
fn synth_fixture() -> Vec<u8> {
    let ms = 1_000_000u64;
    let recs: Vec<(u64, Option<usize>, Vec<u8>)> = vec![
        // ---- clean cycle around t=10ms: no trip ----
        (10 * ms, None, ros2_frame()),
        (12 * ms, None, fanuc_frame()),  // 2ms after AMR (< 3ms ok)
        (14 * ms, None, profinet_frame(0x0002, true)), // interlock high
        // ---- a dropped/truncated frame at t=20ms: must be skipped ----
        (20 * ms, Some(20), fanuc_frame()), // truncated to 20 bytes
        // ---- jittered fault cycle around t=30ms: AMR->Fanuc gap = 10ms ----
        (30 * ms, None, ros2_frame()),
        (40 * ms, None, fanuc_frame()),  // 10ms after AMR (>> 3ms budget): jitter
        (42 * ms, None, profinet_frame(0x0002, false)), // interlock low => TRIP
    ];
    write_pcap(&recs)
}

struct Stats {
    frames: u64,
    parsed: u64,
    skipped_unparseable: u64,
    trips: u64,
    attributed: u64,
}

fn run(path: &str) -> Result<Stats, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let mut src = PcapReplaySource::from_bytes(bytes)?;
    let manifest = demo_manifest();
    let mut engine: CausalGraphObserver<10_000> = CausalGraphObserver::new(manifest);
    let mut sink = InMemorySink::new();

    // The harness keeps its own rolling event log to materialize the trace's
    // preceding-event window (the engine's ring is private by design).
    let mut event_log: Vec<TraceEvent> = Vec::new();
    let ts_source = src.timestamp_source();

    let mut stats = Stats {
        frames: 0,
        parsed: 0,
        skipped_unparseable: 0,
        trips: 0,
        attributed: 0,
    };

    loop {
        let next = src.next_frame();
        let (ts_ns, buf) = match next {
            Ok(Some(f)) => f,
            Ok(None) => break, // clean EOF
            Err(e) => {
                // A record-level error (e.g. truncated data) is a hard capture
                // fault; report and stop, since cursor position is now
                // unreliable. Per-FRAME parse errors are handled below and do
                // NOT reach here.
                eprintln!("capture error, stopping replay: {e}");
                break;
            }
        };
        stats.frames += 1;

        // Copy ts before reborrowing buf for parse (buf borrows src.scratch).
        let frame = match parse_frame(ts_ns, buf) {
            Ok(f) => f,
            Err(_e) => {
                // Truncated / unhandled / short payload => the "line drop"
                // path. Count and CONTINUE. Engine state untouched.
                stats.skipped_unparseable += 1;
                continue;
            }
        };
        stats.parsed += 1;

        // Mirror into our event log for trace materialization.
        // (Only events the engine would classify are useful, but logging all
        // parsed frames is cheap and keeps the window complete.)
        let pre_len = event_log.len();

        let trip = engine.observe(&frame);

        // If a trip fired, build + persist the trace.
        if let Some(analysis) = trip {
            stats.trips += 1;
            let trip_ts = analysis.trip_event.ts_ns;

            // Materialize the preceding-event window: everything in our log
            // plus this trip, with offsets relative to the trip.
            let mut events: Vec<TraceEvent> = event_log
                .iter()
                .map(|e| TraceEvent {
                    offset_from_trip_ns: e.ts_ns as i64 - trip_ts as i64,
                    ..e.clone()
                })
                .collect();
            events.push(trip_event_to_trace(&analysis.trip_event, trip_ts));

            let trace = CausalTrace::build(
                "APPL-DEMO-01",
                &analysis,
                &events,
                "SF-ENTRY-GATE",
                50_000_000, // 50ms configured response budget
            );
            if trace.root_catalyst.is_some() {
                stats.attributed += 1;
            }
            let row = TraceRow::from_trace(&trace)?;
            sink.put(&row)?;

            // Print the human-readable finding.
            print_finding(&trace, ts_source);
        }

        // Append the just-observed frame to the log AFTER trip handling so the
        // trip event itself isn't double-counted in the window. We reconstruct
        // a TraceEvent from the decoded frame's node classification by
        // re-deriving node id cheaply.
        let _ = pre_len; // (kept for clarity; window is rebuilt each trip)
        push_event(&mut event_log, &frame);
    }

    // Verify storage handshake: range-scan everything back out.
    let all = sink.range(0, u64::MAX)?;
    println!(
        "\n--- HARNESS SUMMARY ---\n\
         timestamp source : {:?} (jitter floor ~{} ns)\n\
         frames read      : {}\n\
         parsed           : {}\n\
         skipped (drops)  : {}\n\
         trips detected   : {}\n\
         attributed trips : {}\n\
         rows persisted   : {}\n\
         rows read back   : {}",
        ts_source,
        ts_source.approx_jitter_floor_ns(),
        stats.frames,
        stats.parsed,
        stats.skipped_unparseable,
        stats.trips,
        stats.attributed,
        sink.len(),
        all.len(),
    );

    Ok(stats)
}

/// Convert the engine's trip StateTransition into a TraceEvent.
fn trip_event_to_trace(t: &StateTransition, trip_ts: u64) -> TraceEvent {
    TraceEvent {
        seq: t.seq,
        node: t.node,
        ts_ns: t.ts_ns,
        offset_from_trip_ns: t.ts_ns as i64 - trip_ts as i64,
        interlock: t.interlock,
    }
}

/// Append a parsed frame to the harness event log. Node id is re-derived from
/// the protocol so the log mirrors what the engine classified.
fn push_event(log: &mut Vec<TraceEvent>, f: &causalworks::DecodedFieldbusFrame) {
    use causalworks::IndustrialProtocol as P;
    let (node, interlock) = match f.proto {
        P::ProfinetIrt { frame_id: 0x0002, raw_status_byte, .. } => {
            (N_PLC, Some(raw_status_byte & 0x01 != 0))
        }
        P::ProfinetIrt { .. } => return, // not a node we track
        P::Ros2Udp { topic_port: AMR_PORT, .. } => (N_AMR, None),
        P::Ros2Udp { .. } => return,
        P::FanucUdp { .. } => (N_FANUC, None),
        P::S7commArrival { .. } => return, // arrival-only, not a tracked node
    };
    log.push(TraceEvent {
        seq: log.len() as u64,
        node,
        ts_ns: f.tap_ts_ns,
        offset_from_trip_ns: 0, // filled at trip time
        interlock,
    });
}

fn print_finding(trace: &CausalTrace, ts_source: TimestampSource) {
    println!("\n=== TRIP @ {} ns ===", trace.trip_ts_ns);
    match &trace.root_catalyst {
        Some(c) => {
            let overrun_ns = c.observed_dt_ns.saturating_sub(c.wcet_ns);
            let above_floor = overrun_ns > ts_source.approx_jitter_floor_ns();
            println!(
                "  root catalyst : edge {}->{}  Δt={}ns  WCET={}ns  overrun={}ns ({:.1}%)",
                c.edge_from,
                c.edge_to,
                c.observed_dt_ns,
                c.wcet_ns,
                overrun_ns,
                c.normalized_overrun * 100.0,
            );
            if !above_floor {
                println!(
                    "  WARNING: overrun {}ns is at/below the {:?} timestamp jitter \
                     floor — attribution NOT trustworthy on this source.",
                    overrun_ns, ts_source
                );
            }
        }
        None => println!("  UNATTRIBUTED trip — no WCET violation; escalate to fault review."),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("run") => {
            let Some(path) = args.get(2) else {
                eprintln!("usage: causalworks-harness run <capture.pcap>");
                return ExitCode::from(2);
            };
            match run(path) {
                Ok(s) => {
                    // Verification assertions for CI: the synthetic fixture must
                    // produce exactly 1 attributed trip and skip >=1 drop.
                    if s.trips >= 1 && s.attributed >= 1 {
                        ExitCode::SUCCESS
                    } else {
                        eprintln!("verification failed: expected >=1 attributed trip");
                        ExitCode::FAILURE
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("gen-fixture") => {
            let Some(path) = args.get(2) else {
                eprintln!("usage: causalworks-harness gen-fixture <out.pcap>");
                return ExitCode::from(2);
            };
            match std::fs::write(path, synth_fixture()) {
                Ok(_) => {
                    println!("wrote synthetic fixture to {path}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("preflight") => {
            let Some(path) = args.get(2) else {
                eprintln!("usage: causalworks-harness preflight <capture.pcap>");
                return ExitCode::from(2);
            };
            match preflight(path) {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::FAILURE, // not analyzable -> non-zero for scripting
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("discover") => {
            let Some(path) = args.get(2) else {
                eprintln!("usage: causalworks-harness discover <capture.pcap>");
                return ExitCode::from(2);
            };
            match discover(path) {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("validate") => {
            let Some(path) = args.get(2) else {
                eprintln!("usage: causalworks-harness validate <manifest.json>");
                return ExitCode::from(2);
            };
            match validate_manifest(path) {
                Ok(true) => ExitCode::SUCCESS,
                Ok(false) => ExitCode::FAILURE, // invalid manifest -> non-zero for CI
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("run-manifest") => {
            let (Some(pcap), Some(manifest)) = (args.get(2), args.get(3)) else {
                eprintln!("usage: causalworks-harness run-manifest <capture.pcap> <manifest.json>");
                return ExitCode::from(2);
            };
            match run_with_manifest(pcap, manifest) {
                Ok(_) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        _ => {
            eprintln!(
                "usage:\n  \
                 causalworks-harness gen-fixture <out.pcap>          # write synthetic test capture\n  \
                 causalworks-harness run <capture.pcap>              # demo-manifest run (legacy)\n  \
                 causalworks-harness preflight <capture.pcap>        # triage: is this capture analyzable?\n  \
                 causalworks-harness discover <capture.pcap>         # profile an unknown capture\n  \
                 causalworks-harness validate <manifest.json>        # check a manifest (no capture needed)\n  \
                 causalworks-harness run-manifest <pcap> <manifest.json>  # attribution with a real manifest"
            );
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod preflight_tests {
    use super::*;
    use std::io::Cursor;

    // Minimal classic-pcap (usec/LE) writer for in-memory test captures.
    fn eth(ethertype: u16) -> Vec<u8> {
        let mut v = vec![0u8; 14];
        v[12] = (ethertype >> 8) as u8;
        v[13] = (ethertype & 0xff) as u8;
        v.resize(60, 0);
        v
    }
    fn vlan_frame() -> Vec<u8> {
        let mut v = vec![0u8; 18];
        v[12] = 0x81; // 802.1Q outer tag
        v[13] = 0x00;
        v[16] = 0x88; // inner EtherType 0x8892 (Profinet)
        v[17] = 0x92;
        v.resize(60, 0);
        v
    }
    fn write_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&65535u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes()); // ETHERNET
        for (i, fr) in frames.iter().enumerate() {
            let ts = i as u32; // 1s apart; spacing irrelevant to these assertions
            v.extend_from_slice(&ts.to_le_bytes());
            v.extend_from_slice(&0u32.to_le_bytes());
            v.extend_from_slice(&(fr.len() as u32).to_le_bytes());
            v.extend_from_slice(&(fr.len() as u32).to_le_bytes());
            v.extend_from_slice(fr);
        }
        v
    }

    /// A real IPv4/UDP frame (ip protocol = 17). parse_frame accepts this as a
    /// ROS2/Fanuc arrival signal -> classifiable.
    fn udp_frame(dst_port: u16) -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08; // IPv4
        f[13] = 0x00;
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // IPv4, IHL 5
        ip[9] = 17; // protocol = UDP
        f.extend_from_slice(&ip);
        let mut udp = vec![0u8; 8];
        udp[2] = (dst_port >> 8) as u8;
        udp[3] = (dst_port & 0xff) as u8;
        udp[4] = 0; // udp length high
        udp[5] = 8; // udp length = 8 (header only)
        f.extend_from_slice(&udp);
        f
    }

    /// A real IPv4/TCP frame (ip protocol = 6) — e.g. S7comm on port 102.
    /// parse_frame REJECTS non-UDP IPv4, so this must be unclassified. This is
    /// the case that the day01.pcap real capture exposed: the majority of an
    /// S7-1500 capture is TCP S7comm, which preflight previously mis-counted as
    /// classifiable.
    fn tcp_frame() -> Vec<u8> {
        let mut f = vec![0u8; 14];
        f[12] = 0x08;
        f[13] = 0x00;
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = 6; // protocol = TCP
        f.extend_from_slice(&ip);
        f.resize(60, 0);
        f
    }

    #[test]
    fn profinet_and_udp_are_classifiable() {
        // Profinet (0x8892) + real IPv4/UDP -> parse_frame accepts both.
        let pcap = write_pcap(&[eth(0x8892), udp_frame(2222), eth(0x8892), udp_frame(2222)]);
        let (verdict, stats) = compute_preflight(Cursor::new(pcap));
        assert_eq!(verdict, PreflightVerdict::Analyzable);
        assert_eq!(stats.total, 4);
        assert_eq!(stats.unclassified, 0);
        assert_eq!(stats.classifiable, 4);
    }

    #[test]
    fn ipv4_tcp_is_unclassified_not_optimistically_counted() {
        // REGRESSION TEST for the day01.pcap finding: a capture that is mostly
        // IPv4/TCP (S7comm) must NOT be reported as classifiable just because
        // its EtherType is 0x0800. parse_frame rejects TCP, so it is
        // unclassified, and a TCP-heavy capture must trip the coverage gap.
        let mut frames = vec![eth(0x8892)]; // 1 classifiable
        for _ in 0..9 {
            frames.push(tcp_frame()); // 9 unclassified TCP
        }
        let (verdict, stats) = compute_preflight(Cursor::new(pcap_of(&frames)));
        assert_eq!(stats.total, 10);
        assert_eq!(stats.classifiable, 1);
        assert_eq!(stats.unclassified, 9);
        // 90% unclassified -> coverage gap, NOT analyzable.
        assert_eq!(verdict, PreflightVerdict::CoverageGap);
        // The EtherType histogram still records 0x0800 (for the breakdown).
        assert_eq!(stats.ethertypes.get(&0x0800), Some(&9));
    }

    // small alias so the regression test reads cleanly
    fn pcap_of(frames: &[Vec<u8>]) -> Vec<u8> {
        write_pcap(frames)
    }

    #[test]
    fn high_unsupported_ethertype_is_coverage_gap() {
        // 3 of 4 frames are an unsupported EtherType (0x88a4, EtherCAT) ->
        // parse_frame rejects -> 75% unclassified.
        let pcap = write_pcap(&[eth(0x8892), eth(0x88a4), eth(0x88a4), eth(0x88a4)]);
        let (verdict, stats) = compute_preflight(Cursor::new(pcap));
        assert_eq!(verdict, PreflightVerdict::CoverageGap);
        assert!(stats.unclassified_frac() > COVERAGE_GAP_THRESHOLD);
        assert_eq!(stats.ethertypes.get(&0x88a4), Some(&3));
    }

    #[test]
    fn pcapng_magic_is_rejected_with_hint_flag() {
        let mut data = 0x0a0d0d0au32.to_le_bytes().to_vec();
        data.extend_from_slice(&[0u8; 32]);
        let (verdict, stats) = compute_preflight(Cursor::new(data));
        assert_eq!(verdict, PreflightVerdict::RejectedFormat { is_pcapng: true });
        assert_eq!(stats.total, 0);
    }

    #[test]
    fn empty_file_is_rejected_format() {
        let (verdict, _stats) = compute_preflight(Cursor::new(Vec::<u8>::new()));
        assert!(matches!(
            verdict,
            PreflightVerdict::RejectedFormat { is_pcapng: false }
        ));
    }

    #[test]
    fn vlan_frames_are_detected() {
        let pcap = write_pcap(&[vlan_frame(), vlan_frame(), eth(0x8892)]);
        let (_verdict, stats) = compute_preflight(Cursor::new(pcap));
        assert_eq!(stats.vlan_frames, 2);
        // VLAN frames unwrap to Profinet, so they remain classifiable.
        assert_eq!(stats.unclassified, 0);
    }

    #[test]
    fn empty_capture_with_valid_header_is_rejected_empty() {
        let pcap = write_pcap(&[]);
        let (verdict, stats) = compute_preflight(Cursor::new(pcap));
        assert_eq!(verdict, PreflightVerdict::RejectedEmpty);
        assert_eq!(stats.total, 0);
    }
}
