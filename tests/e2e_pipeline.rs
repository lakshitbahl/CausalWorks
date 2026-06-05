//! End-to-end integration test for the replay → attribution pipeline.
//!
//! Self-contained: builds the synthetic capture inline (no dependency on the
//! harness binary having been run, no committed fixture file). Mirrors the
//! ACTUAL library API:
//!   * `parse_frame(tap_ts_ns, buf)` — timestamp is an argument, not set later
//!   * `CausalGraphObserver::<CAP>::new(manifest)` — const-generic window
//!   * `DecodedFieldbusFrame` is built by `parse_frame`; there is no
//!     `set_timestamp` method
//!   * `TripAnalysis::ranked_catalysts` is a `Vec<CandidateCatalyst>`; index
//!     `[0]` for the top catalyst, then read `.normalized_overrun`
//!
//! What this proves: the full path links and runs, a known timing fault is
//! detected exactly once, attributed to the correct dependency edge, with the
//! expected overrun. What it does NOT prove: behavior on real captures (VLAN
//! stacking, pcapng, multi-GB memory, malformed real frames) — that is the
//! first real SI capture's job, by design.

use causalworks::manifest::ManifestCfg;
use causalworks::replay::PcapReplaySource;
use causalworks::{parse_frame, CausalGraphObserver, CaptureSource};

// ---- Inline synthetic capture builders (classic pcap, usec/LE) ----

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
    f.resize(60, 0); // pad to a realistic minimum frame
    f
}

fn udp_frame(dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = eth(0x0800);
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45; // IPv4, IHL 5
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
    udp_frame(60008, &p)
}

fn ros2_frame() -> Vec<u8> {
    udp_frame(7400, &[0u8; 32])
}

/// classic pcap, microsecond/little-endian. records: (ts_ns, incl_override, frame).
/// `incl_override = Some(n)` truncates stored bytes to n (simulated drop).
fn write_pcap(records: &[(u64, Option<usize>, Vec<u8>)]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic usec LE
    v.extend_from_slice(&2u16.to_le_bytes());
    v.extend_from_slice(&4u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&65535u32.to_le_bytes());
    v.extend_from_slice(&1u32.to_le_bytes()); // ETHERNET linktype
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

/// Manifest matching the synthetic cell: AMR(1)->Fanuc(2)->PLC(3), trip on PLC.
fn manifest_json() -> &'static str {
    r#"{
      "cell_name": "integration-test-cell",
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
fn synthetic_replay_to_attribution_pipeline() {
    // 1. Manifest: parse, structurally validate, lint-clean.
    let cfg = ManifestCfg::from_json_str(manifest_json())
        .expect("manifest JSON must deserialize");
    let manifest = cfg.build().expect("manifest must pass structural validation");
    assert!(
        cfg.lint().is_empty(),
        "this manifest is fully wired; expected zero lint warnings, got {:?}",
        cfg.lint()
    );

    // 2. Build the synthetic capture inline:
    //    clean cycle (no trip), a truncated frame (drop), then a jittered
    //    cycle where AMR->Fanuc gap = 10ms (>> 3ms budget) ending in a trip.
    let ms = 1_000_000u64;
    let records: Vec<(u64, Option<usize>, Vec<u8>)> = vec![
        (10 * ms, None, ros2_frame()),
        (12 * ms, None, fanuc_frame()), // 2ms after AMR (< 3ms ok)
        (14 * ms, None, profinet_frame(0x0002, true)), // interlock high
        (20 * ms, Some(20), fanuc_frame()), // DROP: truncated to 20 bytes
        (30 * ms, None, ros2_frame()),
        (40 * ms, None, fanuc_frame()), // 10ms after AMR (>> 3ms budget): jitter
        (42 * ms, None, profinet_frame(0x0002, false)), // interlock low => TRIP
    ];
    let pcap_bytes = write_pcap(&records);

    // 3. Replay through the engine via the CaptureSource trait.
    let mut src = PcapReplaySource::from_bytes(pcap_bytes)
        .expect("pcap header must parse");
    let mut engine: CausalGraphObserver = CausalGraphObserver::new(manifest);

    let mut trips = 0usize;
    let mut dropped = 0usize;
    let mut top_overrun = 0.0f64;
    let mut top_edge = (0u32, 0u32);

    while let Some((ts_ns, packet)) = src.next_frame().expect("replay must not corrupt") {
        match parse_frame(ts_ns, packet) {
            Ok(frame) => {
                if let Some(analysis) = engine.observe(&frame) {
                    trips += 1;
                    assert!(
                        !analysis.ranked_catalysts.is_empty(),
                        "a timing-induced trip must rank at least one catalyst"
                    );
                    let top = &analysis.ranked_catalysts[0];
                    top_overrun = top.normalized_overrun;
                    top_edge = (top.edge.from, top.edge.to);
                }
            }
            // Truncated / unparseable frame: the drop path. Count and continue;
            // the engine state is untouched and the loop never breaks.
            Err(_) => dropped += 1,
        }
    }

    assert_eq!(dropped, 1, "the truncated frame must be detected and skipped");
    assert_eq!(trips, 1, "exactly one trip in this fixture");
    assert_eq!(
        top_edge,
        (1, 2),
        "root cause must be the AMR->Fanuc edge, not the within-budget Fanuc->PLC edge"
    );
    // overrun = (10ms - 3ms)/3ms = 2.333...
    assert!(
        (top_overrun - 7.0 / 3.0).abs() < 1e-9,
        "expected ~233% overrun, got {}",
        top_overrun * 100.0
    );
}

#[test]
fn invalid_manifest_is_rejected_fail_closed() {
    // Cycle 1->2->3->1 must be rejected at build(), not at run time.
    let j = r#"{
      "cell_name": "cyclic",
      "nodes": [
        { "id": 1, "type": "ros2_port", "topic_port": 7400 },
        { "id": 2, "type": "fanuc_pose" },
        { "id": 3, "type": "profinet", "frame_id": 2, "bit_index": 0 }
      ],
      "edges": [
        { "from": 1, "to": 2, "wcet_ns": 3000000 },
        { "from": 2, "to": 3, "wcet_ns": 4000000 },
        { "from": 3, "to": 1, "wcet_ns": 1000000 }
      ],
      "trip_node": 3
    }"#;
    let cfg = ManifestCfg::from_json_str(j).expect("JSON parses");
    assert!(
        cfg.build().is_err(),
        "a dependency cycle must fail structural validation"
    );
}
