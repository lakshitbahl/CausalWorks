# CausalWorks
Independent replay and attribution engine in Rust. Reconstructs event sequences from captured traffic and
attributes downstream effects to their root causes, built test-first with a dedicated suite and manifest-driven
fixtures.

It is a passive, offline diagnostic engine for industrial Ethernet timing faults. Given
a packet capture of an automation cell, it reconstructs the cross-protocol
sequence of events preceding a safety-interlock trip and attributes that trip to
the upstream timing-budget (WCET) violation that most plausibly caused it — or
reports that no budget was violated, in which case the trip is flagged as a
probable functional fault rather than a timing one.
 
It is a **command-line analysis tool that reads `.pcap` files**. It is not a live
network appliance and has no graphical interface.
 
---
 
## Scope — read this first
 
CausalWorks is deliberately narrow. What it actually does, and what it does not,
matters for using it honestly:
 
**Validated against real data:**
- Streaming `.pcap` ingestion (tested on an 800k-frame real capture, bounded memory).
- **Profinet RT** cyclic parsing (EtherType 0x8892, FrameID + status byte),
  validated against a real Siemens S7-1500 capture.
- S7comm arrival-timing classification (TCP port 102) — cadence only, no PDU decode.
- Discovery profiling and the preflight triage gate.
**Implemented but NOT yet proven on a real fault:**
- The attribution engine itself. Its logic is unit-tested against synthetic
  fixtures; it has never run on a real timing fault. This is the central claim
  of the tool and it is currently unvalidated on real data.
**Out of scope:**
- EtherNet/IP (CIP) — structurally unsuited to passive timing attribution.
- Profinet IRT-specific and TSN framing — different wire structures, untested.
  The parser handles the **RT** cyclic layout only.
- Live hardware capture (`hwcapture.rs` is an unbuilt scaffold).
- ISO 13849 certification — the tool produces evidence, not certification.
**Hard requirement:** timing analysis needs **hardware-TAP-grade capture**. A
switch SPAN/mirror port feeding Wireshark adds timestamp jitter on the same order
as the faults being measured, and cannot support timing claims. See
`docs/CAPTURE_INTAKE_SOP.md`.
 
---
 
## Build
 
Requires a Rust toolchain (developed against cargo 1.96; any recent stable
should work).
 
```bash
cargo build --release
```
 
The default build has no system dependencies. Optional features are gated and
off by default:
 
- `pcap-source` — live libpcap capture (not needed for offline `.pcap` analysis).
- `hw-capture` — hardware SO_TIMESTAMPING source (scaffold, not functional).
- `rocksdb-sink` — persistent RocksDB trace store (compiles a large C++ lib; the
  in-memory sink is used otherwise).
The binary is `causalworks-harness`. Run it via
`cargo run --release --bin causalworks-harness -- <subcommand>`, or directly from
`target/release/causalworks-harness`.
 
## Test
 
```bash
cargo test
```
 
Expect 42 tests across three groups: library unit tests, harness (preflight)
tests, and the end-to-end integration test.
 
---
 
## Usage
 
The intended workflow is a four-step pipeline. **The order matters** — see
"Anti-circularity" below.
 
### 1. Preflight — is this capture even analyzable?
 
```bash
cargo run --release --bin causalworks-harness -- preflight <capture.pcap>
```
 
Reports format, record count, coverage (how much of the traffic the engine can
classify), VLAN presence, and a timestamp-fidelity reminder. Verdict is
`[ANALYZABLE]`, `[COVERAGE GAP]` (too much unparsed protocol), or a format
rejection (e.g. pcapng — convert first with `editcap -F pcap in.pcapng out.pcap`).
 
### 2. Discover — profile the streams
 
```bash
cargo run --release --bin causalworks-harness -- discover <capture.pcap>
```
 
Reports per-stream inter-arrival cadence (p50/p95/p99 — these are histogram
*estimates*, with exact min/max/count), toggling-bit analysis (which bits in the
cyclic payload change — candidate status/interlock bits), and a coverage
breakdown. Hand the nominal cadences to whoever knows the cell's specs.
 
### 3. Validate — check a manifest before running
 
```bash
cargo run --release --bin causalworks-harness -- validate <manifest.json>
```
 
Fail-closed structural validation (dangling edges, cycles, zero/absurd budgets,
non-interlock trip node) plus non-fatal lints. No capture needed; catches
authoring mistakes in milliseconds.
 
### 4. Run — attribution against a manifest
 
```bash
cargo run --release --bin causalworks-harness -- run-manifest <capture.pcap> <manifest.json>
```
 
Runs the attribution engine. For each detected interlock trip, it reports the
ranked candidate catalysts (which dependency edge most overran its budget, and by
how much) or `UNATTRIBUTED` if no budget was violated. `UNATTRIBUTED` is a valid,
honest result — it means the trip was not timing-induced.
 
### Helper commands
 
```bash
# Write a small synthetic capture for testing the pipeline end-to-end:
cargo run --release --bin causalworks-harness -- gen-fixture <out.pcap>
 
# Legacy demo run with a built-in manifest (superseded by run-manifest):
cargo run --release --bin causalworks-harness -- run <capture.pcap>
```
 
### Quick end-to-end check
 
```bash
cargo run --release --bin causalworks-harness -- gen-fixture /tmp/test.pcap
cargo run --release --bin causalworks-harness -- preflight /tmp/test.pcap
cargo run --release --bin causalworks-harness -- discover  /tmp/test.pcap
```
 
---
 
## The manifest
 
A manifest declares the cell's dependency graph and the per-edge timing budgets.
The engine attributes trips to violations of *these declared budgets* — it does
not infer dependencies from data. Example (`manifest.example.json`):
 
```json
{
  "cell_name": "SI-pilot-cell-01",
  "nodes": [
    { "id": 1, "label": "amr_cmd_vel",             "type": "ros2_port", "topic_port": 7400 },
    { "id": 2, "label": "fanuc_predock_pose",      "type": "fanuc_pose" },
    { "id": 3, "label": "siemens_entry_interlock", "type": "profinet", "frame_id": 2, "bit_index": 0 }
  ],
  "edges": [
    { "from": 1, "to": 2, "wcet_ns": 3000000 },
    { "from": 2, "to": 3, "wcet_ns": 4000000 }
  ],
  "trip_node": 3
}
```
 
- `nodes` — each is matched against the capture by protocol and identifier
  (ROS2 UDP port, Fanuc pose, or Profinet frame_id + bit_index).
- `edges` — directed dependencies with an **absolute** WCET budget in
  nanoseconds. Budgets are absolute, not multiples of cycle time (relative
  budgets silently expand under rate changes — disqualifying for safety work).
- `trip_node` — the node whose interlock bit going high-to-low is the trip event.
## Anti-circularity — the rule that makes a result credible
 
**Author the WCET budgets from the cell's engineering specifications BEFORE
looking at where the trips occurred.** Fitting budgets to a known fault makes the
tool trivially "find" that fault — a tautology that proves nothing and that any
competent engineer will see through. The honest sequence is: `discover` to get
nominal cadences, have the cell owner state budgets from specs, `validate`, then
`run-manifest`. The discipline lives in this order, not in the code.
 
---
 
## Project layout
 
```
src/
├── lib.rs          library root
├── ingest.rs       frame parsing (Profinet RT, ROS2/UDP, Fanuc/UDP, S7comm-arrival)
├── causal.rs       attribution engine (dependency DAG + WCET backtracking)
├── discovery.rs    stream profiling, histograms, toggling-bit detection
├── manifest.rs     manifest load + fail-closed validation
├── replay.rs       eager in-memory pcap reader
├── stream.rs       streaming pcap reader (bounded memory, multi-GB safe)
├── storage.rs      trace sinks (in-memory; optional RocksDB)
├── trace.rs        ISO 13849 SRS evidence serialization
├── hwcapture.rs    live capture scaffold (NOT functional)
└── bin/harness.rs  the CLI
```

## License

This project is proprietary. All rights reserved.

Unauthorized copying, modification, distribution, or use of this software is strictly prohibited without explicit permission from the author.
