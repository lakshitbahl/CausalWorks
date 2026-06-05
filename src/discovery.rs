//! Discovery / profiling pass.
//!
//! Purpose: characterize an unknown capture BEFORE any causal attribution, so
//! a dependency manifest can be authored against observed reality + the SI's
//! stated cyclic specs — not guessed, and not fitted to the known fault.
//!
//! Outputs per identified stream:
//!   * frame/packet count
//!   * inter-arrival distribution: p50 / p95 / p99 / p99.9 (histogram
//!     ESTIMATES) plus exact min / max. p50 is the nominal cycle the SI can
//!     sanity-check; the p99.9-vs-p50 gap is the jitter signature.
//! Plus, globally:
//!   * unclassified traffic tallied by (EtherType) or (UDP port) so coverage
//!     gaps are visible.
//!   * per-Profinet-FrameID toggling-bit mask: OR over (payload XOR
//!     first_payload), so any bit that ever changed is set — candidate status
//!     / interlock bits, distinguished from constant configuration bytes.
//!
//! Honesty on the statistics: percentiles are histogram estimates, not exact
//! order statistics. Bucket resolution is logarithmic, so relative error is
//! bounded (~ the bucket width fraction) across the µs–s range we care about.
//! Count, min, and max are exact. We label estimates as such in the report.

use crate::ingest::{IndustrialProtocol, DecodedFieldbusFrame};
use std::collections::HashMap;

/// Logarithmic-bucket histogram for nanosecond inter-arrival times.
///
/// Bucketing: bucket index = number of bits in the value (i.e. floor(log2)+1),
/// further subdivided into `SUB` linear sub-buckets within each power-of-two
/// band. This gives ~ 1/SUB relative resolution — with SUB=8, ~12% relative
/// error on a percentile estimate, tightening as SUB grows. Memory is fixed:
/// 64 bands * SUB buckets. For SUB=8 that's 512 u64 counters = 4KB per stream,
/// independent of sample count or file size.
#[derive(Clone)]
pub struct LogHistogram<const SUB: usize> {
    buckets: Vec<u64>, // 64 * SUB
    count: u64,
    min: u64,
    max: u64,
    sum: u128, // for mean; u128 so 5GB worth of ns sums can't overflow
}

impl<const SUB: usize> LogHistogram<SUB> {
    pub fn new() -> Self {
        Self {
            buckets: vec![0u64; 64 * SUB],
            count: 0,
            min: u64::MAX,
            max: 0,
            sum: 0,
        }
    }

    /// Map a value to a bucket index. value 0 -> band 0; otherwise band =
    /// bit-length, sub = top fractional bits below the leading 1.
    #[inline]
    fn index(value: u64) -> usize {
        if value == 0 {
            return 0;
        }
        let band = 64 - value.leading_zeros() as usize; // 1..=64
        // Position within [2^(band-1), 2^band): use the next log2(SUB) bits.
        let band_base = 1u64 << (band - 1);
        let band_width = band_base; // width of this band == band_base
        let offset = value - band_base;
        // sub in [0, SUB)
        let sub = ((offset as u128 * SUB as u128) / band_width as u128) as usize;
        let sub = sub.min(SUB - 1);
        (band - 1) * SUB + sub
    }

    /// Lower edge (inclusive) of a bucket, for percentile value reconstruction.
    #[inline]
    fn bucket_lower(idx: usize) -> u64 {
        let band = idx / SUB; // 0-based band
        let sub = idx % SUB;
        if band == 0 && sub == 0 {
            return 0;
        }
        let band_base = 1u64 << band; // 2^band
        let band_width = band_base;
        band_base + (sub as u64 * band_width) / SUB as u64
    }

    pub fn record(&mut self, value: u64) {
        let i = Self::index(value);
        self.buckets[i] += 1;
        self.count += 1;
        self.sum += value as u128;
        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }
    }

    pub fn count(&self) -> u64 {
        self.count
    }

    /// Below this many inter-arrival samples, a percentile is not a meaningful
    /// estimate — it is an artifact of too few points. The 7-frame synthetic
    /// fixture, for example, yields 2–3 samples per stream, where a reported
    /// "p50" lands on whatever single large gap happens to fall at the median
    /// rank (this produced the spurious 28 ms p50 in the local report). 30 is a
    /// conventional small-sample floor; count/min/max remain exact and useful
    /// below it, only the percentile *estimates* are suppressed.
    pub const MIN_SAMPLES_FOR_PERCENTILE: u64 = 30;

    /// True when there are enough samples for the quantile estimates to mean
    /// something. Callers should gate percentile DISPLAY on this and fall back
    /// to reporting count/min/max only.
    pub fn percentiles_meaningful(&self) -> bool {
        self.count >= Self::MIN_SAMPLES_FOR_PERCENTILE
    }

    pub fn min(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            self.min
        }
    }
    pub fn max(&self) -> u64 {
        self.max
    }
    pub fn mean(&self) -> u64 {
        if self.count == 0 {
            0
        } else {
            (self.sum / self.count as u128) as u64
        }
    }

    /// Estimated quantile in [0,1]. Returns the lower edge of the bucket in
    /// which the target rank falls. Clamped to [min, max] so a percentile can
    /// never report below the smallest observed or above the largest.
    pub fn quantile(&self, q: f64) -> u64 {
        if self.count == 0 {
            return 0;
        }
        let target = (q * self.count as f64).ceil() as u64;
        let target = target.max(1).min(self.count);
        let mut cum = 0u64;
        for (i, &c) in self.buckets.iter().enumerate() {
            cum += c;
            if cum >= target {
                let est = Self::bucket_lower(i);
                return est.clamp(self.min(), self.max);
            }
        }
        self.max
    }
}

impl<const SUB: usize> Default for LogHistogram<SUB> {
    fn default() -> Self {
        Self::new()
    }
}

/// Logical stream key: how we group frames for inter-arrival profiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StreamKey {
    Profinet { frame_id: u16 },
    UdpPort { dst_port: u16 },
    /// S7comm over TCP (ISO-on-TCP, port 102). Arrival-timing only; no decode.
    S7comm { port: u16 },
}

/// Per-stream accumulator.
pub struct StreamProfile {
    pub key: StreamKey,
    pub interarrival: LogHistogram<8>,
    last_ts_ns: Option<u64>,
    /// Profinet-only: toggling-bit mask over the IO payload. `xor_mask[i]` has
    /// every bit that ever differed from the first observed payload's byte i.
    /// `first_payload` holds that reference. Length grows to the max payload
    /// length seen (payloads can vary; we OR over the common prefix).
    first_payload: Vec<u8>,
    xor_mask: Vec<u8>,
}

impl StreamProfile {
    fn new(key: StreamKey) -> Self {
        Self {
            key,
            interarrival: LogHistogram::new(),
            last_ts_ns: None,
            first_payload: Vec::new(),
            xor_mask: Vec::new(),
        }
    }

    fn observe(&mut self, ts_ns: u64, profinet_payload: Option<&[u8]>) {
        if let Some(prev) = self.last_ts_ns {
            // Inter-arrival on the single capture timeline. Saturating because a
            // capture with reordered timestamps (possible off a SPAN port)
            // could yield ts < prev; we record 0 rather than panic, and the
            // reordering itself is a signal worth noting (future: count it).
            self.interarrival.record(ts_ns.saturating_sub(prev));
        }
        self.last_ts_ns = Some(ts_ns);

        if let Some(p) = profinet_payload {
            if self.first_payload.is_empty() {
                self.first_payload = p.to_vec();
                self.xor_mask = vec![0u8; p.len()];
            } else {
                let n = self.first_payload.len().min(p.len());
                for i in 0..n {
                    // OR-accumulate the difference: any bit that ever flipped.
                    self.xor_mask[i] |= self.first_payload[i] ^ p[i];
                }
            }
        }
    }

    /// Human-readable list of (byte_index, bit_index) that toggled at least
    /// once. These are the candidate status/interlock bits for the manifest.
    pub fn toggling_bits(&self) -> Vec<(usize, u8)> {
        let mut out = Vec::new();
        for (byte_i, &m) in self.xor_mask.iter().enumerate() {
            for bit in 0..8u8 {
                if m & (1 << bit) != 0 {
                    out.push((byte_i, bit));
                }
            }
        }
        out
    }
}

/// Tally of frames we could NOT classify into a known stream, so coverage gaps
/// are explicit. Keyed by a coarse reason.
#[derive(Default)]
pub struct UnclassifiedTally {
    /// Non-Profinet, non-UDP EtherTypes (ARP 0x0806, LLDP 0x88cc, PTP 0x88f7,
    /// PROFINET-DCP shares 0x8892 but with discovery FrameIDs, MRP, etc.).
    pub by_ethertype: HashMap<u16, u64>,
    /// Frames too short / malformed to classify.
    pub malformed: u64,
}

/// The discovery engine. Feed it decoded frames (plus raw bytes for Profinet
/// payload extraction); it accumulates profiles and the unclassified tally.
pub struct DiscoveryEngine {
    pub streams: HashMap<StreamKey, StreamProfile>,
    pub unclassified: UnclassifiedTally,
    pub total_frames: u64,
}

impl DiscoveryEngine {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            unclassified: UnclassifiedTally::default(),
            total_frames: 0,
        }
    }

    /// Observe a successfully-decoded frame. `frame.raw` is the full L2 buffer,
    /// used to re-extract the Profinet IO payload for toggling-bit analysis
    /// (the attribution parser only kept byte 0; discovery wants the whole
    /// cyclic image).
    pub fn observe(&mut self, frame: &DecodedFieldbusFrame) {
        self.total_frames += 1;
        match frame.proto {
            IndustrialProtocol::ProfinetIrt { frame_id, .. } => {
                let key = StreamKey::Profinet { frame_id };
                // Profinet IO payload begins after Ethernet(+VLAN) header + the
                // 2-byte FrameID. We recompute the offset rather than trust a
                // stored one; if the frame is too short the slice is empty.
                let payload = profinet_io_payload(frame.raw);
                self.streams
                    .entry(key)
                    .or_insert_with(|| StreamProfile::new(key))
                    .observe(frame.tap_ts_ns, Some(payload));
            }
            IndustrialProtocol::Ros2Udp { topic_port, .. } => {
                let key = StreamKey::UdpPort { dst_port: topic_port };
                self.streams
                    .entry(key)
                    .or_insert_with(|| StreamProfile::new(key))
                    .observe(frame.tap_ts_ns, None);
            }
            IndustrialProtocol::FanucUdp { .. } => {
                // Fanuc rides UDP; the parser already routed it by port. We key
                // it under its destination port if recoverable, else a sentinel.
                let key = StreamKey::UdpPort {
                    dst_port: udp_dst_port(frame.raw).unwrap_or(0),
                };
                self.streams
                    .entry(key)
                    .or_insert_with(|| StreamProfile::new(key))
                    .observe(frame.tap_ts_ns, None);
            }
            IndustrialProtocol::S7commArrival { port } => {
                // Arrival-timing only — no payload, no toggling-bit analysis
                // (we do not decode S7 PDUs). The cadence of S7comm exchange is
                // the signal here.
                let key = StreamKey::S7comm { port };
                self.streams
                    .entry(key)
                    .or_insert_with(|| StreamProfile::new(key))
                    .observe(frame.tap_ts_ns, None);
            }
        }
    }

    /// Record a frame the parser rejected/ignored, for the coverage tally.
    /// `ethertype` is None if we couldn't even read the L2 header.
    pub fn observe_unclassified(&mut self, ethertype: Option<u16>) {
        self.total_frames += 1;
        match ethertype {
            Some(et) => *self.unclassified.by_ethertype.entry(et).or_insert(0) += 1,
            None => self.unclassified.malformed += 1,
        }
    }
}

impl Default for DiscoveryEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract the Profinet IO payload slice (after eth/VLAN + FrameID). Mirrors
/// the offset logic in `parse_frame` but returns the whole remaining payload.
/// Returns an empty slice on a too-short frame rather than erroring — discovery
/// tolerates partial frames.
fn profinet_io_payload(buf: &[u8]) -> &[u8] {
    if buf.len() < 14 {
        return &[];
    }
    let mut off = 14;
    let mut et = ((buf[12] as u16) << 8) | buf[13] as u16;
    if et == 0x8100 {
        if buf.len() < 18 {
            return &[];
        }
        et = ((buf[16] as u16) << 8) | buf[17] as u16;
        off += 4;
    }
    let _ = et;
    let payload_start = off + 2; // skip FrameID
    if buf.len() <= payload_start {
        return &[];
    }
    &buf[payload_start..]
}

/// Recover UDP destination port from a raw frame, if it is IPv4/UDP.
fn udp_dst_port(buf: &[u8]) -> Option<u16> {
    if buf.len() < 14 {
        return None;
    }
    let mut off = 14;
    let mut et = ((buf[12] as u16) << 8) | buf[13] as u16;
    if et == 0x8100 {
        if buf.len() < 18 {
            return None;
        }
        et = ((buf[16] as u16) << 8) | buf[17] as u16;
        off += 4;
    }
    if et != 0x0800 || buf.len() < off + 20 {
        return None;
    }
    let ihl = (buf[off] & 0x0f) as usize * 4;
    if buf.len() < off + ihl + 4 {
        return None;
    }
    let uo = off + ihl;
    Some(((buf[uo + 2] as u16) << 8) | buf[uo + 3] as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_percentiles_bracket_known_distribution() {
        let mut h: LogHistogram<8> = LogHistogram::new();
        // 1000 samples at ~1ms, 10 outliers at ~10ms.
        for _ in 0..1000 {
            h.record(1_000_000);
        }
        for _ in 0..10 {
            h.record(10_000_000);
        }
        assert_eq!(h.count(), 1010);
        assert_eq!(h.max(), 10_000_000);
        // p50 should sit in the ~1ms band (within log-bucket resolution).
        let p50 = h.quantile(0.50);
        assert!(
            p50 >= 900_000 && p50 <= 1_100_000,
            "p50={} not near 1ms",
            p50
        );
        // p99.9 should be pulled up toward the 10ms outliers.
        let p999 = h.quantile(0.999);
        assert!(p999 >= 5_000_000, "p99.9={} should reflect outliers", p999);
    }

    #[test]
    fn percentile_never_below_min_or_above_max() {
        let mut h: LogHistogram<8> = LogHistogram::new();
        h.record(2_000_000);
        h.record(2_000_000);
        h.record(2_000_000);
        assert!(h.quantile(0.0) >= h.min());
        assert!(h.quantile(1.0) <= h.max());
        assert_eq!(h.min(), 2_000_000);
        assert_eq!(h.max(), 2_000_000);
    }

    #[test]
    fn toggling_bits_detects_only_changed_bits() {
        let key = StreamKey::Profinet { frame_id: 0x0002 };
        let mut sp = StreamProfile::new(key);
        // payload byte 0 toggles bit0 (interlock), byte 1 constant 0xFF.
        sp.observe(0, Some(&[0x01, 0xFF, 0x00]));
        sp.observe(1000, Some(&[0x00, 0xFF, 0x00])); // bit0 of byte0 flipped
        sp.observe(2000, Some(&[0x01, 0xFF, 0x00]));
        let bits = sp.toggling_bits();
        // Only (byte 0, bit 0) should be flagged; byte 1 never changed.
        assert_eq!(bits, vec![(0, 0)]);
    }

    #[test]
    fn percentiles_suppressed_below_min_samples() {
        let mut h: LogHistogram<8> = LogHistogram::new();
        // 3 samples — like a single stream in the 7-frame fixture.
        h.record(1_000_000);
        h.record(28_000_000);
        h.record(2_000_000);
        assert!(
            !h.percentiles_meaningful(),
            "3 samples must not yield meaningful percentiles"
        );
        // Exact stats remain valid and useful.
        assert_eq!(h.count(), 3);
        assert_eq!(h.min(), 1_000_000);
        assert_eq!(h.max(), 28_000_000);

        // Cross the threshold: 30 samples -> meaningful.
        for _ in 0..27 {
            h.record(1_000_000);
        }
        assert_eq!(h.count(), 30);
        assert!(h.percentiles_meaningful());
    }

    #[test]
    fn interarrival_uses_capture_timeline() {
        let key = StreamKey::UdpPort { dst_port: 7400 };
        let mut sp = StreamProfile::new(key);
        sp.observe(0, None);
        sp.observe(1_000_000, None); // 1ms gap
        sp.observe(2_000_000, None); // 1ms gap
        assert_eq!(sp.interarrival.count(), 2);
        let p50 = sp.interarrival.quantile(0.5);
        assert!(p50 >= 900_000 && p50 <= 1_100_000);
    }
}
