//! Offline `.pcap` replay source — dependency-free reader for the classic
//! libpcap file format (magic 0xa1b2c3d4 / 0xd4c3b2a1, and the ns-precision
//! variant 0xa1b23c4d / 0x4d3cb2a1).
//!
//! Why hand-roll instead of using the `pcap` crate: the `pcap` crate links
//! libpcap (a C system dependency). The offline replay harness should build
//! and run with zero system deps so CI and a developer laptop need nothing
//! installed. The on-disk format is small, stable since 2000, and fully
//! specified, so a careful reader is low-risk. Live capture still uses the
//! `pcap`/AF_XDP sources — this is replay only.
//!
//! Scope: classic pcap only. We deliberately do NOT parse pcapng here — pcapng
//! is a different, far more complex TLV-block format. If your captures are
//! pcapng (Wireshark's modern default), convert with
//! `editcap -F pcap in.pcapng out.pcap` first, or add a pcapng reader as a
//! separate module. We FAIL LOUDLY on a pcapng magic rather than misparsing it.

use crate::ingest::{CaptureSource, TimestampSource};
use std::io::{self, Read};
use thiserror::Error;

const PCAP_MAGIC_USEC_LE: u32 = 0xa1b2c3d4; // microsecond, little-endian host
const PCAP_MAGIC_USEC_BE: u32 = 0xd4c3b2a1; // microsecond, byte-swapped
const PCAP_MAGIC_NSEC_LE: u32 = 0xa1b23c4d; // nanosecond, little-endian host
const PCAP_MAGIC_NSEC_BE: u32 = 0x4d3cb2a1; // nanosecond, byte-swapped
const PCAPNG_MAGIC: u32 = 0x0a0d0d0a; // pcapng Section Header Block type

#[derive(Debug, Error)]
pub enum PcapError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("not a pcap file (bad magic 0x{0:08x})")]
    BadMagic(u32),
    #[error("file is pcapng, not classic pcap — convert with `editcap -F pcap`")]
    IsPcapng,
    #[error("truncated record header at offset {0}")]
    TruncatedRecord(u64),
    #[error("record claims {claimed} captured bytes but only {available} remain")]
    TruncatedData { claimed: u32, available: usize },
    #[error("snaplen exceeded: captured length {0} is implausibly large")]
    ImplausibleLength(u32),
}

/// Endianness + timestamp precision derived from the file's magic number.
#[derive(Clone, Copy)]
struct PcapFormat {
    swapped: bool,
    nanos: bool,
}

/// Reads an entire `.pcap` into memory and replays records. For multi-GB
/// captures you'd want a streaming reader; for the harness's verification
/// fixtures (kilobytes to low MB) eager read is simpler and removes a class of
/// partial-read bugs. Documented tradeoff, not an oversight.
pub struct PcapReplaySource {
    data: Vec<u8>,
    cursor: usize,
    fmt: PcapFormat,
    scratch: Vec<u8>,
    /// Stats the harness uses to verify drop handling. A "drop" in a replay
    /// context = a record whose captured length < original length (libpcap
    /// snaplen truncation) OR a gap we are asked to treat as a drop. We surface
    /// truncated captures explicitly because a half-frame must NOT be fed to
    /// the parser as if whole.
    pub records_read: u64,
    pub truncated_records: u64,
    pub max_cap_minus_orig: i64,
}

impl PcapReplaySource {
    /// Global pcap header is 24 bytes: magic(4) ver_major(2) ver_minor(2)
    /// thiszone(4) sigfigs(4) snaplen(4) network/linktype(4).
    pub fn from_bytes(data: Vec<u8>) -> Result<Self, PcapError> {
        if data.len() < 24 {
            return Err(PcapError::TruncatedRecord(0));
        }
        let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let fmt = match magic {
            PCAP_MAGIC_USEC_LE => PcapFormat { swapped: false, nanos: false },
            PCAP_MAGIC_USEC_BE => PcapFormat { swapped: true, nanos: false },
            PCAP_MAGIC_NSEC_LE => PcapFormat { swapped: false, nanos: true },
            PCAP_MAGIC_NSEC_BE => PcapFormat { swapped: true, nanos: true },
            PCAPNG_MAGIC => return Err(PcapError::IsPcapng),
            other => return Err(PcapError::BadMagic(other)),
        };
        Ok(Self {
            data,
            cursor: 24, // skip global header
            fmt,
            scratch: Vec::with_capacity(2048),
            records_read: 0,
            truncated_records: 0,
            max_cap_minus_orig: 0,
        })
    }

    pub fn from_reader<R: Read>(mut r: R) -> Result<Self, PcapError> {
        let mut buf = Vec::new();
        r.read_to_end(&mut buf)?;
        Self::from_bytes(buf)
    }

    #[inline]
    fn rd_u32(&self, off: usize) -> u32 {
        let b = [
            self.data[off],
            self.data[off + 1],
            self.data[off + 2],
            self.data[off + 3],
        ];
        if self.fmt.swapped {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        }
    }
}

impl CaptureSource for PcapReplaySource {
    type Error = PcapError;

    fn next_frame(&mut self) -> Result<Option<(u64, &[u8])>, Self::Error> {
        // Per-record header is 16 bytes: ts_sec(4) ts_frac(4) incl_len(4) orig_len(4)
        if self.cursor + 16 > self.data.len() {
            if self.cursor == self.data.len() {
                return Ok(None); // clean EOF
            }
            return Err(PcapError::TruncatedRecord(self.cursor as u64));
        }
        let ts_sec = self.rd_u32(self.cursor) as u64;
        let ts_frac = self.rd_u32(self.cursor + 4) as u64;
        let incl_len = self.rd_u32(self.cursor + 8);
        let orig_len = self.rd_u32(self.cursor + 12);

        // Sanity bound: a captured frame larger than 256 KiB is implausible on
        // an industrial Ethernet segment and almost certainly indicates a
        // corrupt/misaligned file. Reject rather than allocate wildly.
        if incl_len > 256 * 1024 {
            return Err(PcapError::ImplausibleLength(incl_len));
        }

        let data_start = self.cursor + 16;
        let available = self.data.len().saturating_sub(data_start);
        if (incl_len as usize) > available {
            return Err(PcapError::TruncatedData {
                claimed: incl_len,
                available,
            });
        }

        let ts_ns = if self.fmt.nanos {
            ts_sec * 1_000_000_000 + ts_frac
        } else {
            ts_sec * 1_000_000_000 + ts_frac * 1_000
        };

        // Drop/truncation accounting: incl_len < orig_len means the capture
        // itself dropped bytes (snaplen). Feeding a truncated L2 frame to the
        // parser is exactly the "line drop" condition the harness must handle
        // gracefully — the parser already returns Truncated/ShortPayload errors
        // rather than panicking, so the harness can count and continue.
        self.records_read += 1;
        if incl_len < orig_len {
            self.truncated_records += 1;
        }
        let delta = incl_len as i64 - orig_len as i64;
        if delta > self.max_cap_minus_orig {
            self.max_cap_minus_orig = delta;
        }

        // Copy into scratch so the returned borrow is independent of future
        // cursor moves. (We own `data`, but returning a slice into it while
        // also mutating `self.cursor` next call fights the borrow checker; the
        // scratch copy is the clean, sound choice for a replay path where
        // throughput is not the constraint.)
        self.scratch.clear();
        self.scratch
            .extend_from_slice(&self.data[data_start..data_start + incl_len as usize]);
        self.cursor = data_start + incl_len as usize;

        Ok(Some((ts_ns, &self.scratch)))
    }

    fn timestamp_source(&self) -> TimestampSource {
        TimestampSource::ReplayFile
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid usec/LE pcap with N ethernet-ish records.
    fn synth_pcap(records: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&PCAP_MAGIC_USEC_LE.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes()); // ver major
        v.extend_from_slice(&4u16.to_le_bytes()); // ver minor
        v.extend_from_slice(&0u32.to_le_bytes()); // thiszone
        v.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        v.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        v.extend_from_slice(&1u32.to_le_bytes()); // linktype = ETHERNET
        for (sec, usec, payload) in records {
            v.extend_from_slice(&sec.to_le_bytes());
            v.extend_from_slice(&usec.to_le_bytes());
            v.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // incl
            v.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // orig
            v.extend_from_slice(payload);
        }
        v
    }

    #[test]
    fn reads_records_with_ns_timestamps() {
        let frame = [0u8; 60];
        let pcap = synth_pcap(&[(1, 500_000, &frame), (2, 0, &frame)]);
        let mut src = PcapReplaySource::from_bytes(pcap).unwrap();
        let (ts0, _) = src.next_frame().unwrap().unwrap();
        assert_eq!(ts0, 1_000_000_000 + 500_000 * 1_000); // 1.5s in ns
        let (ts1, _) = src.next_frame().unwrap().unwrap();
        assert_eq!(ts1, 2_000_000_000);
        assert!(src.next_frame().unwrap().is_none()); // clean EOF
        assert_eq!(src.records_read, 2);
    }

    #[test]
    fn rejects_pcapng() {
        let mut v = PCAPNG_MAGIC.to_le_bytes().to_vec();
        v.extend_from_slice(&[0u8; 32]);
        assert!(matches!(
            PcapReplaySource::from_bytes(v),
            Err(PcapError::IsPcapng)
        ));
    }

    #[test]
    fn detects_truncated_record_data() {
        // incl_len says 100 but file has only a few bytes after the header.
        let mut v = synth_pcap(&[]);
        v.extend_from_slice(&1u32.to_le_bytes()); // sec
        v.extend_from_slice(&0u32.to_le_bytes()); // usec
        v.extend_from_slice(&100u32.to_le_bytes()); // incl_len = 100
        v.extend_from_slice(&100u32.to_le_bytes()); // orig_len
        v.extend_from_slice(&[0u8; 10]); // only 10 bytes present
        let mut src = PcapReplaySource::from_bytes(v).unwrap();
        assert!(matches!(
            src.next_frame(),
            Err(PcapError::TruncatedData { claimed: 100, available: 10 })
        ));
    }
}
