//! Streaming `.pcap` reader — bounded memory regardless of capture size.
//!
//! Replaces the eager `from_bytes` path for production captures. The earlier
//! `PcapReplaySource` read the whole file into a `Vec` (fine for KB fixtures,
//! fatal for a 5GB commissioning capture). This reader pulls one record at a
//! time off a `BufReader<File>`, so resident memory is O(largest single frame),
//! not O(file size).
//!
//! Format support is identical to the eager reader: classic pcap, both
//! endiannesses, usec and nsec precision. pcapng is rejected loudly (convert
//! with `editcap -F pcap`).
//!
//! Soundness note on the borrow: like the eager reader, `next_frame` returns a
//! slice into an internal scratch buffer that is overwritten on the next call.
//! The `CaptureSource` contract (parse-or-copy before requesting the next
//! frame) makes this safe and zero-allocation per record after warmup.

use crate::ingest::{CaptureSource, TimestampSource};
use std::io::{self, BufReader, Read};
use thiserror::Error;

const PCAP_MAGIC_USEC_LE: u32 = 0xa1b2c3d4;
const PCAP_MAGIC_USEC_BE: u32 = 0xd4c3b2a1;
const PCAP_MAGIC_NSEC_LE: u32 = 0xa1b23c4d;
const PCAP_MAGIC_NSEC_BE: u32 = 0x4d3cb2a1;
const PCAPNG_MAGIC: u32 = 0x0a0d0d0a;
const MAX_FRAME: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum StreamPcapError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("not a pcap file (bad magic 0x{0:08x})")]
    BadMagic(u32),
    #[error("file is pcapng, not classic pcap — convert with `editcap -F pcap`")]
    IsPcapng,
    #[error("record claims {0} bytes, exceeds sane max — file likely corrupt")]
    ImplausibleLength(u32),
}

#[derive(Clone, Copy)]
struct Fmt {
    swapped: bool,
    nanos: bool,
}

pub struct StreamingPcapSource<R: Read> {
    rdr: BufReader<R>,
    fmt: Fmt,
    scratch: Vec<u8>,
    /// Records whose captured length was less than original length (a real
    /// capture-side drop / snaplen truncation). Surfaced for the harness.
    pub truncated_records: u64,
    pub records_read: u64,
    /// Set when a record header is read but its body is short (file ended
    /// mid-record). Distinct from a clean EOF at a record boundary.
    pub ended_mid_record: bool,
}

impl<R: Read> StreamingPcapSource<R> {
    pub fn new(inner: R) -> Result<Self, StreamPcapError> {
        // 1 MiB buffer: amortizes syscalls without holding the whole file.
        let mut rdr = BufReader::with_capacity(1 << 20, inner);
        let mut ghdr = [0u8; 24];
        rdr.read_exact(&mut ghdr)?;
        let magic = u32::from_le_bytes([ghdr[0], ghdr[1], ghdr[2], ghdr[3]]);
        let fmt = match magic {
            PCAP_MAGIC_USEC_LE => Fmt { swapped: false, nanos: false },
            PCAP_MAGIC_USEC_BE => Fmt { swapped: true, nanos: false },
            PCAP_MAGIC_NSEC_LE => Fmt { swapped: false, nanos: true },
            PCAP_MAGIC_NSEC_BE => Fmt { swapped: true, nanos: true },
            PCAPNG_MAGIC => return Err(StreamPcapError::IsPcapng),
            other => return Err(StreamPcapError::BadMagic(other)),
        };
        Ok(Self {
            rdr,
            fmt,
            scratch: Vec::with_capacity(2048),
            truncated_records: 0,
            records_read: 0,
            ended_mid_record: false,
        })
    }

    #[inline]
    fn rd_u32(&self, b: &[u8]) -> u32 {
        let arr = [b[0], b[1], b[2], b[3]];
        if self.fmt.swapped {
            u32::from_be_bytes(arr)
        } else {
            u32::from_le_bytes(arr)
        }
    }
}

impl<R: Read> CaptureSource for StreamingPcapSource<R> {
    type Error = StreamPcapError;

    fn next_frame(&mut self) -> Result<Option<(u64, &[u8])>, Self::Error> {
        let mut rhdr = [0u8; 16];
        // A clean EOF must occur exactly at a record boundary. read_exact maps
        // EOF to UnexpectedEof; we translate a 0-byte read into clean end and a
        // partial read into ended_mid_record.
        match read_full_or_eof(&mut self.rdr, &mut rhdr)? {
            ReadState::Eof => return Ok(None),
            ReadState::Partial => {
                self.ended_mid_record = true;
                return Ok(None);
            }
            ReadState::Full => {}
        }

        let ts_sec = self.rd_u32(&rhdr[0..4]) as u64;
        let ts_frac = self.rd_u32(&rhdr[4..8]) as u64;
        let incl_len = self.rd_u32(&rhdr[8..12]);
        let orig_len = self.rd_u32(&rhdr[12..16]);

        if incl_len > MAX_FRAME as u32 {
            return Err(StreamPcapError::ImplausibleLength(incl_len));
        }

        self.scratch.resize(incl_len as usize, 0);
        // Read the captured bytes. A short read here means the file was
        // truncated mid-body; treat as clean end with the flag set, so a
        // partially-downloaded 5GB capture degrades gracefully.
        match read_exact_or_short(&mut self.rdr, &mut self.scratch)? {
            true => {}
            false => {
                self.ended_mid_record = true;
                return Ok(None);
            }
        }

        let ts_ns = if self.fmt.nanos {
            ts_sec * 1_000_000_000 + ts_frac
        } else {
            ts_sec * 1_000_000_000 + ts_frac * 1_000
        };

        self.records_read += 1;
        if incl_len < orig_len {
            self.truncated_records += 1;
        }

        Ok(Some((ts_ns, &self.scratch)))
    }

    fn timestamp_source(&self) -> TimestampSource {
        TimestampSource::ReplayFile
    }
}

enum ReadState {
    Full,
    Partial,
    Eof,
}

/// Read exactly `buf.len()` bytes, distinguishing clean EOF (0 bytes read) from
/// a partial read (some-but-not-all).
fn read_full_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<ReadState> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                return Ok(if filled == 0 {
                    ReadState::Eof
                } else {
                    ReadState::Partial
                });
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(ReadState::Full)
}

/// Returns Ok(true) if fully read, Ok(false) if EOF reached before filling.
fn read_exact_or_short<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => return Ok(false),
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn synth(records: &[(u32, u32, u32, &[u8])]) -> Vec<u8> {
        // records: (sec, usec, incl_len_override, frame)
        let mut v = Vec::new();
        v.extend_from_slice(&PCAP_MAGIC_USEC_LE.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&65535u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        for (sec, usec, incl, payload) in records {
            v.extend_from_slice(&sec.to_le_bytes());
            v.extend_from_slice(&usec.to_le_bytes());
            v.extend_from_slice(&incl.to_le_bytes());
            v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            v.extend_from_slice(&payload[..*incl as usize]);
        }
        v
    }

    #[test]
    fn streams_records_bounded() {
        let frame = [0xABu8; 60];
        let data = synth(&[(1, 0, 60, &frame), (2, 500_000, 60, &frame)]);
        let mut s = StreamingPcapSource::new(Cursor::new(data)).unwrap();
        let (t0, b0) = s.next_frame().unwrap().unwrap();
        assert_eq!(t0, 1_000_000_000);
        assert_eq!(b0.len(), 60);
        let (t1, _) = s.next_frame().unwrap().unwrap();
        assert_eq!(t1, 2_500_000_000);
        assert!(s.next_frame().unwrap().is_none());
        assert_eq!(s.records_read, 2);
        assert!(!s.ended_mid_record);
    }

    #[test]
    fn counts_truncated_capture_records() {
        let frame = [0u8; 60];
        // incl 40 < orig 60 => capture-side truncation
        let data = synth(&[(1, 0, 40, &frame)]);
        let mut s = StreamingPcapSource::new(Cursor::new(data)).unwrap();
        let _ = s.next_frame().unwrap().unwrap();
        s.next_frame().unwrap();
        assert_eq!(s.truncated_records, 1);
    }

    #[test]
    fn partial_trailing_record_is_clean_end_with_flag() {
        let frame = [0u8; 60];
        let mut data = synth(&[(1, 0, 60, &frame)]);
        // append a half record header (8 of 16 bytes)
        data.extend_from_slice(&[0u8; 8]);
        let mut s = StreamingPcapSource::new(Cursor::new(data)).unwrap();
        let _ = s.next_frame().unwrap().unwrap();
        assert!(s.next_frame().unwrap().is_none());
        assert!(s.ended_mid_record, "partial trailing data must set the flag");
    }
}
