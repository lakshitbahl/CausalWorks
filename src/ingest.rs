//! MODULE A — High-Speed Packet Ingestion & Parsing
//!
//! Design constraints and the honest boundary of "zero-copy":
//!
//! * "Zero-copy" here means **zero-copy parse**: every `DecodedFieldbusFrame`
//!   borrows directly from the capture buffer (`&'a [u8]`) and copies out only
//!   the handful of scalar fields we actually need (frame id, one bit, a few
//!   floats). No `Vec` allocation, no `String`, no clone of the payload on the
//!   hot path.
//! * It does **not** mean zero-copy *capture*. The `pcap` crate performs the
//!   kernel→userspace copy that libpcap/AF_PACKET imposes. Achieving true
//!   zero-copy capture at fieldbus line rate requires AF_XDP/DPDK/PF_RING-ZC.
//!   The `CaptureSource` trait below is the seam where that swap happens; the
//!   parser is agnostic to where the bytes came from.
//! * Timestamps: we rely on the capture source's per-packet timestamp as the
//!   single monotonic timeline (`tap_ts_ns`). For correct jitter attribution
//!   you want NIC **hardware** timestamps (SO_TIMESTAMPING / PTP-disciplined),
//!   not the libpcap software timestamp, which adds its own jitter. The field
//!   is plumbed through; the capture impl decides its quality.

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use thiserror::Error;

/// EtherType for PROFINET (RT and IRT both use 0x8892 at the Ethernet layer;
/// the RT-class is distinguished by Frame ID ranges, not EtherType).
const ETHERTYPE_PROFINET: u16 = 0x8892;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_VLAN: u16 = 0x8100;

const ETH_HDR_LEN: usize = 14; // dst(6) + src(6) + ethertype(2)
const VLAN_TAG_LEN: usize = 4; // when 802.1Q present, ethertype sits 4 bytes later
const IPV4_PROTO_UDP: u8 = 17;
/// TCP protocol number. We do NOT do TCP reassembly; S7comm is tracked as an
/// arrival-timing signal only (see S7commArrival).
const IPV4_PROTO_TCP: u8 = 6;
/// S7comm / S7 communication runs over ISO-on-TCP (RFC 1006) on TCP port 102.
/// We classify arrivals to/from this port without decoding TPKT/COTP/S7 PDUs.
const S7COMM_TCP_PORT: u16 = 102;

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("frame shorter than Ethernet header ({0} bytes)")]
    Truncated(usize),
    #[error("ethertype 0x{0:04x} not a protocol we trace")]
    UnhandledEtherType(u16),
    #[error("IPv4 header malformed or truncated")]
    BadIpv4,
    #[error("UDP datagram truncated")]
    BadUdp,
    #[error("payload too short for {proto} decode: need {need}, have {have}")]
    ShortPayload { proto: &'static str, need: usize, have: usize },
}

/// The protocols we model. This is an enum of *decoded variants*, each holding
/// only the fields the causal engine consumes — not the raw payload.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IndustrialProtocol {
    /// PROFINET IRT/RT cyclic frame.
    ProfinetIrt {
        frame_id: u16,
        /// The single safety/interlock bit we track. Which byte/bit this is is
        /// **cell-specific** and comes from the dependency manifest, not from
        /// the wire — there is no universal "interlock bit" in PROFINET. The
        /// parser exposes the first payload byte's LSB by default and the
        /// engine remaps via manifest. We surface both the raw byte and the
        /// extracted bit so the manifest can override the bit index.
        interlock_bit: bool,
        raw_status_byte: u8,
    },
    /// ROS2 traffic over UDP (DDS/RTPS). We do **not** fully parse RTPS here —
    /// full RTPS submessage parsing is a module of its own. We track the UDP
    /// 4-tuple + length as the async "a message on this topic-port arrived"
    /// signal, which is what the causal layer needs (arrival timing, not
    /// content). `topic_port` is the dst UDP port, mapped to a logical topic
    /// by the manifest (e.g. the DDS port for /amr/cmd_vel).
    Ros2Udp { topic_port: u16, payload_len: u16 },
    /// Fanuc proprietary UDP stream carrying pose/kinematic data. Layout is
    /// vendor-specific; we decode a documented subset (3 little-endian f32
    /// position components) guarded by length. If your integration uses a
    /// different Fanuc payload (e.g. RMI/Stream Motion has its own framing),
    /// this is the one decoder you will re-map per deployment.
    FanucUdp { x_mm: f32, y_mm: f32, z_mm: f32 },
    /// S7comm over ISO-on-TCP (port 102) — ARRIVAL-TIMING ONLY. We deliberately
    /// do NOT decode TPKT/COTP/S7 PDUs or reassemble TCP streams. This variant
    /// exists so a Siemens S7-1500 capture (which is mostly S7comm) is correctly
    /// classified and its exchange cadence is visible in `discover`, rather than
    /// showing as a large unclassified gap. `port` is the S7comm port observed
    /// (dst if it's 102, else src), for reference. Full S7 decode is a separate,
    /// larger task (TCP reassembly + ROSCTR/parameter parsing) deferred until a
    /// real engagement pulls for it.
    S7commArrival { port: u16 },
}

/// A decoded frame. Borrows the original buffer for the duration of `'a` so no
/// payload bytes are copied. Scalar fields are copied out (cheap, register-sized).
#[derive(Debug, Clone, Copy)]
pub struct DecodedFieldbusFrame<'a> {
    /// Single monotonic capture timestamp (nanoseconds). This is the only
    /// timeline the causal engine trusts. See module docs on HW vs SW stamps.
    pub tap_ts_ns: u64,
    pub proto: IndustrialProtocol,
    /// Borrowed view of the L2-and-up payload, retained for forensic dumps in
    /// the evidence package without copying on the hot path.
    pub raw: &'a [u8],
}

/// Provenance + precision of a source's timestamps. The causal engine's jitter
/// attribution is only as trustworthy as this. We make it explicit rather than
/// pretending all `u64` nanosecond stamps are equal — a replay file's stamps
/// and a NIC hardware stamp differ by orders of magnitude in fidelity, and a
/// system that conflates them produces confident nonsense.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampSource {
    /// NIC hardware RX timestamp (SO_TIMESTAMPING / SOF_TIMESTAMPING_RX_HARDWARE)
    /// or a TAP-inserted hardware trailer. Sub-µs. The only source on which
    /// the product's microsecond-jitter claims are defensible.
    NicHardware,
    /// Kernel software timestamp (SOF_TIMESTAMPING_RX_SOFTWARE) or libpcap's
    /// default. Jitter typically tens of µs to low ms under load — comparable
    /// to the signal being measured. Usable for *sequencing*, NOT for
    /// sub-ms magnitude attribution.
    KernelSoftware,
    /// Timestamps replayed verbatim from a capture file. Fidelity is whatever
    /// the original capture had; we cannot improve on it and must not claim to.
    ReplayFile,
}

impl TimestampSource {
    /// Coarse worst-case jitter envelope, used by the engine/reporting to
    /// decide whether a measured overrun is above the noise floor. These are
    /// ESTIMATES (order-of-magnitude), not measured guarantees — a real
    /// deployment should characterize its own NIC. Documented as such.
    pub fn approx_jitter_floor_ns(&self) -> u64 {
        match self {
            // ~sub-µs; conservative 1µs floor.
            TimestampSource::NicHardware => 1_000,
            // tens of µs to low ms; conservative 100µs floor.
            TimestampSource::KernelSoftware => 100_000,
            // unknown; defer to the capture's own characteristics.
            TimestampSource::ReplayFile => 0,
        }
    }
}

/// Abstraction over the capture mechanism. libpcap, AF_XDP, a replay file, or a
/// test fixture all implement this. The engine never knows which it is.
///
/// `next_frame` hands back a borrowed buffer + timestamp. The borrow lifetime is
/// tied to the source so the caller must parse-or-copy before requesting the
/// next frame — this is what enforces zero-copy at the type level.
pub trait CaptureSource {
    type Error: std::error::Error;
    /// Returns `Ok(None)` on clean end-of-stream (e.g. replay file exhausted).
    fn next_frame(&mut self) -> Result<Option<(u64, &[u8])>, Self::Error>;
    /// Declares the timestamp provenance of this source. Reported into the
    /// evidence record so a validator knows the fidelity of the timing claims.
    fn timestamp_source(&self) -> TimestampSource;
}

/// libpcap-backed source. Uses the `pcap` crate. Note: for production you must
/// set the device to promiscuous + immediate mode and, critically, request
/// hardware timestamps via the platform mechanism; the `pcap` crate's timestamp
/// is software unless the underlying libpcap is configured for HW stamping.
#[cfg(feature = "pcap-source")]
pub struct PcapSource {
    cap: pcap::Capture<pcap::Active>,
    // Scratch to hold the current packet so we can return a borrow with a
    // lifetime decoupled from pcap's internal buffer reuse. pcap reuses its
    // buffer on the next `next_packet`, so to be sound we copy into this
    // owned scratch. This is ONE copy at the capture boundary — unavoidable
    // with libpcap, and exactly the copy AF_XDP would eliminate.
    scratch: Vec<u8>,
    last_ts_ns: u64,
}

#[cfg(feature = "pcap-source")]
impl CaptureSource for PcapSource {
    type Error = pcap::Error;
    fn next_frame(&mut self) -> Result<Option<(u64, &[u8])>, Self::Error> {
        match self.cap.next_packet() {
            Ok(pkt) => {
                let ts = &pkt.header.ts;
                // tv_sec/tv_usec -> ns. If HW timestamping is enabled libpcap
                // populates these from the NIC; otherwise it is the kernel SW
                // stamp. We do not silently upgrade precision we do not have.
                self.last_ts_ns =
                    (ts.tv_sec as u64) * 1_000_000_000 + (ts.tv_usec as u64) * 1_000;
                self.scratch.clear();
                self.scratch.extend_from_slice(pkt.data);
                Ok(Some((self.last_ts_ns, &self.scratch)))
            }
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn timestamp_source(&self) -> TimestampSource {
        // libpcap default is a kernel software stamp. If you configure the
        // device for HW timestamping (pcap_set_tstamp_type with
        // PCAP_TSTAMP_ADAPTER), change this to NicHardware — but only then.
        TimestampSource::KernelSoftware
    }
}

/// Parse a raw Ethernet frame into a `DecodedFieldbusFrame`, zero-copy over `buf`.
///
/// `buf` is the full L2 frame starting at the destination MAC. Returns
/// `UnhandledEtherType`/`ShortPayload` for frames we deliberately skip rather
/// than erroring the whole loop — the caller treats those as "not a frame we
/// trace" and continues, which keeps the ingest loop allocation- and
/// branch-predictable.
pub fn parse_frame(tap_ts_ns: u64, buf: &[u8]) -> Result<DecodedFieldbusFrame<'_>, ParseError> {
    if buf.len() < ETH_HDR_LEN {
        return Err(ParseError::Truncated(buf.len()));
    }

    // Resolve EtherType, skipping a single 802.1Q VLAN tag if present. We only
    // handle one tag (Q-in-Q is rare on a control-network SPAN; extend if seen).
    let mut ethertype = BigEndian::read_u16(&buf[12..14]);
    let mut l3_offset = ETH_HDR_LEN;
    if ethertype == ETHERTYPE_VLAN {
        if buf.len() < ETH_HDR_LEN + VLAN_TAG_LEN {
            return Err(ParseError::Truncated(buf.len()));
        }
        ethertype = BigEndian::read_u16(&buf[16..18]);
        l3_offset += VLAN_TAG_LEN;
    }

    match ethertype {
        ETHERTYPE_PROFINET => parse_profinet(tap_ts_ns, buf, l3_offset),
        ETHERTYPE_IPV4 => parse_ipv4_udp(tap_ts_ns, buf, l3_offset),
        other => Err(ParseError::UnhandledEtherType(other)),
    }
}

/// PROFINET RT/IRT real-time frame.
///
/// Wire layout after EtherType 0x8892:
///   [FrameID : u16 BE][ ...cyclic IO data... ][ APDU status / cycle counter ]
///
/// The FrameID range identifies the RT class (e.g. 0x0100–0x6FFF RT_CLASS_1/2,
/// 0x8000–0xBBFF IRT, 0xFC01 alarm, etc.). We extract the FrameID and the first
/// IO-data byte; the interlock bit *within* that byte is selected by the
/// manifest downstream. We do NOT assume a fixed bit because PROFINET carries
/// no standardized "interlock" semantic — that mapping is the engineering
/// configured per GSDML/per-cell.
fn parse_profinet(
    tap_ts_ns: u64,
    buf: &[u8],
    l3_offset: usize,
) -> Result<DecodedFieldbusFrame<'_>, ParseError> {
    // Need at least FrameID(2) + one IO byte.
    let need = l3_offset + 3;
    if buf.len() < need {
        return Err(ParseError::ShortPayload {
            proto: "ProfinetIrt",
            need,
            have: buf.len(),
        });
    }
    let frame_id = BigEndian::read_u16(&buf[l3_offset..l3_offset + 2]);
    let raw_status_byte = buf[l3_offset + 2];
    // Default extraction: LSB. Manifest can remap to any bit of any byte; we
    // hand the raw byte through so that remap is lossless.
    let interlock_bit = (raw_status_byte & 0x01) != 0;
    Ok(DecodedFieldbusFrame {
        tap_ts_ns,
        proto: IndustrialProtocol::ProfinetIrt {
            frame_id,
            interlock_bit,
            raw_status_byte,
        },
        raw: buf,
    })
}

/// IPv4 + UDP, then dispatch to ROS2 or Fanuc by destination port (manifest-
/// configurable; ports here are illustrative defaults).
fn parse_ipv4_udp(
    tap_ts_ns: u64,
    buf: &[u8],
    ip_off: usize,
) -> Result<DecodedFieldbusFrame<'_>, ParseError> {
    // IPv4 header: IHL is low nibble of first byte, in 32-bit words.
    if buf.len() < ip_off + 20 {
        return Err(ParseError::BadIpv4);
    }
    let ihl_words = (buf[ip_off] & 0x0F) as usize;
    let ip_hdr_len = ihl_words * 4;
    if ihl_words < 5 || buf.len() < ip_off + ip_hdr_len + 8 {
        return Err(ParseError::BadIpv4);
    }
    let proto = buf[ip_off + 9];
    let l4_off = ip_off + ip_hdr_len;
    // S7comm: TCP port 102 (ISO-on-TCP). Classify as an arrival signal WITHOUT
    // TCP reassembly or PDU decode. TCP src/dst ports sit at the same offsets as
    // UDP (bytes 0-1 src, 2-3 dst of the L4 header), so we can read them without
    // a full TCP header parse. We need at least 4 bytes of TCP header for ports.
    if proto == IPV4_PROTO_TCP {
        if buf.len() < l4_off + 4 {
            return Err(ParseError::BadIpv4);
        }
        let src_port = BigEndian::read_u16(&buf[l4_off..l4_off + 2]);
        let dst_port = BigEndian::read_u16(&buf[l4_off + 2..l4_off + 4]);
        if src_port == S7COMM_TCP_PORT || dst_port == S7COMM_TCP_PORT {
            // Report the S7comm port (the :102 endpoint). Arrival timing only.
            let port = if dst_port == S7COMM_TCP_PORT {
                dst_port
            } else {
                src_port
            };
            return Ok(DecodedFieldbusFrame {
                tap_ts_ns,
                proto: IndustrialProtocol::S7commArrival { port },
                raw: buf,
            });
        }
        // Other TCP (not S7comm) is not something we track.
        return Err(ParseError::UnhandledEtherType(ETHERTYPE_IPV4));
    }
    if proto != IPV4_PROTO_UDP {
        return Err(ParseError::UnhandledEtherType(ETHERTYPE_IPV4)); // not UDP/handled-TCP -> skip
    }
    let udp_off = ip_off + ip_hdr_len;
    let dst_port = BigEndian::read_u16(&buf[udp_off + 2..udp_off + 4]);
    let udp_len = BigEndian::read_u16(&buf[udp_off + 4..udp_off + 6]);
    if (udp_len as usize) < 8 || buf.len() < udp_off + (udp_len as usize) {
        return Err(ParseError::BadUdp);
    }
    let payload_off = udp_off + 8;
    let payload_len = udp_len.saturating_sub(8);

    // Port-based dispatch. The DDS/RTPS port range for ROS2 is computed from the
    // domain id; Fanuc streams use a configured port. Both are manifest-driven
    // in production — these constants are the default mapping.
    const FANUC_POSE_PORT: u16 = 60008;
    if dst_port == FANUC_POSE_PORT {
        // Documented subset: 3 little-endian f32 position components (12 bytes).
        if (payload_len as usize) < 12 {
            return Err(ParseError::ShortPayload {
                proto: "FanucUdp",
                need: 12,
                have: payload_len as usize,
            });
        }
        let p = &buf[payload_off..payload_off + 12];
        Ok(DecodedFieldbusFrame {
            tap_ts_ns,
            proto: IndustrialProtocol::FanucUdp {
                x_mm: LittleEndian::read_f32(&p[0..4]),
                y_mm: LittleEndian::read_f32(&p[4..8]),
                z_mm: LittleEndian::read_f32(&p[8..12]),
            },
            raw: buf,
        })
    } else {
        // Treat everything else on UDP as ROS2/DDS arrival signal. We track
        // arrival timing + size, not content. (Distinguishing ROS2 from other
        // DDS requires RTPS parsing; arrival timing is sufficient for the
        // causal layer's jitter detection.)
        Ok(DecodedFieldbusFrame {
            tap_ts_ns,
            proto: IndustrialProtocol::Ros2Udp {
                topic_port: dst_port,
                payload_len,
            },
            raw: buf,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_header(ethertype: u16) -> Vec<u8> {
        let mut v = vec![0u8; 14];
        v[12] = (ethertype >> 8) as u8;
        v[13] = (ethertype & 0xff) as u8;
        v
    }

    #[test]
    fn parses_profinet_interlock_bit() {
        let mut f = eth_header(ETHERTYPE_PROFINET);
        f.extend_from_slice(&[0x00, 0x02]); // FrameID 0x0002
        f.push(0x01); // status byte, LSB set
        let d = parse_frame(1000, &f).unwrap();
        match d.proto {
            IndustrialProtocol::ProfinetIrt {
                frame_id,
                interlock_bit,
                raw_status_byte,
            } => {
                assert_eq!(frame_id, 0x0002);
                assert!(interlock_bit);
                assert_eq!(raw_status_byte, 0x01);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn short_frame_errors_not_panics() {
        let f = vec![0u8; 8];
        assert!(matches!(parse_frame(0, &f), Err(ParseError::Truncated(8))));
    }

    #[test]
    fn fanuc_pose_decodes_le_floats() {
        // eth + ipv4(20) + udp(8) + 12 bytes pose, dst port 60008
        let mut f = eth_header(ETHERTYPE_IPV4);
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45; // version 4, IHL 5
        ip[9] = IPV4_PROTO_UDP;
        f.extend_from_slice(&ip);
        let mut udp = vec![0u8; 8];
        // dst port 60008 = 0xEA68
        udp[2] = 0xEA;
        udp[3] = 0x68;
        let total_udp_len = 8 + 12u16;
        udp[4] = (total_udp_len >> 8) as u8;
        udp[5] = (total_udp_len & 0xff) as u8;
        f.extend_from_slice(&udp);
        f.extend_from_slice(&100.0f32.to_le_bytes());
        f.extend_from_slice(&200.0f32.to_le_bytes());
        f.extend_from_slice(&50.0f32.to_le_bytes());
        let d = parse_frame(42, &f).unwrap();
        match d.proto {
            IndustrialProtocol::FanucUdp { x_mm, y_mm, z_mm } => {
                assert_eq!((x_mm, y_mm, z_mm), (100.0, 200.0, 50.0));
            }
            _ => panic!("wrong variant"),
        }
    }

    // Helper: IPv4 frame with a given protocol byte and L4 header bytes.
    fn ipv4_frame(proto: u8, l4: &[u8]) -> Vec<u8> {
        let mut f = eth_header(ETHERTYPE_IPV4);
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        ip[9] = proto;
        f.extend_from_slice(&ip);
        f.extend_from_slice(l4);
        f
    }
    fn tcp_ports(src: u16, dst: u16) -> Vec<u8> {
        let mut t = vec![0u8; 20]; // minimal TCP header
        t[0] = (src >> 8) as u8;
        t[1] = (src & 0xff) as u8;
        t[2] = (dst >> 8) as u8;
        t[3] = (dst & 0xff) as u8;
        t
    }

    #[test]
    fn s7comm_classified_on_dst_port_102() {
        let f = ipv4_frame(IPV4_PROTO_TCP, &tcp_ports(50000, S7COMM_TCP_PORT));
        match parse_frame(0, &f).unwrap().proto {
            IndustrialProtocol::S7commArrival { port } => assert_eq!(port, 102),
            other => panic!("expected S7commArrival, got {:?}", other),
        }
    }

    #[test]
    fn s7comm_classified_on_src_port_102() {
        // PLC responses originate FROM port 102.
        let f = ipv4_frame(IPV4_PROTO_TCP, &tcp_ports(S7COMM_TCP_PORT, 50000));
        match parse_frame(0, &f).unwrap().proto {
            IndustrialProtocol::S7commArrival { port } => assert_eq!(port, 102),
            other => panic!("expected S7commArrival, got {:?}", other),
        }
    }

    #[test]
    fn non_s7_tcp_is_not_classified() {
        // TCP that isn't S7comm (e.g. HTTP:80) must still be rejected, so it
        // counts as unclassified coverage rather than being mislabeled.
        let f = ipv4_frame(IPV4_PROTO_TCP, &tcp_ports(50000, 80));
        assert!(parse_frame(0, &f).is_err());
    }
}
