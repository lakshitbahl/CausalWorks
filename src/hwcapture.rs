//! Live capture with hardware RX timestamps — PRODUCTION SCAFFOLD.
//!
//! ============================ READ THIS FIRST ============================
//! The task framing was "extract microsecond timestamps from packet headers."
//! That is not where they are. There is NO microsecond wall-clock timestamp
//! inside a Profinet/EtherCAT/Ethernet-IP or UDP frame header. The cyclic
//! counters those protocols carry are sequence/cycle counters, not time.
//!
//! Real sub-µs RX timing comes from ONE of:
//!   (a) NIC hardware timestamping surfaced via the kernel as an ancillary
//!       control message (SO_TIMESTAMPING with SOF_TIMESTAMPING_RX_HARDWARE),
//!       read alongside the packet via recvmsg(). REQUIRES a NIC + driver that
//!       support hardware RX timestamping (most Intel i210/i225, many others).
//!   (b) A timestamping TAP that PREPENDS/APPENDS a hardware timestamp trailer
//!       to each mirrored frame (e.g. certain Profitap/Garland/Endace units).
//!       Then you DO parse a header/trailer — but a VENDOR-SPECIFIC one the TAP
//!       inserted, not a fieldbus field. This module supports that path too,
//!       gated behind a configured trailer layout.
//!
//! This file implements path (a) against raw libc syscalls. It is a SCAFFOLD:
//! it cannot be exercised in a sandbox with no NIC, and the recvmsg/cmsg
//! plumbing is the kind of unsafe FFI that MUST be validated on real hardware
//! with a known packet source before trust. I have written it to be correct to
//! the Linux ABI as documented, but it is unverified against a live socket.
//! Confidence: medium on the ABI constants/layout, LOW that it runs first-try
//! without a hardware debugging pass. Do not ship without that pass.
//! =========================================================================

#![cfg(target_os = "linux")]

use crate::ingest::{CaptureSource, TimestampSource};
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HwCaptureError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("socket setup failed at step '{step}': {source}")]
    Setup { step: &'static str, source: io::Error },
    #[error("no hardware timestamp in control message — NIC/driver may lack SOF_TIMESTAMPING_RX_HARDWARE, or the PHC/PTP clock is not running")]
    NoHardwareTimestamp,
}

/// Configuration for a live hardware-timestamped capture.
pub struct HwCaptureConfig {
    /// Interface index to bind (from `if_nametoindex`). The TAP/SPAN feed must
    /// be on this interface. The interface should be in promiscuous mode and
    /// ideally dedicated to capture (no host IP stack noise).
    pub ifindex: i32,
    /// Expect hardware (true) vs. accept software (false) timestamps. If true
    /// and the NIC yields only software stamps, `next_frame` errors rather than
    /// silently downgrading fidelity — fail loud, per the timestamp-honesty
    /// principle.
    pub require_hardware: bool,
}

/// AF_PACKET raw socket with SO_TIMESTAMPING enabled.
///
/// IMPLEMENTATION STATUS: the constants and the recvmsg/cmsg parsing below
/// follow the Linux kernel ABI (Documentation/networking/timestamping.rst).
/// They are written from the documented ABI, NOT validated against a live
/// socket in this environment. The `libc` crate provides the syscall bindings;
/// it is intentionally an OPTIONAL dependency gated by the `hw-capture`
/// feature so the rest of the crate (and the offline harness) builds with no
/// system/networking deps.
#[cfg(feature = "hw-capture")]
pub struct HwTimestampSource {
    fd: i32,
    pkt_buf: Vec<u8>,
    last_ts_was_hardware: bool,
    require_hardware: bool,
}

#[cfg(feature = "hw-capture")]
impl HwTimestampSource {
    /// Open an AF_PACKET socket, bind to the interface, and request RX
    /// hardware+software timestamps. Returns an error (not a panic) on any
    /// setup syscall failure so a supervisor can restart cleanly.
    pub fn open(cfg: HwCaptureConfig) -> Result<Self, HwCaptureError> {
        use libc::{
            bind, setsockopt, sockaddr_ll, socket, AF_PACKET, ETH_P_ALL, SOCK_RAW, SOL_SOCKET,
            SO_TIMESTAMPING,
        };
        // SAFETY: each syscall's arguments are constructed per its man page;
        // we check every return value and convert errno to io::Error.
        unsafe {
            let fd = socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as i32);
            if fd < 0 {
                return Err(HwCaptureError::Setup {
                    step: "socket",
                    source: io::Error::last_os_error(),
                });
            }

            // SO_TIMESTAMPING flags: request RX hardware + software stamps and
            // raw (un-adjusted) hardware values. These bit values are stable
            // kernel UAPI (linux/net_tstamp.h):
            //   SOF_TIMESTAMPING_RX_HARDWARE = 1<<2
            //   SOF_TIMESTAMPING_RX_SOFTWARE = 1<<3
            //   SOF_TIMESTAMPING_RAW_HARDWARE = 1<<6
            //   SOF_TIMESTAMPING_SOFTWARE     = 1<<4
            const SOF_TS_RX_HW: u32 = 1 << 2;
            const SOF_TS_RX_SW: u32 = 1 << 3;
            const SOF_TS_SW: u32 = 1 << 4;
            const SOF_TS_RAW_HW: u32 = 1 << 6;
            let flags: u32 = SOF_TS_RX_HW | SOF_TS_RX_SW | SOF_TS_SW | SOF_TS_RAW_HW;
            let rc = setsockopt(
                fd,
                SOL_SOCKET,
                SO_TIMESTAMPING,
                &flags as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            );
            if rc < 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(HwCaptureError::Setup {
                    step: "setsockopt(SO_TIMESTAMPING)",
                    source: e,
                });
            }

            // Bind to the interface so we only receive its mirrored traffic.
            let mut sll: sockaddr_ll = std::mem::zeroed();
            sll.sll_family = AF_PACKET as u16;
            sll.sll_protocol = (ETH_P_ALL as u16).to_be();
            sll.sll_ifindex = cfg.ifindex;
            let rc = bind(
                fd,
                &sll as *const sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<sockaddr_ll>() as libc::socklen_t,
            );
            if rc < 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(HwCaptureError::Setup {
                    step: "bind",
                    source: e,
                });
            }

            Ok(Self {
                fd,
                pkt_buf: vec![0u8; 9216], // jumbo-safe
                last_ts_was_hardware: false,
                require_hardware: cfg.require_hardware,
            })
        }
    }

    /// recvmsg into pkt_buf, parse the SCM_TIMESTAMPING control message.
    /// The cmsg carries `struct scm_timestamping { struct timespec ts[3]; }`
    /// where ts[0]=software, ts[1]=deprecated, ts[2]=raw hardware.
    fn recv_one(&mut self) -> Result<(u64, usize), HwCaptureError> {
        use libc::{
            c_void, cmsghdr, iovec, msghdr, recvmsg, timespec, CMSG_DATA, CMSG_FIRSTHDR,
            CMSG_NXTHDR, SCM_TIMESTAMPING, SOL_SOCKET,
        };
        // Control buffer sized for a few cmsgs. 256 is comfortably enough for
        // a single SCM_TIMESTAMPING (3 timespecs = 48 bytes + header).
        let mut ctrl = [0u8; 256];
        let mut iov = iovec {
            iov_base: self.pkt_buf.as_mut_ptr() as *mut c_void,
            iov_len: self.pkt_buf.len(),
        };
        // SAFETY: msghdr fully initialized; pointers reference live local buffers
        // that outlive the recvmsg call.
        unsafe {
            let mut mh: msghdr = std::mem::zeroed();
            mh.msg_iov = &mut iov;
            mh.msg_iovlen = 1;
            mh.msg_control = ctrl.as_mut_ptr() as *mut c_void;
            mh.msg_controllen = ctrl.len() as _;

            let n = recvmsg(self.fd, &mut mh, 0);
            if n < 0 {
                return Err(HwCaptureError::Io(io::Error::last_os_error()));
            }

            // Walk control messages looking for SCM_TIMESTAMPING.
            let mut sw_ns: Option<u64> = None;
            let mut hw_ns: Option<u64> = None;
            let mut cmsg = CMSG_FIRSTHDR(&mh);
            while !cmsg.is_null() {
                let c: &cmsghdr = &*cmsg;
                if c.cmsg_level == SOL_SOCKET && c.cmsg_type == SCM_TIMESTAMPING {
                    let data = CMSG_DATA(cmsg) as *const timespec;
                    // ts[0] software, ts[2] raw hardware.
                    let ts_sw = &*data;
                    let ts_hw = &*data.add(2);
                    let to_ns = |t: &timespec| (t.tv_sec as u64) * 1_000_000_000 + t.tv_nsec as u64;
                    let sw = to_ns(ts_sw);
                    let hw = to_ns(ts_hw);
                    if sw != 0 {
                        sw_ns = Some(sw);
                    }
                    if hw != 0 {
                        hw_ns = Some(hw);
                    }
                }
                cmsg = CMSG_NXTHDR(&mh, cmsg);
            }

            match (hw_ns, sw_ns, self.require_hardware) {
                (Some(hw), _, _) => {
                    self.last_ts_was_hardware = true;
                    Ok((hw, n as usize))
                }
                (None, Some(_sw), true) => Err(HwCaptureError::NoHardwareTimestamp),
                (None, Some(sw), false) => {
                    self.last_ts_was_hardware = false;
                    Ok((sw, n as usize))
                }
                (None, None, _) => Err(HwCaptureError::NoHardwareTimestamp),
            }
        }
    }
}

#[cfg(feature = "hw-capture")]
impl CaptureSource for HwTimestampSource {
    type Error = HwCaptureError;
    fn next_frame(&mut self) -> Result<Option<(u64, &[u8])>, Self::Error> {
        let (ts, len) = self.recv_one()?;
        Ok(Some((ts, &self.pkt_buf[..len])))
    }
    fn timestamp_source(&self) -> TimestampSource {
        if self.last_ts_was_hardware {
            TimestampSource::NicHardware
        } else {
            TimestampSource::KernelSoftware
        }
    }
}

#[cfg(feature = "hw-capture")]
impl Drop for HwTimestampSource {
    fn drop(&mut self) {
        // SAFETY: fd owned by self, closed exactly once.
        unsafe {
            libc::close(self.fd);
        }
    }
}
