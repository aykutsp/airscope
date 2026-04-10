//! Packet capture.
//!
//! There are two supported sources:
//!
//! * [`PcapFileReader`] – reads a `.pcap` or `.pcapng` file. Always
//!   available; useful for offline analysis and CI.
//! * [`LiveCapture`]    – opens a live interface. Needs the `live`
//!   feature and, at runtime, libpcap (Linux) or Npcap (Windows).
//!
//! Both emit [`CapturedPacket`] values: a timestamp plus the raw bytes
//! as they came off the wire, including radiotap. The upper layers are
//! responsible for decoding with [`super::radiotap`] and [`super::frame`].

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use airscope_core::{Error, Result};
use byteorder::{ByteOrder, LittleEndian};

/// One packet as it came out of a capture source.
#[derive(Debug, Clone)]
pub struct CapturedPacket {
    pub timestamp_micros: i64,
    pub data: Vec<u8>,
}

/// Common magic numbers found at the start of a pcap file.
const PCAP_MAGIC_LE: u32 = 0xa1b2_c3d4;
const PCAP_MAGIC_NS: u32 = 0xa1b2_3c4d;

/// Link types we know how to decode further up the stack.
pub const LINKTYPE_IEEE802_11: u32 = 105;
pub const LINKTYPE_IEEE802_11_RADIOTAP: u32 = 127;
pub const LINKTYPE_ETHERNET: u32 = 1;

/// Classic libpcap file reader (savefile v2.4 format).
///
/// We deliberately avoid pulling in a full pcap-parser dependency:
/// the file format is small and stable and the saved bytes are easier
/// to reason about if we parse them ourselves.
pub struct PcapFileReader {
    reader: BufReader<File>,
    nanosecond_precision: bool,
    pub linktype: u32,
    pub snaplen: u32,
}

impl PcapFileReader {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let file = File::open(path.as_ref())?;
        let mut reader = BufReader::new(file);
        let mut header = [0u8; 24];
        reader.read_exact(&mut header)?;
        let magic = LittleEndian::read_u32(&header[0..4]);
        let (nanosecond, little_endian) = match magic {
            PCAP_MAGIC_LE => (false, true),
            PCAP_MAGIC_NS => (true, true),
            _ => {
                return Err(Error::Parse(format!(
                    "pcap: unknown magic 0x{:08x}",
                    magic
                )))
            }
        };
        if !little_endian {
            return Err(Error::Unsupported("big-endian pcap".into()));
        }
        let snaplen = LittleEndian::read_u32(&header[16..20]);
        let linktype = LittleEndian::read_u32(&header[20..24]);
        Ok(Self {
            reader,
            nanosecond_precision: nanosecond,
            linktype,
            snaplen,
        })
    }

    /// Read the next packet, or `Ok(None)` at EOF.
    pub fn next_packet(&mut self) -> Result<Option<CapturedPacket>> {
        let mut rec = [0u8; 16];
        match self.reader.read_exact(&mut rec) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let ts_sec = LittleEndian::read_u32(&rec[0..4]) as i64;
        let ts_frac = LittleEndian::read_u32(&rec[4..8]) as i64;
        let incl_len = LittleEndian::read_u32(&rec[8..12]) as usize;
        let _orig_len = LittleEndian::read_u32(&rec[12..16]);

        if incl_len > self.snaplen as usize * 2 {
            return Err(Error::Parse(format!(
                "pcap: record larger than expected: {incl_len}"
            )));
        }

        let mut data = vec![0u8; incl_len];
        self.reader.read_exact(&mut data)?;

        let ts_micros = if self.nanosecond_precision {
            ts_sec * 1_000_000 + ts_frac / 1_000
        } else {
            ts_sec * 1_000_000 + ts_frac
        };

        Ok(Some(CapturedPacket {
            timestamp_micros: ts_micros,
            data,
        }))
    }

    /// Drain the file into a Vec, short-circuiting on the first error.
    pub fn into_vec(mut self) -> Result<Vec<CapturedPacket>> {
        let mut out = Vec::new();
        while let Some(pkt) = self.next_packet()? {
            out.push(pkt);
        }
        Ok(out)
    }
}

/// Write a libpcap savefile. Uses the classic microsecond format (magic
/// `0xa1b2c3d4`) so anything - Wireshark, tshark, another airscope - can
/// read it back.
pub struct PcapFileWriter {
    file: std::io::BufWriter<File>,
}

impl PcapFileWriter {
    pub fn create(path: impl AsRef<Path>, linktype: u32, snaplen: u32) -> Result<Self> {
        let file = File::create(path.as_ref())?;
        let mut w = std::io::BufWriter::new(file);
        let mut header = [0u8; 24];
        LittleEndian::write_u32(&mut header[0..4], PCAP_MAGIC_LE);
        // version 2.4
        LittleEndian::write_u16(&mut header[4..6], 2);
        LittleEndian::write_u16(&mut header[6..8], 4);
        // thiszone = 0, sigfigs = 0
        LittleEndian::write_u32(&mut header[8..12], 0);
        LittleEndian::write_u32(&mut header[12..16], 0);
        LittleEndian::write_u32(&mut header[16..20], snaplen);
        LittleEndian::write_u32(&mut header[20..24], linktype);
        use std::io::Write;
        w.write_all(&header)?;
        Ok(Self { file: w })
    }

    pub fn write(&mut self, pkt: &CapturedPacket) -> Result<()> {
        use std::io::Write;
        let mut rec = [0u8; 16];
        let ts_sec = (pkt.timestamp_micros / 1_000_000) as u32;
        let ts_us  = (pkt.timestamp_micros % 1_000_000) as u32;
        LittleEndian::write_u32(&mut rec[0..4], ts_sec);
        LittleEndian::write_u32(&mut rec[4..8], ts_us);
        LittleEndian::write_u32(&mut rec[8..12], pkt.data.len() as u32);
        LittleEndian::write_u32(&mut rec[12..16], pkt.data.len() as u32);
        self.file.write_all(&rec)?;
        self.file.write_all(&pkt.data)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        use std::io::Write;
        self.file.flush().map_err(Into::into)
    }
}

// ---------- live capture ----------------------------------------------------

#[cfg(feature = "live")]
pub mod live {
    use super::*;

    /// Information about an interface reported by libpcap.
    #[derive(Debug, Clone)]
    pub struct LiveInterface {
        pub name: String,
        pub description: Option<String>,
        pub is_up: bool,
    }

    pub fn list_interfaces() -> Result<Vec<LiveInterface>> {
        let devs = pcap::Device::list()
            .map_err(|e| Error::Capture(format!("list: {e}")))?;
        Ok(devs
            .into_iter()
            .map(|d| LiveInterface {
                name: d.name,
                description: d.desc,
                is_up: d.flags.is_up(),
            })
            .collect())
    }

    /// A live packet source.
    ///
    /// This is a thin wrapper around `pcap::Capture<pcap::Active>` so the
    /// rest of the crate never has to touch the raw FFI types.
    pub struct LiveCapture {
        cap: pcap::Capture<pcap::Active>,
        pub linktype: u32,
    }

    impl LiveCapture {
        /// Open an interface in promiscuous mode with a 128 ms read timeout.
        /// The timeout is what lets the TUI run smoothly: shorter reads
        /// let us poll the UI between batches instead of blocking.
        pub fn open(interface: &str) -> Result<Self> {
            let cap = pcap::Capture::from_device(interface)
                .map_err(|e| Error::Capture(e.to_string()))?
                .promisc(true)
                .timeout(128)
                .immediate_mode(true)
                .snaplen(4096)
                .open()
                .map_err(|e| Error::Capture(e.to_string()))?;
            let linktype = cap.get_datalink().0 as u32;
            Ok(Self { cap, linktype })
        }

        /// Apply a BPF filter to the capture.
        pub fn set_filter(&mut self, filter: &str) -> Result<()> {
            self.cap
                .filter(filter, true)
                .map_err(|e| Error::Capture(e.to_string()))
        }

        /// Pull the next packet. Returns `Ok(None)` on a timeout so
        /// callers can stay interactive.
        pub fn next(&mut self) -> Result<Option<CapturedPacket>> {
            match self.cap.next_packet() {
                Ok(p) => Ok(Some(CapturedPacket {
                    timestamp_micros: p.header.ts.tv_sec as i64 * 1_000_000
                        + p.header.ts.tv_usec as i64,
                    data: p.data.to_vec(),
                })),
                Err(pcap::Error::TimeoutExpired) => Ok(None),
                Err(e) => Err(Error::Capture(e.to_string())),
            }
        }

        /// Send a raw frame on the interface (injection). The caller is
        /// responsible for including the radiotap header when needed.
        pub fn inject(&mut self, frame: &[u8]) -> Result<()> {
            self.cap
                .sendpacket(frame)
                .map_err(|e| Error::Injection(e.to_string()))
        }
    }
}

#[cfg(not(feature = "live"))]
pub mod live {
    use super::*;

    /// Without the `live` feature the type still exists so binaries
    /// can refer to it, but every operation returns `Unsupported` with
    /// a clear install message. This is not a bug – it's how we keep
    /// the default build portable.
    ///
    /// `linktype` mirrors the real struct's public field so callers
    /// (like airodump's LiveSource) don't need #[cfg] splits just to
    /// read it. It stays `0` because we never actually open anything.
    pub struct LiveCapture {
        pub linktype: u32,
    }

    #[derive(Debug, Clone)]
    pub struct LiveInterface {
        pub name: String,
        pub description: Option<String>,
        pub is_up: bool,
    }

    /// The one message every `Unsupported` error in this module shares.
    /// Kept as a constant so airodump / aireplay / airbase all print the
    /// same, auditable text.
    const NEED_LIVE: &str = "\
live capture is not available in this build.

on linux:
  sudo apt install libpcap-dev         # or your distro's equivalent
  cargo build --release --features \"airscope-airodump/live airscope-aireplay/live airscope-airbase/live airscope-airmon/live\"

on macos:
  brew install libpcap
  cargo build --release --features \"airscope-airodump/live airscope-aireplay/live airscope-airbase/live\"

on windows:
  1) install the npcap runtime from https://npcap.com (tick 'install in winpcap api-compatible mode')
  2) download the npcap sdk zip and extract it somewhere, e.g. C:\\npcap-sdk
  3) in the shell where you run cargo, point the linker at the sdk:
        set LIB=C:\\npcap-sdk\\Lib\\x64
     (mingw users: also rename wpcap.lib -> libwpcap.a inside Lib\\x64)
  4) cargo build --release --features \"airscope-airodump/live airscope-aireplay/live\"

full step-by-step, including troubleshooting, in docs/INSTALL.md.";

    pub fn list_interfaces() -> Result<Vec<LiveInterface>> {
        Err(Error::Unsupported(NEED_LIVE.into()))
    }

    impl LiveCapture {
        pub fn open(_interface: &str) -> Result<Self> {
            Err(Error::Unsupported(NEED_LIVE.into()))
        }
        pub fn set_filter(&mut self, _filter: &str) -> Result<()> {
            Err(Error::Unsupported(NEED_LIVE.into()))
        }
        pub fn next(&mut self) -> Result<Option<CapturedPacket>> {
            Err(Error::Unsupported(NEED_LIVE.into()))
        }
        pub fn inject(&mut self, _frame: &[u8]) -> Result<()> {
            Err(Error::Unsupported(NEED_LIVE.into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn synthetic_pcap_with_one_packet() -> Vec<u8> {
        // Global header
        let mut buf = Vec::new();
        buf.extend_from_slice(&PCAP_MAGIC_LE.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&(65_535u32).to_le_bytes());
        buf.extend_from_slice(&LINKTYPE_IEEE802_11.to_le_bytes());

        // Record header: ts_sec=1, ts_usec=2, incl=4, orig=4
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        buf
    }

    #[test]
    fn round_trip_file_reader() {
        let tmp = std::env::temp_dir().join("airscope_cap_test.pcap");
        {
            let mut f = File::create(&tmp).unwrap();
            f.write_all(&synthetic_pcap_with_one_packet()).unwrap();
        }
        let mut r = PcapFileReader::open(&tmp).unwrap();
        let pkt = r.next_packet().unwrap().unwrap();
        assert_eq!(pkt.data, vec![0xde, 0xad, 0xbe, 0xef]);
        assert!(r.next_packet().unwrap().is_none());
        std::fs::remove_file(tmp).ok();
    }
}
