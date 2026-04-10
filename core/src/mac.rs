use std::fmt;
use std::str::FromStr;

use crate::{Error, Result};

/// A 48-bit MAC address.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const BROADCAST: Self = MacAddr([0xff; 6]);
    pub const ZERO: Self = MacAddr([0; 6]);

    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(s: &[u8]) -> Result<Self> {
        if s.len() != 6 {
            return Err(Error::Parse(format!("mac: expected 6 bytes, got {}", s.len())));
        }
        let mut b = [0u8; 6];
        b.copy_from_slice(s);
        Ok(Self(b))
    }

    pub fn bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// The first three octets of the MAC - the OUI.
    pub fn oui(&self) -> [u8; 3] {
        [self.0[0], self.0[1], self.0[2]]
    }

    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }

    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }

    /// Generate a pseudo-random locally administered unicast MAC.
    /// Deterministic given the provided seed.
    pub fn random_with_seed(mut seed: u64) -> Self {
        let mut out = [0u8; 6];
        for byte in out.iter_mut() {
            // xorshift - we don't need cryptographic quality here.
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *byte = seed as u8;
        }
        out[0] = (out[0] & 0xfc) | 0x02; // locally administered, unicast
        MacAddr(out)
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        <Self as fmt::Display>::fmt(self, f)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if cleaned.len() != 12 {
            return Err(Error::Parse(format!("mac: bad length `{s}`")));
        }
        let raw = hex::decode(&cleaned).map_err(|e| Error::Parse(format!("mac: {e}")))?;
        Self::from_slice(&raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_render_roundtrip() {
        let m = MacAddr::from_str("aa:bb:cc:11:22:33").unwrap();
        assert_eq!(m.to_string(), "AA:BB:CC:11:22:33");
    }

    #[test]
    fn random_is_locally_administered_unicast() {
        let m = MacAddr::random_with_seed(0xdead_beef);
        assert!(m.is_locally_administered());
        assert!(!m.is_multicast());
    }

    #[test]
    fn broadcast_detected() {
        assert!(MacAddr::BROADCAST.is_broadcast());
        assert!(MacAddr::BROADCAST.is_multicast());
    }
}
