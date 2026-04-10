use crate::{Error, Result};

/// 802.11 operating bands we understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Band {
    /// 2.4 GHz ISM band (channels 1..=14).
    Twenty4,
    /// 5 GHz U-NII band (channels 36..=177 in 4-wide steps).
    Five,
    /// 6 GHz band (channels 1..=233, Wi-Fi 6E).
    Six,
}

impl Band {
    pub fn label(&self) -> &'static str {
        match self {
            Band::Twenty4 => "2.4 GHz",
            Band::Five => "5 GHz",
            Band::Six => "6 GHz",
        }
    }
}

/// A single 802.11 channel, identified by its number and band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Channel {
    pub number: u16,
    pub band: Band,
}

impl Channel {
    /// Construct from a channel number, guessing the band.
    /// 1..=14 → 2.4 GHz; everything else is treated as 5 GHz by default.
    pub fn from_number(number: u16) -> Result<Self> {
        let band = match number {
            1..=14 => Band::Twenty4,
            32..=177 => Band::Five,
            _ => return Err(Error::InvalidChannel(number)),
        };
        Ok(Self { number, band })
    }

    /// Construct a 6 GHz channel explicitly (the band can't be guessed from
    /// the number alone because 2.4/6 GHz overlap numerically).
    pub fn from_6ghz(number: u16) -> Result<Self> {
        if (1..=233).contains(&number) {
            Ok(Self { number, band: Band::Six })
        } else {
            Err(Error::InvalidChannel(number))
        }
    }

    /// Convert a channel number to its centre frequency in MHz.
    pub fn frequency_mhz(&self) -> u16 {
        match self.band {
            Band::Twenty4 if self.number == 14 => 2484,
            Band::Twenty4 => 2407 + 5 * self.number,
            Band::Five => 5000 + 5 * self.number,
            Band::Six => 5950 + 5 * self.number,
        }
    }

    /// Return the full list of channels commonly legal in the given band.
    /// This is what airodump-ng uses when no `-c` is supplied.
    pub fn hop_set(band: Band) -> Vec<Channel> {
        match band {
            Band::Twenty4 => (1u16..=13).map(|n| Channel { number: n, band }).collect(),
            Band::Five => [
                36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136,
                140, 144, 149, 153, 157, 161, 165,
            ]
            .iter()
            .map(|n| Channel { number: *n, band })
            .collect(),
            Band::Six => (1..=233).step_by(4).map(|n| Channel { number: n as u16, band }).collect(),
        }
    }
}

impl std::fmt::Display for Channel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.number)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ch1_freq_is_2412() {
        assert_eq!(Channel::from_number(1).unwrap().frequency_mhz(), 2412);
    }

    #[test]
    fn ch14_freq_is_2484() {
        assert_eq!(Channel::from_number(14).unwrap().frequency_mhz(), 2484);
    }

    #[test]
    fn ch36_is_5ghz() {
        let c = Channel::from_number(36).unwrap();
        assert_eq!(c.band, Band::Five);
        assert_eq!(c.frequency_mhz(), 5180);
    }

    #[test]
    fn hop_set_24ghz_has_13_entries() {
        assert_eq!(Channel::hop_set(Band::Twenty4).len(), 13);
    }
}
