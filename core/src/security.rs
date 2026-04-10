use std::fmt;

/// Cipher suites we recognise in the RSN / WPA information elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Cipher {
    None,
    Wep40,
    Wep104,
    Tkip,
    Ccmp128,
    Ccmp256,
    Gcmp128,
    Gcmp256,
    Unknown,
}

impl Cipher {
    pub fn from_ieee(oui: [u8; 3], suite: u8) -> Self {
        // 00-0f-ac = IEEE 802.11i
        if oui == [0x00, 0x0f, 0xac] {
            return match suite {
                1  => Cipher::Wep40,
                2  => Cipher::Tkip,
                4  => Cipher::Ccmp128,
                5  => Cipher::Wep104,
                8  => Cipher::Gcmp128,
                9  => Cipher::Gcmp256,
                10 => Cipher::Ccmp256,
                _  => Cipher::Unknown,
            };
        }
        Cipher::Unknown
    }

    pub fn short(&self) -> &'static str {
        match self {
            Cipher::None    => "-",
            Cipher::Wep40   => "WEP40",
            Cipher::Wep104  => "WEP104",
            Cipher::Tkip    => "TKIP",
            Cipher::Ccmp128 => "CCMP",
            Cipher::Ccmp256 => "CCMP256",
            Cipher::Gcmp128 => "GCMP",
            Cipher::Gcmp256 => "GCMP256",
            Cipher::Unknown => "?",
        }
    }
}

/// Authentication key management suites (RSN AKM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyManagement {
    None,
    Psk,
    Eap,
    FtPsk,
    FtEap,
    Sae,
    FtSae,
    Owe,
    Unknown,
}

impl KeyManagement {
    pub fn from_ieee(oui: [u8; 3], suite: u8) -> Self {
        if oui == [0x00, 0x0f, 0xac] {
            return match suite {
                1  => KeyManagement::Eap,
                2  => KeyManagement::Psk,
                3  => KeyManagement::FtEap,
                4  => KeyManagement::FtPsk,
                8  => KeyManagement::Sae,
                9  => KeyManagement::FtSae,
                18 => KeyManagement::Owe,
                _  => KeyManagement::Unknown,
            };
        }
        KeyManagement::Unknown
    }

    pub fn short(&self) -> &'static str {
        match self {
            KeyManagement::None    => "-",
            KeyManagement::Psk     => "PSK",
            KeyManagement::Eap     => "EAP",
            KeyManagement::FtPsk   => "FT/PSK",
            KeyManagement::FtEap   => "FT/EAP",
            KeyManagement::Sae     => "SAE",
            KeyManagement::FtSae   => "FT/SAE",
            KeyManagement::Owe     => "OWE",
            KeyManagement::Unknown => "?",
        }
    }
}

/// A flattened view of an AP's security configuration, the way airodump
/// shows it in the scanner columns.
#[derive(Debug, Clone)]
pub struct Encryption {
    pub open: bool,
    pub wep: bool,
    pub wpa: bool,
    pub wpa2: bool,
    pub wpa3: bool,
    pub pairwise: Vec<Cipher>,
    pub group: Cipher,
    pub akm: Vec<KeyManagement>,
}

impl Default for Encryption {
    fn default() -> Self {
        Self {
            open: true,
            wep: false,
            wpa: false,
            wpa2: false,
            wpa3: false,
            pairwise: Vec::new(),
            group: Cipher::None,
            akm: Vec::new(),
        }
    }
}

impl Encryption {
    /// The short family string shown in the `ENC` column.
    pub fn family(&self) -> &'static str {
        if self.wpa3 { "WPA3" }
        else if self.wpa2 { "WPA2" }
        else if self.wpa  { "WPA"  }
        else if self.wep  { "WEP"  }
        else { "OPN" }
    }
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.family())?;
        if let Some(c) = self.pairwise.first() {
            write!(f, "/{}", c.short())?;
        }
        if let Some(a) = self.akm.first() {
            write!(f, "/{}", a.short())?;
        }
        Ok(())
    }
}
