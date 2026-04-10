//! Integration-style "fuzz lite" coverage for the parsers.
//!
//! We don't pull cargo-fuzz into the main test loop because it needs
//! nightly; instead we build a large corpus of deliberately hostile
//! byte sequences and assert that the parsers either decode them
//! cleanly or return a tidy `Err`. No panics, no out-of-bounds reads,
//! ever. If any future change regresses that property these tests
//! will catch it.

use airscope_core::MacAddr;
use airscope_wifi::builder::{build_beacon, build_deauth, build_probe_request, ReasonCode};
use airscope_wifi::capture::{CapturedPacket, PcapFileReader, PcapFileWriter, LINKTYPE_IEEE802_11};
use airscope_wifi::frame::Dot11Frame;
use airscope_wifi::radiotap::RadiotapHeader;

// ----- graceful degradation ------------------------------------------------

#[test]
fn parse_empty_buffer_errors() {
    assert!(Dot11Frame::parse(&[]).is_err());
}

#[test]
fn parse_sub_header_buffer_errors() {
    for n in 0..24 {
        let buf = vec![0u8; n];
        assert!(Dot11Frame::parse(&buf).is_err(), "n={n}");
    }
}

#[test]
fn parse_minimum_header_is_ok() {
    let mut buf = vec![0u8; 24];
    // type=management, subtype=beacon
    buf[0] = 0x80;
    let f = Dot11Frame::parse(&buf).expect("24 zeros + subtype=beacon should parse");
    assert!(f.body.is_empty());
}

#[test]
fn radiotap_rejects_non_zero_version() {
    let buf = [1u8, 0, 8, 0, 0, 0, 0, 0];
    assert!(RadiotapHeader::parse(&buf).is_err());
}

#[test]
fn radiotap_rejects_truncated_length_field() {
    // length says 64 but only 12 bytes of buffer exist
    let buf = [0u8, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    assert!(RadiotapHeader::parse(&buf).is_err());
}

// ----- random noise --------------------------------------------------------

/// Pseudorandom bytes without pulling in rand at test time.
fn pseudo(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.push(state as u8);
    }
    out
}

#[test]
fn random_bytes_never_panic() {
    // Parse 10k short random buffers across a range of sizes. The
    // parser must always terminate with Ok or Err, never panic.
    for n in 0..10_000u64 {
        let len = (n % 300) as usize;
        let buf = pseudo(0x0BAD_F00D + n, len);
        // either outcome is fine, we just want no panic
        let _ = Dot11Frame::parse(&buf);
    }
}

#[test]
fn random_radiotap_never_panic() {
    for n in 0..5_000u64 {
        let len = (n % 256) as usize;
        let buf = pseudo(0xDEAD_BEEF + n, len);
        let _ = RadiotapHeader::parse(&buf);
    }
}

// ----- built + parsed -----------------------------------------------------

#[test]
fn every_builder_round_trips() {
    let bssid: MacAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
    let sta: MacAddr = "11:22:33:44:55:66".parse().unwrap();

    // Beacons carry bssid in addr2 (ToDS=0, FromDS=0 -> addr2=source).
    let beacon = build_beacon(bssid, "RoundTripSSID", 11, 100, true);
    let parsed = Dot11Frame::parse(&beacon).expect("beacon must parse");
    assert_eq!(parsed.addr2, bssid);

    // Probe requests carry the station MAC in addr2 because it's the
    // transmitter; the AP isn't involved yet.
    let probe = build_probe_request(sta, "RoundTripSSID");
    let parsed = Dot11Frame::parse(&probe).expect("probe must parse");
    assert_eq!(parsed.addr2, sta);

    // Deauth frames we build with the AP "kicking" the client: source
    // is the AP, so addr2 is the BSSID.
    let deauth = build_deauth(sta, bssid, bssid, ReasonCode::Unspecified);
    let parsed = Dot11Frame::parse(&deauth).expect("deauth must parse");
    assert_eq!(parsed.addr2, bssid);
    assert_eq!(parsed.addr1, sta);
}

#[test]
fn beacon_survives_every_channel_number() {
    let bssid: MacAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
    for ch in 1u8..=13 {
        let frame = build_beacon(bssid, "Scan", ch, 100, false);
        let parsed = Dot11Frame::parse(&frame).unwrap();
        let decoded = parsed.management_body().unwrap().decode();
        assert_eq!(decoded.channel, Some(ch as u16));
    }
}

#[test]
fn long_ssid_is_handled() {
    // The tag length field is 1 byte, so anything ≤ 255 is legal.
    let ssid: String = (0..200).map(|i| (b'A' + (i as u8 % 26)) as char).collect();
    let bssid: MacAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
    let frame = build_beacon(bssid, &ssid, 1, 100, false);
    let parsed = Dot11Frame::parse(&frame).unwrap();
    assert_eq!(parsed.management_body().unwrap().decode().ssid, Some(ssid));
}

#[test]
fn bssid_helper_matches_to_from_ds_bits() {
    let bssid: MacAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
    let frame = build_beacon(bssid, "BSSIDTest", 6, 100, false);
    let parsed = Dot11Frame::parse(&frame).unwrap();
    // Beacons are (ToDS=0, FromDS=0) so BSSID == addr3.
    assert_eq!(parsed.bssid(), parsed.addr3);
}

// ----- pcap file layer ----------------------------------------------------

#[test]
fn pcap_writer_round_trips_a_beacon() {
    let tmp = std::env::temp_dir().join("airscope_wifi_integ.pcap");
    let bssid: MacAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
    let beacon = build_beacon(bssid, "HelloPcap", 6, 100, false);

    {
        let mut w = PcapFileWriter::create(&tmp, LINKTYPE_IEEE802_11, 4096).expect("create pcap");
        w.write(&CapturedPacket { timestamp_micros: 123_456, data: beacon.clone() }).unwrap();
        w.flush().unwrap();
    }

    let mut r = PcapFileReader::open(&tmp).unwrap();
    let pkt = r.next_packet().unwrap().unwrap();
    assert_eq!(pkt.data, beacon);
    assert_eq!(pkt.timestamp_micros, 123_456);
    assert!(r.next_packet().unwrap().is_none());
    let _ = std::fs::remove_file(&tmp);
}
