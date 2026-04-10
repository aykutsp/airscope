//! `cargo run -p airscope-wifi --example make_sample`
//!
//! Writes `samples/demo-01.pcap`: a tiny deterministic capture that
//! mixes beacons from a few fake APs, a deauth, and some probe
//! requests. The file is checked in so `airview` and `airodump --read`
//! can demo themselves without a radio.

use airscope_core::MacAddr;
use airscope_wifi::builder::{build_beacon, build_deauth, build_probe_request, ReasonCode};
use airscope_wifi::capture::{CapturedPacket, PcapFileWriter, LINKTYPE_IEEE802_11};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "samples/demo-01.pcap".to_string());

    let mut w = PcapFileWriter::create(&out_path, LINKTYPE_IEEE802_11, 4096)
        .map_err(|e| e.to_string())?;

    // Four synthetic APs on channel 6.
    let aps: &[(&str, &str)] = &[
        ("AA:11:22:33:44:55", "home-network"),
        ("BB:22:33:44:55:66", "CoffeeShop_5G"),
        ("CC:33:44:55:66:77", "IoT-Hub"),
        ("DD:44:55:66:77:88", "hidden"),
    ];

    let mut ts = 1_712_758_800_000_000i64; // fixed wallclock, matches timezone-independent tests

    for round in 0..3 {
        for (bssid_s, ssid) in aps {
            let bssid: MacAddr = bssid_s.parse()?;
            // Hidden SSIDs carry an empty SSID element in reality.
            let effective_ssid = if *ssid == "hidden" { "" } else { *ssid };
            let frame = build_beacon(bssid, effective_ssid, 6, 100, round == 2 && *ssid == "home-network");
            w.write(&CapturedPacket { timestamp_micros: ts, data: frame })
                .map_err(|e| e.to_string())?;
            ts += 102_400; // one beacon interval
        }

        // A station probes for the coffee shop.
        let sta: MacAddr = "11:22:33:aa:bb:cc".parse()?;
        let probe = build_probe_request(sta, "CoffeeShop_5G");
        w.write(&CapturedPacket { timestamp_micros: ts, data: probe })
            .map_err(|e| e.to_string())?;
        ts += 50_000;
    }

    // And one deauth from the home AP to broadcast - the kind of frame
    // you'd see during a channel switch or a rogue jam.
    let home: MacAddr = "AA:11:22:33:44:55".parse()?;
    let deauth = build_deauth(MacAddr::BROADCAST, home, home, ReasonCode::PrevAuthNotValid);
    w.write(&CapturedPacket { timestamp_micros: ts, data: deauth })
        .map_err(|e| e.to_string())?;

    w.flush().map_err(|e| e.to_string())?;
    eprintln!("wrote {out_path}");
    Ok(())
}
