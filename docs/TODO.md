# things I still want to do

rough, unsorted, not a contract. marking items as I knock them out.

## done

- [x] A JSON output mode for headless airodump so it can feed dashboards.
- [x] Record the full pcap from the scanner when `--write` is passed.
- [x] Sample pcap generator checked in under `samples/` so the whole
      suite is demoable without a radio.

## still open

- [ ] Wire airodump channel-hopping (today we stay on whatever channel
      the interface is locked to).
- [ ] HT/VHT/HE IE decoding so the scanner can show 80 MHz / 160 MHz
      widths and MCS rates next to the rate column.
- [ ] BPF filter pre-compilation for airview so filter expressions
      beyond the kind enum work ("host <mac>", "wlan type data", ...).
- [ ] airbase: RSN IE injection for WPA2 honeypot mode (right now only
      open + privacy-bit beacons are built).
- [ ] A small `airscope bench` command that measures parsing throughput
      on a sample pcap so I can spot regressions.
- [ ] A proper man-page generated from the clap trees.
- [ ] Replace the tiny OUI table with an opt-in full lookup (download
      at first run, cache under `~/.cache/airscope`).
