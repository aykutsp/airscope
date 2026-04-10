# sample pcaps

Shipped capture files used for demos, docs, and a few integration tests.

| file                  | what's in it                                          |
|-----------------------|-------------------------------------------------------|
| `demo-01.pcap`        | 12 beacons across 4 synthetic APs on channel 6        |
| `demo-01.log`         | one-line description of how it was generated         |

The synthetic files are produced by the `wifi::builder` module in the
`airscope-wifi` crate. They're deterministic, so running `cargo test`
and running `airview samples/demo-01.pcap` should always agree.

If you have a real monitor-mode radio, you can replace these with a
real capture:

```bash
airodump -i wlan0mon --write samples/live.pcap
```

(write support is on the TODO list - today you can use `tcpdump -w` to
record and then point airodump at the pcap with `-r`).
