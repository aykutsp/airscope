//! Throughput benchmarks for the 802.11 parser.
//!
//! Ran with `cargo bench -p airscope-wifi`. Results land under
//! `target/criterion/`, and the HTML report (`target/criterion/report/index.html`)
//! is what you want to diff between commits.
//!
//! Workload: a mix of beacons, probe requests, and deauth frames
//! mirroring a realistic capture. Every benchmark builds its input
//! once with the frame builder, then times only the parse path.

use airscope_core::MacAddr;
use airscope_wifi::builder::{build_beacon, build_deauth, build_probe_request, ReasonCode};
use airscope_wifi::frame::Dot11Frame;
use airscope_wifi::radiotap::RadiotapHeader;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion, Throughput};

fn corpus() -> Vec<Vec<u8>> {
    // 1000 frames alternating through the three shapes we care about.
    let mut out = Vec::with_capacity(1000);
    let bssid: MacAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
    let station: MacAddr = "11:22:33:44:55:66".parse().unwrap();
    for i in 0..1000u32 {
        match i % 3 {
            0 => out.push(build_beacon(bssid, "BenchmarkAP", 6, 100, false)),
            1 => out.push(build_probe_request(station, "BenchmarkAP")),
            _ => out.push(build_deauth(station, bssid, bssid, ReasonCode::Unspecified)),
        }
    }
    out
}

fn radiotap_corpus() -> Vec<Vec<u8>> {
    // Wrap every frame in a minimal 8-byte radiotap header so we
    // also measure the strip path (which is what live captures hit).
    corpus()
        .into_iter()
        .map(|f| {
            let mut out = Vec::with_capacity(f.len() + 8);
            out.extend_from_slice(&[0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
            out.extend_from_slice(&f);
            out
        })
        .collect()
}

fn bench_parse_beacon(c: &mut Criterion) {
    let bssid: MacAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
    let frame = build_beacon(bssid, "BenchmarkAP", 6, 100, false);
    let mut group = c.benchmark_group("parse/single");
    group.throughput(Throughput::Bytes(frame.len() as u64));
    group.bench_function("beacon", |b| {
        b.iter(|| {
            let f = Dot11Frame::parse(black_box(&frame)).unwrap();
            let _ = black_box(f.management_body().map(|m| m.decode()));
        });
    });
    group.finish();
}

fn bench_parse_mixed(c: &mut Criterion) {
    let frames = corpus();
    let total: usize = frames.iter().map(Vec::len).sum();
    let mut group = c.benchmark_group("parse/mixed");
    group.throughput(Throughput::Bytes(total as u64));
    group.bench_function("1k_frames", |b| {
        b.iter_batched(
            || &frames,
            |frames| {
                for raw in frames {
                    let _ = black_box(Dot11Frame::parse(black_box(raw)));
                }
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

fn bench_strip_radiotap(c: &mut Criterion) {
    let frames = radiotap_corpus();
    let total: usize = frames.iter().map(Vec::len).sum();
    let mut group = c.benchmark_group("parse/radiotap");
    group.throughput(Throughput::Bytes(total as u64));
    group.bench_function("strip+parse", |b| {
        b.iter_batched(
            || &frames,
            |frames| {
                for raw in frames {
                    let (_, n) = RadiotapHeader::parse(black_box(raw)).unwrap();
                    let _ = black_box(Dot11Frame::parse(black_box(&raw[n..])));
                }
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_parse_beacon, bench_parse_mixed, bench_strip_radiotap);
criterion_main!(benches);
