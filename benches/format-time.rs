//! Check if `tracing_subscriber`'s built in datetime formatting implementation,
//! is faster or slower than `time`.

#![expect(deprecated, reason = "criterion::black_box, std version not in MSRV")]

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use time::format_description::well_known::Rfc3339;
use time::UtcDateTime;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};

const MAX_TIME_LEN: usize = "0000-00-00T00:00:00.000000000Z".len();

#[expect(clippy::missing_panics_doc)]
pub fn format_time(c: &mut Criterion) {
    c.bench_function("format-time: tracing-subscriber SystemTime", |b| {
        b.iter(|| {
            let mut ts = String::with_capacity(MAX_TIME_LEN);
            SystemTime.format_time(&mut Writer::new(&mut ts)).unwrap();
            black_box(ts.as_str());
        });
    });

    c.bench_function("format-time: time::UtcDateTime format", |b| {
        b.iter(|| {
            let now = UtcDateTime::now();
            let ts = now.format(&Rfc3339).unwrap();
            black_box(ts.as_str());
        });
    });

    c.bench_function("format-time: time::UtcDateTime format_into", |b| {
        b.iter(|| {
            let mut ts = Vec::with_capacity(MAX_TIME_LEN);
            let now = UtcDateTime::now();
            now.format_into(&mut ts, &Rfc3339).unwrap();
            let ts = String::from_utf8(ts).unwrap();
            black_box(ts.as_str());
        });
    });

    c.bench_function("format-time: time::UtcDateTime format_into unsafe", |b| {
        b.iter(|| {
            let mut ts = Vec::with_capacity(MAX_TIME_LEN);
            let now = UtcDateTime::now();
            now.format_into(&mut ts, &Rfc3339).unwrap();
            let ts = unsafe { String::from_utf8_unchecked(ts) };
            black_box(ts.as_str());
        });
    });

    c.bench_function("format-time: time::UtcDateTime format_into array", |b| {
        b.iter(|| {
            let mut ts_buf = [0u8; MAX_TIME_LEN];
            let mut ts_cursor = &mut ts_buf[..];
            let now = UtcDateTime::now();
            now.format_into(&mut ts_cursor, &Rfc3339).unwrap();
            let ts_len = MAX_TIME_LEN - ts_cursor.len();
            let ts = unsafe { std::str::from_utf8_unchecked(&ts_buf[..ts_len]) };
            black_box(ts);
        });
    });
}

criterion_group!(benches, format_time);
criterion_main!(benches);
