//! Verify nothing has gone horribly wrong with `tracing-flat-json`.

use criterion::{criterion_group, criterion_main, Criterion};
use tracing::{info, info_span};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn zero_field_spans() {
    let _g1 = info_span!("test span 1").entered();
    let _g2 = info_span!("test span 2").entered();
    let _g3 = info_span!("test span 3").entered();
    let _g4 = info_span!("test span 4").entered();
    info!("test event");
}

fn one_field_spans() {
    let _g1 = info_span!("test span 1", test_field_1 = "test value 1").entered();
    let _g2 = info_span!("test span 2", test_field_2 = "test value 2").entered();
    let _g3 = info_span!("test span 3", test_field_3 = "test value 3").entered();
    let _g4 = info_span!("test span 4", test_field_4 = "test value 4").entered();
    info!(event_field_1 = "event value 1", "test event");
}

#[rustfmt::skip]
fn two_field_spans() {
    let _g1 = info_span!("test span 1", test_field_1 = "test value 1", test_field_5 = "test value 5").entered();
    let _g2 = info_span!("test span 2", test_field_2 = "test value 2", test_field_6 = "test value 6").entered();
    let _g3 = info_span!("test span 3", test_field_3 = "test value 3", test_field_7 = "test value 7").entered();
    let _g3 = info_span!("test span 4", test_field_4 = "test value 4", test_field_8 = "test value 8").entered();
    info!(event_field_1 = "event value 1", event_field_2 = "event value 2", "test event");
}

pub fn flat_json(c: &mut Criterion) {
    let layer = tracing_flat_json::FlatJsonLayer::new(std::io::sink);
    let _g = tracing_subscriber::registry::Registry::default()
        .with(layer)
        .set_default();

    c.bench_function("other-crates: tracing-flat-json 0 fields", |b| {
        b.iter(zero_field_spans);
    });
    c.bench_function("other-crates: tracing-flat-json 1 field", |b| {
        b.iter(one_field_spans);
    });
    c.bench_function("other-crates: tracing-flat-json 2 fields", |b| {
        b.iter(two_field_spans);
    });
}
pub fn tracing_subscriber_full(c: &mut Criterion) {
    let layer = tracing_subscriber::fmt::layer()
        .with_timer(tracing_subscriber::fmt::time::time())
        .with_file(true)
        .with_level(true)
        .with_line_number(true)
        .with_ansi(false)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_writer(std::io::sink);
    let _g = tracing_subscriber::registry::Registry::default()
        .with(layer)
        .set_default();

    c.bench_function("other-crates: tracing-subscriber full 0 fields", |b| {
        b.iter(zero_field_spans);
    });
    c.bench_function("other-crates: tracing-subscriber full 1 field", |b| {
        b.iter(one_field_spans);
    });
    c.bench_function("other-crates: tracing-subscriber full 2 fields", |b| {
        b.iter(two_field_spans);
    });
}
pub fn tracing_subscriber_json(c: &mut Criterion) {
    let layer = tracing_subscriber::fmt::layer()
        .json()
        .with_timer(tracing_subscriber::fmt::time::time())
        .with_file(true)
        .with_level(true)
        .with_line_number(true)
        .with_ansi(false)
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .with_current_span(false)
        .with_writer(std::io::sink);
    let _g = tracing_subscriber::registry::Registry::default()
        .with(layer)
        .set_default();

    c.bench_function("other-crates: tracing-subscriber json 0 fields", |b| {
        b.iter(zero_field_spans);
    });
    c.bench_function("other-crates: tracing-subscriber json 1 field", |b| {
        b.iter(one_field_spans);
    });
    c.bench_function("other-crates: tracing-subscriber json 2 fields", |b| {
        b.iter(two_field_spans);
    });
}

pub fn json_subscriber(c: &mut Criterion) {
    let mut layer = json_subscriber::JsonLayer::new(std::io::sink);
    layer
        .with_timer("timestamp", tracing_subscriber::fmt::time::time())
        .with_level("level")
        .with_file("code.file.path")
        .with_line_number("code.line.number")
        .with_flattened_event()
        .with_top_level_flattened_span_list();
    let _g = tracing_subscriber::registry::Registry::default()
        .with(layer)
        .set_default();

    c.bench_function("other-crates: json-subscriber 0 fields", |b| {
        b.iter(zero_field_spans);
    });
    c.bench_function("other-crates: json-subscriber 1 field", |b| {
        b.iter(one_field_spans);
    });
    c.bench_function("other-crates: json-subscriber 2 fields", |b| {
        b.iter(two_field_spans);
    });
}

criterion_group!(
    benches,
    flat_json,
    tracing_subscriber_full,
    tracing_subscriber_json,
    json_subscriber
);
criterion_main!(benches);
