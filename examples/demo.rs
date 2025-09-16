use tracing::{info, info_span};
use tracing_flat_json::FlatJsonLayer;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

fn main() {
    tracing_subscriber::Registry::default()
        .with(FlatJsonLayer::new(std::io::stdout).with_filter(LevelFilter::DEBUG))
        .init();
    info!("tracing initialized");

    // Demonstrate external crate output.
    let _ = ureq::get("https://google.com").call();

    // Demonstrate span behavior.
    info!(first_event_field = 1, "no spans");
    let g1 = info_span!("first span", first_span_field = 1, dup_field = 1).entered();
    info!(second_event_field = 2, "one span");
    let g2 = info_span!("second span", second_span_field = 2, dup_field = 2).entered();
    info!(third_event_field = 3, "two spans");
    let g3 = info_span!("third span", third_span_field = 3, dup_field = 3).entered();
    info!(fourth_event_field = 4, "three spans");
    info!(dup_field = 4, "dup field");
    drop(g3);
    info!("two spans");
    drop(g2);
    info!("one span");
    drop(g1);
    info!("no spans");
}
