use tracing::{info, info_span};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

fn main() {
    let mut layer = json_subscriber::JsonLayer::new(std::io::stdout);
    layer
        .with_flattened_event()
        .with_top_level_flattened_span_list();
    let _dispatch = tracing_subscriber::registry::Registry::default()
        .with(layer)
        .set_default();

    info!(
        name: "event1",
        dup_field = "event1 value",
        event1_field = "event1 value",
        "message for event1"
    );

    let span1 = info_span!(
        target: "span1",
        "span1",
        dup_field = "span1 value",
        span1_field = "span1 value"
    );
    let _g1 = span1.enter();

    // dup_field will be emitted 2 times, json-subscriber doesn't dedup fields
    // between events and spans at the top level.
    info!(
        name: "event2",
        dup_field = "event2 value",
        event2_field = "event2 value",
        "message for event2"
    );

    let span2 = info_span!(
        target: "span2",
        "span1",
        dup_field = "span2 value",
        span2_field = "span2 value"
    );
    let _g2 = span2.enter();

    // dup_field will be emitted 2 times, json-subscriber merges fields from
    // parent spans, keeping furthest from root.
    info!(
        name: "event3",
        dup_field = "event3 value",
        event3_field = "event3 value",
        "message for event3"
    );
}
