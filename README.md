# `tracing-flat-json`

A simple [`tracing_subscriber::Layer`] emitting newline-delimited JSON, with
all event and span fields flattened onto the top level JSON object. Similar
to combining the [`json-subscriber`] options [`with_flattened_event`] and
[`with_top_level_flattened_span_list`], without the caveats about duplicate
fields noted in the documentation for those options.

[`tracing_subscriber::Layer`]: https://docs.rs/tracing-subscriber/0.3.20/tracing_subscriber/layer/trait.Layer.html
[`json-subscriber`]: https://crates.io/crates/json-subscriber
[`with_flattened_event`]: https://docs.rs/json-subscriber/0.2.6/json_subscriber/struct.JsonLayer.html#method.with_flattened_event
[`with_top_level_flattened_span_list`]: https://docs.rs/json-subscriber/0.2.6/json_subscriber/struct.JsonLayer.html#method.with_top_level_flattened_span_list

## Usage

```rust
use tracing_subscriber::prelude::*;

tracing_subscriber::Registry::default()
    .with(tracing_flat_json::FlatJsonLayer::new(std::io::stdout))
    .init();
```

## Feature Flags

- `tracing-log`: Handle [`log`] events emitted by [`tracing-log`]. Enabled
  by default.
- `tracing-opentelemetry`: Outputs the `trace_id` added to spans by
  [`tracing-opentelemetry`]. May not work when compiled with multiple
  versions of [`tracing-opentelemetry`] in the same executable.

[`log`]: https://crates.io/crates/log
[`tracing-log`]: https://crates.io/crates/tracing-log
[`tracing-opentelemetry`]: https://crates.io/crates/tracing-opentelemetry
