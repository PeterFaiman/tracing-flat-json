//! A simple [`tracing_subscriber::Layer`] emitting newline-delimited JSON, with
//! all event and span fields flattened onto the top level JSON object. Similar
//! to combining the [`json-subscriber`] options [`with_flattened_event`] and
//! [`with_top_level_flattened_span_list`], without the caveats about duplicate
//! fields noted in the documentation for those options.
//!
//! [`tracing_subscriber::Layer`]: https://docs.rs/tracing-subscriber/0.3.20/tracing_subscriber/layer/trait.Layer.html
//! [`json-subscriber`]: https://crates.io/crates/json-subscriber
//! [`with_flattened_event`]: https://docs.rs/json-subscriber/0.2.6/json_subscriber/struct.JsonLayer.html#method.with_flattened_event
//! [`with_top_level_flattened_span_list`]: https://docs.rs/json-subscriber/0.2.6/json_subscriber/struct.JsonLayer.html#method.with_top_level_flattened_span_list
//!
//! ## Usage
//!
//! ```rust
//! use tracing_subscriber::prelude::*;
//!
//! tracing_subscriber::Registry::default()
//!     .with(tracing_flat_json::FlatJsonLayer::new(std::io::stdout))
//!     .init();
//! ```
//!
//! ## Feature Flags
//!
//! - `tracing-log`: Handle [`log`] events emitted by [`tracing-log`]. Enabled
//!   by default.
//! - `tracing-opentelemetry`: Outputs the `trace_id` added to spans by
//!   [`tracing-opentelemetry`]. May not work when compiled with multiple
//!   versions of [`tracing-opentelemetry`] in the same executable.
//!
//! [`log`]: https://crates.io/crates/log
//! [`tracing-log`]: https://crates.io/crates/tracing-log
//! [`tracing-opentelemetry`]: https://crates.io/crates/tracing-opentelemetry

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::Debug;
use std::io::Write;
use std::marker::PhantomData;

use serde::ser::{SerializeMap, Serializer};
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::UtcDateTime;
use tracing::field::Field;
use tracing::span::{Attributes, Record};
use tracing::{Event, Id, Subscriber};
use tracing_core::field::Visit;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

trait SerializationInfallibleExt<T> {
    fn expect_serialization_infallible(self) -> T;
}
impl<T, E> SerializationInfallibleExt<T> for Result<T, E>
where
    E: Debug,
{
    #[inline]
    fn expect_serialization_infallible(self: Result<T, E>) -> T {
        self.expect("serialization to buffer should never fail")
    }
}

// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/MAX_SAFE_INTEGER
const MAX_SAFE_INTEGER: i64 = (1i64 << 53) - 1;
const MIN_SAFE_INTEGER: i64 = -MAX_SAFE_INTEGER;

// Casts an integer to i64 if JavaScript / JSON can precisely represent it.
trait TryIntoSafeInteger
where
    Self: itoa::Integer,
{
    fn try_into_safe_integer(self) -> Option<i64>;
}

impl TryIntoSafeInteger for i64 {
    #[inline]
    fn try_into_safe_integer(self) -> Option<i64> {
        #[allow(clippy::manual_range_contains)]
        if self <= MAX_SAFE_INTEGER && self >= MIN_SAFE_INTEGER {
            Some(self)
        } else {
            None
        }
    }
}

impl TryIntoSafeInteger for u64 {
    #[inline]
    fn try_into_safe_integer(self) -> Option<i64> {
        if self <= MAX_SAFE_INTEGER as u64 {
            #[expect(clippy::cast_possible_wrap, reason = "explicitly checked")]
            Some(self as i64)
        } else {
            None
        }
    }
}

impl TryIntoSafeInteger for i128 {
    #[inline]
    fn try_into_safe_integer(self) -> Option<i64> {
        if self <= i128::from(MAX_SAFE_INTEGER) && self >= i128::from(MIN_SAFE_INTEGER) {
            #[expect(clippy::cast_possible_truncation, reason = "explicitly checked")]
            Some(self as i64)
        } else {
            None
        }
    }
}

impl TryIntoSafeInteger for u128 {
    #[inline]
    fn try_into_safe_integer(self) -> Option<i64> {
        if self <= MAX_SAFE_INTEGER as u128 {
            #[expect(clippy::cast_possible_truncation, reason = "explicitly checked")]
            Some(self as i64)
        } else {
            None
        }
    }
}

// This tomfoolery allows using the same Visit implementation for event fields
// and span fields. They only differ in how they are recorded. Events write to
// the JSON serializer directly, as there's no need to store values. Spans write
// to a map, as the values must be stored until an event occurs, and may be used
// multiple times for multiple events.
trait FlatJsonRecorder {
    fn record_value<T>(&mut self, field: &Field, value: T)
    where
        T: Serialize + Into<serde_json::Value>;

    // Many JSON parsers treat all numbers as floats. Serialize int types as
    // strings if they're not exactly representable as 64-bit floats. For log
    // purposes, all fields will eventually be displayed as strings anyway, so
    // changing the field type should be harmless.
    #[inline]
    fn record_int(&mut self, field: &Field, value: impl TryIntoSafeInteger) {
        if let Some(i) = value.try_into_safe_integer() {
            self.record_value(field, i);
        } else {
            let mut b = itoa::Buffer::new();
            let s = b.format(value);
            self.record_value(field, s);
        }
    }
}

// Unlikely serde_json will ever change the default formatter, but 1 object per
// line is a hard requirement for logging, so it's good to specify.
type OutputSerializer = serde_json::Serializer<Vec<u8>, serde_json::ser::CompactFormatter>;

// Recorder for events, serializing event fields directly to the output buffer.
struct FlatJsonEventRecorder<'state: 'state_borrow, 'state_borrow> {
    json_out: &'state_borrow mut <&'state mut OutputSerializer as Serializer>::SerializeMap,
    seen_fields: &'state_borrow mut HashSet<&'static str>,
}

impl FlatJsonRecorder for FlatJsonEventRecorder<'_, '_> {
    #[inline]
    fn record_value<T>(&mut self, field: &Field, value: T)
    where
        T: Serialize + Into<serde_json::Value>,
    {
        if self.seen_fields.insert(field.name()) {
            self.json_out
                .serialize_entry(field.name(), &value)
                .expect_serialization_infallible();
        }
    }
}

// Recorder for spans, storing spans fields in a map to serialize later. Unlike
// events, span fields are not guaranteed to be recorded in order, and could be
// recorded more than once, so a map is necessary.
struct FlatJsonSpanRecorder<'a>(&'a mut HashMap<&'static str, serde_json::Value>);

impl FlatJsonRecorder for FlatJsonSpanRecorder<'_> {
    #[inline]
    fn record_value<T>(&mut self, field: &Field, value: T)
    where
        T: Serialize + Into<serde_json::Value>,
    {
        self.0.insert(field.name(), value.into());
    }
}

// Common Visit impl, delegating to either the event or span recorder.
#[repr(transparent)]
struct FlatJsonVisitor<T: FlatJsonRecorder>(T);

impl<T: FlatJsonRecorder> Visit for FlatJsonVisitor<T> {
    #[inline]
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.record_value(field, value);
    }
    #[inline]
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.record_int(field, value);
    }
    #[inline]
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.record_int(field, value);
    }
    #[inline]
    fn record_i128(&mut self, field: &Field, value: i128) {
        self.0.record_int(field, value);
    }
    #[inline]
    fn record_u128(&mut self, field: &Field, value: u128) {
        self.0.record_int(field, value);
    }
    #[inline]
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.record_value(field, value);
    }
    #[inline]
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.record_value(field, value);
    }
    #[inline]
    fn record_bytes(&mut self, field: &Field, value: &[u8]) {
        // Assume raw binary data logged is mostly human readable.
        self.0.record_value(field, value.escape_ascii().to_string());
    }
    #[inline]
    fn record_error(&mut self, field: &Field, value: &(dyn Error + 'static)) {
        // Use alternate format to include context chain for anyhow::Error.
        self.0.record_value(field, format!("{value:#}"));
    }
    #[inline]
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        self.0.record_value(field, format!("{value:?}"));
    }
}

// Only needs to record the "message" field added by tracing-log. The only other
// fields are created by tracing-log to save metadata, and efficiently exposed
// by tracing-log via tracing_log::NormalizeEvent.
#[cfg(feature = "tracing-log")]
struct TracingLogVisitor<'state: 'state_borrow, 'state_borrow> {
    json_out: &'state_borrow mut <&'state mut OutputSerializer as Serializer>::SerializeMap,
    seen_fields: &'state_borrow mut HashSet<&'static str>,
}

#[cfg(feature = "tracing-log")]
impl Visit for TracingLogVisitor<'_, '_> {
    #[inline]
    fn record_f64(&mut self, field: &Field, _value: f64) {
        debug_assert!(false, "{}", field.name());
    }
    #[inline]
    fn record_i64(&mut self, field: &Field, _value: i64) {
        debug_assert!(false, "{}", field.name());
    }
    #[inline]
    fn record_u64(&mut self, field: &Field, _value: u64) {
        debug_assert_eq!(field.name(), "log.line");
    }
    #[inline]
    fn record_i128(&mut self, field: &Field, _value: i128) {
        debug_assert!(false, "{}", field.name());
    }
    #[inline]
    fn record_u128(&mut self, field: &Field, _value: u128) {
        debug_assert!(false, "{}", field.name());
    }
    #[inline]
    fn record_bool(&mut self, field: &Field, _value: bool) {
        debug_assert!(false, "{}", field.name());
    }
    #[inline]
    fn record_str(&mut self, field: &Field, _value: &str) {
        let n = field.name();
        debug_assert!(
            n == "log.target" || n == "log.module_path" || n == "log.file",
            "{n}"
        );
    }
    #[inline]
    fn record_bytes(&mut self, field: &Field, _value: &[u8]) {
        debug_assert!(false, "{}", field.name());
    }
    #[inline]
    fn record_error(&mut self, field: &Field, _value: &(dyn Error + 'static)) {
        debug_assert!(false, "{}", field.name());
    }
    #[inline]
    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        const MESSAGE: &str = "message";
        debug_assert_eq!(field.name(), MESSAGE);
        if field.name() == MESSAGE {
            let is_new = self.seen_fields.insert(MESSAGE);
            debug_assert!(is_new);
            self.json_out
                .serialize_entry(MESSAGE, &format!("{value:?}"))
                .expect_serialization_infallible();
        }
    }
}

/// See the [module-level documentation](crate) for usage.
pub struct FlatJsonLayer<S, W>
where
    W: for<'writer> MakeWriter<'writer> + 'static,
{
    make_writer: W,
    _inner: PhantomData<fn(S)>,
}

impl<S, W> FlatJsonLayer<S, W>
where
    W: for<'writer> MakeWriter<'writer> + 'static,
{
    /// Returns a new [`FlatJsonLayer`] using the provided [`MakeWriter`] to
    /// write events.
    #[inline]
    pub fn new(make_writer: W) -> Self {
        Self {
            make_writer,
            _inner: PhantomData,
        }
    }
}

// Span extension for storing span fields until they're used emitting events.
struct FlatJsonSpanData(HashMap<&'static str, serde_json::Value>);

impl<S, W> Layer<S> for FlatJsonLayer<S, W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + 'static,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if attrs.fields().is_empty() {
            return;
        }
        let span = ctx
            .span(id)
            .expect("span not found, this is a subscriber bug");
        let mut extensions = span.extensions_mut();
        let mut json_map = HashMap::with_capacity(attrs.fields().len());
        attrs.record(&mut FlatJsonVisitor(FlatJsonSpanRecorder(&mut json_map)));
        extensions.insert(FlatJsonSpanData(json_map));
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, ctx: Context<'_, S>) {
        let span = ctx
            .span(id)
            .expect("span not found, this is a subscriber bug");
        let mut extensions = span.extensions_mut();
        // This layer's on_new_span callback always inserts an extension if the
        // span has any fields, and spans cannot have fields recorded at all if
        // no fields were initially declared.
        let FlatJsonSpanData(json_map) = extensions
            .get_mut::<FlatJsonSpanData>()
            .expect("tracing-flat-json span extension not found, this is a bug");
        values.record(&mut FlatJsonVisitor(FlatJsonSpanRecorder(json_map)));
    }

    #[expect(clippy::too_many_lines)]
    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        // The time crate always uses Z for UTC, and will output 9 digits of
        // nanoseconds without rounding if that resolution is available.
        // https://github.com/time-rs/time/blob/v0.3.44/time/src/formatting/formattable.rs#L236-L275
        const MAX_TIME_LEN: usize = "0000-00-00T00:00:00.000000000Z".len();
        let mut ts_buf = [0u8; MAX_TIME_LEN];
        let mut ts_cursor = &mut ts_buf[..];
        UtcDateTime::now()
            .format_into(&mut ts_cursor, &Rfc3339)
            .expect("formatting current UTC time should never fail");
        let ts_len = MAX_TIME_LEN - ts_cursor.len();
        // SAFETY: In the inconceivable case that time formats a timestamp as
        // non-utf8, it's better to output non-utf8 than crash or log nothing.
        let ts = unsafe { std::str::from_utf8_unchecked(&ts_buf[..ts_len]) };

        let mut serializer: OutputSerializer =
            serde_json::Serializer::new(Vec::with_capacity(1024));
        // serde_json only uses the size hint when it's 0, for empty maps.
        let mut json_out = serializer
            .serialize_map(None)
            .expect_serialization_infallible();

        #[cfg(feature = "tracing-log")]
        let log_metadata = {
            use tracing_log::NormalizeEvent;
            event.normalized_metadata()
        };
        #[cfg(feature = "tracing-log")]
        let metadata = match &log_metadata {
            Some(metadata) => metadata,
            None => event.metadata(),
        };
        #[cfg(not(feature = "tracing-log"))]
        let log_metadata: Option<()> = None;
        #[cfg(not(feature = "tracing-log"))]
        let metadata = event.metadata();

        // timestamp + level + file + line + fields.
        let total_event_fields = 4 + metadata.fields().len();
        // trace_id.
        #[cfg(feature = "tracing-opentelemetry")]
        let total_event_fields = total_event_fields + 1;

        // Avoid outputting the same JSON key twice. +4 bumps a small bucket
        // count up to the next size class, saving a realloc when parent spans
        // have fields. Nets a 7-10% speedup in single threaded microbenchmarks,
        // but mostly it just makes me feel better.
        let mut seen_fields = HashSet::with_capacity(total_event_fields + 4);
        macro_rules! serialize_entry {
            ($k:literal, $v: expr) => {
                let is_new = seen_fields.insert($k);
                debug_assert!(is_new, "{}", $k);
                json_out
                    .serialize_entry($k, $v)
                    .expect_serialization_infallible();
            };
        }

        // Write timestamp, level, and code location first, like text loggers
        // typically do (including tracing-subscriber), making the logs easier
        // to read when looking at the raw JSON output.
        serialize_entry!("timestamp", &ts);
        serialize_entry!("level", metadata.level().as_str());

        // Output trace_id before code location, since it has consistent width.
        #[cfg(feature = "tracing-opentelemetry")]
        {
            use opentelemetry::trace::{TraceContextExt, TraceId};
            use tracing_opentelemetry::OtelData;

            if let Some(span) = ctx.event_span(event) {
                if let Some(otel_data) = span.extensions().get::<OtelData>() {
                    let mut trace_id = otel_data.parent_cx.span().span_context().trace_id();

                    // This event's parent span is a root span, with no parent
                    // context explicitly set. If this span closes without a
                    // parent context, it will use this trace_id. A parent may
                    // be set after an event is emitted, making this trace_id
                    // meaningless, but that future trace_id cannot be known
                    // from here. Child spans have the same problem, i.e. they
                    // also inherit this trace_id when created before setting a
                    // parent context.
                    // See also: tracing_opentelemetry::PreSampledTracer.
                    if trace_id == TraceId::INVALID {
                        if let Some(builder_trace_id) = otel_data.builder.trace_id {
                            trace_id = builder_trace_id;
                        }
                    }

                    // I don't think it's possible to have an invalid trace_id
                    // at this point. If there's a parent span, and that span
                    // has OtelData, it should have either a parent context or
                    // a builder trace_id, even when not sampled.
                    debug_assert_ne!(trace_id, TraceId::INVALID);
                    serialize_entry!("trace_id", &format!("{trace_id}"));
                }
            }
        }

        // Use names from opentelemetry semantic conventions.
        if let Some(file) = metadata.file() {
            serialize_entry!("code.file.path", file);
        }
        if let Some(line) = metadata.line() {
            serialize_entry!("code.line.number", &line);
        }

        // Serialize the event before spans, then spans from nearest to root,
        // putting the most specific information first. This is purely a matter
        // of taste, tracing-subscriber's text format does the opposite, i.e. it
        // outputs spans in hierarchical order.
        if log_metadata.is_some() {
            #[cfg(feature = "tracing-log")]
            event.record(&mut TracingLogVisitor {
                json_out: &mut json_out,
                seen_fields: &mut seen_fields,
            });
            #[cfg(not(feature = "tracing-log"))]
            unreachable!();
        } else {
            event.record(&mut FlatJsonVisitor(FlatJsonEventRecorder {
                json_out: &mut json_out,
                seen_fields: &mut seen_fields,
            }));
        }
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope {
                // Spans have no extension if the span has no fields.
                if let Some(FlatJsonSpanData(json_map)) = span.extensions().get() {
                    // Output fields in the order they appeared on the span.
                    for field in span.fields() {
                        let k = field.name();
                        // Fields initialized as tracing::field::Empty and never
                        // given a value will not be in the map.
                        if let Some(v) = json_map.get(k) {
                            // Only serialize each field once.
                            if seen_fields.insert(k) {
                                json_out
                                    .serialize_entry(k, v)
                                    .expect_serialization_infallible();
                            }
                        }
                    }
                }
            }
        }

        json_out.end().expect_serialization_infallible();
        let mut buf = serializer.into_inner();
        buf.push(b'\n');

        if let Err(e) = self.make_writer.make_writer_for(metadata).write_all(&buf) {
            // Avoid spamming stderr when the output is a closed pipe, as that
            // often happens for benign reasons, e.g. piping stdout to head.
            if e.kind() != std::io::ErrorKind::BrokenPipe {
                eprintln!("[tracing-flat-json] write error: {e:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tracing::dispatcher::DefaultGuard;
    use tracing::{debug, error, info, info_span, warn};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::registry::SpanData;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::Registry;

    use super::*;

    #[derive(Clone, Default)]
    struct MockWriter(Arc<Mutex<Vec<u8>>>);

    impl Write for MockWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            // Tests are all single-threaded.
            self.0.try_lock().unwrap().write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            // Tests are all single-threaded.
            self.0.try_lock().unwrap().flush()
        }
    }

    impl MockWriter {
        fn read_json(&self) -> serde_json::Value {
            let mut buf = self.0.try_lock().unwrap();
            let json = serde_json::from_slice(&buf).unwrap();
            buf.clear();
            json
        }
        fn read_string(&self) -> String {
            let mut buf = self.0.try_lock().unwrap();
            let vec = std::mem::take(&mut *buf);
            String::from_utf8(vec).unwrap()
        }
    }

    fn mock_subscriber() -> (DefaultGuard, MockWriter) {
        let writer = MockWriter::default();
        let make_writer = move || writer.clone();
        let return_writer = make_writer();

        #[cfg(feature = "tracing-opentelemetry")]
        let subscriber = {
            use opentelemetry::trace::TracerProvider;
            let exporter = opentelemetry_stdout::SpanExporter::default();
            let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_simple_exporter(exporter)
                .build();
            let tracer = provider.tracer(env!("CARGO_PKG_NAME"));
            let layer = tracing_opentelemetry::layer().with_tracer(tracer);
            Registry::default().with(layer)
        };

        #[cfg(not(feature = "tracing-opentelemetry"))]
        let subscriber = Registry::default();

        let subscriber = subscriber.with(FlatJsonLayer::new(make_writer));
        (subscriber.set_default(), return_writer)
    }

    macro_rules! pline {
        ($n:literal) => {
            i64::from(line!()) - $n
        };
    }

    #[test]
    fn field_values() {
        let (_dispatch, writer) = mock_subscriber();

        info!("test message");
        let json = writer.read_json();
        println!("{json}");
        assert!(json["timestamp"].as_str().unwrap().ends_with('Z'));
        assert_eq!(json["level"].as_str().unwrap(), "INFO");
        assert_eq!(json["code.file.path"].as_str().unwrap(), "src/lib.rs");
        assert_eq!(json["code.line.number"].as_i64().unwrap(), pline!(6));
        assert_eq!(json["message"].as_str().unwrap(), "test message");
        assert_eq!(json.as_object().unwrap().len(), 5);

        warn!(a = 1, b = "two", "test fields");
        let json = writer.read_json();
        println!("{json}");
        assert!(json["timestamp"].as_str().unwrap().ends_with('Z'));
        assert_eq!(json["level"].as_str().unwrap(), "WARN");
        assert_eq!(json["code.file.path"].as_str().unwrap(), "src/lib.rs");
        assert_eq!(json["code.line.number"].as_i64().unwrap(), pline!(6));
        assert_eq!(json["message"].as_str().unwrap(), "test fields");
        assert_eq!(json["a"].as_i64().unwrap(), 1);
        assert_eq!(json["b"].as_str().unwrap(), "two");
        assert_eq!(json.as_object().unwrap().len(), 7);

        // trace_id
        #[cfg(feature = "tracing-opentelemetry")]
        let extra_fields = 1;
        #[cfg(not(feature = "tracing-opentelemetry"))]
        let extra_fields = 0;

        let span1 = info_span!("span1", c = "three");
        let _g1 = span1.enter();
        error!("test span1");
        let json = writer.read_json();
        println!("{json}");
        assert!(json["timestamp"].as_str().unwrap().ends_with('Z'));
        assert_eq!(json["level"].as_str().unwrap(), "ERROR");
        assert_eq!(json["code.file.path"].as_str().unwrap(), "src/lib.rs");
        assert_eq!(json["code.line.number"].as_i64().unwrap(), pline!(6));
        #[cfg(feature = "tracing-opentelemetry")]
        assert_eq!(json["trace_id"].as_str().unwrap().len(), 32);
        assert_eq!(json["message"].as_str().unwrap(), "test span1");
        assert_eq!(json["c"].as_str().unwrap(), "three");
        assert_eq!(json.as_object().unwrap().len(), 6 + extra_fields);

        let span2 = info_span!("span2", d = 4.0);
        let _g2 = span2.enter();
        debug!("test span2");
        let json = writer.read_json();
        println!("{json}");
        assert!(json["timestamp"].as_str().unwrap().ends_with('Z'));
        assert_eq!(json["level"].as_str().unwrap(), "DEBUG");
        assert_eq!(json["code.file.path"].as_str().unwrap(), "src/lib.rs");
        assert_eq!(json["code.line.number"].as_i64().unwrap(), pline!(6));
        #[cfg(feature = "tracing-opentelemetry")]
        assert_eq!(json["trace_id"].as_str().unwrap().len(), 32);
        assert_eq!(json["message"].as_str().unwrap(), "test span2");
        assert_eq!(json["c"].as_str().unwrap(), "three");
        assert_eq!(json["d"].as_f64().unwrap(), 4.0);
        assert_eq!(json.as_object().unwrap().len(), 7 + extra_fields);
    }

    #[test]
    fn no_dup_fields() {
        let (_dispatch, writer) = mock_subscriber();

        // Baseline, there is obviously no duplicate field here.
        let span1 = info_span!("span1", f = "a");
        let _g1 = span1.enter();
        info!("e");
        let s = writer.read_string();
        println!("{s}");
        let json: serde_json::Value = serde_json::from_str(&s).unwrap();
        println!("{json}");
        assert_eq!(json["f"].as_str().unwrap(), "a");
        let f_count = s.split(',').filter(|s| s.starts_with("\"f\":")).count();
        assert_eq!(f_count, 1);

        // Duplicated "f", latest span should take precedent.
        let span2 = info_span!("span2", f = "b");
        let _g2 = span2.enter();
        info!("e");
        let s = writer.read_string();
        println!("{s}");
        let json: serde_json::Value = serde_json::from_str(&s).unwrap();
        println!("{json}");
        assert_eq!(json["f"].as_str().unwrap(), "b");
        let f_count = s.split(',').filter(|s| s.starts_with("\"f\":")).count();
        assert_eq!(f_count, 1);

        // Duplicated "f", event should take precedent.
        info!(f = "c");
        let s = writer.read_string();
        println!("{s}");
        let json: serde_json::Value = serde_json::from_str(&s).unwrap();
        println!("{json}");
        assert_eq!(json["f"].as_str().unwrap(), "c");
        let f_count = s.split(',').filter(|s| s.starts_with("\"f\":")).count();
        assert_eq!(f_count, 1);
    }

    #[test]
    fn record_fields() {
        let (_dispatch, writer) = mock_subscriber();

        let span = info_span!(
            "span",
            f1 = tracing::field::Empty,
            f2 = "a",
            f3 = tracing::field::Empty
        );
        let _g = span.enter();

        // Baseline, "f1" and "f3" should have no value.
        info!("e");
        let s = writer.read_string();
        println!("{s}");
        let json: serde_json::Value = serde_json::from_str(&s).unwrap();
        println!("{json}");
        assert_eq!(json["f1"], serde_json::Value::Null);
        assert_eq!(json["f2"].as_str().unwrap(), "a");
        assert_eq!(json["f3"], serde_json::Value::Null);

        // Record new value to "f1".
        span.record("f1", "b");
        info!("e");
        let s = writer.read_string();
        println!("{s}");
        let json: serde_json::Value = serde_json::from_str(&s).unwrap();
        println!("{json}");
        assert_eq!(json["f1"].as_str().unwrap(), "b");
        assert_eq!(json["f2"].as_str().unwrap(), "a");
        assert_eq!(json["f3"], serde_json::Value::Null);

        // Re-record new value to "f1", and ensure last value wins, as duplicate
        // keys in the output would be invalid JSON.
        // Interestingly, tracing-opentelemetry doesn't seem to prevent this,
        // generating spans with duplicate attributes, even though the otel spec
        // says last value wins.
        span.record("f1", "c");
        span.record("f4", "invalid, not initially declared");
        info!("e");
        let s = writer.read_string();
        println!("{s}");
        let json: serde_json::Value = serde_json::from_str(&s).unwrap();
        println!("{json}");
        assert_eq!(json["f1"].as_str().unwrap(), "c");
        assert_eq!(json["f2"].as_str().unwrap(), "a");
        assert_eq!(json["f3"], serde_json::Value::Null);
        assert_eq!(json["f4"], serde_json::Value::Null);

        // Setting f1 twice should not result in more than 1 output.
        let f1_count = s.split(',').filter(|s| s.starts_with("\"f1\":")).count();
        assert_eq!(f1_count, 1);

        // f1 set after f2, but should still be first in output.
        assert!(s.contains(r#""f1":"c","f2":"a""#));
    }

    #[test]
    fn no_extension() {
        let (_dispatch, writer) = mock_subscriber();

        let span = info_span!("span2");
        let _g = span.enter();

        // A span with no initially declared fields should not have an extension
        // inserted by FlatJsonLayer.
        span.with_subscriber(|(id, subscriber)| {
            let registry = subscriber.downcast_ref::<Registry>().unwrap();
            let span_data = registry.span_data(id).unwrap();
            assert!(span_data.extensions().get::<FlatJsonSpanData>().is_none());
        });

        // Recording fields with no extension shouldn't crash when the span had
        // no initial fields.
        span.record("f", 1);
        info!("e");
        let json = writer.read_json();
        println!("{json}");
        assert_eq!(json["f"], serde_json::Value::Null);
    }

    #[test]
    fn field_order() {
        let (_dispatch, writer) = mock_subscriber();

        let span1 = info_span!("span1", b = "b", c = "c");
        let _g1 = span1.enter();
        let span2 = info_span!("span2", d = "d", a = "a");
        let _g2 = span2.enter();
        info!(e = "e", "event1");
        let s = writer.read_string();
        let s = s.trim_ascii_end();
        println!("{s}");

        let mut field_names = Vec::new();
        let field_str = s.strip_prefix("{").unwrap().strip_suffix("}").unwrap();
        for field in field_str.split(',') {
            let field_key_str = field.split(':').next().unwrap();
            field_names.push(&field_key_str[1..field_key_str.len() - 1]);
        }
        assert_eq!(
            field_names,
            &[
                "timestamp",
                "level",
                #[cfg(feature = "tracing-opentelemetry")]
                "trace_id",
                "code.file.path",
                "code.line.number",
                "message",
                "e",
                "d",
                "a",
                "b",
                "c"
            ]
        );
    }

    #[cfg(feature = "tracing-log")]
    #[test]
    fn tracing_log() {
        let (_dispatch, writer) = mock_subscriber();

        log::warn!("test log");
        let json = writer.read_json();
        println!("{json}");
        assert!(json["timestamp"].as_str().unwrap().ends_with('Z'));
        assert_eq!(json["level"].as_str().unwrap(), "WARN");
        assert_eq!(json["code.file.path"].as_str().unwrap(), "src/lib.rs");
        assert_eq!(json["code.line.number"].as_i64().unwrap(), pline!(6));
        assert_eq!(json["message"].as_str().unwrap(), "test log");
        assert_eq!(json.as_object().unwrap().len(), 5);

        #[cfg(feature = "tracing-opentelemetry")]
        let extra_fields = 1;
        #[cfg(not(feature = "tracing-opentelemetry"))]
        let extra_fields = 0;

        let span1 = info_span!("span1", c = "three");
        let _g1 = span1.enter();
        log::error!("test log span1");
        let json = writer.read_json();
        println!("{json}");
        assert!(json["timestamp"].as_str().unwrap().ends_with('Z'));
        assert_eq!(json["level"].as_str().unwrap(), "ERROR");
        assert_eq!(json["code.file.path"].as_str().unwrap(), "src/lib.rs");
        assert_eq!(json["code.line.number"].as_i64().unwrap(), pline!(6));
        #[cfg(feature = "tracing-opentelemetry")]
        assert_eq!(json["trace_id"].as_str().unwrap().len(), 32);
        assert_eq!(json["message"].as_str().unwrap(), "test log span1");
        assert_eq!(json["c"].as_str().unwrap(), "three");
        assert_eq!(json.as_object().unwrap().len(), 6 + extra_fields);

        let span2 = info_span!("span2", d = 4.0);
        let _g2 = span2.enter();
        log::debug!("test log span2");
        let json = writer.read_json();
        println!("{json}");
        assert!(json["timestamp"].as_str().unwrap().ends_with('Z'));
        assert_eq!(json["level"].as_str().unwrap(), "DEBUG");
        assert_eq!(json["code.file.path"].as_str().unwrap(), "src/lib.rs");
        assert_eq!(json["code.line.number"].as_i64().unwrap(), pline!(6));
        #[cfg(feature = "tracing-opentelemetry")]
        assert_eq!(json["trace_id"].as_str().unwrap().len(), 32);
        assert_eq!(json["message"].as_str().unwrap(), "test log span2");
        assert_eq!(json["c"].as_str().unwrap(), "three");
        assert_eq!(json["d"].as_f64().unwrap(), 4.0);
        assert_eq!(json.as_object().unwrap().len(), 7 + extra_fields);
    }

    #[cfg(feature = "tracing-opentelemetry")]
    #[test]
    fn tracing_opentelemetry() {
        use std::collections::HashMap;

        use opentelemetry::propagation::TextMapPropagator;
        use opentelemetry::trace::TraceContextExt;
        use opentelemetry_sdk::propagation::TraceContextPropagator;
        use tracing_opentelemetry::OpenTelemetrySpanExt;

        let (_dispatch, writer) = mock_subscriber();

        // Test auto-generated trace_id.
        {
            // No trace_id without a span.
            warn!("test event");
            let json = writer.read_json();
            println!("{json}");
            assert_eq!(json["trace_id"], serde_json::Value::Null);

            let span1 = info_span!("span1");
            // Uses a generated trace_id when the parent context is not set.
            let generated_trace_id =
                format!("{}", span1.context().span().span_context().trace_id());

            let _g1 = span1.enter();
            error!("test span1");
            let json = writer.read_json();
            println!("{json}");
            assert_eq!(json["trace_id"].as_str().unwrap(), generated_trace_id);

            let span2 = info_span!("span2");
            let _g2 = span2.enter();
            debug!("test span2");
            let json = writer.read_json();
            println!("{json}");
            assert_eq!(json["trace_id"].as_str().unwrap(), generated_trace_id);
        }

        // Test an explicitly set trace_id.
        {
            let fixed_trace_id = "09f91f229168786afbed35fa3a98d86a".to_owned();
            let mut m = HashMap::with_capacity(1);
            m.insert(
                "traceparent".to_owned(),
                format!("00-{fixed_trace_id}-ce812d502e8f1299-01"),
            );
            let cx = TraceContextPropagator::new().extract(&m);

            // No trace_id without a span.
            warn!("test event");
            let json = writer.read_json();
            println!("{json}");
            assert_eq!(json["trace_id"], serde_json::Value::Null);

            let span1 = info_span!("span1");
            span1.set_parent(cx);

            let _g1 = span1.enter();
            error!("test span1");
            let json = writer.read_json();
            println!("{json}");
            assert_eq!(json["trace_id"].as_str().unwrap(), fixed_trace_id);

            let span2 = info_span!("span2");
            let _g2 = span2.enter();
            debug!("test span2");
            let json = writer.read_json();
            println!("{json}");
            assert_eq!(json["trace_id"].as_str().unwrap(), fixed_trace_id);
        }
    }
}
