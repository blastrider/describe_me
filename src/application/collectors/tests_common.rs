use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{field::Visit, Event};
use tracing_subscriber::{layer::Context, prelude::*, registry::LookupSpan, Layer, Registry};

pub(crate) fn record_field_eq(record: &HashMap<String, String>, key: &str, expected: &str) -> bool {
    let value = record.get(key).or_else(|| {
        if key == "where" {
            record.get("r#where")
        } else {
            None
        }
    });
    value
        .map(|value| value.trim_matches('"') == expected)
        .unwrap_or(false)
}

#[derive(Clone, Default)]
pub(crate) struct RecordingLayer {
    events: Arc<Mutex<Vec<HashMap<String, String>>>>,
}

impl RecordingLayer {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn records(&self) -> Vec<HashMap<String, String>> {
        self.events.lock().unwrap().clone()
    }

    pub(crate) fn clear(&self) {
        self.events.lock().unwrap().clear();
    }

    pub(crate) fn install(self) -> tracing::dispatcher::DefaultGuard {
        let subscriber = Registry::default().with(self);
        let guard = tracing::subscriber::set_default(subscriber);
        tracing::callsite::rebuild_interest_cache();
        guard
    }
}

impl<S> Layer<S> for RecordingLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = FieldRecorder::default();
        event.record(&mut visitor);
        let mut record = visitor.finish();
        record.insert(
            "level".into(),
            event.metadata().level().as_str().to_string(),
        );
        record.insert("target".into(), event.metadata().target().to_string());
        self.events.lock().unwrap().push(record);
    }
}

#[derive(Default)]
struct FieldRecorder {
    fields: HashMap<String, String>,
}

impl FieldRecorder {
    fn finish(self) -> HashMap<String, String> {
        self.fields
    }
}

impl Visit for FieldRecorder {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_string(), format!("{:?}", value));
    }
}
