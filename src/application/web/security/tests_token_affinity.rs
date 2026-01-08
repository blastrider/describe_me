use super::tests_common::*;
use super::*;
use axum::http::StatusCode;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{field::Visit, Event};
use tracing_subscriber::{layer::Context, prelude::*, registry::LookupSpan, Layer, Registry};

#[derive(Clone, Default)]
struct RecordingLayer {
    events: Arc<Mutex<Vec<HashMap<String, String>>>>,
}

impl RecordingLayer {
    fn new() -> Self {
        Self::default()
    }

    fn records(&self) -> Vec<HashMap<String, String>> {
        self.events.lock().unwrap().clone()
    }

    fn clear(&self) {
        self.events.lock().unwrap().clear();
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

#[tokio::test]
async fn logs_token_affinity_violation() {
    let layer = RecordingLayer::new();
    let subscriber = Registry::default().with(layer.clone());
    let guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();

    LogEvent::SecurityIncident {
        category: Cow::Borrowed("test"),
        route: Cow::Borrowed("/"),
        request_path: None,
        ip: None,
        token: None,
        detail: None,
    }
    .emit();
    assert!(
        !layer.records().is_empty(),
        "recording layer inactive before test"
    );
    layer.clear();

    let hash = cached_hash();
    let security = build_security(Some(hash));
    let token = "secret";

    let ip1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let ip3 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 12));

    let parts1 = make_parts("/", ip1, Some(token));
    let parts2 = make_parts("/", ip2, Some(token));
    let parts3 = make_parts("/", ip3, Some(token));

    let session1 = security
        .authorize(&parts1, WebRoute::Html)
        .await
        .expect("first request should succeed");
    let session2 = security
        .authorize(&parts2, WebRoute::Html)
        .await
        .expect("second request should succeed");

    let err = security
        .authorize(&parts3, WebRoute::Html)
        .await
        .expect_err("third request should be rejected");
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    drop(session1);
    drop(session2);

    tokio::task::yield_now().await;
    let mut found = false;
    let mut records_snapshot = Vec::new();
    for _ in 0..10 {
        let records = layer.records();
        if records.iter().any(|record| {
            record
                .get("category")
                .map(|value| value == "token_affinity_violation")
                .unwrap_or(false)
        }) {
            records_snapshot = records;
            found = true;
            break;
        }
        records_snapshot = records;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(guard);
    assert!(
        found,
        "expected token_affinity_violation log, got {records_snapshot:?}"
    );
}

#[tokio::test]
async fn token_affinity_violation_triggers_rate_limit() {
    let hash = cached_hash();
    let security = build_security(Some(hash));
    let token = "secret";

    let ip1 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
    let ip2 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 21));
    let ip3 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 22));

    let parts1 = make_parts("/", ip1, Some(token));
    let parts2 = make_parts("/", ip2, Some(token));
    let parts3 = make_parts("/", ip3, Some(token));

    let _ = security
        .authorize(&parts1, WebRoute::Html)
        .await
        .expect("first request should succeed");
    let _ = security
        .authorize(&parts2, WebRoute::Html)
        .await
        .expect("second request should succeed");

    let err = security
        .authorize(&parts3, WebRoute::Html)
        .await
        .expect_err("third request should be rejected");
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    let mut rate_limited = false;
    for _ in 0..20 {
        let err = security
            .authorize(&parts3, WebRoute::Html)
            .await
            .expect_err("affinity violation should be rejected");
        if err.status == StatusCode::TOO_MANY_REQUESTS {
            assert!(err.retry_after.is_some());
            rate_limited = true;
            break;
        }
    }

    assert!(
        rate_limited,
        "expected rate limiting after repeated violations"
    );
}
