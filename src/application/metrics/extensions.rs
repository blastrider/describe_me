use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::application::exposure::SnapshotView;
use crate::domain::{is_valid_plugin_name, PLUGIN_NAME_MAX_LEN};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::encode::{escape_label_value, write_metric_header, write_metric_sample};

const EXTENSION_METRICS_LIMIT: usize = 100;
const EXTENSION_SIGNAL_MAX_LEN: usize = 64;
const EXTENSION_LABEL_MAX_LEN: usize = PLUGIN_NAME_MAX_LEN;
const EXTENSION_LABEL_HASH_LEN: usize = 16;
const INVALID_EXTENSION_PREFIX: &str = "invalid";
const EXTENSION_PLUGIN_STATE_LIMIT: usize = 200;
const EXTENSION_PLUGIN_OVERFLOW_LABEL: &str = "__overflow__";

/// État partagé pour les compteurs cumulés d'extensions.
/// Les noms de plugins sont plafonnés pour éviter une croissance illimitée, le
/// surplus étant agrégé sous `EXTENSION_PLUGIN_OVERFLOW_LABEL`.
#[derive(Debug, Default)]
pub struct ExtensionMetricsState {
    dropped_totals: Mutex<BTreeMap<String, u64>>,
}

impl ExtensionMetricsState {
    pub fn new() -> Self {
        Self {
            dropped_totals: Mutex::new(BTreeMap::new()),
        }
    }

    fn add_dropped(&self, plugin_label: &str, dropped: u64) -> (String, u64) {
        let mut guard = self
            .dropped_totals
            .lock()
            .expect("ExtensionMetricsState lock");
        if let Some(total) = guard.get_mut(plugin_label) {
            *total = total.saturating_add(dropped);
            return (plugin_label.to_string(), *total);
        }
        let label = if guard.len() < EXTENSION_PLUGIN_STATE_LIMIT {
            plugin_label
        } else {
            EXTENSION_PLUGIN_OVERFLOW_LABEL
        };
        let entry = guard.entry(label.to_string()).or_insert(0);
        *entry = entry.saturating_add(dropped);
        (label.to_string(), *entry)
    }
}

pub(super) fn write_extension_metrics(
    out: &mut String,
    view: &SnapshotView,
    state: Option<&ExtensionMetricsState>,
) {
    let Some(extensions) = view.extensions.as_ref() else {
        return;
    };
    if extensions.is_empty() {
        return;
    }

    let mut header_written = false;
    let mut dropped_counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut dropped_totals: BTreeMap<String, u64> = BTreeMap::new();

    for (plugin, output) in extensions {
        struct Candidate {
            raw_key: String,
            num: NumericValue,
        }

        let mut dropped = 0usize;
        let extension_label = normalize_extension_label(plugin);
        let mut selected: BTreeMap<String, Candidate> = BTreeMap::new();

        for (key, value) in output.as_map() {
            let Some(num) = numeric_value(value) else {
                continue;
            };
            let Some(signal) = normalize_signal_key(key) else {
                continue;
            };

            if let Some(candidate) = selected.get_mut(&signal) {
                if key.as_str() < candidate.raw_key.as_str() {
                    candidate.raw_key = key.clone();
                    candidate.num = num;
                }
                continue;
            }

            if selected.len() < EXTENSION_METRICS_LIMIT {
                selected.insert(
                    signal,
                    Candidate {
                        raw_key: key.clone(),
                        num,
                    },
                );
                continue;
            }

            let Some(max_signal) = selected.keys().next_back().cloned() else {
                selected.insert(
                    signal,
                    Candidate {
                        raw_key: key.clone(),
                        num,
                    },
                );
                continue;
            };
            if signal < max_signal {
                selected.remove(&max_signal);
                selected.insert(
                    signal,
                    Candidate {
                        raw_key: key.clone(),
                        num,
                    },
                );
            }
        }

        for (key, value) in output.as_map() {
            let Some(_num) = numeric_value(value) else {
                continue;
            };
            let Some(signal) = normalize_signal_key(key) else {
                dropped += 1;
                continue;
            };
            match selected.get(&signal) {
                None => dropped += 1,
                Some(candidate) => {
                    if candidate.raw_key != *key {
                        dropped += 1;
                    }
                }
            }
        }

        for (signal, candidate) in selected {
            if !header_written {
                write_metric_header(
                    out,
                    "describe_me_extension_value",
                    "Numeric plugin outputs exposed with low-cardinality labels",
                    "gauge",
                );
                header_written = true;
            }
            let labels = format!(
                "extension=\"{}\",signal=\"{}\"",
                escape_label_value(&extension_label),
                escape_label_value(&signal)
            );
            write_metric_sample(
                out,
                "describe_me_extension_value",
                Some(&labels),
                candidate.num,
            );
        }

        if dropped > 0 {
            dropped_counts.insert(extension_label.clone(), dropped as u64);
            if let Some(state) = state {
                let (label, total) = state.add_dropped(&extension_label, dropped as u64);
                dropped_totals.insert(label, total);
            }
        }
    }

    if !dropped_counts.is_empty() {
        write_metric_header(
            out,
            "describe_me_extension_dropped",
            "Number of numeric extension signals dropped during this scrape",
            "gauge",
        );
        for (label, count) in dropped_counts {
            let labels = format!("extension=\"{}\"", escape_label_value(&label));
            write_metric_sample(out, "describe_me_extension_dropped", Some(&labels), count);
        }
    }

    if !dropped_totals.is_empty() {
        write_metric_header(
            out,
            "describe_me_extension_dropped_total",
            "Number of numeric extension signals dropped during metrics export",
            "counter",
        );
        for (label, total) in dropped_totals {
            let labels = format!("extension=\"{}\"", escape_label_value(&label));
            write_metric_sample(
                out,
                "describe_me_extension_dropped_total",
                Some(&labels),
                total,
            );
        }
    }
}

enum NumericValue {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
}

impl std::fmt::Display for NumericValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NumericValue::Unsigned(v) => write!(f, "{v}"),
            NumericValue::Signed(v) => write!(f, "{v}"),
            NumericValue::Float(v) => write!(f, "{v}"),
        }
    }
}

fn numeric_value(value: &Value) -> Option<NumericValue> {
    let Value::Number(num) = value else {
        return None;
    };
    if let Some(v) = num.as_u64() {
        return Some(NumericValue::Unsigned(v));
    }
    if let Some(v) = num.as_i64() {
        return Some(NumericValue::Signed(v));
    }
    num.as_f64().map(NumericValue::Float)
}

// Normalise en ASCII `[A-Za-z0-9_]` avec trimming; les clés non-ASCII sont ignorées.
fn normalize_signal_key(raw: &str) -> Option<String> {
    if raw.is_empty() {
        return None;
    }
    if !raw.is_ascii() {
        return None;
    }
    let mut out = String::with_capacity(raw.len().min(EXTENSION_SIGNAL_MAX_LEN));
    for ch in raw.chars() {
        if out.len() >= EXTENSION_SIGNAL_MAX_LEN {
            break;
        }
        if ch.is_ascii_alphanumeric() || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    let trimmed = out.trim_matches('_');
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() == out.len() {
        Some(out)
    } else {
        Some(trimmed.to_string())
    }
}

fn normalize_extension_label(raw: &str) -> String {
    if is_valid_plugin_name(raw) {
        return raw.to_string();
    }
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let hash = hex::encode(hasher.finalize());
    let hash_short = &hash[..EXTENSION_LABEL_HASH_LEN];
    let prefix_len = EXTENSION_LABEL_MAX_LEN.saturating_sub(1 + EXTENSION_LABEL_HASH_LEN);
    let sanitized = sanitize_invalid_label(raw);
    let base = if sanitized.is_empty() {
        INVALID_EXTENSION_PREFIX.to_string()
    } else {
        format!("{INVALID_EXTENSION_PREFIX}_{sanitized}")
    };
    let prefix = base.chars().take(prefix_len).collect::<String>();
    format!("{prefix}_{hash_short}")
}

fn sanitize_invalid_label(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if out.len() >= EXTENSION_LABEL_MAX_LEN {
            break;
        }
        let ch = ch.to_ascii_lowercase();
        if matches!(ch, 'a'..='z' | '0'..='9' | '-' | '_') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out.trim_matches('_').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::exposure::SnapshotView;
    use crate::application::metrics::render_prometheus_metrics_with_state;
    use describe_me_plugin_sdk::PluginOutput;
    use std::collections::BTreeMap;

    #[test]
    fn renders_numeric_extension_metrics() {
        let mut plugin = PluginOutput::new();
        plugin.insert("count", 3);
        plugin.insert("ratio", 1.5);
        plugin.insert("status", "ok");
        plugin.insert("nested", serde_json::json!({"a": 1}));

        let mut extensions = BTreeMap::new();
        extensions.insert("demo".into(), plugin);

        let view = SnapshotView {
            redacted: false,
            hostname: None,
            os: None,
            kernel: None,
            uptime_seconds: 0,
            cpu_count: 0,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 0,
            used_memory_bytes: 0,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            server_description: None,
            server_tags: Vec::new(),
            disk_usage: None,
            os_name: None,
            kernel_release: None,
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "systemd")]
            services_running: None,
            #[cfg(feature = "systemd")]
            services_summary: None,
            containers: None,
            updates: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            extensions: Some(extensions),
        };

        let state = ExtensionMetricsState::new();
        let rendered = render_prometheus_metrics_with_state(&view, 0, Some(&state));
        assert!(
            rendered.contains("describe_me_extension_value{extension=\"demo\",signal=\"count\"} 3")
        );
        assert!(rendered.contains("signal=\"ratio\""));
        assert!(!rendered.contains("signal=\"status\""));
        assert!(!rendered.contains("signal=\"nested\""));
        assert!(!rendered.contains("describe_me_extension_dropped_total"));
    }

    #[test]
    fn normalizes_extension_signal_keys() {
        let cases = [
            ("cpu.total", Some("cpu_total")),
            ("a/b/c", Some("a_b_c")),
            ("a b", Some("a_b")),
            ("__ok__", Some("ok")),
            ("été", None),
            ("", None),
        ];

        for (raw, expected) in cases {
            let normalized = normalize_signal_key(raw);
            assert_eq!(normalized.as_deref(), expected, "raw={raw}");
        }

        let long_key = "a".repeat(EXTENSION_SIGNAL_MAX_LEN + 10);
        let normalized = normalize_signal_key(&long_key).expect("normalized");
        assert!(normalized.len() <= EXTENSION_SIGNAL_MAX_LEN);
    }

    #[test]
    fn drops_excess_extension_metrics() {
        let mut plugin = PluginOutput::new();
        for idx in 0..(EXTENSION_METRICS_LIMIT + 5) {
            plugin.insert(format!("k{idx:03}"), idx as u64);
        }
        let mut extensions = BTreeMap::new();
        extensions.insert("demo".into(), plugin);

        let view = SnapshotView {
            redacted: false,
            hostname: None,
            os: None,
            kernel: None,
            uptime_seconds: 0,
            cpu_count: 0,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 0,
            used_memory_bytes: 0,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            server_description: None,
            server_tags: Vec::new(),
            disk_usage: None,
            os_name: None,
            kernel_release: None,
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "systemd")]
            services_running: None,
            #[cfg(feature = "systemd")]
            services_summary: None,
            containers: None,
            updates: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            extensions: Some(extensions),
        };

        let state = ExtensionMetricsState::new();
        let rendered = render_prometheus_metrics_with_state(&view, 0, Some(&state));
        assert!(rendered.contains("signal=\"k099\""));
        assert!(!rendered.contains("signal=\"k100\""));
        assert!(rendered.contains("describe_me_extension_dropped{extension=\"demo\"} 5"));
        assert!(rendered.contains("describe_me_extension_dropped_total{extension=\"demo\"} 5"));
    }

    #[test]
    fn drops_duplicate_normalized_extension_metrics() {
        let mut plugin = PluginOutput::new();
        plugin.insert("cpu-usage", 10);
        plugin.insert("cpu_usage", 12);

        let mut extensions = BTreeMap::new();
        extensions.insert("demo".into(), plugin);

        let view = SnapshotView {
            redacted: false,
            hostname: None,
            os: None,
            kernel: None,
            uptime_seconds: 0,
            cpu_count: 0,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 0,
            used_memory_bytes: 0,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            server_description: None,
            server_tags: Vec::new(),
            disk_usage: None,
            os_name: None,
            kernel_release: None,
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "systemd")]
            services_running: None,
            #[cfg(feature = "systemd")]
            services_summary: None,
            containers: None,
            updates: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            extensions: Some(extensions),
        };

        let state = ExtensionMetricsState::new();
        let rendered = render_prometheus_metrics_with_state(&view, 0, Some(&state));
        assert_eq!(rendered.matches("signal=\"cpu_usage\"").count(), 1);
        assert!(rendered.contains("describe_me_extension_dropped{extension=\"demo\"} 1"));
        assert!(rendered.contains("describe_me_extension_dropped_total{extension=\"demo\"} 1"));
    }

    #[test]
    fn drops_are_visible_without_state() {
        let mut plugin = PluginOutput::new();
        plugin.insert("cpu-usage", 10);
        plugin.insert("cpu_usage", 12);

        let mut extensions = BTreeMap::new();
        extensions.insert("demo".into(), plugin);

        let view = SnapshotView {
            redacted: false,
            hostname: None,
            os: None,
            kernel: None,
            uptime_seconds: 0,
            cpu_count: 0,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 0,
            used_memory_bytes: 0,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            server_description: None,
            server_tags: Vec::new(),
            disk_usage: None,
            os_name: None,
            kernel_release: None,
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "systemd")]
            services_running: None,
            #[cfg(feature = "systemd")]
            services_summary: None,
            containers: None,
            updates: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            extensions: Some(extensions),
        };

        let rendered = render_prometheus_metrics_with_state(&view, 0, None);
        assert!(rendered.contains("describe_me_extension_dropped{extension=\"demo\"} 1"));
        assert!(!rendered.contains("describe_me_extension_dropped_total{extension=\"demo\"} 1"));
    }

    #[test]
    fn caps_dropped_state_per_plugin() {
        let state = ExtensionMetricsState::new();
        for idx in 0..(EXTENSION_PLUGIN_STATE_LIMIT + 5) {
            let name = format!("plugin-{idx:03}");
            state.add_dropped(&name, 1);
        }
        let guard = state
            .dropped_totals
            .lock()
            .expect("ExtensionMetricsState lock");
        assert!(guard.len() <= EXTENSION_PLUGIN_STATE_LIMIT + 1);
        assert!(guard.contains_key(EXTENSION_PLUGIN_OVERFLOW_LABEL));
    }

    #[test]
    fn normalizes_extension_labels() {
        assert_eq!(normalize_extension_label("demo"), "demo");
        let invalid = normalize_extension_label("  demo  ");
        assert!(invalid.starts_with("invalid_demo_"));
        let empty = normalize_extension_label("");
        assert!(empty.starts_with("invalid_"));

        let long = "a".repeat(EXTENSION_LABEL_MAX_LEN + 10);
        let normalized = normalize_extension_label(&long);
        assert!(normalized.len() <= EXTENSION_LABEL_MAX_LEN);
        assert!(normalized.contains('_'));
    }
}
