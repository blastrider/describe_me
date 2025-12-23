#![cfg(feature = "serde")]

use describe_me::{AppContext, CaptureOptions, Exposure, SnapshotView, SystemSnapshot};
use describe_me_plugin_sdk::PluginOutput;
use std::collections::BTreeMap;

#[cfg(feature = "config")]
fn capture_with_view(exposure: Exposure, ctx: &AppContext) -> (SystemSnapshot, SnapshotView) {
    describe_me::capture_snapshot_with_view(minimal_capture_opts(), exposure, None, ctx)
        .expect("capture")
}

#[cfg(not(feature = "config"))]
fn capture_with_view(exposure: Exposure, ctx: &AppContext) -> (SystemSnapshot, SnapshotView) {
    describe_me::capture_snapshot_with_view(minimal_capture_opts(), exposure, ctx).expect("capture")
}

#[test]
fn exposure_flags_toggle_hostname_visibility() {
    let ctx = AppContext::in_memory();

    let (_snap, redacted_view) = capture_with_view(Exposure::default(), &ctx);
    assert!(redacted_view.hostname.is_none());

    let (snap_full, full_view) = capture_with_view(Exposure::all(), &ctx);
    assert_eq!(
        full_view.hostname.as_deref(),
        Some(snap_full.hostname.as_str())
    );
}

#[test]
fn extensions_follow_exposure_flags() {
    let mut snapshot = minimal_snapshot();

    let mut plugin = PluginOutput::new();
    plugin.insert("count", 1);
    let mut extensions = BTreeMap::new();
    extensions.insert("demo".into(), plugin);
    snapshot.extensions = Some(extensions);

    let hidden_view = SnapshotView::new(&snapshot, Exposure::default());
    assert!(hidden_view.extensions.is_none());

    let mut exposure = Exposure::default();
    exposure.set_extensions(true);
    let visible_view = SnapshotView::new(&snapshot, exposure);
    assert!(visible_view.extensions.is_some());
}

fn minimal_capture_opts() -> CaptureOptions {
    CaptureOptions {
        with_services: false,
        with_disk_usage: false,
        with_listening_sockets: false,
        resolve_socket_processes: false,
        with_network_traffic: false,
        with_updates: false,
        with_containers: false,
    }
}

fn minimal_snapshot() -> SystemSnapshot {
    SystemSnapshot {
        hostname: "host".into(),
        os: Some("os".into()),
        kernel: Some("kernel".into()),
        uptime_seconds: 0,
        cpu_count: 1,
        load_average: (0.0, 0.0, 0.0),
        total_memory_bytes: 0,
        used_memory_bytes: 0,
        total_swap_bytes: 0,
        used_swap_bytes: 0,
        disk_usage: None,
        #[cfg(feature = "systemd")]
        services_running: describe_me::SharedSlice::from_vec(Vec::new()),
        #[cfg(feature = "net")]
        listening_sockets: None,
        #[cfg(feature = "net")]
        network_traffic: None,
        containers: None,
        updates: None,
        extensions: None,
    }
}
