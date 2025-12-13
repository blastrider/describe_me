#![cfg(target_os = "freebsd")]

use describe_me::{tail_host_logs, AppContext, CaptureOptions, SystemSnapshot};
use tempfile::NamedTempFile;

#[test]
fn snapshot_collects_basic_metrics() {
    let ctx = AppContext::in_memory();
    let mut opts = CaptureOptions::default();
    opts.with_services = false;
    opts.with_disk_usage = false;
    opts.with_listening_sockets = false;
    opts.resolve_socket_processes = false;
    opts.with_network_traffic = false;
    opts.with_updates = false;
    opts.with_containers = false;

    let snap = SystemSnapshot::capture_with_ctx(opts, &ctx).expect("snapshot");
    assert!(!snap.hostname.is_empty());
    assert!(snap.cpu_count >= 1);
}

#[test]
fn syslog_backend_reads_sample_file() {
    let tmp = NamedTempFile::new().expect("temp syslog");
    std::fs::write(
        tmp.path(),
        "Jan  1 00:00:01 host describe_me: started\nJan  1 00:00:02 host sshd[1]: ok\n",
    )
    .expect("write syslog sample");

    let previous = std::env::var("DESCRIBE_ME_SYSLOG_PATH").ok();
    std::env::set_var("DESCRIBE_ME_SYSLOG_PATH", tmp.path());

    let page = tail_host_logs(10).expect("tail syslog");
    assert_eq!(page.entries.len(), 2);
    assert_eq!(page.entries[0].message, "started");
    assert_eq!(page.entries[1].message, "ok");

    match previous {
        Some(val) => std::env::set_var("DESCRIBE_ME_SYSLOG_PATH", val),
        None => std::env::remove_var("DESCRIBE_ME_SYSLOG_PATH"),
    }
}
