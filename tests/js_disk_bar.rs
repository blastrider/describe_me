use std::process::Command;

#[test]
fn js_disk_bar_width() {
    let node_available = Command::new("node").arg("--version").output();
    if node_available.is_err() {
        eprintln!("node binary not found, skipping JS disk bar test");
        return;
    }

    let status = Command::new("node")
        .arg("tests/js/disk-utils.test.js")
        .status()
        .expect("failed to run disk-utils JS test");
    assert!(status.success(), "disk-utils JS test failed");
}
