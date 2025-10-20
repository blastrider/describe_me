#[test]
fn smoke_snapshot() {
    let s = decribe_me::SystemSnapshot::capture().expect("capture");
    assert!(s.uptime_seconds >= 0);
}
