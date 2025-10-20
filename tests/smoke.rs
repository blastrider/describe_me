#[test]
fn smoke_snapshot() {
    let s = describe_me::SystemSnapshot::capture().expect("capture");
    assert!(s.uptime_seconds >= 0);
}
