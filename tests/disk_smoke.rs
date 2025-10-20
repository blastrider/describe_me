#[test]
fn disk_usage_basic() {
    let du = describe_me::disk_usage().expect("disk_usage");
    assert!(du.total_bytes >= du.available_bytes);
    // On ne présume pas du nombre de partitions (containers CI peuvent en exposer 0 ou 1)
}
