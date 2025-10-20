#[test]
fn smoke_snapshot() {
    let s = describe_me::SystemSnapshot::capture().expect("capture");
    // évite la comparaison absurde avec 0 (u64)
    assert!(s.cpu_count >= 1);
    assert!(s.total_memory_bytes >= s.used_memory_bytes);
    // Optionnel si tu veux vérifier un champ non-vide :
    // assert!(!s.hostname.is_empty());
}
