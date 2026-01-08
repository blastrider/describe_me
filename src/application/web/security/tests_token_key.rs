use super::TokenKey;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[test]
fn token_key_is_stable_within_process() {
    let first = TokenKey::from_value("secret");
    let second = TokenKey::from_value("secret");
    assert_eq!(first, second);
}

#[test]
fn token_key_is_not_unkeyed_default_hasher() {
    let mut hasher = DefaultHasher::new();
    "__token_key_probe__".hash(&mut hasher);
    let unkeyed = hasher.finish();
    let keyed = match TokenKey::from_value("__token_key_probe__") {
        TokenKey::Fingerprint(value) => value,
        TokenKey::Anonymous => panic!("expected fingerprint"),
    };
    assert_ne!(keyed, unkeyed);
}

#[test]
fn token_key_display_format_unchanged() {
    let token = TokenKey::from_value("secret");
    let rendered = format!("{token}");
    assert!(rendered.starts_with("fp:"));
    assert!(rendered.len() >= 3);
}
