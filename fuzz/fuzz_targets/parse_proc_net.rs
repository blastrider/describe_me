#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        use describe_me::internals::parse_table_from_str;
        use std::collections::HashMap;

        let empty = HashMap::new();
        let _ = parse_table_from_str(text, "tcp", Some("0A"), &empty, false);
        let _ = parse_table_from_str(text, "udp", Some("07"), &empty, false);
    }
});
