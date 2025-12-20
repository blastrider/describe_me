#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        use describe_me::internals::{
            parse_table_from_str, table_parse_opts_tcp, table_parse_opts_udp, AddressKind,
        };
        use std::collections::HashMap;

        let empty = HashMap::new();
        let _ = parse_table_from_str(
            text,
            table_parse_opts_tcp(AddressKind::V4),
            &empty,
            false,
        );
        let _ = parse_table_from_str(
            text,
            table_parse_opts_udp(AddressKind::V4),
            &empty,
            false,
        );
    }
});
