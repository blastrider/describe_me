#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        #[cfg(feature = "systemd")]
        {
            let _ = describe_me::internals::__parse_systemctl_line_for_tests(line);
        }
    }
});
