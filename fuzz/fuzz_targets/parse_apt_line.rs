#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(line) = std::str::from_utf8(data) {
        #[cfg(target_os = "linux")]
        {
            let _ = describe_me::internals::parse_apt_upgradable_line_for_tests(line);
        }
    }
});
