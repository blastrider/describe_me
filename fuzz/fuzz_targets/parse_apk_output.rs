#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        #[cfg(target_os = "linux")]
        {
            let _ = describe_me::internals::count_apk_updates_for_tests(text);
        }
    }
});
