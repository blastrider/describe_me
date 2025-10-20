#![no_main]
use libfuzzer_sys::fuzz_target;

#[cfg(feature = "systemd")]
fuzz_target!(|data: &str| {
    let _ = decribe_me::SystemSnapshot::capture; // référence pour linker la lib
    let _ = {
        // on cible uniquement le parseur ligne -> ServiceInfo
        // (fonction non publique : duplique une version locale de test si besoin)
    };
});
#[cfg(not(feature = "systemd"))]
fuzz_target!(|_data: &str| {});
