#![cfg(feature = "systemd")]

use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_never_panics(name in "[A-Za-z0-9._-]{1,20}", desc in "\\PC{0,60}") {
        let line = format!("{name}.service loaded active running {desc}");
        let _ = describe_me::internals::__parse_systemctl_line_for_tests(&line);
    }
}
