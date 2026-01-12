use crate::domain::UpdatesInfo;
use std::path::Path;
use tracing::debug;

use super::common::{hardened_command, run_command};

pub(super) fn gather_apk_updates() -> Option<UpdatesInfo> {
    let mut cmd = hardened_command("apk");
    cmd.args(["version", "-l", "<"]);
    let output = match run_command(cmd, "apk version -l <") {
        Ok(out) => out,
        Err(err) => {
            if err.kind() != std::io::ErrorKind::NotFound {
                debug!(error = %err, "apk version -l '<' failed");
            }
            return None;
        }
    };
    if !output.status.success() {
        debug!(status = ?output.status, "apk version returned non-zero status");
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pending = count_apk_updates(&stdout) as u32;
    if pending == 0 {
        return Some(UpdatesInfo {
            pending: 0,
            reboot_required: Path::new("/run/reboot-required").exists(),
            packages: None,
        });
    }
    Some(UpdatesInfo {
        pending,
        reboot_required: Path::new("/run/reboot-required").exists(),
        packages: None,
    })
}

pub(super) fn count_apk_updates(output: &str) -> usize {
    output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn count_apk_updates_counts_non_empty(lines in proptest::collection::vec(
            proptest::string::string_regex("[A-Za-z0-9\\s./-]{0,24}").unwrap(),
            0..32
        )) {
            let text = lines.join("\n");
            let expected = text
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count();
            prop_assert_eq!(count_apk_updates(&text), expected);
        }
    }
}
