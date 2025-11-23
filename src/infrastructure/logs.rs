use std::path::Path;
use std::process::Command;

use crate::domain::{DescribeError, ExecutionScope};

pub(crate) fn capture_logs(_scope: ExecutionScope) -> Result<String, DescribeError> {
    // Préférence journald local; sinon message explicite.
    if !Path::new("/run/systemd/journal/socket").exists() {
        return Ok("Journal systemd inaccessible (socket absent)".to_string());
    }

    let output = Command::new("journalctl")
        .args(["-b", "-n", "500", "--no-pager"])
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .map_err(|e| DescribeError::External(e.to_string()))?;

    if !output.status.success() {
        return Err(DescribeError::External(format!(
            "journalctl exit code: {}",
            output.status
        )));
    }

    String::from_utf8(output.stdout).map_err(|e| DescribeError::Parse(format!("utf8: {e}")))
}
