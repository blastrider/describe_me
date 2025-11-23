use crate::domain::{DescribeError, ExecutionScope};

/// Capture des journaux système (journald si disponible).
pub fn capture_logs(scope: ExecutionScope) -> Result<String, DescribeError> {
    crate::infrastructure::logs::capture_logs(scope)
}
