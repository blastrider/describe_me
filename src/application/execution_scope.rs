use crate::domain::ExecutionScope;
use std::sync::OnceLock;

static EXECUTION_SCOPE: OnceLock<ExecutionScope> = OnceLock::new();

pub fn current_scope() -> ExecutionScope {
    *EXECUTION_SCOPE.get_or_init(|| crate::infrastructure::container::detect_execution_scope())
}
