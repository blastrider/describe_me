use crate::domain::DescribeError;

pub const NON_ROOT_MESSAGE: &str = "exécution en root interdite";

/// Returns `true` when running as effective UID 0 (Unix).
#[cfg(all(unix, any(feature = "serde", feature = "systemd")))]
pub fn running_as_root() -> bool {
    nix::unistd::geteuid().is_root()
}

#[cfg(any(not(unix), all(unix, not(any(feature = "serde", feature = "systemd")))))]
pub fn running_as_root() -> bool {
    false
}

/// Fails if executed as root to avoid dangerous side effects.
pub fn ensure_non_root() -> Result<(), DescribeError> {
    if running_as_root() {
        Err(DescribeError::External(NON_ROOT_MESSAGE.into()))
    } else {
        Ok(())
    }
}
