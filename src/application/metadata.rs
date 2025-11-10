use crate::domain::DescribeError;
use crate::infrastructure::storage::MetadataStore;

/// Persist the free-form server description (role, context, owners).
pub fn set_server_description(text: &str) -> Result<(), DescribeError> {
    MetadataStore::open_default()?.set_description(text)
}

/// Returns the stored description, if any.
pub fn load_server_description() -> Result<Option<String>, DescribeError> {
    MetadataStore::open_default()?.get_description()
}

/// Removes any stored description.
pub fn clear_server_description() -> Result<(), DescribeError> {
    MetadataStore::open_default()?.clear_description()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::tempdir;

    static STATE_GUARD: Mutex<()> = Mutex::new(());

    fn with_temp_state_dir<F: FnOnce()>(f: F) {
        let _guard = STATE_GUARD.lock().unwrap();
        let dir = tempdir().expect("tempdir");
        std::env::set_var("DESCRIBE_ME_STATE_DIR", dir.path());
        f();
        std::env::remove_var("DESCRIBE_ME_STATE_DIR");
        // tempdir drops here
    }

    #[test]
    fn roundtrip_description() {
        with_temp_state_dir(|| {
            set_server_description("Serveur FTP de tests").expect("set");
            let stored = load_server_description().expect("load");
            assert_eq!(stored.as_deref(), Some("Serveur FTP de tests"));
        });
    }

    #[test]
    fn clearing_description_removes_data() {
        with_temp_state_dir(|| {
            set_server_description("temp value").expect("set");
            clear_server_description().expect("clear");
            let stored = load_server_description().expect("load");
            assert!(stored.is_none());
        });
    }
}
