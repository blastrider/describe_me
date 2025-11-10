use crate::domain::DescribeError;
use crate::infrastructure::storage::{self, MetadataStore};
use std::path::Path;

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

/// Override the directory where the metadata database is stored.
pub fn override_state_directory<P: AsRef<Path>>(path: P) {
    storage::set_state_dir_override(path.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn with_temp_state_dir<F: FnOnce()>(f: F) {
        let _guard = crate::infrastructure::storage::state_dir_test_lock();
        crate::infrastructure::storage::clear_state_dir_override_for_tests();
        std::env::remove_var("DESCRIBE_ME_STATE_DIR");
        std::env::remove_var("STATE_DIRECTORY");
        let dir = tempdir().expect("tempdir");
        super::override_state_directory(dir.path());
        let db_path = crate::infrastructure::storage::metadata_db_path_for_tests();
        assert!(
            db_path.starts_with(dir.path()),
            "db path {:?} should live under {:?}",
            db_path,
            dir.path()
        );
        f();
        crate::infrastructure::storage::clear_state_dir_override_for_tests();
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
