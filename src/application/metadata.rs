use crate::application::context::AppContext;
use crate::domain::{
    server_metadata, DescribeError, MetadataValidationError, ServerDescription, TagsBatch,
};
use crate::infrastructure::storage;
use std::collections::BTreeSet;
use std::path::Path;
use tracing::warn;

pub mod registry;

pub fn set_server_description_with(ctx: &AppContext, text: &str) -> Result<(), DescribeError> {
    let desc = ServerDescription::try_from(text).map_err(map_validation_error)?;
    ctx.metadata_store().set_description(desc.as_ref())
}

pub fn load_server_description_with(ctx: &AppContext) -> Result<Option<String>, DescribeError> {
    ctx.metadata_store().get_description()
}

pub fn clear_server_description_with(ctx: &AppContext) -> Result<(), DescribeError> {
    ctx.metadata_store().clear_description()
}

/// Sets the normalized tag list (replacing any existing value).
pub fn set_server_tags_with<I, S>(ctx: &AppContext, tags: I) -> Result<Vec<String>, DescribeError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let requested: Vec<String> = tags
        .into_iter()
        .map(|tag| tag.as_ref().to_string())
        .collect();
    let validated = validate_tags(requested)?;
    persist_tags_with(ctx, &validated)?;
    Ok(validated)
}

/// Adds tags to the existing list, returning the normalized result.
pub fn add_server_tags_with<I, S>(ctx: &AppContext, tags: I) -> Result<Vec<String>, DescribeError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut current = load_server_tags_with(ctx)?;
    let mut additions: Vec<String> = tags.into_iter().map(|t| t.as_ref().to_string()).collect();
    if additions.is_empty() {
        return Ok(current);
    }
    current.append(&mut additions);
    let validated = validate_tags(current)?;
    persist_tags_with(ctx, &validated)?;
    Ok(validated)
}

/// Removes the provided tags.
pub fn remove_server_tags_with<I, S>(
    ctx: &AppContext,
    tags: I,
) -> Result<Vec<String>, DescribeError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let to_remove: BTreeSet<String> = tags
        .into_iter()
        .filter_map(|tag| normalize_tag_for_removal(tag.as_ref()))
        .collect();
    if to_remove.is_empty() {
        return load_server_tags_with(ctx);
    }
    let retained: Vec<String> = load_server_tags_with(ctx)?
        .into_iter()
        .filter(|tag| !to_remove.contains(tag))
        .collect();
    let validated = validate_tags(retained)?;
    persist_tags_with(ctx, &validated)?;
    Ok(validated)
}

/// Loads the normalized tag list (empty if unset).
pub fn load_server_tags_with(ctx: &AppContext) -> Result<Vec<String>, DescribeError> {
    let store = ctx.metadata_store();
    let raw = store.get_tags_raw()?;
    if let Some(data) = raw {
        if data.is_empty() {
            return Ok(Vec::new());
        }
        let list = data
            .split('\n')
            .filter(|entry| !entry.is_empty())
            .map(|entry| entry.to_string())
            .collect::<Vec<_>>();
        validate_tags(list)
    } else {
        Ok(Vec::new())
    }
}

/// Clears all tags.
pub fn clear_server_tags_with(ctx: &AppContext) -> Result<(), DescribeError> {
    ctx.metadata_store().clear_tags()
}

/// Override the directory where the metadata database is stored.
///
/// Must be called before the metadata store is first accessed. Once initialized,
/// overrides are ignored to avoid switching backends under active use; a warning
/// is emitted in that case.
pub fn override_state_directory<P: AsRef<Path>>(path: P) {
    if registry::metadata_store_initialized() {
        warn!("metadata state_dir override after initialisation: override will apply after reset");
    }
    storage::set_state_dir_override(path.as_ref());
}

fn persist_tags_with(ctx: &AppContext, tags: &[String]) -> Result<(), DescribeError> {
    if tags.is_empty() {
        ctx.metadata_store().set_tags_raw("")
    } else {
        ctx.metadata_store().set_tags_raw(&tags.join("\n"))
    }
}

fn validate_tags(raw: Vec<String>) -> Result<Vec<String>, DescribeError> {
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let validated = raw
        .into_iter()
        .map(|tag| server_metadata::ServerTag::try_from(tag.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_validation_error)?;
    let batch = TagsBatch::try_from(
        validated
            .into_iter()
            .map(|t| t.into_inner())
            .collect::<Vec<_>>(),
    )
    .map_err(map_validation_error)?;
    Ok(batch.as_strings())
}

fn normalize_tag_for_removal(raw: &str) -> Option<String> {
    server_metadata::ServerTag::try_from(raw)
        .ok()
        .map(|t| t.into_inner())
}

fn map_validation_error(err: MetadataValidationError) -> DescribeError {
    DescribeError::Config(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::context::MetadataStoreHealth;
    use crate::infrastructure::storage::MetadataStore;
    use std::time::{Duration, Instant};
    use tempfile::tempdir;

    fn with_temp_state_dir<F: FnOnce()>(f: F) {
        let _guard = crate::infrastructure::storage::state_dir_test_lock();
        registry::reset_metadata_store_for_tests();
        crate::infrastructure::storage::clear_state_dir_override_for_tests();
        std::env::remove_var("DESCRIBE_ME_STATE_DIR");
        std::env::remove_var("STATE_DIRECTORY");
        let dir = tempdir().expect("tempdir");
        super::override_state_directory(dir.path());
        registry::reset_metadata_store_for_tests();
        let db_path = crate::infrastructure::storage::metadata_db_path_for_tests();
        assert!(
            db_path.starts_with(dir.path()),
            "db path {:?} should live under {:?}",
            db_path,
            dir.path()
        );
        f();
        registry::reset_metadata_store_for_tests();
        crate::infrastructure::storage::clear_state_dir_override_for_tests();
        // tempdir drops here
    }

    fn wait_for_metadata_upgrade(store: &MetadataStore) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            let _ = store.get_description();
            if registry::metadata_store_health() == MetadataStoreHealth::Persistent {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            registry::metadata_store_health(),
            MetadataStoreHealth::Persistent
        );
    }

    #[test]
    fn roundtrip_description() {
        with_temp_state_dir(|| {
            let ctx = AppContext::new_default().expect("ctx");
            set_server_description_with(&ctx, "Serveur FTP de tests").expect("set");
            let stored = load_server_description_with(&ctx).expect("load");
            assert_eq!(stored.as_deref(), Some("Serveur FTP de tests"));
        });
    }

    #[test]
    fn clearing_description_removes_data() {
        with_temp_state_dir(|| {
            let ctx = AppContext::new_default().expect("ctx");
            set_server_description_with(&ctx, "temp value").expect("set");
            clear_server_description_with(&ctx).expect("clear");
            let stored = load_server_description_with(&ctx).expect("load");
            assert!(stored.is_none());
        });
    }

    #[test]
    fn normalized_tags_are_persisted_once() {
        with_temp_state_dir(|| {
            let ctx = AppContext::new_default().expect("ctx");
            let tags = set_server_tags_with(&ctx, [" Ubuntu  ", "FTP", "ubuntu"]).expect("set");
            assert_eq!(tags, vec!["ftp", "ubuntu"]);
            let stored = load_server_tags_with(&ctx).expect("load");
            assert_eq!(stored, vec!["ftp", "ubuntu"]);
        });
    }

    #[test]
    fn add_and_remove_tags_work() {
        with_temp_state_dir(|| {
            let ctx = AppContext::new_default().expect("ctx");
            set_server_tags_with(&ctx, ["debian"]).expect("set");
            let after_add = add_server_tags_with(&ctx, ["ftp", "prod"]).expect("add");
            assert_eq!(after_add, vec!["debian", "ftp", "prod"]);
            let after_remove = remove_server_tags_with(&ctx, ["ftp"]).expect("remove");
            assert_eq!(after_remove, vec!["debian", "prod"]);
            clear_server_tags_with(&ctx).expect("clear tags");
            assert!(load_server_tags_with(&ctx).expect("load").is_empty());
        });
    }

    #[test]
    fn registry_returns_initialized_store() {
        with_temp_state_dir(|| {
            let store = MetadataStore::open_default().expect("store");
            registry::init_metadata_store_for_internals(store);
            let handle = registry::metadata_store();
            handle.set_description("registry desc").expect("set");
            let stored = handle.get_description().expect("load");
            assert_eq!(stored.as_deref(), Some("registry desc"));
        });
    }

    #[test]
    fn fallback_upgrades_and_migrates_metadata() {
        let _guard = crate::infrastructure::storage::state_dir_test_lock();
        registry::reset_metadata_store_for_tests();
        crate::infrastructure::storage::clear_state_dir_override_for_tests();
        crate::infrastructure::storage::reset_metadata_backend_factory_for_tests();
        std::env::remove_var("DESCRIBE_ME_STATE_DIR");
        std::env::remove_var("STATE_DIRECTORY");

        let dir = tempdir().expect("tempdir");
        let bad_path = dir.path().join("notadir");
        std::fs::write(&bad_path, "x").expect("write file");
        super::override_state_directory(&bad_path);
        registry::reset_metadata_store_for_tests();

        let store = registry::metadata_store();
        store
            .set_description("fallback desc")
            .expect("set description");
        store.set_tags_raw("prod\nweb").expect("set tags");

        super::override_state_directory(dir.path());
        wait_for_metadata_upgrade(&store);

        let persistent = MetadataStore::open_default().expect("open");
        assert_eq!(
            persistent.get_description().expect("get").as_deref(),
            Some("fallback desc")
        );
        assert_eq!(
            persistent.get_tags_raw().expect("get").as_deref(),
            Some("prod\nweb")
        );

        registry::reset_metadata_store_for_tests();
        crate::infrastructure::storage::clear_state_dir_override_for_tests();
    }

    #[test]
    fn existing_app_context_observes_metadata_upgrade() {
        let _guard = crate::infrastructure::storage::state_dir_test_lock();
        registry::reset_metadata_store_for_tests();
        crate::infrastructure::storage::clear_state_dir_override_for_tests();
        crate::infrastructure::storage::reset_metadata_backend_factory_for_tests();
        std::env::remove_var("DESCRIBE_ME_STATE_DIR");
        std::env::remove_var("STATE_DIRECTORY");

        let dir = tempdir().expect("tempdir");
        let bad_path = dir.path().join("notadir");
        std::fs::write(&bad_path, "x").expect("write file");
        super::override_state_directory(&bad_path);
        registry::reset_metadata_store_for_tests();

        let ctx = AppContext::new_default().expect("ctx");
        assert_eq!(
            ctx.metadata_store_health(),
            MetadataStoreHealth::FallbackInMemory
        );
        set_server_description_with(&ctx, "ctx-desc").expect("set");

        super::override_state_directory(dir.path());
        wait_for_metadata_upgrade(&registry::metadata_store());

        assert_eq!(ctx.metadata_store_health(), MetadataStoreHealth::Persistent);
        let persistent = MetadataStore::open_default().expect("open");
        assert_eq!(
            persistent.get_description().expect("get").as_deref(),
            Some("ctx-desc")
        );

        registry::reset_metadata_store_for_tests();
        crate::infrastructure::storage::clear_state_dir_override_for_tests();
    }

    #[test]
    fn description_validation_is_enforced() {
        with_temp_state_dir(|| {
            let ctx = AppContext::new_default().expect("ctx");
            let long = "x".repeat(server_metadata::DESCRIPTION_MAX_BYTES + 1);
            let err = set_server_description_with(&ctx, &long).unwrap_err();
            assert!(matches!(err, DescribeError::Config(_)));
        });
    }

    #[test]
    fn tags_validation_is_enforced() {
        with_temp_state_dir(|| {
            let ctx = AppContext::new_default().expect("ctx");
            let too_long = "x".repeat(server_metadata::TAG_LENGTH_LIMIT + 1);
            let err = set_server_tags_with(&ctx, [&too_long]).unwrap_err();
            assert!(matches!(err, DescribeError::Config(_)));
        });
    }
}
