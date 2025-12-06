use crate::application::context::AppContext;
use crate::domain::{server_metadata, DescribeError};
use crate::infrastructure::storage;
use std::collections::BTreeSet;
use std::path::Path;

pub mod registry;

pub fn set_server_description_with(ctx: &AppContext, text: &str) -> Result<(), DescribeError> {
    ctx.metadata_store().set_description(text)
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
    let normalized = normalize_tags(tags);
    persist_tags_with(ctx, &normalized)?;
    Ok(normalized)
}

/// Adds tags to the existing list, returning the normalized result.
pub fn add_server_tags_with<I, S>(ctx: &AppContext, tags: I) -> Result<Vec<String>, DescribeError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut current = load_server_tags_with(ctx)?;
    let mut additions = normalize_tags(tags);
    if additions.is_empty() {
        return Ok(current);
    }
    current.append(&mut additions);
    current = unique_sorted(current);
    persist_tags_with(ctx, &current)?;
    Ok(current)
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
    let to_remove = normalize_tags(tags);
    if to_remove.is_empty() {
        return load_server_tags_with(ctx);
    }
    let remove_set: BTreeSet<String> = to_remove.into_iter().collect();
    let retained: Vec<String> = load_server_tags_with(ctx)?
        .into_iter()
        .filter(|tag| !remove_set.contains(tag))
        .collect();
    persist_tags_with(ctx, &retained)?;
    Ok(retained)
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
        Ok(unique_sorted(list))
    } else {
        Ok(Vec::new())
    }
}

/// Clears all tags.
pub fn clear_server_tags_with(ctx: &AppContext) -> Result<(), DescribeError> {
    ctx.metadata_store().clear_tags()
}

/// Override the directory where the metadata database is stored.
pub fn override_state_directory<P: AsRef<Path>>(path: P) {
    storage::set_state_dir_override(path.as_ref())
}

fn persist_tags_with(ctx: &AppContext, tags: &[String]) -> Result<(), DescribeError> {
    if tags.is_empty() {
        ctx.metadata_store().set_tags_raw("")
    } else {
        ctx.metadata_store().set_tags_raw(&tags.join("\n"))
    }
}

fn normalize_tags<I, S>(tags: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut set = BTreeSet::new();
    for tag in tags {
        if let Some(clean) = normalize_tag(tag.as_ref()) {
            set.insert(clean);
        }
    }
    set.into_iter().collect()
}

fn unique_sorted(mut tags: Vec<String>) -> Vec<String> {
    tags.sort();
    tags.dedup();
    tags
}

fn normalize_tag(raw: &str) -> Option<String> {
    server_metadata::normalize_tag(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::storage::MetadataStore;
    use tempfile::tempdir;

    fn with_temp_state_dir<F: FnOnce()>(f: F) {
        let _guard = crate::infrastructure::storage::state_dir_test_lock();
        registry::reset_metadata_store_for_tests();
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
        registry::reset_metadata_store_for_tests();
        crate::infrastructure::storage::clear_state_dir_override_for_tests();
        // tempdir drops here
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
            registry::init_metadata_store(store);
            let handle = registry::metadata_store();
            handle.set_description("registry desc").expect("set");
            let stored = handle.get_description().expect("load");
            assert_eq!(stored.as_deref(), Some("registry desc"));
        });
    }
}
