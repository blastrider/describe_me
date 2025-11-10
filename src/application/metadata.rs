use crate::domain::DescribeError;
use crate::infrastructure::storage::{self, MetadataStore};
use std::collections::BTreeSet;
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

/// Sets the normalized tag list (replacing any existing value).
pub fn set_server_tags<I, S>(tags: I) -> Result<Vec<String>, DescribeError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let normalized = normalize_tags(tags);
    persist_tags(&normalized)?;
    Ok(normalized)
}

/// Adds tags to the existing list, returning the normalized result.
pub fn add_server_tags<I, S>(tags: I) -> Result<Vec<String>, DescribeError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut current = load_server_tags()?;
    let mut additions = normalize_tags(tags);
    if additions.is_empty() {
        return Ok(current);
    }
    current.append(&mut additions);
    current = unique_sorted(current);
    persist_tags(&current)?;
    Ok(current)
}

/// Removes the provided tags.
pub fn remove_server_tags<I, S>(tags: I) -> Result<Vec<String>, DescribeError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let to_remove = normalize_tags(tags);
    if to_remove.is_empty() {
        return load_server_tags();
    }
    let remove_set: BTreeSet<String> = to_remove.into_iter().collect();
    let retained: Vec<String> = load_server_tags()?
        .into_iter()
        .filter(|tag| !remove_set.contains(tag))
        .collect();
    persist_tags(&retained)?;
    Ok(retained)
}

/// Loads the normalized tag list (empty if unset).
pub fn load_server_tags() -> Result<Vec<String>, DescribeError> {
    let store = MetadataStore::open_default()?;
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
pub fn clear_server_tags() -> Result<(), DescribeError> {
    MetadataStore::open_default()?.clear_tags()
}

/// Override the directory where the metadata database is stored.
pub fn override_state_directory<P: AsRef<Path>>(path: P) {
    storage::set_state_dir_override(path.as_ref())
}

fn persist_tags(tags: &[String]) -> Result<(), DescribeError> {
    if tags.is_empty() {
        MetadataStore::open_default()?.set_tags_raw("")
    } else {
        MetadataStore::open_default()?.set_tags_raw(&tags.join("\n"))
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
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut out = String::new();
    let mut last_dash = false;
    for mut ch in trimmed.chars() {
        if ch.is_ascii_uppercase() {
            ch = ch.to_ascii_lowercase();
        }
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_dash = false;
        } else if matches!(ch, '-' | '_' | ' ' | '.' | '/' | '\\') && !last_dash && !out.is_empty()
        {
            out.push('-');
            last_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
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

    #[test]
    fn normalized_tags_are_persisted_once() {
        with_temp_state_dir(|| {
            let tags = set_server_tags([" Ubuntu  ", "FTP", "ubuntu"]).expect("set");
            assert_eq!(tags, vec!["ftp", "ubuntu"]);
            let stored = load_server_tags().expect("load");
            assert_eq!(stored, vec!["ftp", "ubuntu"]);
        });
    }

    #[test]
    fn add_and_remove_tags_work() {
        with_temp_state_dir(|| {
            set_server_tags(["debian"]).expect("set");
            let after_add = add_server_tags(["ftp", "prod"]).expect("add");
            assert_eq!(after_add, vec!["debian", "ftp", "prod"]);
            let after_remove = remove_server_tags(["ftp"]).expect("remove");
            assert_eq!(after_remove, vec!["debian", "prod"]);
            clear_server_tags().expect("clear tags");
            assert!(load_server_tags().expect("load").is_empty());
        });
    }
}
