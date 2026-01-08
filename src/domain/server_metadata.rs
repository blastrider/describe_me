use std::collections::BTreeSet;

use thiserror::Error;

/// Taille maximale autorisée pour la description (en octets).
pub const DESCRIPTION_MAX_BYTES: usize = 2048;
/// Nombre maximal de tags acceptés par requête.
pub const TAGS_MAX_PER_REQUEST: usize = 64;
/// Longueur maximale (en caractères) d'un tag.
pub const TAG_LENGTH_LIMIT: usize = 48;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MetadataValidationError {
    #[error("La description ne peut pas dépasser {0} octets.")]
    DescriptionTooLong(usize),
    #[error("Merci de fournir au moins un tag.")]
    NoTags,
    #[error("Trop de tags fournis.")]
    TooManyTags,
    #[error("Un tag dépasse la longueur maximale autorisée.")]
    TagTooLong,
    #[error("Tag invalide.")]
    InvalidTag,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ServerDescription(pub String);

impl ServerDescription {
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for ServerDescription {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ServerDescription {
    type Error = MetadataValidationError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let sanitized = sanitize_description(raw);
        if sanitized.len() > DESCRIPTION_MAX_BYTES {
            return Err(MetadataValidationError::DescriptionTooLong(
                DESCRIPTION_MAX_BYTES,
            ));
        }
        Ok(ServerDescription(sanitized))
    }
}

fn sanitize_description(raw: &str) -> String {
    let normalized = raw.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::with_capacity(normalized.len());
    let mut prev_space = false;
    let mut at_line_start = true;

    for ch in normalized.chars() {
        if ch == '\n' {
            while out.ends_with(' ') {
                out.pop();
            }
            out.push('\n');
            prev_space = false;
            at_line_start = true;
            continue;
        }

        let mut c = ch;
        if c.is_control() {
            c = ' ';
        }

        if c.is_whitespace() {
            if at_line_start || prev_space {
                continue;
            }
            out.push(' ');
            prev_space = true;
            continue;
        }

        out.push(c);
        prev_space = false;
        at_line_start = false;
    }

    while out.ends_with(' ') {
        out.pop();
    }

    out
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServerTag(pub String);

impl ServerTag {
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl AsRef<str> for ServerTag {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for ServerTag {
    type Error = MetadataValidationError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let trimmed = raw.trim();
        if trimmed.chars().count() > TAG_LENGTH_LIMIT {
            return Err(MetadataValidationError::TagTooLong);
        }
        let normalized = normalize_tag(trimmed).ok_or(MetadataValidationError::InvalidTag)?;
        Ok(ServerTag(normalized))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TagsBatch(pub Vec<ServerTag>);

impl TagsBatch {
    pub fn into_strings(self) -> Vec<String> {
        self.0.into_iter().map(|tag| tag.0).collect()
    }

    pub fn as_strings(&self) -> Vec<String> {
        self.0.iter().map(|tag| tag.0.clone()).collect()
    }
}

impl TryFrom<Vec<String>> for TagsBatch {
    type Error = MetadataValidationError;

    fn try_from(raw: Vec<String>) -> Result<Self, Self::Error> {
        if raw.is_empty() {
            return Err(MetadataValidationError::NoTags);
        }
        let mut normalized = BTreeSet::new();
        for tag in raw {
            let validated = ServerTag::try_from(tag.as_str())?;
            normalized.insert(validated);
        }
        if normalized.is_empty() {
            return Err(MetadataValidationError::NoTags);
        }
        if normalized.len() > TAGS_MAX_PER_REQUEST {
            return Err(MetadataValidationError::TooManyTags);
        }
        Ok(TagsBatch(normalized.into_iter().collect()))
    }
}

pub fn normalize_tag(raw: &str) -> Option<String> {
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

    #[test]
    fn description_rejects_too_long() {
        let long = "x".repeat(DESCRIPTION_MAX_BYTES + 1);
        let err = ServerDescription::try_from(long.as_str()).unwrap_err();
        assert_eq!(
            err,
            MetadataValidationError::DescriptionTooLong(DESCRIPTION_MAX_BYTES)
        );
    }

    #[test]
    fn description_sanitizes_controls_and_spaces() {
        let raw = "  hello\tworld\r\nnew\u{0007}line \n  spaced  out\t\tend ";
        let desc = ServerDescription::try_from(raw).expect("description");
        assert_eq!(desc.as_ref(), "hello world\nnew line\nspaced out end");
    }

    #[test]
    fn tag_normalization_and_limits() {
        let tag = ServerTag::try_from("  Foo_Bar  ").expect("tag");
        assert_eq!(tag.as_ref(), "foo-bar");
        let too_long = "x".repeat(TAG_LENGTH_LIMIT + 1);
        assert!(ServerTag::try_from(too_long.as_str()).is_err());
    }

    #[test]
    fn tags_batch_validates_and_dedups() {
        let batch =
            TagsBatch::try_from(vec!["Prod".into(), "prod".into(), "db".into()]).expect("batch");
        assert_eq!(batch.as_strings(), vec!["db", "prod"]);
    }

    #[test]
    fn tags_batch_limits_after_dedup() {
        let mut raw = Vec::new();
        for _ in 0..(TAGS_MAX_PER_REQUEST + 10) {
            raw.push("web".to_string());
        }
        raw.push("api".to_string());

        let batch = TagsBatch::try_from(raw).expect("batch with deduped tags");
        assert_eq!(batch.as_strings(), vec!["api", "web"]);
    }
}
