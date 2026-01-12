#[cfg(feature = "serde")]
pub(super) fn sanitize_os_hint(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let mut base = trimmed;
    for delim in ['(', '[', '{'] {
        if let Some(idx) = base.find(delim) {
            base = base[..idx].trim();
        }
    }
    if base.is_empty() {
        return None;
    }

    let mut words = base.split_whitespace();
    let vendor = words.next()?;
    let version_token = find_version_token(base);

    let mut result = String::from(vendor);
    if let Some(token) = version_token {
        if let Some(version) = truncate_version(&token) {
            if !version.is_empty() {
                result.push(' ');
                result.push_str(&version);
            }
        }
    }

    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

#[cfg(feature = "serde")]
pub(super) fn sanitize_kernel_hint(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let version_token = find_version_token(trimmed)?;
    truncate_version(&version_token)
}

#[cfg(feature = "serde")]
pub(super) fn find_version_token(text: &str) -> Option<String> {
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() || ch == '.' {
            current.push(ch);
        } else if !current.is_empty() {
            break;
        }
    }
    if current.is_empty() {
        None
    } else {
        Some(current)
    }
}

#[cfg(feature = "serde")]
pub(super) fn truncate_version(token: &str) -> Option<String> {
    let segments: Vec<&str> = token.split('.').filter(|seg| !seg.is_empty()).collect();
    match segments.len() {
        0 => None,
        1 => Some(segments[0].to_string()),
        _ => Some(format!("{}.{}", segments[0], segments[1])),
    }
}
