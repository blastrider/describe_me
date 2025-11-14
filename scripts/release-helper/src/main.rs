use std::{env, error::Error, fs, path::Path, process::Command};

fn main() -> Result<(), Box<dyn Error>> {
    let opts = parse_args()?;
    if !opts.allow_dirty {
        ensure_clean_git()?;
    }

    let manifest_src = fs::read_to_string("Cargo.toml")?;
    let current_version =
        extract_version(&manifest_src).ok_or("package.version introuvable dans Cargo.toml")?;
    let mut parts = parse_semver(&current_version)?;
    bump_version(&mut parts, opts.level);
    let new_version = format_version(&parts);

    println!(
        "Préparation de la release: {} -> {} ({:?})",
        current_version, new_version, opts.level
    );

    if opts.dry_run {
        println!("dry-run: aucun fichier n'a été modifié");
        return Ok(());
    }

    let updated_manifest = rewrite_manifest_version(&manifest_src, &new_version)?;
    fs::write("Cargo.toml", updated_manifest)?;

    let lock_src = fs::read_to_string("Cargo.lock")?;
    let updated_lock = rewrite_lock_version(&lock_src, "describe_me", &new_version)?;
    fs::write("Cargo.lock", updated_lock)?;

    promote_changelog(Path::new("CHANGELOG.md"), &new_version)?;

    stage_files(&["Cargo.toml", "Cargo.lock", "CHANGELOG.md"])?;
    create_release_commit(&new_version)?;
    create_tag(&new_version, opts.sign_tag)?;

    println!("Commit et tag créés pour v{}", new_version);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Patch,
    Minor,
    Major,
}

struct Options {
    level: Level,
    dry_run: bool,
    allow_dirty: bool,
    sign_tag: bool,
}

fn parse_args() -> Result<Options, Box<dyn Error>> {
    let mut level = None;
    let mut dry_run = false;
    let mut allow_dirty = false;
    let mut sign_tag = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "patch" => level = level.or(Some(Level::Patch)),
            "minor" => level = level.or(Some(Level::Minor)),
            "major" => level = level.or(Some(Level::Major)),
            "--dry-run" => dry_run = true,
            "--allow-dirty" => allow_dirty = true,
            "--sign-tag" => sign_tag = true,
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => {
                return Err(format!("argument inconnu: {other}").into());
            }
        }
    }

    let level = level.ok_or("précisez le niveau de bump: patch | minor | major")?;
    Ok(Options {
        level,
        dry_run,
        allow_dirty,
        sign_tag,
    })
}

fn print_usage() {
    eprintln!("Usage: release-helper <patch|minor|major> [--dry-run] [--allow-dirty] [--sign-tag]");
}

fn ensure_clean_git() -> Result<(), Box<dyn Error>> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .output()?;
    if !output.status.success() {
        return Err("git status a échoué".into());
    }
    if !String::from_utf8_lossy(&output.stdout).trim().is_empty() {
        return Err("la copie de travail contient déjà des changements".into());
    }
    Ok(())
}

fn parse_semver(input: &str) -> Result<(u64, u64, u64), Box<dyn Error>> {
    let parts: Vec<&str> = input.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("version semver invalide: {input}").into());
    }
    let major = parts[0].parse()?;
    let minor = parts[1].parse()?;
    let patch = parts[2].parse()?;
    Ok((major, minor, patch))
}

fn bump_version(parts: &mut (u64, u64, u64), level: Level) {
    match level {
        Level::Patch => parts.2 += 1,
        Level::Minor => {
            parts.1 += 1;
            parts.2 = 0;
        }
        Level::Major => {
            parts.0 += 1;
            parts.1 = 0;
            parts.2 = 0;
        }
    }
}

fn format_version(parts: &(u64, u64, u64)) -> String {
    format!("{}.{}.{}", parts.0, parts.1, parts.2)
}

fn extract_version(manifest: &str) -> Option<String> {
    let mut in_package = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_package = trimmed == "[package]";
        }
        if in_package && trimmed.starts_with("version") {
            let value = trimmed.split('=').nth(1)?.trim().trim_matches('"');
            return Some(value.to_string());
        }
    }
    None
}

fn rewrite_manifest_version(src: &str, new_version: &str) -> Result<String, Box<dyn Error>> {
    let mut result = String::with_capacity(src.len() + 16);
    let mut in_package = false;
    let mut replaced = false;

    for chunk in src.split_inclusive('\n') {
        let trimmed_start = chunk.trim_start();
        if trimmed_start.starts_with('[') {
            in_package = trimmed_start.starts_with("[package]");
        }
        if in_package
            && trimmed_start.starts_with("version")
            && trimmed_start.contains('=')
            && !replaced
        {
            let indent_len = chunk.len() - trimmed_start.len();
            let indent = &chunk[..indent_len];
            let newline = if chunk.ends_with('\n') { "\n" } else { "" };
            result.push_str(indent);
            result.push_str("version = \"");
            result.push_str(new_version);
            result.push_str("\"");
            result.push_str(newline);
            replaced = true;
        } else {
            result.push_str(chunk);
        }
    }

    if !replaced {
        return Err("impossible de surcharger package.version".into());
    }
    Ok(result)
}

fn rewrite_lock_version(
    src: &str,
    crate_name: &str,
    new_version: &str,
) -> Result<String, Box<dyn Error>> {
    let mut result = String::with_capacity(src.len());
    let mut in_package = false;
    let mut target_block = false;
    let mut replaced = false;

    for chunk in src.split_inclusive('\n') {
        let trimmed = chunk.trim();
        if trimmed.starts_with("[[package]]") {
            in_package = true;
            target_block = false;
        } else if trimmed.starts_with('[') && !trimmed.starts_with("[[package]]") {
            in_package = false;
            target_block = false;
        }

        if in_package && trimmed.starts_with("name = ") {
            target_block = trimmed == format!("name = \"{}\"", crate_name);
        }

        if target_block && trimmed.starts_with("version = ") && !replaced {
            let indent_len = chunk.len() - chunk.trim_start().len();
            let indent = &chunk[..indent_len];
            let newline = if chunk.ends_with('\n') { "\n" } else { "" };
            result.push_str(indent);
            result.push_str("version = \"");
            result.push_str(new_version);
            result.push_str("\"");
            result.push_str(newline);
            replaced = true;
            target_block = false;
            continue;
        }

        result.push_str(chunk);
    }

    if !replaced {
        return Err(format!("package {crate_name} introuvable dans Cargo.lock").into());
    }
    Ok(result)
}

fn promote_changelog(path: &Path, new_version: &str) -> Result<(), Box<dyn Error>> {
    let content = fs::read_to_string(path)?;
    let heading = "## Unreleased";
    let start = content
        .find(heading)
        .ok_or("entrée '## Unreleased' introuvable dans CHANGELOG.md")?;
    let after_heading = content[start..]
        .find('\n')
        .map(|idx| start + idx + 1)
        .ok_or("le titre '## Unreleased' doit être suivi d'une nouvelle ligne")?;
    let rest = &content[after_heading..];
    let next_heading = rest.find("\n## ");
    let body_end = next_heading
        .map(|idx| after_heading + idx)
        .unwrap_or(content.len());
    let body = content[after_heading..body_end].trim();
    let release_notes = if body.is_empty() {
        "- Aucun changement documenté pour cette version.".to_string()
    } else {
        body.to_string()
    };
    let suffix = content[body_end..].trim_start_matches('\n');
    let today = current_date()?;

    let mut rebuilt = String::new();
    rebuilt.push_str(&content[..start]);
    rebuilt.push_str("## Unreleased\n\n- Ajoutez vos changements ici.\n\n");
    rebuilt.push_str(&format!(
        "## v{} - {}\n\n{}\n",
        new_version, today, release_notes
    ));
    rebuilt.push('\n');
    if !suffix.is_empty() {
        rebuilt.push_str(suffix);
        if !suffix.ends_with('\n') {
            rebuilt.push('\n');
        }
    }

    fs::write(path, rebuilt)?;
    Ok(())
}

fn current_date() -> Result<String, Box<dyn Error>> {
    let output = Command::new("date").arg("+%Y-%m-%d").output()?;
    if !output.status.success() {
        return Err("la commande 'date' a échoué".into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn stage_files(files: &[&str]) -> Result<(), Box<dyn Error>> {
    let status = Command::new("git").arg("add").args(files).status()?;
    if !status.success() {
        return Err("git add a échoué".into());
    }
    Ok(())
}

fn create_release_commit(version: &str) -> Result<(), Box<dyn Error>> {
    let message = format!("release v{}", version);
    let status = Command::new("git")
        .args(["commit", "-m", &message])
        .status()?;
    if !status.success() {
        return Err("git commit a échoué".into());
    }
    Ok(())
}

fn create_tag(version: &str, sign_tag: bool) -> Result<(), Box<dyn Error>> {
    let tag = format!("v{}", version);
    let message = format!("describe_me v{}", version);
    let mut cmd = Command::new("git");
    cmd.arg("tag");
    if sign_tag {
        cmd.arg("-s");
    } else {
        cmd.arg("-a");
    }
    let status = cmd.arg(&tag).args(["-m", &message]).status()?;
    if !status.success() {
        return Err("git tag a échoué".into());
    }
    Ok(())
}
