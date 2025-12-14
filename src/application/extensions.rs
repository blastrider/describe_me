use describe_me_plugin_sdk::PluginOutput;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
#[cfg(feature = "config")]
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

mod policy;

use crate::application::error::{serialize_error_body, ErrorBody};
use crate::application::logging::LogEvent;
#[cfg(feature = "config")]
use crate::domain::{DescribeConfig, ExtensionsConfig, PluginDefinition};
pub use policy::PluginPolicy;

#[derive(Debug)]
pub struct PluginProcess<'a> {
    pub path: PathBuf,
    pub args: &'a [String],
    pub timeout: Duration,
    pub env: Vec<(OsString, OsString)>,
    pub(crate) identity: PluginFileIdentity,
}

#[derive(Debug, Error)]
pub enum PluginExecutionError {
    #[error("impossible de lancer {command}: {source}")]
    Spawn {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("commande {command} bloquée après {timeout:?}")]
    Timeout { command: String, timeout: Duration },
    #[error("commande {command} a échoué (code {code:?}): {stderr}")]
    Exit {
        command: String,
        code: Option<i32>,
        stderr: String,
    },
    #[error("lecture stdout {command}: {source}")]
    Stdout {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("lecture stderr {command}: {source}")]
    Stderr {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("attente commande {command}: {source}")]
    Wait {
        command: String,
        #[source]
        source: io::Error,
    },
    #[error("JSON invalide produit par {command}: {source}")]
    Json {
        command: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("validation {path}: {message}")]
    Validation { path: String, message: String },
    #[error("lecture binaire {path}: {source}")]
    BinaryIo {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("empreinte SHA-256 invalide (attendue {expected}, calculée {actual})")]
    ValidationFailed { expected: String, actual: String },
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct PluginFailure {
    pub name: String,
    pub command: String,
    pub error: String,
    pub logged: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PluginFileIdentity {
    size: u64,
    modified_ns: Option<u128>,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
}

impl PluginFileIdentity {
    fn from_metadata(meta: &Metadata) -> Self {
        let modified_ns = meta
            .modified()
            .ok()
            .and_then(|ts| ts.duration_since(UNIX_EPOCH).ok())
            .map(|dur| dur.as_nanos());

        Self {
            size: meta.len(),
            modified_ns,
            #[cfg(unix)]
            dev: meta.dev(),
            #[cfg(unix)]
            ino: meta.ino(),
        }
    }
}

pub fn execute_process(spec: &PluginProcess<'_>) -> Result<PluginOutput, PluginExecutionError> {
    enforce_file_identity(&spec.path, &spec.identity)?;

    let command_str = spec.path.display().to_string();

    let mut command = Command::new(&spec.path);
    command
        .args(spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    for (key, value) in &spec.env {
        command.env(key, value);
    }

    let mut child = command
        .spawn()
        .map_err(|source| PluginExecutionError::Spawn {
            command: command_str.clone(),
            source,
        })?;

    let mut stdout_handle = child.stdout.take().map(read_stream);
    let mut stderr_handle = child.stderr.take().map(read_stream);
    let timeout = spec.timeout;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout_bytes = join_stream(stdout_handle.take()).map_err(|source| {
                    PluginExecutionError::Stdout {
                        command: command_str.clone(),
                        source,
                    }
                })?;
                let stderr_bytes = join_stream(stderr_handle.take()).map_err(|source| {
                    PluginExecutionError::Stderr {
                        command: command_str.clone(),
                        source,
                    }
                })?;

                if !status.success() {
                    return Err(PluginExecutionError::Exit {
                        command: command_str.clone(),
                        code: status.code(),
                        stderr: bytes_to_string(stderr_bytes),
                    });
                }

                if stdout_bytes.is_empty() {
                    return Ok(PluginOutput::new());
                }

                let output = serde_json::from_slice(&stdout_bytes).map_err(|source| {
                    PluginExecutionError::Json {
                        command: command_str.clone(),
                        source,
                    }
                })?;
                return Ok(output);
            }
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = join_stream(stdout_handle.take());
                    let _ = join_stream(stderr_handle.take());
                    return Err(PluginExecutionError::Timeout {
                        command: command_str.clone(),
                        timeout,
                    });
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                let _ = child.kill();
                return Err(PluginExecutionError::Wait {
                    command: command_str.clone(),
                    source: err,
                });
            }
        }
    }
}

fn read_stream<T>(reader: T) -> thread::JoinHandle<io::Result<Vec<u8>>>
where
    T: Read + Send + 'static,
{
    thread::spawn(move || {
        let mut buffer = Vec::new();
        let mut handle = reader;
        handle.read_to_end(&mut buffer)?;
        Ok(buffer)
    })
}

fn join_stream(handle: Option<thread::JoinHandle<io::Result<Vec<u8>>>>) -> io::Result<Vec<u8>> {
    if let Some(join_handle) = handle {
        join_handle
            .join()
            .map_err(|_| io::Error::other("reader thread panicked"))?
    } else {
        Ok(Vec::new())
    }
}

fn bytes_to_string(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(err) => String::from_utf8_lossy(&err.into_bytes()).into_owned(),
    }
}

#[cfg(feature = "config")]
pub fn execute_configured_plugins(
    cfg: &DescribeConfig,
) -> (BTreeMap<String, PluginOutput>, Vec<PluginFailure>) {
    execute_configured_plugins_with_policy(cfg, &PluginPolicy::default())
}

#[cfg(feature = "config")]
pub fn execute_configured_plugins_with_policy(
    cfg: &DescribeConfig,
    policy: &PluginPolicy,
) -> (BTreeMap<String, PluginOutput>, Vec<PluginFailure>) {
    let Some(extensions) = cfg.extensions.as_ref() else {
        return (BTreeMap::new(), Vec::new());
    };

    run_extensions(extensions, policy)
}

#[cfg(feature = "config")]
fn run_extensions(
    cfg: &ExtensionsConfig,
    policy: &PluginPolicy,
) -> (BTreeMap<String, PluginOutput>, Vec<PluginFailure>) {
    let mut outputs = BTreeMap::new();
    let mut failures = Vec::new();

    for plugin in &cfg.plugins {
        let timeout = Duration::from_secs(plugin.timeout_secs.unwrap_or(10).max(1));
        let policy = plugin_policy_for_definition(policy, plugin);
        match prepare_plugin_process(&plugin.path, &plugin.name, &plugin.args, timeout, &policy) {
            Ok(spec) => match execute_process(&spec) {
                Ok(output) => {
                    outputs.insert(plugin.name.clone(), output);
                }
                Err(err) => {
                    failures.push(PluginFailure {
                        name: plugin.name.clone(),
                        command: plugin.path.clone(),
                        error: serialize_error_body(ErrorBody {
                            error: Cow::Owned(err.to_string()),
                        }),
                        logged: false,
                    });
                }
            },
            Err(err) => {
                let mut failure = PluginFailure {
                    name: plugin.name.clone(),
                    command: plugin.path.clone(),
                    error: serialize_error_body(ErrorBody {
                        error: Cow::Owned(err.to_string()),
                    }),
                    logged: false,
                };
                if is_prelaunch_error(&err) {
                    emit_plugin_failure(&failure);
                    failure.logged = true;
                    sleep_bruteforce_jitter();
                }
                failures.push(failure);
            }
        }
    }

    (outputs, failures)
}

#[cfg(feature = "config")]
fn plugin_policy_for_definition(base: &PluginPolicy, plugin: &PluginDefinition) -> PluginPolicy {
    let mut policy = base.clone();
    policy.expected_sha256 = Some(plugin.sha256.clone());
    policy
}

pub fn log_failures(failures: &[PluginFailure]) {
    for failure in failures {
        if failure.logged {
            continue;
        }
        emit_plugin_failure(failure);
    }
}

fn emit_plugin_failure(failure: &PluginFailure) {
    LogEvent::PluginError {
        plugin: Cow::Owned(failure.name.clone()),
        command: Cow::Owned(failure.command.clone()),
        error: Cow::Owned(failure.error.clone()),
    }
    .emit();
}

pub fn run_ad_hoc_plugin(
    binary_path: &str,
    plugin_name: &str,
    args: &[String],
    timeout: Duration,
) -> Result<PluginOutput, PluginExecutionError> {
    run_ad_hoc_plugin_with_policy(
        binary_path,
        plugin_name,
        args,
        timeout,
        &PluginPolicy::default(),
    )
}

pub fn run_ad_hoc_plugin_with_policy(
    binary_path: &str,
    plugin_name: &str,
    args: &[String],
    timeout: Duration,
    policy: &PluginPolicy,
) -> Result<PluginOutput, PluginExecutionError> {
    match prepare_plugin_process(binary_path, plugin_name, args, timeout, policy) {
        Ok(spec) => execute_process(&spec),
        Err(err) => {
            if is_prelaunch_error(&err) {
                sleep_bruteforce_jitter();
            }
            Err(err)
        }
    }
}

fn prepare_plugin_process<'a>(
    binary_path: &'a str,
    plugin_name: &'a str,
    args: &'a [String],
    timeout: Duration,
    policy: &PluginPolicy,
) -> Result<PluginProcess<'a>, PluginExecutionError> {
    let path = Path::new(binary_path);
    let canonical = ensure_plugin_path_allowed(path, policy)?;
    let metadata = ensure_plugin_file_allowed(&canonical, policy)?;
    let baseline_identity = PluginFileIdentity::from_metadata(&metadata);
    let identity = if let Some(expected) = policy.expected_sha256.as_deref() {
        verify_plugin_signature(&canonical, expected, &baseline_identity)?
    } else {
        baseline_identity
    };
    Ok(PluginProcess {
        path: canonical,
        args,
        timeout,
        env: build_plugin_env(plugin_name),
        identity,
    })
}

fn ensure_plugin_path_allowed(
    path: &Path,
    policy: &PluginPolicy,
) -> Result<PathBuf, PluginExecutionError> {
    let path_str = path.display().to_string();
    if !path.is_absolute() {
        return Err(PluginExecutionError::Validation {
            path: path_str,
            message: "le chemin doit être absolu".into(),
        });
    }

    if path
        .components()
        .any(|comp| matches!(comp, Component::ParentDir))
    {
        return Err(PluginExecutionError::Validation {
            path: path_str,
            message: "composant .. interdit dans le chemin plugin".into(),
        });
    }

    let canonical = path
        .canonicalize()
        .map_err(|source| PluginExecutionError::Validation {
            path: path_str.clone(),
            message: format!("résolution canonique impossible: {source}"),
        })?;

    let root = policy.root();
    if !root.is_absolute() {
        return Err(PluginExecutionError::Validation {
            path: root.display().to_string(),
            message: "le répertoire racine des plugins doit être absolu".into(),
        });
    }
    let root_canon = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
    if !canonical.starts_with(&root_canon) {
        return Err(PluginExecutionError::Validation {
            path: path_str,
            message: format!("le chemin doit rester sous {}", root_canon.display()),
        });
    }

    Ok(canonical)
}

fn ensure_plugin_file_allowed(
    path: &Path,
    policy: &PluginPolicy,
) -> Result<std::fs::Metadata, PluginExecutionError> {
    let path_str = path.display().to_string();
    let metadata = std::fs::metadata(path).map_err(|source| PluginExecutionError::BinaryIo {
        path: path_str.clone(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(PluginExecutionError::Validation {
            path: path_str,
            message: "le binaire doit être un fichier régulier".into(),
        });
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if policy.require_exec && mode & 0o111 == 0 {
            return Err(PluginExecutionError::Validation {
                path: path_str,
                message: "permis d'exécution manquants".into(),
            });
        }
        if mode & 0o022 != 0 {
            return Err(PluginExecutionError::Validation {
                path: path_str,
                message: format!(
                    "permissions trop ouvertes (mode {}), retirer l'écriture groupe/monde",
                    format_mode(mode)
                ),
            });
        }
    }
    Ok(metadata)
}

#[cfg(unix)]
fn format_mode(mode: u32) -> String {
    format!("{mode:04o}")
}

fn capture_identity(path: &Path) -> Result<PluginFileIdentity, PluginExecutionError> {
    let metadata = std::fs::metadata(path).map_err(|source| PluginExecutionError::BinaryIo {
        path: path.display().to_string(),
        source,
    })?;
    Ok(PluginFileIdentity::from_metadata(&metadata))
}

fn enforce_file_identity(
    path: &Path,
    expected: &PluginFileIdentity,
) -> Result<(), PluginExecutionError> {
    let current = capture_identity(path)?;
    if &current != expected {
        return Err(PluginExecutionError::Validation {
            path: path.display().to_string(),
            message: "le binaire a changé après validation (taille/mtime/inode)".into(),
        });
    }
    Ok(())
}

fn build_plugin_env(plugin_name: &str) -> Vec<(OsString, OsString)> {
    let token = generate_plugin_token();
    vec![
        (
            OsString::from("DESCRIBE_ME_HOST"),
            OsString::from("describe_me"),
        ),
        (
            OsString::from("DESCRIBE_ME_PLUGIN_NAME"),
            OsString::from(plugin_name),
        ),
        (
            OsString::from("DESCRIBE_ME_PLUGIN_PROTO"),
            OsString::from("v1"),
        ),
        (
            OsString::from("DESCRIBE_ME_PLUGIN_TOKEN"),
            OsString::from(token),
        ),
    ]
}

fn generate_plugin_token() -> String {
    let mut bytes = [0u8; 16];
    fastrand::fill(&mut bytes);
    hex::encode(bytes)
}

fn verify_plugin_signature(
    path: &Path,
    expected_hex: &str,
    baseline: &PluginFileIdentity,
) -> Result<PluginFileIdentity, PluginExecutionError> {
    let expected = expected_hex.trim();
    if expected.is_empty() {
        return Err(PluginExecutionError::Validation {
            path: path.display().to_string(),
            message: "empreinte SHA-256 manquante".into(),
        });
    }
    let expected_norm = expected.to_ascii_lowercase();
    let mut file = File::open(path).map_err(|source| PluginExecutionError::BinaryIo {
        path: path.display().to_string(),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| PluginExecutionError::BinaryIo {
                path: path.display().to_string(),
                source,
            })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = hex::encode(hasher.finalize());
    if actual != expected_norm {
        return Err(PluginExecutionError::ValidationFailed {
            expected: expected_norm,
            actual,
        });
    }

    let post_hash_identity = capture_identity(path)?;
    if &post_hash_identity != baseline {
        return Err(PluginExecutionError::Validation {
            path: path.display().to_string(),
            message: "le binaire a changé pendant la vérification (taille/mtime/inode)".into(),
        });
    }

    Ok(post_hash_identity)
}

fn sleep_bruteforce_jitter() {
    let delay = fastrand::u64(100..=500);
    thread::sleep(Duration::from_millis(delay));
}

fn is_prelaunch_error(error: &PluginExecutionError) -> bool {
    matches!(
        error,
        PluginExecutionError::Validation { .. }
            | PluginExecutionError::BinaryIo { .. }
            | PluginExecutionError::ValidationFailed { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    #[cfg(unix)]
    #[test]
    fn capture_timeout_is_reported() {
        let dir = tempdir().unwrap();
        let script_path = dir.path().join("sleep.sh");
        let mut file = File::create(&script_path).unwrap();
        writeln!(file, "#!/bin/sh\nsleep 2").unwrap();
        drop(file);
        let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o755);
        }
        std::fs::set_permissions(&script_path, perms).unwrap();

        let identity = capture_identity(&script_path).unwrap();
        let spec = PluginProcess {
            path: script_path,
            args: &[],
            timeout: Duration::from_millis(100),
            env: Vec::new(),
            identity,
        };
        let err = execute_process(&spec).unwrap_err();
        assert!(matches!(err, PluginExecutionError::Timeout { .. }));
    }

    #[test]
    fn verify_plugin_signature_detects_match() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bin");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"ok").unwrap();
        drop(file);

        let baseline = capture_identity(&path).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"ok");
        let expected = hex::encode(hasher.finalize());
        verify_plugin_signature(&path, &expected, &baseline).unwrap();
    }

    #[test]
    fn verify_plugin_signature_detects_mismatch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bin");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"ko").unwrap();
        drop(file);

        let baseline = capture_identity(&path).unwrap();
        let err = verify_plugin_signature(&path, "aaaaaaaa", &baseline).unwrap_err();
        assert!(matches!(err, PluginExecutionError::ValidationFailed { .. }));
    }

    #[test]
    fn prepare_plugin_process_accepts_custom_root_and_sha() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bin");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"ok").unwrap();
        drop(file);
        #[cfg(unix)]
        {
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&path, perms).unwrap();
        }

        let mut hasher = Sha256::new();
        hasher.update(b"ok");
        let expected = hex::encode(hasher.finalize());

        let policy = PluginPolicy::with_root(dir.path()).with_expected_sha256(Some(expected));
        let path_str = path.to_string_lossy().to_string();
        prepare_plugin_process(&path_str, "demo", &[], Duration::from_secs(1), &policy).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn prepare_plugin_process_honors_exec_requirement_flag() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bin");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"exec-flag").unwrap();
        drop(file);

        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).unwrap();

        let policy = PluginPolicy::with_root(dir.path());
        let path_str = path.to_string_lossy().to_string();
        let err = prepare_plugin_process(&path_str, "demo", &[], Duration::from_secs(1), &policy)
            .unwrap_err();
        assert!(matches!(err, PluginExecutionError::Validation { .. }));

        let relaxed = policy.with_exec_check(false);
        prepare_plugin_process(&path_str, "demo", &[], Duration::from_secs(1), &relaxed).unwrap();
    }

    #[test]
    fn prepare_plugin_process_rejects_parent_dir_components() {
        let root = tempdir().unwrap();
        let sibling = root.path().parent().unwrap().join("evil-plugin");
        File::create(&sibling).unwrap();

        let traversal_path = root.path().join("..").join("evil-plugin");
        let policy = PluginPolicy::with_root(root.path());
        let err = prepare_plugin_process(
            traversal_path.to_str().unwrap(),
            "demo",
            &[],
            Duration::from_secs(1),
            &policy,
        )
        .unwrap_err();
        assert!(matches!(err, PluginExecutionError::Validation { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn prepare_plugin_process_rejects_symlink_escape() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let target = outside.path().join("outside");
        File::create(&target).unwrap();
        let link_path = root.path().join("plugin");
        symlink(&target, &link_path).unwrap();

        let policy = PluginPolicy::with_root(root.path());
        let err = prepare_plugin_process(
            link_path.to_str().unwrap(),
            "demo",
            &[],
            Duration::from_secs(1),
            &policy,
        )
        .unwrap_err();
        assert!(matches!(err, PluginExecutionError::Validation { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn prepare_plugin_process_rejects_world_writable_files() {
        let root = tempdir().unwrap();
        let path = root.path().join("bin");
        File::create(&path).unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o777);
        fs::set_permissions(&path, perms).unwrap();

        let policy = PluginPolicy::with_root(root.path());
        let err = prepare_plugin_process(
            path.to_str().unwrap(),
            "demo",
            &[],
            Duration::from_secs(1),
            &policy,
        )
        .unwrap_err();
        assert!(matches!(err, PluginExecutionError::Validation { .. }));
    }

    #[test]
    fn verify_plugin_signature_detects_mid_verification_change() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bin");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"old").unwrap();
        drop(file);

        let baseline = capture_identity(&path).unwrap();
        fs::write(&path, b"new").unwrap();

        let mut hasher = Sha256::new();
        hasher.update(b"new");
        let expected = hex::encode(hasher.finalize());

        let err = verify_plugin_signature(&path, &expected, &baseline).unwrap_err();
        assert!(matches!(err, PluginExecutionError::Validation { .. }));
    }

    #[test]
    fn enforce_identity_detects_mutation_after_prepare() {
        let root = tempdir().unwrap();
        let path = root.path().join("bin");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"unchanged").unwrap();
        drop(file);
        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&path, perms).unwrap();
        }

        let policy = PluginPolicy::with_root(root.path());
        let spec = prepare_plugin_process(
            path.to_str().unwrap(),
            "demo",
            &[],
            Duration::from_secs(1),
            &policy,
        )
        .unwrap();

        fs::write(&spec.path, b"changed").unwrap();
        let err = enforce_file_identity(&spec.path, &spec.identity).unwrap_err();
        assert!(matches!(err, PluginExecutionError::Validation { .. }));
    }
}
