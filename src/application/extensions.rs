use describe_me_plugin_sdk::PluginOutput;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
#[cfg(feature = "config")]
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::fs::{File, Metadata};
use std::io::{self, Read};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};
use thiserror::Error;

#[cfg(all(unix, any(feature = "cli", feature = "systemd")))]
use nix::sys::signal::{kill, Signal};
#[cfg(all(unix, any(feature = "cli", feature = "systemd")))]
use nix::unistd::Pid;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

mod policy;

use crate::application::error::{serialize_error_body, ErrorBody};
use crate::application::logging::LogEvent;
use crate::domain::validate_plugin_name;
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

const STDOUT_LIMIT_BYTES: usize = 5 * 1024 * 1024; // 5 MiB
const STDERR_LIMIT_BYTES: usize = 256 * 1024; // 256 KiB
const DEFAULT_PLUGIN_ENV_ALLOWLIST: &[&str] = &["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "HOME"];

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
    #[error("flux {stream} du plugin dépasse la limite ({observed} > {limit} octets)")]
    OutputLimitExceeded {
        stream: &'static str,
        limit: usize,
        observed: usize,
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
    #[error("nom de plugin invalide {name} pour {command}: {message}")]
    InvalidName {
        name: String,
        command: String,
        message: String,
    },
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
    sha256: [u8; 32],
}

impl PluginFileIdentity {
    fn from_metadata(meta: &Metadata, sha256: [u8; 32]) -> Self {
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
            sha256,
        }
    }
}

pub fn execute_process(spec: &PluginProcess<'_>) -> Result<PluginOutput, PluginExecutionError> {
    enforce_file_identity(&spec.path, &spec.identity)?;

    let command_str = spec.path.display().to_string();

    let mut command = Command::new(&spec.path);
    #[cfg(unix)]
    {
        // Isolate plugin into its own process group to ensure we can terminate all descendants.
        command.process_group(0);
    }
    command
        .args(spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command.env_clear();

    for (key, value) in &spec.env {
        command.env(key, value);
    }

    #[cfg(unix)]
    const ETXTBSY: i32 = 26;
    let mut spawn_attempts = 0;
    let mut child = loop {
        match command.spawn() {
            Ok(child) => break child,
            Err(err) => {
                #[cfg(unix)]
                let is_text_busy = err.raw_os_error() == Some(ETXTBSY);
                #[cfg(not(unix))]
                let is_text_busy = false;

                if is_text_busy && spawn_attempts < 2 {
                    spawn_attempts += 1;
                    thread::sleep(Duration::from_millis(5));
                    continue;
                }
                return Err(PluginExecutionError::Spawn {
                    command: command_str.clone(),
                    source: err,
                });
            }
        }
    };

    let (stdout_tx, stdout_rx) = mpsc::channel();
    let stdout_handle = child
        .stdout
        .take()
        .map(|r| spawn_reader(r, STDOUT_LIMIT_BYTES, stdout_tx));

    let (stderr_tx, stderr_rx) = mpsc::channel();
    let stderr_handle = child
        .stderr
        .take()
        .map(|r| spawn_reader(r, STDERR_LIMIT_BYTES, stderr_tx));

    if let Err(err) = verify_child_identity(&child, &spec.path, &spec.identity) {
        kill_process_tree(&mut child);
        return Err(err);
    }

    let mut stdout_result: Option<Result<Vec<u8>, StreamReadError>> = None;
    let mut stderr_result: Option<Result<Vec<u8>, StreamReadError>> = None;
    let mut limit_error: Option<PluginExecutionError> = None;
    let mut killed = false;

    let timeout = spec.timeout;
    let started = Instant::now();
    loop {
        if stdout_result.is_none() {
            if let Ok(res) = stdout_rx.try_recv() {
                stdout_result = Some(res);
            }
        }
        if stderr_result.is_none() {
            if let Ok(res) = stderr_rx.try_recv() {
                stderr_result = Some(res);
            }
        }

        if limit_error.is_none() {
            if let Some(Err(StreamReadError::LimitExceeded { limit, observed })) =
                stdout_result.as_ref()
            {
                limit_error = Some(PluginExecutionError::OutputLimitExceeded {
                    stream: "stdout",
                    limit: *limit,
                    observed: *observed,
                });
            }
            if let Some(Err(StreamReadError::LimitExceeded { limit, observed })) =
                stderr_result.as_ref()
            {
                limit_error = Some(PluginExecutionError::OutputLimitExceeded {
                    stream: "stderr",
                    limit: *limit,
                    observed: *observed,
                });
            }
            if limit_error.is_some() && !killed {
                kill_process_tree(&mut child);
                killed = true;
            }
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout_bytes =
                    collect_stream(stdout_handle, stdout_result, stdout_rx, "stdout")
                        .map_err(|err| map_stream_error(err, "stdout", &command_str))?;
                let stderr_bytes =
                    collect_stream(stderr_handle, stderr_result, stderr_rx, "stderr")
                        .map_err(|err| map_stream_error(err, "stderr", &command_str))?;

                if let Some(err) = limit_error {
                    return Err(err);
                }

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
                    kill_process_tree(&mut child);
                    let _ = child.wait();
                    drop(stdout_rx);
                    drop(stderr_rx);
                    return Err(PluginExecutionError::Timeout {
                        command: command_str.clone(),
                        timeout,
                    });
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                kill_process_tree(&mut child);
                return Err(PluginExecutionError::Wait {
                    command: command_str.clone(),
                    source: err,
                });
            }
        }
    }
}

#[derive(Debug)]
enum StreamReadError {
    Io(io::Error),
    LimitExceeded { limit: usize, observed: usize },
}

fn read_bounded<R: Read>(mut reader: R, limit: usize) -> Result<Vec<u8>, StreamReadError> {
    let mut buffer = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    loop {
        let read = reader.read(&mut chunk).map_err(StreamReadError::Io)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > limit {
            return Err(StreamReadError::LimitExceeded {
                limit,
                observed: buffer.len(),
            });
        }
    }
    Ok(buffer)
}

fn spawn_reader<R: Read + Send + 'static>(
    reader: R,
    limit: usize,
    tx: mpsc::Sender<Result<Vec<u8>, StreamReadError>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let _ = tx.send(read_bounded(reader, limit));
    })
}

fn collect_stream(
    handle: Option<thread::JoinHandle<()>>,
    initial: Option<Result<Vec<u8>, StreamReadError>>,
    rx: mpsc::Receiver<Result<Vec<u8>, StreamReadError>>,
    stream: &'static str,
) -> Result<Vec<u8>, StreamReadError> {
    if handle.is_none() {
        return initial.unwrap_or_else(|| Ok(Vec::new()));
    }

    let result = match initial {
        Some(res) => res,
        None => rx.recv().map_err(|_| {
            StreamReadError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("{stream} reader channel closed"),
            ))
        })?,
    };

    if let Some(join_handle) = handle {
        if join_handle.join().is_err() {
            return Err(StreamReadError::Io(io::Error::other(
                "reader thread panicked",
            )));
        }
    }

    result
}

fn map_stream_error(
    err: StreamReadError,
    stream: &'static str,
    command: &str,
) -> PluginExecutionError {
    match err {
        StreamReadError::Io(source) => match stream {
            "stdout" => PluginExecutionError::Stdout {
                command: command.to_string(),
                source,
            },
            "stderr" => PluginExecutionError::Stderr {
                command: command.to_string(),
                source,
            },
            _ => PluginExecutionError::Wait {
                command: command.to_string(),
                source,
            },
        },
        StreamReadError::LimitExceeded { limit, observed } => {
            PluginExecutionError::OutputLimitExceeded {
                stream,
                limit,
                observed,
            }
        }
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
    if let Err(err) = cfg.validate_plugin_names() {
        let failure = PluginFailure {
            name: "config".into(),
            command: "extensions.plugins".into(),
            error: err.to_string(),
            logged: false,
        };
        return (BTreeMap::new(), vec![failure]);
    }
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
                    emit_failure(&failure);
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
    if !plugin.allowed_env.is_empty() {
        policy.allowed_env = plugin.allowed_env.clone();
    }
    if !plugin.extra_env.is_empty() {
        policy.extra_env.extend(plugin.extra_env.clone());
    }
    policy
}

pub fn log_failures(failures: &[PluginFailure]) {
    for failure in failures {
        if failure.logged {
            continue;
        }
        emit_failure(failure);
    }
}

fn emit_failure(failure: &PluginFailure) {
    if failure.command == "extensions.plugins" && failure.name == "config" {
        LogEvent::ConfigError {
            path: Cow::Owned(failure.command.clone()),
            error: Cow::Owned(failure.error.clone()),
        }
        .emit();
        return;
    }
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
    if let Err(err) = validate_plugin_name(plugin_name) {
        return Err(PluginExecutionError::InvalidName {
            name: plugin_name.to_string(),
            command: binary_path.to_string(),
            message: err.to_string(),
        });
    }
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
    ensure_plugin_file_allowed(&canonical, policy)?;
    let baseline_identity = capture_identity(&canonical)?;
    let identity = if let Some(expected) = policy.expected_sha256.as_deref() {
        verify_plugin_signature(&canonical, expected, &baseline_identity)?
    } else {
        baseline_identity
    };
    Ok(PluginProcess {
        path: canonical,
        args,
        timeout,
        env: build_plugin_env(plugin_name, policy),
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
    let mut file = File::open(path).map_err(|source| PluginExecutionError::BinaryIo {
        path: path.display().to_string(),
        source,
    })?;
    let metadata = file
        .metadata()
        .map_err(|source| PluginExecutionError::BinaryIo {
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
    let sha256: [u8; 32] = hasher.finalize().into();
    Ok(PluginFileIdentity::from_metadata(&metadata, sha256))
}

fn enforce_file_identity(
    path: &Path,
    expected: &PluginFileIdentity,
) -> Result<(), PluginExecutionError> {
    let current = capture_identity(path)?;
    if &current != expected {
        return Err(PluginExecutionError::Validation {
            path: path.display().to_string(),
            message: "le binaire a changé après validation (taille/mtime/inode/sha256)".into(),
        });
    }
    Ok(())
}

fn verify_child_identity(
    child: &std::process::Child,
    path: &Path,
    expected: &PluginFileIdentity,
) -> Result<(), PluginExecutionError> {
    #[cfg(target_os = "linux")]
    {
        let exe_path = PathBuf::from(format!("/proc/{}/exe", child.id()));
        if let Ok(()) = enforce_file_identity(&exe_path, expected) {
            return Ok(());
        }
    }
    enforce_file_identity(path, expected)
}

#[cfg(all(unix, any(feature = "cli", feature = "systemd")))]
fn kill_process_tree(child: &mut std::process::Child) {
    let pid = child.id() as i32;
    if pid > 0 {
        // Send the signal to the whole process group to catch forked descendants.
        let _ = kill(Pid::from_raw(-pid), Signal::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(not(all(unix, any(feature = "cli", feature = "systemd"))))]
fn kill_process_tree(child: &mut std::process::Child) {
    let _ = child.kill();
}

fn build_plugin_env(plugin_name: &str, policy: &PluginPolicy) -> Vec<(OsString, OsString)> {
    let allowlist = if policy.allowed_env.is_empty() {
        DEFAULT_PLUGIN_ENV_ALLOWLIST
            .iter()
            .map(|name| OsString::from(*name))
            .collect::<HashSet<_>>()
    } else {
        policy
            .allowed_env
            .iter()
            .map(OsString::from)
            .collect::<HashSet<_>>()
    };

    let mut env: HashMap<OsString, OsString> = HashMap::new();
    for (key, value) in std::env::vars_os() {
        if allowlist.contains(&key) {
            env.insert(key, value);
        }
    }
    for (key, value) in &policy.extra_env {
        env.insert(OsString::from(key), OsString::from(value));
    }

    // Always override with the host-provided plugin context.
    env.insert(
        OsString::from("DESCRIBE_ME_HOST"),
        OsString::from("describe_me"),
    );
    env.insert(
        OsString::from("DESCRIBE_ME_PLUGIN_NAME"),
        OsString::from(plugin_name),
    );
    env.insert(
        OsString::from("DESCRIBE_ME_PLUGIN_PROTO"),
        OsString::from("v1"),
    );
    env.insert(
        OsString::from("DESCRIBE_ME_PLUGIN_TOKEN"),
        OsString::from(generate_plugin_token()),
    );

    env.into_iter().collect()
}

fn generate_plugin_token() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
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
    let identity = capture_identity(path)?;
    if &identity != baseline {
        return Err(PluginExecutionError::Validation {
            path: path.display().to_string(),
            message: "le binaire a changé pendant la vérification (taille/mtime/inode/sha256)"
                .into(),
        });
    }

    let actual = hex::encode(identity.sha256);
    if actual != expected_norm {
        return Err(PluginExecutionError::ValidationFailed {
            expected: expected_norm,
            actual,
        });
    }

    Ok(identity)
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
            | PluginExecutionError::InvalidName { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::ffi::OsStr;
    use std::fs::{self, File};
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

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
            env: vec![(OsString::from("PATH"), OsString::from("/bin:/usr/bin"))],
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

    #[test]
    fn plugin_env_filters_unlisted_vars() {
        let _guard = env_lock();
        let secret_key = "AWS_SECRET_ACCESS_KEY";
        let lang_key = "LANG";
        let extra_key = "EXTRA_VAR";

        let prev_secret = env::var_os(secret_key);
        let prev_lang = env::var_os(lang_key);
        let prev_extra = env::var_os(extra_key);

        env::set_var(secret_key, "supersecret");
        env::set_var(lang_key, "C");
        env::remove_var(extra_key);

        let policy = PluginPolicy::default()
            .with_allowed_env([lang_key.to_string()])
            .with_extra_env([(extra_key.to_string(), "1".to_string())]);
        let envs = build_plugin_env("demo", &policy);
        let map: HashMap<OsString, OsString> = envs.into_iter().collect();

        assert_eq!(map.get(OsStr::new(secret_key)), None);
        assert_eq!(map.get(OsStr::new(lang_key)), Some(&OsString::from("C")));
        assert_eq!(map.get(OsStr::new(extra_key)), Some(&OsString::from("1")));
        assert_eq!(
            map.get(OsStr::new("DESCRIBE_ME_PLUGIN_NAME")),
            Some(&OsString::from("demo"))
        );

        match prev_secret {
            Some(val) => env::set_var(secret_key, val),
            None => env::remove_var(secret_key),
        }
        match prev_lang {
            Some(val) => env::set_var(lang_key, val),
            None => env::remove_var(lang_key),
        }
        match prev_extra {
            Some(val) => env::set_var(extra_key, val),
            None => env::remove_var(extra_key),
        }
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
    fn run_ad_hoc_plugin_rejects_invalid_name() {
        let err = run_ad_hoc_plugin_with_policy(
            "/usr/lib/describe_me/plugins/describe-me-plugin-invalid",
            "Bad/Name",
            &[],
            Duration::from_secs(1),
            &PluginPolicy::default(),
        )
        .unwrap_err();

        assert!(matches!(err, PluginExecutionError::InvalidName { .. }));
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

    #[cfg(unix)]
    #[test]
    fn execute_process_limits_stdout() {
        let dir = tempdir().unwrap();
        let script = dir.path().join("spam.sh");
        let mut file = File::create(&script).unwrap();
        let bytes = STDOUT_LIMIT_BYTES + 1024;
        writeln!(file, "#!/bin/sh\nyes X | head -c {bytes}\n",).unwrap();
        drop(file);
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();

        let policy = PluginPolicy::with_root(dir.path());
        let spec = prepare_plugin_process(
            script.to_str().unwrap(),
            "demo",
            &[],
            Duration::from_secs(1),
            &policy,
        )
        .unwrap();
        let err = execute_process(&spec).unwrap_err();
        match err {
            PluginExecutionError::OutputLimitExceeded {
                stream,
                limit,
                observed,
            } => {
                assert_eq!(stream, "stdout");
                assert_eq!(limit, STDOUT_LIMIT_BYTES);
                assert!(observed > limit);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn execute_process_limits_stderr() {
        let dir = tempdir().unwrap();
        let script = dir.path().join("spam_err.sh");
        let mut file = File::create(&script).unwrap();
        let bytes = STDERR_LIMIT_BYTES + 1024;
        writeln!(file, "#!/bin/sh\nyes X | head -c {bytes} >&2\n",).unwrap();
        drop(file);
        let mut perms = fs::metadata(&script).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&script, perms).unwrap();

        let policy = PluginPolicy::with_root(dir.path());
        let spec = prepare_plugin_process(
            script.to_str().unwrap(),
            "demo",
            &[],
            Duration::from_secs(1),
            &policy,
        )
        .unwrap();
        let err = execute_process(&spec).unwrap_err();
        match err {
            PluginExecutionError::OutputLimitExceeded {
                stream,
                limit,
                observed,
            } => {
                assert_eq!(stream, "stderr");
                assert_eq!(limit, STDERR_LIMIT_BYTES);
                assert!(observed > limit);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
