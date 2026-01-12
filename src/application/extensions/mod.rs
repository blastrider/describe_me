use describe_me_plugin_sdk::PluginOutput;
use rand_core::{OsRng, RngCore};
use std::borrow::Cow;
#[cfg(feature = "config")]
use std::collections::BTreeMap;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use thiserror::Error;

mod fs;
mod hash;
mod policy;
mod runner;

use crate::application::error::{serialize_error_body, ErrorBody};
use crate::application::logging::LogEvent;
use crate::domain::validate_plugin_name;
#[cfg(feature = "config")]
use crate::domain::{DescribeConfig, ExtensionsConfig, PluginDefinition};

use self::fs::{ensure_plugin_file_allowed, ensure_plugin_path_allowed};
#[cfg(test)]
use self::hash::enforce_file_identity;
use self::hash::{capture_identity, verify_plugin_signature, PluginFileIdentity};
#[cfg(test)]
use self::runner::{STDERR_LIMIT_BYTES, STDOUT_LIMIT_BYTES};

pub use policy::PluginPolicy;
pub use runner::execute_process;

#[derive(Debug)]
pub struct PluginProcess<'a> {
    pub path: PathBuf,
    pub args: &'a [String],
    pub timeout: Duration,
    pub env: Vec<(OsString, OsString)>,
    pub(crate) identity: PluginFileIdentity,
}

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
    use sha2::{Digest, Sha256};
    use std::env;
    use std::ffi::OsStr;
    use std::fs::{self, File};
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
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
