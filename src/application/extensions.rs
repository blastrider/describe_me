use describe_me_plugin_sdk::PluginOutput;
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

use crate::application::logging::LogEvent;
#[cfg(feature = "config")]
use crate::domain::{DescribeConfig, ExtensionsConfig};

#[derive(Debug)]
pub struct PluginProcess<'a> {
    pub command: &'a OsStr,
    pub args: &'a [String],
    pub timeout: Duration,
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
}

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct PluginFailure {
    pub name: String,
    pub command: String,
    pub error: String,
}

pub fn execute_process(spec: &PluginProcess<'_>) -> Result<PluginOutput, PluginExecutionError> {
    let mut command = Command::new(spec.command);
    command
        .args(spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|source| PluginExecutionError::Spawn {
            command: spec.command.to_string_lossy().into_owned(),
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
                        command: spec.command.to_string_lossy().into_owned(),
                        source,
                    }
                })?;
                let stderr_bytes = join_stream(stderr_handle.take()).map_err(|source| {
                    PluginExecutionError::Stderr {
                        command: spec.command.to_string_lossy().into_owned(),
                        source,
                    }
                })?;

                if !status.success() {
                    return Err(PluginExecutionError::Exit {
                        command: spec.command.to_string_lossy().into_owned(),
                        code: status.code(),
                        stderr: bytes_to_string(stderr_bytes),
                    });
                }

                if stdout_bytes.is_empty() {
                    return Ok(PluginOutput::new());
                }

                let output = serde_json::from_slice(&stdout_bytes).map_err(|source| {
                    PluginExecutionError::Json {
                        command: spec.command.to_string_lossy().into_owned(),
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
                        command: spec.command.to_string_lossy().into_owned(),
                        timeout,
                    });
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(err) => {
                let _ = child.kill();
                return Err(PluginExecutionError::Wait {
                    command: spec.command.to_string_lossy().into_owned(),
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
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "reader thread panicked"))?
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
    let Some(extensions) = cfg.extensions.as_ref() else {
        return (BTreeMap::new(), Vec::new());
    };

    run_extensions(extensions)
}

#[cfg(feature = "config")]
fn run_extensions(cfg: &ExtensionsConfig) -> (BTreeMap<String, PluginOutput>, Vec<PluginFailure>) {
    let mut outputs = BTreeMap::new();
    let mut failures = Vec::new();

    for plugin in &cfg.plugins {
        let timeout = Duration::from_secs(plugin.timeout_secs.unwrap_or(10).max(1));
        let spec = PluginProcess {
            command: OsStr::new(&plugin.cmd),
            args: &plugin.args,
            timeout,
        };
        match execute_process(&spec) {
            Ok(output) => {
                outputs.insert(plugin.name.clone(), output);
            }
            Err(err) => {
                failures.push(PluginFailure {
                    name: plugin.name.clone(),
                    command: plugin.cmd.clone(),
                    error: err.to_string(),
                });
            }
        }
    }

    (outputs, failures)
}

pub fn log_failures(failures: &[PluginFailure]) {
    for failure in failures {
        LogEvent::PluginError {
            plugin: Cow::Owned(failure.name.clone()),
            command: Cow::Owned(failure.command.clone()),
            error: Cow::Owned(failure.error.clone()),
        }
        .emit();
    }
}

pub fn run_ad_hoc_plugin(
    command: &str,
    args: &[String],
    timeout: Duration,
) -> Result<PluginOutput, PluginExecutionError> {
    let spec = PluginProcess {
        command: OsStr::new(command),
        args,
        timeout,
    };
    execute_process(&spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
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

        let spec = PluginProcess {
            command: script_path.as_os_str(),
            args: &[],
            timeout: Duration::from_millis(100),
        };
        let err = execute_process(&spec).unwrap_err();
        assert!(matches!(err, PluginExecutionError::Timeout { .. }));
    }
}
