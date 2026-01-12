use describe_me_plugin_sdk::PluginOutput;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(all(unix, any(feature = "cli", feature = "systemd")))]
use nix::sys::signal::{kill, Signal};
#[cfg(all(unix, any(feature = "cli", feature = "systemd")))]
use nix::unistd::Pid;

use super::hash::{enforce_file_identity, verify_child_identity};
use super::{PluginExecutionError, PluginProcess};

pub(super) const STDOUT_LIMIT_BYTES: usize = 5 * 1024 * 1024; // 5 MiB
pub(super) const STDERR_LIMIT_BYTES: usize = 256 * 1024; // 256 KiB

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
