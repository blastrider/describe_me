use std::io::{self, Read};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tracing::{debug, warn};

pub struct CommandOutput {
    pub output: Output,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

pub fn run_command_with_timeout(
    mut cmd: Command,
    timeout: Duration,
    max_output_bytes: usize,
    label: &str,
) -> io::Result<CommandOutput> {
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    configure_process_group(&mut cmd);

    let start = Instant::now();
    let mut child = cmd.spawn()?;

    let stdout_handle = child
        .stdout
        .take()
        .map(|stdout| spawn_reader(stdout, max_output_bytes));
    let stderr_handle = child
        .stderr
        .take()
        .map(|stderr| spawn_reader(stderr, max_output_bytes));

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout_capture = join_reader(stdout_handle, label, "stdout");
                let stderr_capture = join_reader(stderr_handle, label, "stderr");
                let output = Output {
                    status,
                    stdout: stdout_capture.buf,
                    stderr: stderr_capture.buf,
                };
                let elapsed = start.elapsed();
                debug!(
                    "command_completed command={} status={} duration_ms={}",
                    label,
                    output.status,
                    elapsed.as_millis()
                );
                return Ok(CommandOutput {
                    output,
                    stdout_truncated: stdout_capture.truncated,
                    stderr_truncated: stderr_capture.truncated,
                });
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    warn!(
                        "command_timeout command={} timeout_s={}",
                        label,
                        timeout.as_secs()
                    );
                    kill_process_group(&mut child);
                    let _ = child.wait();
                    let _ = join_reader(stdout_handle, label, "stdout");
                    let _ = join_reader(stderr_handle, label, "stderr");
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "command timed out"));
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(err) => {
                warn!(error = %err, "command_wait_failed command={}", label);
                kill_process_group(&mut child);
                let _ = child.wait();
                let _ = join_reader(stdout_handle, label, "stdout");
                let _ = join_reader(stderr_handle, label, "stderr");
                return Err(err);
            }
        }
    }
}

struct StreamCapture {
    buf: Vec<u8>,
    truncated: bool,
    err: Option<io::Error>,
}

fn spawn_reader(
    reader: impl Read + Send + 'static,
    max: usize,
) -> thread::JoinHandle<StreamCapture> {
    thread::spawn(move || read_with_limit(reader, max))
}

fn read_with_limit(mut reader: impl Read, max: usize) -> StreamCapture {
    let mut buf = Vec::new();
    let mut truncated = false;
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                if buf.len() < max {
                    let remaining = max.saturating_sub(buf.len());
                    let take = remaining.min(read);
                    buf.extend_from_slice(&chunk[..take]);
                    if take < read {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(err) => {
                return StreamCapture {
                    buf,
                    truncated,
                    err: Some(err),
                }
            }
        }
    }
    StreamCapture {
        buf,
        truncated,
        err: None,
    }
}

fn join_reader(
    handle: Option<thread::JoinHandle<StreamCapture>>,
    label: &str,
    stream: &str,
) -> StreamCapture {
    match handle {
        Some(handle) => match handle.join() {
            Ok(capture) => {
                if let Some(err) = capture.err.as_ref() {
                    warn!(
                        error = %err,
                        "command_io_failed command={} stream={}",
                        label,
                        stream
                    );
                }
                if capture.truncated {
                    warn!(
                        "command_output_truncated command={} stream={}",
                        label, stream
                    );
                }
                capture
            }
            Err(_) => {
                warn!("command_io_panicked command={} stream={}", label, stream);
                StreamCapture {
                    buf: Vec::new(),
                    truncated: false,
                    err: None,
                }
            }
        },
        None => StreamCapture {
            buf: Vec::new(),
            truncated: false,
            err: None,
        },
    }
}

#[cfg(unix)]
fn configure_process_group(cmd: &mut Command) {
    use std::os::unix::process::CommandExt;

    cmd.process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_cmd: &mut Command) {}

#[cfg(all(unix, any(feature = "serde", feature = "systemd")))]
fn kill_process_group(child: &mut Child) {
    use nix::sys::signal::{killpg, Signal};
    use nix::unistd::Pid;

    let pid = child.id() as i32;
    if pid > 0 {
        if let Err(err) = killpg(Pid::from_raw(pid), Signal::SIGKILL) {
            warn!(error = %err, "command_killpg_failed pid={}", pid);
            let _ = child.kill();
        }
    } else {
        let _ = child.kill();
    }
}

#[cfg(any(not(unix), not(any(feature = "serde", feature = "systemd"))))]
fn kill_process_group(child: &mut Child) {
    let _ = child.kill();
}
