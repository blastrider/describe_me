use std::io;
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct OutputCapture {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    #[allow(dead_code)]
    pub timed_out: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct CaptureLimits {
    pub stdout_max: usize,
    pub stderr_max: usize,
}

#[derive(Debug)]
pub enum RunError {
    Spawn(io::Error),
    Wait(io::Error),
    Stdout(io::Error),
    Stderr(io::Error),
    Timeout,
    OutputLimitExceeded {
        stream: &'static str,
        limit: usize,
        observed: usize,
    },
}

pub fn run_with_timeout(
    mut cmd: Command,
    timeout: Duration,
    limits: Option<CaptureLimits>,
    poll_interval: Duration,
) -> Result<OutputCapture, RunError> {
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().map_err(RunError::Spawn)?;
    let limits = limits.unwrap_or(CaptureLimits {
        stdout_max: usize::MAX,
        stderr_max: usize::MAX,
    });

    let (stdout_tx, stdout_rx) = mpsc::channel();
    let stdout_handle = child
        .stdout
        .take()
        .map(|reader| spawn_reader(reader, limits.stdout_max, "stdout", stdout_tx));

    let (stderr_tx, stderr_rx) = mpsc::channel();
    let stderr_handle = child
        .stderr
        .take()
        .map(|reader| spawn_reader(reader, limits.stderr_max, "stderr", stderr_tx));

    let mut stdout_result: Option<Result<Vec<u8>, StreamReadError>> = None;
    let mut stderr_result: Option<Result<Vec<u8>, StreamReadError>> = None;
    let mut limit_error: Option<RunError> = None;
    let mut killed = false;

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
            if let Some(Err(StreamReadError::LimitExceeded {
                stream,
                limit,
                observed,
            })) = stdout_result.as_ref()
            {
                limit_error = Some(RunError::OutputLimitExceeded {
                    stream,
                    limit: *limit,
                    observed: *observed,
                });
            }
            if let Some(Err(StreamReadError::LimitExceeded {
                stream,
                limit,
                observed,
            })) = stderr_result.as_ref()
            {
                limit_error = Some(RunError::OutputLimitExceeded {
                    stream,
                    limit: *limit,
                    observed: *observed,
                });
            }
            if limit_error.is_some() && !killed {
                let _ = child.kill();
                killed = true;
            }
        }

        if let Some(err) = limit_error.take() {
            let _ = child.wait();
            let _ = collect_stream(stdout_handle, stdout_result, &stdout_rx, "stdout");
            let _ = collect_stream(stderr_handle, stderr_result, &stderr_rx, "stderr");
            return Err(err);
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = collect_stream(stdout_handle, stdout_result, &stdout_rx, "stdout")
                    .map_err(RunError::Stdout)?;
                let stderr = collect_stream(stderr_handle, stderr_result, &stderr_rx, "stderr")
                    .map_err(RunError::Stderr)?;

                return Ok(OutputCapture {
                    status,
                    stdout,
                    stderr,
                    timed_out: false,
                });
            }
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = collect_stream(stdout_handle, stdout_result, &stdout_rx, "stdout");
                    let _ = collect_stream(stderr_handle, stderr_result, &stderr_rx, "stderr");
                    return Err(RunError::Timeout);
                }
                thread::sleep(poll_interval);
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = collect_stream(stdout_handle, stdout_result, &stdout_rx, "stdout");
                let _ = collect_stream(stderr_handle, stderr_result, &stderr_rx, "stderr");
                return Err(RunError::Wait(err));
            }
        }
    }
}

#[derive(Debug)]
enum StreamReadError {
    Io(io::Error),
    LimitExceeded {
        stream: &'static str,
        limit: usize,
        observed: usize,
    },
}

fn spawn_reader<R: io::Read + Send + 'static>(
    mut reader: R,
    limit: usize,
    stream: &'static str,
    tx: mpsc::Sender<Result<Vec<u8>, StreamReadError>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = Vec::with_capacity(8192);
        let mut chunk = [0u8; 8192];
        loop {
            let read = match reader.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) => {
                    let _ = tx.send(Err(StreamReadError::Io(err)));
                    return;
                }
            };
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.len() > limit {
                let _ = tx.send(Err(StreamReadError::LimitExceeded {
                    stream,
                    limit,
                    observed: buffer.len(),
                }));
                return;
            }
        }
        let _ = tx.send(Ok(buffer));
    })
}

fn collect_stream(
    handle: Option<thread::JoinHandle<()>>,
    initial: Option<Result<Vec<u8>, StreamReadError>>,
    rx: &mpsc::Receiver<Result<Vec<u8>, StreamReadError>>,
    stream: &'static str,
) -> Result<Vec<u8>, io::Error> {
    let result = match initial {
        Some(res) => res,
        None => rx.recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                format!("{stream} reader channel closed"),
            )
        })?,
    };

    if let Some(join_handle) = handle {
        join_handle
            .join()
            .map_err(|_| io::Error::other("reader thread panicked"))?;
    }

    match result {
        Ok(buf) => Ok(buf),
        Err(StreamReadError::Io(err)) => Err(err),
        Err(StreamReadError::LimitExceeded {
            limit, observed, ..
        }) => Err(io::Error::other(format!(
            "limit exceeded ({observed} > {limit})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn run_with_timeout_hits_timeout() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 2"]);
        let res = run_with_timeout(
            cmd,
            Duration::from_millis(100),
            None,
            Duration::from_millis(20),
        );
        assert!(matches!(res, Err(RunError::Timeout)));
    }

    #[cfg(unix)]
    #[test]
    fn run_with_timeout_captures_streams() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "echo out && echo err 1>&2"]);
        let out = run_with_timeout(cmd, Duration::from_secs(2), None, Duration::from_millis(20))
            .expect("process");

        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "out");
        assert_eq!(String::from_utf8_lossy(&out.stderr).trim(), "err");
    }

    #[cfg(unix)]
    #[test]
    fn run_with_timeout_enforces_limits() {
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "cat /dev/zero | head -c 5000"]);
        let res = run_with_timeout(
            cmd,
            Duration::from_secs(2),
            Some(CaptureLimits {
                stdout_max: 1024,
                stderr_max: 1024,
            }),
            Duration::from_millis(20),
        );
        match res {
            Err(RunError::OutputLimitExceeded { stream, .. }) => assert_eq!(stream, "stdout"),
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
