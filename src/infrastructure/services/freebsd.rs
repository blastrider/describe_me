use crate::application::services::ServiceBackend;
use crate::application::AppContext;
use crate::domain::{DescribeError, ServiceInfo};
use std::collections::HashSet;
use std::process::{Command, Stdio};

const SERVICE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// FreeBSD rc.d backend using `service` listings.
#[derive(Debug, Default, Clone, Copy)]
pub struct RcServiceBackend;

impl ServiceBackend for RcServiceBackend {
    fn list_services(&self, ctx: &AppContext) -> Result<Vec<ServiceInfo>, DescribeError> {
        let _ = ctx;
        list_rc_services()
    }
}

fn list_rc_services() -> Result<Vec<ServiceInfo>, DescribeError> {
    let names = gather_service_names()?;
    let mut services = Vec::new();
    for name in names {
        services.push(probe_service_status(&name));
    }
    Ok(services)
}

fn gather_service_names() -> Result<Vec<String>, DescribeError> {
    if let Ok(names) = list_services_with_flag("-e") {
        if !names.is_empty() {
            return Ok(names);
        }
    }
    list_services_with_flag("-l")
}

fn list_services_with_flag(flag: &str) -> Result<Vec<String>, DescribeError> {
    let mut cmd = Command::new("service");
    cmd.arg(flag)
        .env_clear()
        .env("PATH", SERVICE_PATH)
        .stdin(Stdio::null());

    let output = cmd
        .output()
        .map_err(|err| DescribeError::External(format!("service {flag}: {err}")))?;

    if !output.status.success() {
        return Err(DescribeError::External(format!(
            "service {flag} exited with {status}",
            status = output.status
        )));
    }

    Ok(parse_service_list_output(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn probe_service_status(name: &str) -> ServiceInfo {
    let mut cmd = Command::new("service");
    cmd.args([name, "onestatus"])
        .env_clear()
        .env("PATH", SERVICE_PATH)
        .stdin(Stdio::null());

    match cmd.output() {
        Ok(output) => {
            let running = output.status.success();
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let summary = extract_summary(&stdout).or_else(|| extract_summary(&stderr));
            let state = if running { "running" } else { "stopped" }.to_string();
            ServiceInfo {
                name: name.to_string(),
                state,
                summary,
            }
        }
        Err(err) => ServiceInfo {
            name: name.to_string(),
            state: "unknown".to_string(),
            summary: Some(format!("status error: {err}")),
        },
    }
}

fn extract_summary(output: &str) -> Option<String> {
    output
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
}

fn parse_service_list_output(output: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut names = Vec::new();
    for token in output.split_whitespace() {
        let base = token.rsplit('/').next().unwrap_or(token);
        if base.is_empty() {
            continue;
        }
        if seen.insert(base.to_string()) {
            names.push(base.to_string());
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_service_list_deduplicates_and_strips_paths() {
        let sample = "/etc/rc.d/sshd /etc/rc.d/syslogd\n/etc/rc.d/sshd";
        let names = parse_service_list_output(sample);
        assert_eq!(names, vec!["sshd".to_string(), "syslogd".to_string()]);
    }

    #[test]
    fn extract_summary_picks_first_non_empty_line() {
        let text = "\n\nsshd is running as pid 123\nextra";
        let summary = extract_summary(text).expect("summary");
        assert_eq!(summary, "sshd is running as pid 123");
    }
}
