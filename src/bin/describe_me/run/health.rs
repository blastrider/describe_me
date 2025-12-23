#[derive(Debug)]
pub enum HealthcheckOutcome {
    Skip,
    Exit {
        exit_code: i32,
        messages: Vec<String>,
    },
}

pub fn evaluate_healthchecks(
    checks: &[String],
    snap: &describe_me_lib::SystemSnapshot,
) -> HealthcheckOutcome {
    if checks.is_empty() {
        return HealthcheckOutcome::Skip;
    }

    let mut parsed = Vec::with_capacity(checks.len());
    for e in checks {
        match describe_me_lib::parse_check(e) {
            Ok(c) => parsed.push(c),
            Err(err) => {
                return HealthcheckOutcome::Exit {
                    exit_code: 2,
                    messages: vec![format!("[CHECK] parse error pour '{e}': {err}")],
                };
            }
        }
    }

    match describe_me_lib::eval_checks(snap, &parsed) {
        Ok((max_sev, results)) => {
            let messages = results
                .into_iter()
                .map(|r| format!("[CHECK] {}", r.message))
                .collect::<Vec<_>>();
            HealthcheckOutcome::Exit {
                exit_code: max_sev as i32,
                messages,
            }
        }
        Err(err) => HealthcheckOutcome::Exit {
            exit_code: 2,
            messages: vec![format!("[CHECK] evaluation error: {err}")],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn healthcheck_parse_error_is_reported() {
        let snapshot = describe_me_lib::SystemSnapshot {
            hostname: "host".into(),
            os: None,
            kernel: None,
            uptime_seconds: 0,
            cpu_count: 1,
            load_average: (0.0, 0.0, 0.0),
            total_memory_bytes: 0,
            used_memory_bytes: 0,
            total_swap_bytes: 0,
            used_swap_bytes: 0,
            disk_usage: None,
            #[cfg(feature = "systemd")]
            services_running: describe_me_lib::SharedSlice::from_vec(Vec::new()),
            #[cfg(feature = "net")]
            listening_sockets: None,
            #[cfg(feature = "net")]
            network_traffic: None,
            containers: None,
            updates: None,
            extensions: None,
        };

        let outcome = evaluate_healthchecks(&["???".into()], &snapshot);
        match outcome {
            HealthcheckOutcome::Exit {
                exit_code,
                messages,
            } => {
                assert_eq!(exit_code, 2);
                assert!(messages[0].contains("parse error"));
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
}
