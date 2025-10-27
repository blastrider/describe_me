// src/application/health.rs
#![allow(clippy::upper_case_acronyms)]

use crate::domain::{DescribeError, SystemSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    OK = 0,
    WARN = 1,
    CRIT = 2,
}

impl Severity {
    fn max(a: Self, b: Self) -> Self {
        if a as u8 >= b as u8 {
            a
        } else {
            b
        }
    }
}

#[derive(Debug)]
pub enum Check {
    // mem>90%[:warn|:crit]
    Mem {
        op: Cmp,
        pct: f64,
        sev: Severity,
    },
    // disk(/path)>80%[:warn|:crit]
    Disk {
        mount: String,
        op: Cmp,
        pct: f64,
        sev: Severity,
    },
    // service=nginx.service:running[:warn|:crit]
    Service {
        name: String,
        expect: String,
        sev: Severity,
    },
}

#[derive(Debug, Clone, Copy)]
pub enum Cmp {
    Lt,
    Le,
    Gt,
    Ge,
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub ok: bool,
    pub severity: Severity, // si ok=false ⇒ severity=OK
    pub message: String,
}

fn parse_sev(s: &str) -> Option<Severity> {
    match s.to_ascii_lowercase().as_str() {
        "warn" => Some(Severity::WARN),
        "crit" => Some(Severity::CRIT),
        _ => None,
    }
}

fn parse_op(s: &str) -> Option<Cmp> {
    match s {
        ">" => Some(Cmp::Gt),
        ">=" => Some(Cmp::Ge),
        "<" => Some(Cmp::Lt),
        "<=" => Some(Cmp::Le),
        _ => None,
    }
}

fn apply_cmp(op: Cmp, left: f64, right: f64) -> bool {
    match op {
        Cmp::Gt => left > right,
        Cmp::Ge => left >= right,
        Cmp::Lt => left < right,
        Cmp::Le => left <= right,
    }
}

/// Parse une expression `--check`.
/// Formes supportées :
/// - `mem>90%[:warn|:crit]`
/// - `disk(/var)>80%[:warn|:crit]`
/// - `service=nginx.service:running[:warn|:crit]`
/// Par défaut la sévérité est CRIT si non précisée.
pub fn parse_check(expr: &str) -> Result<Check, DescribeError> {
    let expr = expr.trim();

    // Optionnel suffixe ":warn" | ":crit"
    let (core, sev) = match expr.rsplit_once(':') {
        Some((left, right)) if parse_sev(right).is_some() => (left, parse_sev(right).unwrap()),
        _ => (expr, Severity::CRIT),
    };

    // service=NAME:STATE (on a déjà retiré le suffixe de sévérité)
    if core.starts_with("service=") {
        // service=nginx.service:running
        let after = &core["service=".len()..];
        let (name, expect) = after.split_once(':').ok_or_else(|| {
            DescribeError::Parse("service check: attendu service=NAME:STATE".into())
        })?;
        let name = name.trim().to_string();
        let expect = expect.trim().to_string();
        if name.is_empty() || expect.is_empty() {
            return Err(DescribeError::Parse(
                "service check: NAME/STATE vides".into(),
            ));
        }
        return Ok(Check::Service { name, expect, sev });
    }

    // mem OP PCT%
    if core.starts_with("mem") {
        // mem>90%
        let rest = &core["mem".len()..];
        let (op, pct) = parse_op_and_pct(rest)?;
        return Ok(Check::Mem { op, pct, sev });
    }

    // disk(/path)OPpct%
    if core.starts_with("disk(") {
        // disk(/var)>80%
        let after = &core["disk(".len()..];
        let (mount, tail) = after
            .split_once(')')
            .ok_or_else(|| DescribeError::Parse("disk check: attendu disk(/path)OPpct%".into()))?;
        let mount = mount.trim().to_string();
        if mount.is_empty() {
            return Err(DescribeError::Parse("disk check: mount vide".into()));
        }
        let (op, pct) = parse_op_and_pct(tail)?;
        return Ok(Check::Disk {
            mount,
            op,
            pct,
            sev,
        });
    }

    Err(DescribeError::Parse("check: expression inconnue".into()))
}

fn parse_op_and_pct(tail: &str) -> Result<(Cmp, f64), DescribeError> {
    // tail comme `>90%` ou `<=75%`
    let ops = [">=", "<=", ">", "<"];
    let (op_str, num_with_pct) = ops
        .iter()
        .find_map(|&o| tail.strip_prefix(o).map(|rest| (o, rest)))
        .ok_or_else(|| DescribeError::Parse("comparateur manquant (> >= < <=)".into()))?;
    let num_with_pct = num_with_pct.trim();
    let pct_str = num_with_pct
        .strip_suffix('%')
        .ok_or_else(|| DescribeError::Parse("pourcentage attendu (ex: 80%)".into()))?;
    let pct: f64 = pct_str
        .parse()
        .map_err(|_| DescribeError::Parse("pourcentage invalide".into()))?;
    let op = parse_op(op_str).unwrap();
    Ok((op, pct))
}

/// Évalue un check sur un snapshot.
pub fn eval_check(s: &SystemSnapshot, c: &Check) -> Result<CheckResult, DescribeError> {
    match c {
        Check::Mem { op, pct, sev } => {
            let total = s.total_memory_bytes as f64;
            let used = s.used_memory_bytes as f64;
            let percent = if total > 0.0 {
                (used / total) * 100.0
            } else {
                0.0
            };
            let trig = apply_cmp(*op, percent, *pct);
            let msg = format!(
                "mem: used={percent:.1}% threshold {}{:.1}% -> {}",
                fmt_op(*op),
                *pct,
                if trig { "TRIGGER" } else { "OK" }
            );
            Ok(CheckResult {
                ok: !trig,
                severity: if trig { *sev } else { Severity::OK },
                message: msg,
            })
        }

        Check::Disk {
            mount,
            op,
            pct,
            sev,
        } => {
            let du = s.disk_usage.as_ref().ok_or_else(|| {
                DescribeError::System(
                    "disk check: disk_usage absent (with_disk_usage=false ?)".into(),
                )
            })?;
            // cherche la partition exacte par mount_point
            if let Some(p) = du.partitions.iter().find(|p| &p.mount_point == mount) {
                let total = p.total_bytes as f64;
                let avail = p.available_bytes as f64;
                let used_pct = if total > 0.0 {
                    ((total - avail) / total) * 100.0
                } else {
                    0.0
                };
                let trig = apply_cmp(*op, used_pct, *pct);
                let msg = format!(
                    "disk({mount}): used={used_pct:.1}% threshold {}{:.1}% -> {}",
                    fmt_op(*op),
                    *pct,
                    if trig { "TRIGGER" } else { "OK" }
                );
                Ok(CheckResult {
                    ok: !trig,
                    severity: if trig { *sev } else { Severity::OK },
                    message: msg,
                })
            } else {
                Err(DescribeError::Parse(format!(
                    "disk check: mount introuvable: {mount}"
                )))
            }
        }

        Check::Service { name, expect, sev } => {
            #[cfg(not(feature = "systemd"))]
            {
                return Err(DescribeError::System(
                    "service check: nécessite la feature `systemd`".into(),
                ));
            }
            #[cfg(feature = "systemd")]
            {
                let exp = expect.to_ascii_lowercase();
                let found = s.services_running.iter().find(|svc| svc.name == *name);
                match found {
                    Some(svc) => {
                        let ok_state = svc.state.to_ascii_lowercase().contains(&exp);
                        let msg = format!(
                            "service={}: state='{}' expect*='{}' -> {}",
                            name,
                            svc.state,
                            expect,
                            if ok_state { "OK" } else { "TRIGGER" }
                        );
                        Ok(CheckResult {
                            ok: ok_state,
                            severity: if ok_state { Severity::OK } else { *sev },
                            message: msg,
                        })
                    }
                    None => Ok(CheckResult {
                        ok: false,
                        severity: *sev,
                        message: format!("service={}: introuvable -> TRIGGER", name),
                    }),
                }
            }
        }
    }
}

fn fmt_op(op: Cmp) -> &'static str {
    match op {
        Cmp::Gt => ">",
        Cmp::Ge => ">=",
        Cmp::Lt => "<",
        Cmp::Le => "<=",
    }
}

/// Évalue une liste de checks, retourne (max_severity, messages).
pub fn eval_checks(
    s: &SystemSnapshot,
    checks: &[Check],
) -> Result<(Severity, Vec<CheckResult>), DescribeError> {
    let mut max = Severity::OK;
    let mut out = Vec::with_capacity(checks.len());
    for c in checks {
        let r = eval_check(s, c)?;
        if !r.ok {
            max = Severity::max(max, r.severity);
        }
        out.push(r);
    }
    Ok((max, out))
}
