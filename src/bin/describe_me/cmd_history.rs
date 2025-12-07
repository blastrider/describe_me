use std::time::Duration;

use anyhow::{bail, Result};
use describe_me_lib::{AppContext, HistoryQueryError, HistorySeries, MetricAggregate};

use crate::describe_me::args::HistoryCommand;

pub fn handle_history_command(cmd: HistoryCommand, ctx: &AppContext) -> Result<()> {
    let settings = ctx.history().settings_snapshot();
    if !settings.is_active() {
        bail!("L'historique n'est pas activé sur cette instance.");
    }

    let server_id = if let Some(id) = cmd.server {
        id
    } else if let Some(default_id) = ctx.history().default_server_id() {
        default_id
    } else {
        bail!("Aucun identifiant serveur n'est disponible (aucun snapshot capturé ?).");
    };

    let window_secs = cmd.window.max(1);
    let rounding = settings.rounding_seconds.max(1);
    let retention_cap = settings.retention_points.max(16) as usize;
    let default_limit = retention_cap.min(256);
    let limit = cmd
        .limit
        .filter(|v| *v > 0)
        .unwrap_or(default_limit)
        .min(retention_cap)
        .max(1);

    let series = match ctx.history().query_series(
        &server_id,
        Duration::from_secs(window_secs),
        limit,
        rounding,
    ) {
        Ok(series) => series,
        Err(err) => {
            map_history_error(err)?;
            return Ok(());
        }
    };

    print_history_series(&series);
    Ok(())
}

fn map_history_error(err: HistoryQueryError) -> Result<()> {
    match err {
        HistoryQueryError::Disabled => {
            bail!("L'historique n'est plus actif ou a été désactivé.");
        }
        HistoryQueryError::InvalidLimit => {
            bail!("La limite demandée n'est pas valide.");
        }
        HistoryQueryError::InvalidServer => {
            bail!("Identifiant de serveur invalide.");
        }
        HistoryQueryError::NotFound => {
            println!("Aucune donnée historique disponible pour ce serveur.");
            Ok(())
        }
        HistoryQueryError::Storage(err) => {
            bail!("Lecture de l'historique impossible: {err}");
        }
    }
}

fn print_history_series(series: &HistorySeries) {
    println!(
        "Serveur: {}\nFenêtre: {}s | Points: {} | Bucket: {}s | Agrégé: {} | Tronqué: {}",
        series.server_id,
        series.window_seconds,
        series.points.len(),
        series.bucket_seconds,
        if series.aggregated { "oui" } else { "non" },
        if series.truncated { "oui" } else { "non" }
    );
    println!(
        "{:>20}  {:>18}  {:>18}  {:>18}",
        "timestamp", "cpu avg/min/max", "mem avg/min/max", "disk avg/min/max"
    );
    for point in &series.points {
        println!(
            "{:>20}  {:>18}  {:>18}  {:>18}",
            point.timestamp,
            format_metric(&point.cpu),
            format_metric(&point.mem),
            format_metric(&point.disk),
        );
    }
}

fn format_metric(metric: &MetricAggregate) -> String {
    match metric.avg {
        Some(avg) => {
            let min = metric.min.unwrap_or(avg);
            let max = metric.max.unwrap_or(avg);
            if approx_equal(min, avg) && approx_equal(max, avg) {
                format!("{avg:>6.1}%")
            } else {
                format!("{avg:>5.1}% ({min:>4.1}-{max:>4.1})")
            }
        }
        None => String::from("    --"),
    }
}

fn approx_equal(a: f32, b: f32) -> bool {
    (a - b).abs() < 0.05
}
