#[cfg(not(feature = "journald"))]
use anyhow::bail;
use anyhow::Result;

use crate::describe_me::args::LogsCommand;

pub fn handle_logs_command(cmd: LogsCommand) -> Result<()> {
    let requested = cmd.lines.max(1);
    let cap = describe_me_lib::HOST_LOGS_MAX_LINES;
    let lines = requested.min(cap);

    #[cfg(feature = "journald")]
    {
        let page = describe_me_lib::tail_host_logs(lines)?;
        if page.entries.is_empty() {
            println!("(aucune entrée journald disponible)");
            return Ok(());
        }

        for entry in page.entries {
            if let Some(source) = entry.source.as_deref() {
                println!("{} [{}] {}", entry.timestamp, source, entry.message);
            } else {
                println!("{} {}", entry.timestamp, entry.message);
            }
        }

        if page.truncated || requested > cap {
            println!(
                "\n(affiche les {} dernières lignes — borne max: {})",
                lines, cap
            );
        }
    }

    #[cfg(not(feature = "journald"))]
    {
        let _ = lines;
        bail!("La lecture des logs journald requiert la feature `journald`.");
    }

    Ok(())
}
