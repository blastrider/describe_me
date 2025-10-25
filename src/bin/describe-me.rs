#![forbid(unsafe_code)]
#[path = "../cli/opts.rs"]
mod cli_opts;
#[cfg(feature = "config")]
#[path = "describe_me/config_guard.rs"]
mod config_guard;
#[path = "describe_me/output.rs"]
mod output;
#[cfg(feature = "web")]
#[path = "describe_me/web_mode.rs"]
mod web_mode;

use anyhow::Result;
use clap::Parser;

#[cfg(feature = "net")]
use output::ListeningSocketOut;

use cli_opts::Opts;

fn main() -> Result<()> {
    let opts = Opts::parse();

    #[cfg(feature = "config")]
    let cfg = config_guard::load_config(&opts)?;

    #[cfg(not(feature = "config"))]
    if opts.config.is_some() {
        anyhow::bail!(
            "--config nécessite la feature `config` (cargo run --features \"cli systemd config\")."
        );
    }

    #[cfg(feature = "web")]
    if web_mode::handle_web_mode(
        &opts,
        #[cfg(feature = "config")]
        &cfg,
    )? {
        return Ok(());
    }

    #[cfg(not(feature = "web"))]
    if opts.web.is_some() {
        anyhow::bail!("--web nécessite la feature `web` (cargo run --features \"cli web\").");
    }

    #[cfg(not(feature = "systemd"))]
    if opts.with_services {
        anyhow::bail!("--with-services nécessite la feature `systemd` (cargo run --features \"cli systemd\").");
    }

    #[cfg(not(feature = "net"))]
    if opts.net_listen {
        anyhow::bail!("--net-listen nécessite la feature `net` (cargo run --features \"cli net\").");
    }

    #[allow(unused_mut)]
    let mut snap = describe_me::SystemSnapshot::capture_with(describe_me::CaptureOptions {
        with_services: opts.with_services,
        with_disk_usage: true,
    })?;

    #[cfg(all(feature = "systemd", feature = "config"))]
    if let Some(cfg) = &cfg {
        snap.services_running =
            describe_me::filter_services(std::mem::take(&mut snap.services_running), cfg);
    }

    #[cfg(feature = "net")]
    let net_listen_vec: Option<Vec<ListeningSocketOut>> = if opts.net_listen {
        Some(output::collect_net_listen()?)
    } else {
        None
    };

    if opts.json || opts.pretty {
        #[cfg(feature = "cli")]
        {
            output::emit_json(
                snap,
                opts.pretty,
                #[cfg(feature = "net")]
                net_listen_vec,
            )?;
        }
        #[cfg(not(feature = "cli"))]
        {
            output::emit_json(snap, opts.pretty)?;
        }
        return Ok(());
    }

    #[cfg(feature = "net")]
    if opts.net_listen {
        output::print_net_table(net_listen_vec.as_deref(), opts.show_process);
        println!();
    }

    if opts.disks {
        output::print_disks(&snap);
        println!();
    }

    output::print_snapshot(&snap)?;
    Ok(())
}
