use crate::cli_opts::Opts;
use anyhow::{bail, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::runtime;

pub(crate) fn handle_web_mode(
    opts: &Opts,
    #[cfg(feature = "config")] cfg: &Option<describe_me::DescribeConfig>,
) -> Result<bool> {
    if let Some(addr) = opts.web {
        ensure_safe_defaults(opts, addr)?;
        validate_bind(&addr, opts.web_allow_remote)?;

        let tick = Duration::from_secs(opts.web_interval_secs);

        #[cfg(feature = "config")]
        let cfg_for_web = cfg.clone();

        let web_debug = opts.web_debug;
        let rt = runtime::Builder::new_multi_thread().enable_all().build()?;
        rt.block_on(async move {
            describe_me::serve_http(
                addr,
                tick,
                #[cfg(feature = "config")]
                cfg_for_web,
                web_debug,
            )
            .await
        })?;
        return Ok(true);
    }

    Ok(false)
}

fn ensure_safe_defaults(opts: &Opts, addr: SocketAddr) -> Result<()> {
    if opts.safe_defaults && opts.web_allow_remote {
        bail!("--safe-defaults actif : --web-allow-remote interdit.");
    }
    if opts.safe_defaults && !is_loopback(addr.ip()) {
        bail!("--safe-defaults actif : écoute limitée à 127.0.0.1/::1.");
    }
    Ok(())
}

fn is_loopback(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

fn validate_bind(addr: &SocketAddr, allow_remote: bool) -> Result<()> {
    if !is_loopback(addr.ip()) && !allow_remote {
        bail!(
            "refus d’écoute non locale: utilisez --web-allow-remote si vous assumez l’exposition."
        );
    }
    Ok(())
}
