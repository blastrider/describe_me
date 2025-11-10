use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::{ArgAction, Parser, ValueEnum};
use rand_core::OsRng;

#[derive(Parser, Debug)]
#[command(name = "describe-me", version, about = "Décrit rapidement le serveur")]
pub struct Opts {
    /// Énumérer aussi les services (Linux/systemd)
    #[arg(long)]
    pub with_services: bool,

    /// Afficher l'usage disque (agrégé + partitions)
    /// (Note: l'usage disque est de toute façon présent dans le snapshot JSON)
    #[arg(long)]
    pub disks: bool,

    /// Fichier de config TOML (feature `config`)
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Affiche les sockets d’écoute (TCP/UDP) — nécessite la feature `net`
    #[arg(long = "net-listen", action = ArgAction::SetTrue)]
    pub net_listen: bool,

    /// Affiche le trafic réseau agrégé par interface — nécessite la feature `net`
    #[arg(long = "net-traffic", action = ArgAction::SetTrue)]
    pub net_traffic: bool,

    /// Affiche aussi le PID propriétaire (si résolu) — nécessite `--net-listen`
    #[arg(long = "process", requires = "net_listen", action = ArgAction::SetTrue)]
    pub show_process: bool,

    /// Force la sortie 100% JSON (un seul document)
    #[arg(long, action = ArgAction::SetTrue)]
    pub json: bool,

    /// Mise en forme JSON indentée (implique --json)
    #[arg(long, action = ArgAction::SetTrue)]
    pub pretty: bool,

    /// Affiche un résumé concis sur une ligne (ex: updates=3 reboot=no)
    #[arg(long, action = ArgAction::SetTrue)]
    pub summary: bool,

    /// Lance un serveur web SSE (HTML/CSS/JS) — nécessite la feature `web`.
    /// Optionnellement préciser l'adresse:port (ex: 127.0.0.1:9000). Par défaut: 127.0.0.1:8080.
    #[arg(
        long = "web",
        value_name = "ADDR:PORT",
        default_missing_value = "127.0.0.1:8080",
        num_args = 0..=1
    )]
    pub web: Option<String>,

    /// Intervalle d'actualisation (secondes) pour le mode --web (défaut: 2)
    #[arg(long = "web-interval", value_name = "SECS", default_value_t = 2)]
    pub web_interval_secs: u64,

    /// Affiche également le JSON brut dans l'interface --web
    #[arg(long = "web-debug", action = ArgAction::SetTrue)]
    pub web_debug: bool,

    /// Hash du jeton requis pour --web (Authorization: Bearer ou en-tête x-describe-me-token)
    #[arg(long = "web-token", value_name = "TOKEN")]
    pub web_token: Option<String>,

    /// IP ou réseaux autorisés pour --web (peut être répété, ex: 127.0.0.1, 10.0.0.0/16)
    #[arg(long = "web-allow-ip", value_name = "IP[/PREFIX]", action = ArgAction::Append)]
    pub web_allow_ip: Vec<String>,

    /// Origin autorisé pour l'interface web (peut être répété, ex: https://admin.example.com)
    #[arg(
        long = "web-allow-origin",
        value_name = "ORIGIN",
        action = ArgAction::Append
    )]
    pub web_allow_origin: Vec<String>,

    /// Proxy de confiance fournissant X-Forwarded-For (--web uniquement)
    #[arg(
        long = "web-trusted-proxy",
        value_name = "IP[/PREFIX]",
        action = ArgAction::Append
    )]
    pub web_trusted_proxy: Vec<String>,

    /// Génère un hash (Argon2id/bcrypt) pour configurer --web-token (helper)
    #[arg(
        long = "hash-web-token",
        value_name = "TOKEN",
        conflicts_with = "hash_web_token_stdin"
    )]
    pub hash_web_token: Option<String>,

    /// Lit le token depuis stdin et génère un hash (helper)
    #[arg(
        long = "hash-web-token-stdin",
        action = ArgAction::SetTrue,
        conflicts_with = "hash_web_token"
    )]
    pub hash_web_token_stdin: bool,

    /// Algorithme utilisé avec --hash-web-token (--hash-web-token-stdin)
    #[arg(
        long = "hash-web-token-alg",
        value_enum,
        default_value_t = TokenHashAlgorithm::Argon2id
    )]
    pub hash_web_token_alg: TokenHashAlgorithm,

    /// Expose le hostname exact dans le JSON (opt-in, sinon masqué)
    #[arg(long = "expose-hostname", action = ArgAction::SetTrue)]
    pub expose_hostname: bool,

    /// Expose la version complète de l'OS dans le JSON
    #[arg(long = "expose-os", action = ArgAction::SetTrue)]
    pub expose_os: bool,

    /// Expose la version complète du noyau dans le JSON
    #[arg(long = "expose-kernel", action = ArgAction::SetTrue)]
    pub expose_kernel: bool,

    /// Expose la liste détaillée des services dans le JSON
    #[arg(long = "expose-services", action = ArgAction::SetTrue)]
    pub expose_services: bool,

    /// Expose le détail des partitions disque (points de montage, etc.)
    #[arg(long = "expose-disk-partitions", action = ArgAction::SetTrue)]
    pub expose_disk_partitions: bool,

    /// Expose le trafic réseau par interface dans le JSON
    #[arg(long = "expose-network-traffic", action = ArgAction::SetTrue)]
    pub expose_network_traffic: bool,

    /// Expose le statut des mises à jour (nombre, reboot requis)
    #[arg(long = "expose-updates", action = ArgAction::SetTrue)]
    pub expose_updates: bool,

    /// Désactive le mode redacted (versions OS/noyau tronquées par défaut).
    #[arg(long = "no-redacted", action = ArgAction::SetTrue)]
    pub no_redacted: bool,

    /// Active tous les champs sensibles d'un coup (hostname, kernel, services...)
    #[arg(long = "expose-all", action = ArgAction::SetTrue)]
    pub expose_all: bool,

    /// Expose le hostname côté --web (sinon masqué par défaut)
    #[arg(long = "web-expose-hostname", action = ArgAction::SetTrue)]
    pub web_expose_hostname: bool,

    /// Expose la version complète de l'OS côté --web
    #[arg(long = "web-expose-os", action = ArgAction::SetTrue)]
    pub web_expose_os: bool,

    /// Expose la version complète du noyau côté --web
    #[arg(long = "web-expose-kernel", action = ArgAction::SetTrue)]
    pub web_expose_kernel: bool,

    /// Expose la liste détaillée des services côté --web
    #[arg(long = "web-expose-services", action = ArgAction::SetTrue)]
    pub web_expose_services: bool,

    /// Expose les partitions disque détaillées côté --web
    #[arg(long = "web-expose-disk-partitions", action = ArgAction::SetTrue)]
    pub web_expose_disk_partitions: bool,

    /// Expose le trafic réseau par interface côté --web
    #[arg(long = "web-expose-network-traffic", action = ArgAction::SetTrue)]
    pub web_expose_network_traffic: bool,

    /// Expose le statut des mises à jour côté --web
    #[arg(long = "web-expose-updates", action = ArgAction::SetTrue)]
    pub web_expose_updates: bool,

    /// Active tous les détails sensibles pour --web
    #[arg(long = "web-expose-all", action = ArgAction::SetTrue)]
    pub web_expose_all: bool,

    /// Autorise l'application des drapeaux d'exposition sensibles depuis le fichier de configuration.
    #[arg(long = "allow-config-exposure", action = ArgAction::SetTrue)]
    pub allow_config_exposure: bool,

    /// Vérifications healthcheck (peut être répété). Ex:
    /// --check mem>90%[:warn|:crit]
    /// --check disk(/var)>80%[:warn|:crit]
    /// --check service=nginx.service:running[:warn|:crit]
    #[arg(long = "check", value_name = "EXPR", action = ArgAction::Append)]
    pub checks: Vec<String>,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum TokenHashAlgorithm {
    #[value(alias = "argon2")]
    Argon2id,
    Bcrypt,
}

pub fn parse() -> Opts {
    Opts::parse()
}

pub fn hash_web_token(token: &str, algorithm: TokenHashAlgorithm) -> Result<String> {
    match algorithm {
        TokenHashAlgorithm::Argon2id => {
            let salt = SaltString::generate(&mut OsRng);
            let params = Params::new(128 * 1024, 4, 1, None)
                .map_err(|err| anyhow!("argon2 params: {err}"))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let hash = argon2
                .hash_password(token.as_bytes(), &salt)
                .map_err(|err| anyhow!("argon2id: {err}"))?;
            Ok(hash.to_string())
        }
        TokenHashAlgorithm::Bcrypt => {
            let hash = bcrypt::hash(token, bcrypt::DEFAULT_COST)?;
            Ok(hash)
        }
    }
}

pub fn read_token_from_stdin() -> Result<String> {
    use std::io::{self, Read};

    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .context("lecture du token depuis stdin")?;
    Ok(buffer.trim_end_matches(&['\n', '\r'][..]).to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_expose_updates_flags() {
        let opts = Opts::try_parse_from(["describe-me", "--expose-updates"]).unwrap();
        assert!(opts.expose_updates);
        assert!(!opts.web_expose_updates);

        let opts = Opts::try_parse_from(["describe-me", "--web-expose-updates"]).unwrap();
        assert!(!opts.expose_updates);
        assert!(opts.web_expose_updates);
    }

    #[test]
    fn parses_expose_network_traffic_flags() {
        let opts = Opts::try_parse_from(["describe-me", "--expose-network-traffic"]).unwrap();
        assert!(opts.expose_network_traffic);
        assert!(!opts.web_expose_network_traffic);

        let opts = Opts::try_parse_from(["describe-me", "--web-expose-network-traffic"]).unwrap();
        assert!(!opts.expose_network_traffic);
        assert!(opts.web_expose_network_traffic);
    }

    #[test]
    fn argon2_hash_uses_hardened_params() {
        let hash = hash_web_token("secret", TokenHashAlgorithm::Argon2id).expect("hash");
        assert!(
            hash.contains("m=131072"),
            "expected Argon2 memory cost 131072, got {hash}"
        );
        assert!(
            hash.contains("t=4"),
            "expected Argon2 iteration count 4, got {hash}"
        );
    }
}
