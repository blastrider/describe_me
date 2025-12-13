use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use argon2::password_hash::{PasswordHasher, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use clap::{ArgAction, Args, Parser, Subcommand, ValueEnum};
use rand_core::OsRng;

#[derive(Parser, Debug)]
#[command(name = "describe-me", version, about = "Décrit rapidement le serveur")]
pub struct Opts {
    /// Fichier de config TOML (feature `config`)
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Autorise l'application des drapeaux d'exposition sensibles depuis le fichier de configuration.
    #[arg(long = "allow-config-exposure", action = ArgAction::SetTrue)]
    pub allow_config_exposure: bool,

    #[command(flatten)]
    pub capture: CaptureOpts,

    #[command(flatten)]
    pub output: OutputOpts,

    #[command(flatten)]
    pub history: HistoryOpts,

    #[command(flatten)]
    pub web: WebOpts,

    #[command(flatten)]
    pub exposure: ExposureOpts,

    #[command(flatten)]
    pub web_exposure: WebExposureOpts,

    #[command(flatten)]
    pub checks: CheckOpts,

    #[command(subcommand)]
    pub command: Option<CliCommand>,
}

#[derive(Debug, Args, Clone)]
pub struct CaptureOpts {
    /// Énumérer aussi les services (Linux/systemd)
    #[arg(long)]
    pub with_services: bool,

    /// Collecter aussi les informations sur les conteneurs (plugin externe)
    #[arg(long)]
    pub with_containers: bool,

    /// Limite d'affichage pour les services (mode CLI human-readable).
    #[arg(long = "services-limit", value_name = "N")]
    pub services_limit: Option<usize>,

    /// Décalage de pagination pour les services.
    #[arg(long = "services-offset", value_name = "N", default_value_t = 0)]
    pub services_offset: usize,

    /// Afficher l'usage disque (agrégé + partitions)
    /// (Note: l'usage disque est de toute façon présent dans le snapshot JSON)
    #[arg(long)]
    pub disks: bool,

    /// Affiche les sockets d’écoute (TCP/UDP) — nécessite la feature `net`
    #[arg(long = "net-listen", action = ArgAction::SetTrue)]
    pub net_listen: bool,

    /// Limite d'affichage pour les sockets (mode CLI human-readable).
    #[arg(long = "sockets-limit", value_name = "N")]
    pub sockets_limit: Option<usize>,

    /// Décalage de pagination pour les sockets.
    #[arg(long = "sockets-offset", value_name = "N", default_value_t = 0)]
    pub sockets_offset: usize,

    /// Affiche le trafic réseau agrégé par interface — nécessite la feature `net`
    #[arg(long = "net-traffic", action = ArgAction::SetTrue)]
    pub net_traffic: bool,

    /// Affiche les conteneurs détectés (résumé + tableau)
    #[arg(long = "containers", action = ArgAction::SetTrue)]
    pub containers: bool,

    /// Affiche aussi le PID propriétaire (si résolu) — nécessite `--net-listen`
    #[arg(long = "process", requires = "net_listen", action = ArgAction::SetTrue)]
    pub show_process: bool,
}

#[derive(Debug, Args, Clone)]
pub struct OutputOpts {
    /// Force la sortie 100% JSON (un seul document)
    #[arg(long, action = ArgAction::SetTrue)]
    pub json: bool,

    /// Mise en forme JSON indentée (implique --json)
    #[arg(long, action = ArgAction::SetTrue)]
    pub pretty: bool,

    /// Affiche un résumé concis sur une ligne (ex: updates=3 reboot=no)
    #[arg(long, action = ArgAction::SetTrue)]
    pub summary: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Cli,
    Json,
    JsonPretty,
}

impl OutputOpts {
    pub fn format(&self) -> OutputFormat {
        if self.pretty {
            OutputFormat::JsonPretty
        } else if self.json {
            OutputFormat::Json
        } else {
            OutputFormat::Cli
        }
    }
}

#[derive(Debug, Args, Clone)]
pub struct HistoryOpts {
    /// Profil d'historique à activer (default, ops, paranoid).
    #[arg(long = "history-profile", value_enum)]
    pub profile: Option<HistoryProfileArg>,

    /// Désactive explicitement l'historique (prioritaire).
    #[arg(long = "history-disabled", action = ArgAction::SetTrue)]
    pub disabled: bool,

    /// Nombre de points conservés (ring buffer) pour l'historique local.
    #[arg(long = "history-retention", value_name = "POINTS")]
    pub retention: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistorySelection {
    ConfigOrDefault,
    Disabled,
    Profile(HistoryProfileArg),
}

impl HistoryOpts {
    pub fn selection(&self) -> HistorySelection {
        if self.disabled {
            HistorySelection::Disabled
        } else if let Some(profile) = self.profile {
            HistorySelection::Profile(profile)
        } else {
            HistorySelection::ConfigOrDefault
        }
    }
}

#[derive(Debug, Args, Clone)]
pub struct WebOpts {
    /// Lance un serveur web SSE (HTML/CSS/JS) — nécessite la feature `web`.
    /// Optionnellement préciser l'adresse:port (ex: 127.0.0.1:9000). Par défaut: 127.0.0.1:8080.
    #[arg(
        long = "web",
        value_name = "ADDR:PORT",
        default_missing_value = "127.0.0.1:8080",
        num_args = 0..=1
    )]
    pub bind: Option<String>,

    /// Intervalle d'actualisation (secondes) pour le mode --web (défaut: 2)
    #[arg(long = "web-interval", value_name = "SECS", default_value_t = 2)]
    pub interval_secs: u64,

    /// Affiche également le JSON brut dans l'interface --web
    #[arg(long = "web-debug", action = ArgAction::SetTrue)]
    pub debug: bool,

    /// Mode dev HTTP (désactive Secure sur le cookie de session describe_me_session).
    #[arg(long = "web-dev", action = ArgAction::SetTrue)]
    pub dev_mode: bool,

    /// Hash du jeton requis pour --web (Authorization: Bearer ou en-tête x-describe-me-token)
    #[arg(long = "web-token", value_name = "TOKEN")]
    pub token: Option<String>,

    /// IP ou réseaux autorisés pour --web (peut être répété, ex: 127.0.0.1, 10.0.0.0/16)
    #[arg(long = "web-allow-ip", value_name = "IP[/PREFIX]", action = ArgAction::Append)]
    pub allow_ip: Vec<String>,

    /// Origin autorisé pour l'interface web (peut être répété, ex: https://admin.example.com)
    #[arg(
        long = "web-allow-origin",
        value_name = "ORIGIN",
        action = ArgAction::Append
    )]
    pub allow_origin: Vec<String>,

    /// Proxy de confiance fournissant X-Forwarded-For (--web uniquement)
    #[arg(
        long = "web-trusted-proxy",
        value_name = "IP[/PREFIX]",
        action = ArgAction::Append
    )]
    pub trusted_proxy: Vec<String>,

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
}

#[derive(Debug, Clone)]
pub enum WebTokenSource {
    Literal(String),
    Stdin,
}

#[derive(Debug, Clone)]
pub struct WebTokenHashRequest {
    pub source: WebTokenSource,
    pub algorithm: TokenHashAlgorithm,
}

impl WebOpts {
    pub fn hash_request(&self) -> Option<WebTokenHashRequest> {
        if let Some(token) = &self.hash_web_token {
            Some(WebTokenHashRequest {
                source: WebTokenSource::Literal(token.clone()),
                algorithm: self.hash_web_token_alg,
            })
        } else if self.hash_web_token_stdin {
            Some(WebTokenHashRequest {
                source: WebTokenSource::Stdin,
                algorithm: self.hash_web_token_alg,
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Args, Clone)]
pub struct ExposureOpts {
    /// Expose le hostname exact dans le JSON (opt-in, sinon masqué)
    #[arg(id = "cli-expose-hostname", long = "expose-hostname", action = ArgAction::SetTrue)]
    pub expose_hostname: bool,

    /// Expose la version complète de l'OS dans le JSON
    #[arg(id = "cli-expose-os", long = "expose-os", action = ArgAction::SetTrue)]
    pub expose_os: bool,

    /// Expose la version complète du noyau dans le JSON
    #[arg(id = "cli-expose-kernel", long = "expose-kernel", action = ArgAction::SetTrue)]
    pub expose_kernel: bool,

    /// Expose la liste détaillée des services dans le JSON
    #[arg(id = "cli-expose-services", long = "expose-services", action = ArgAction::SetTrue)]
    pub expose_services: bool,

    /// Expose le détail des partitions disque (points de montage, etc.)
    #[arg(
        id = "cli-expose-disk-partitions",
        long = "expose-disk-partitions",
        action = ArgAction::SetTrue
    )]
    pub expose_disk_partitions: bool,

    /// Expose le trafic réseau par interface dans le JSON
    #[arg(
        id = "cli-expose-network-traffic",
        long = "expose-network-traffic",
        action = ArgAction::SetTrue
    )]
    pub expose_network_traffic: bool,

    /// Expose uniquement le résumé conteneurs (total/running)
    #[arg(
        id = "cli-expose-containers-summary",
        long = "expose-containers-summary",
        action = ArgAction::SetTrue
    )]
    pub expose_containers_summary: bool,

    /// Expose le détail des conteneurs (nom, runtime, IP, image)
    #[arg(
        id = "cli-expose-containers-details",
        long = "expose-containers-details",
        action = ArgAction::SetTrue
    )]
    pub expose_containers_details: bool,

    /// Expose le statut des mises à jour (nombre, reboot requis)
    #[arg(id = "cli-expose-updates", long = "expose-updates", action = ArgAction::SetTrue)]
    pub expose_updates: bool,

    /// Expose les résultats des extensions/plugins
    #[arg(id = "cli-expose-extensions", long = "expose-extensions", action = ArgAction::SetTrue)]
    pub expose_extensions: bool,

    /// Désactive le mode redacted (versions OS/noyau tronquées par défaut). Opt-out explicite : peut exposer des données sensibles.
    #[arg(id = "cli-no-redacted", long = "no-redacted", action = ArgAction::SetTrue)]
    pub no_redacted: bool,

    /// Active tous les champs sensibles d'un coup (hostname, kernel, services...)
    #[arg(id = "cli-expose-all", long = "expose-all", action = ArgAction::SetTrue)]
    pub expose_all: bool,
}

#[derive(Debug, Args, Clone)]
pub struct WebExposureOpts {
    /// Expose le hostname côté --web (sinon masqué par défaut)
    #[arg(
        id = "web-expose-hostname",
        long = "web-expose-hostname",
        action = ArgAction::SetTrue
    )]
    pub expose_hostname: bool,

    /// Expose la version complète de l'OS côté --web
    #[arg(id = "web-expose-os", long = "web-expose-os", action = ArgAction::SetTrue)]
    pub expose_os: bool,

    /// Expose la version complète du noyau côté --web
    #[arg(id = "web-expose-kernel", long = "web-expose-kernel", action = ArgAction::SetTrue)]
    pub expose_kernel: bool,

    /// Expose la liste détaillée des services côté --web
    #[arg(
        id = "web-expose-services",
        long = "web-expose-services",
        action = ArgAction::SetTrue
    )]
    pub expose_services: bool,

    /// Expose les partitions disque détaillées côté --web
    #[arg(
        id = "web-expose-disk-partitions",
        long = "web-expose-disk-partitions",
        action = ArgAction::SetTrue
    )]
    pub expose_disk_partitions: bool,

    /// Expose le trafic réseau par interface côté --web
    #[arg(
        id = "web-expose-network-traffic",
        long = "web-expose-network-traffic",
        action = ArgAction::SetTrue
    )]
    pub expose_network_traffic: bool,

    /// Expose uniquement le résumé conteneurs côté --web
    #[arg(
        id = "web-expose-containers-summary",
        long = "web-expose-containers-summary",
        action = ArgAction::SetTrue
    )]
    pub expose_containers_summary: bool,

    /// Expose le détail des conteneurs côté --web
    #[arg(
        id = "web-expose-containers-details",
        long = "web-expose-containers-details",
        action = ArgAction::SetTrue
    )]
    pub expose_containers_details: bool,

    /// Expose le statut des mises à jour côté --web
    #[arg(id = "web-expose-updates", long = "web-expose-updates", action = ArgAction::SetTrue)]
    pub expose_updates: bool,

    /// Expose les extensions/plugins côté --web
    #[arg(
        id = "web-expose-extensions",
        long = "web-expose-extensions",
        action = ArgAction::SetTrue
    )]
    pub expose_extensions: bool,

    /// Active tous les détails sensibles pour --web
    #[arg(id = "web-expose-all", long = "web-expose-all", action = ArgAction::SetTrue)]
    pub expose_all: bool,
}

#[derive(Debug, Args, Clone, Default)]
pub struct CheckOpts {
    /// Vérifications healthcheck (peut être répété). Ex:
    /// --check mem>90%[:warn|:crit]
    /// --check disk(/var)>80%[:warn|:crit]
    /// --check service=nginx.service:running[:warn|:crit]
    #[arg(long = "check", value_name = "EXPR", action = ArgAction::Append)]
    pub checks: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CliConfig {
    pub config_path: Option<PathBuf>,
    pub allow_config_exposure: bool,
    pub capture: CaptureOpts,
    pub output: OutputOpts,
    pub history: HistoryOpts,
    pub web: WebOpts,
    pub exposure: ExposureOpts,
    pub web_exposure: WebExposureOpts,
    pub checks: Vec<String>,
    pub command: Option<CliCommand>,
}

impl From<Opts> for CliConfig {
    fn from(opts: Opts) -> Self {
        Self {
            config_path: opts.config,
            allow_config_exposure: opts.allow_config_exposure,
            capture: opts.capture,
            output: opts.output,
            history: opts.history,
            web: opts.web,
            exposure: opts.exposure,
            web_exposure: opts.web_exposure,
            checks: opts.checks.checks,
            command: opts.command,
        }
    }
}

pub fn parse() -> CliConfig {
    Opts::parse().into()
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum TokenHashAlgorithm {
    #[value(alias = "argon2")]
    Argon2id,
    Bcrypt,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum HistoryProfileArg {
    Default,
    Ops,
    Paranoid,
}

#[derive(Debug, Subcommand, Clone)]
pub enum CliCommand {
    /// Gère les métadonnées persistées (redb).
    #[command(subcommand)]
    Metadata(MetadataCommand),
    /// Outils autour des plugins/collecteurs externes.
    #[command(subcommand)]
    Plugin(PluginCommand),
    /// Interroge l'historique local (mini time-series).
    History(HistoryCommand),
    /// Affiche les logs système de l'hôte (dern. lignes).
    Logs(LogsCommand),
}

#[derive(Debug, Subcommand, Clone)]
pub enum MetadataCommand {
    /// Manipule la description du serveur stockée en base.
    #[command(subcommand)]
    Description(DescriptionCommand),
    /// Gère la liste des tags serveur.
    #[command(subcommand)]
    Tags(TagsCommand),
}

#[derive(Debug, Subcommand, Clone)]
pub enum DescriptionCommand {
    /// Affiche la description actuelle.
    Show,
    /// Définit une nouvelle description (texte libre).
    Set {
        #[arg(value_name = "TEXTE")]
        text: String,
    },
    /// Supprime la description persistée.
    Clear,
}

#[derive(Debug, Subcommand, Clone)]
pub enum TagsCommand {
    /// Affiche les tags actuels.
    Show,
    /// Remplace complètement la liste des tags.
    Set {
        #[arg(value_name = "TAG", required = true, num_args = 1..)]
        tags: Vec<String>,
    },
    /// Ajoute un ou plusieurs tags à la liste existante.
    Add {
        #[arg(value_name = "TAG", required = true, num_args = 1..)]
        tags: Vec<String>,
    },
    /// Supprime un ou plusieurs tags existants.
    Remove {
        #[arg(value_name = "TAG", required = true, num_args = 1..)]
        tags: Vec<String>,
    },
    /// Supprime tous les tags.
    Clear,
}

#[derive(Debug, Subcommand, Clone)]
pub enum PluginCommand {
    /// Lance un plugin externe et affiche sa sortie JSON.
    Run(PluginRunCommand),
}

#[derive(Debug, Args, Clone)]
pub struct HistoryCommand {
    /// Identifiant de serveur (hash stable).
    #[arg(long = "server", value_name = "ID")]
    pub server: Option<String>,
    /// Fenêtre temporelle à analyser (secondes).
    #[arg(long = "window", value_name = "SECS", default_value_t = 900)]
    pub window: u64,
    /// Nombre maximum de points à afficher (≤ rétention).
    #[arg(long = "limit", value_name = "POINTS")]
    pub limit: Option<usize>,
}

#[derive(Debug, Args, Clone)]
pub struct PluginRunCommand {
    /// Nom logique du plugin (ex: certificates, inventory).
    #[arg(long = "name", value_name = "NAME")]
    pub name: String,
    /// Arguments transmis au plugin (répéter --arg pour plusieurs valeurs).
    #[arg(long = "arg", value_name = "ARG", action = ArgAction::Append)]
    pub args: Vec<String>,
    /// Timeout maximum (secondes) avant d'interrompre le plugin.
    #[arg(long = "timeout", value_name = "SECS", default_value_t = 10)]
    pub timeout_secs: u64,
}

#[derive(Debug, Args, Clone)]
pub struct LogsCommand {
    /// Nombre de lignes à lire (borné côté programme).
    #[arg(long = "lines", value_name = "N", default_value_t = 200)]
    pub lines: usize,
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
        assert!(opts.exposure.expose_updates);
        assert!(!opts.web_exposure.expose_updates);

        let opts = Opts::try_parse_from(["describe-me", "--web-expose-updates"]).unwrap();
        assert!(!opts.exposure.expose_updates);
        assert!(opts.web_exposure.expose_updates);
    }

    #[test]
    fn parses_expose_network_traffic_flags() {
        let opts = Opts::try_parse_from(["describe-me", "--expose-network-traffic"]).unwrap();
        assert!(opts.exposure.expose_network_traffic);
        assert!(!opts.web_exposure.expose_network_traffic);

        let opts = Opts::try_parse_from(["describe-me", "--web-expose-network-traffic"]).unwrap();
        assert!(!opts.exposure.expose_network_traffic);
        assert!(opts.web_exposure.expose_network_traffic);
    }

    #[test]
    fn parses_expose_extensions_flags() {
        let opts = Opts::try_parse_from(["describe-me", "--expose-extensions"]).unwrap();
        assert!(opts.exposure.expose_extensions);
        assert!(!opts.web_exposure.expose_extensions);

        let opts = Opts::try_parse_from(["describe-me", "--web-expose-extensions"]).unwrap();
        assert!(!opts.exposure.expose_extensions);
        assert!(opts.web_exposure.expose_extensions);
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

    #[test]
    fn parses_metadata_description_set_command() {
        let opts = Opts::try_parse_from([
            "describe-me",
            "metadata",
            "description",
            "set",
            "Serveur FTP",
        ])
        .unwrap();
        match opts.command {
            Some(CliCommand::Metadata(MetadataCommand::Description(DescriptionCommand::Set {
                text,
            }))) => assert_eq!(text, "Serveur FTP"),
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_metadata_description_show_command() {
        let opts =
            Opts::try_parse_from(["describe-me", "metadata", "description", "show"]).unwrap();
        assert!(matches!(
            opts.command,
            Some(CliCommand::Metadata(MetadataCommand::Description(
                DescriptionCommand::Show
            )))
        ));
    }

    #[test]
    fn parses_metadata_tags_commands() {
        let opts =
            Opts::try_parse_from(["describe-me", "metadata", "tags", "set", "ubuntu", "ftp"])
                .unwrap();
        match opts.command {
            Some(CliCommand::Metadata(MetadataCommand::Tags(TagsCommand::Set { tags }))) => {
                assert_eq!(tags, vec!["ubuntu", "ftp"]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parses_plugin_run_command() {
        let opts = Opts::try_parse_from([
            "describe-me",
            "plugin",
            "run",
            "--name",
            "certificates",
            "--arg",
            "foo",
            "--timeout",
            "7",
        ])
        .unwrap();
        match opts.command {
            Some(CliCommand::Plugin(PluginCommand::Run(run))) => {
                assert_eq!(run.name, "certificates");
                assert_eq!(run.args, vec!["foo"]);
                assert_eq!(run.timeout_secs, 7);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
