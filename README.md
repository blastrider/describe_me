describe_me

Décrit rapidement un serveur (CPU, RAM, OS, uptime, services…), utile aux admins système.
Fonctionne en lib Rust et en CLI (describe-me).

Le binaire refuse volontairement d'être exécuté en root (UID 0). Utilise un compte dédié ou `sudo -u` pour le lancer.

MSRV : 1.90.0

Licence : Apache-2.0

Repo : https://github.com/Max-Perso/describe_me

Documentation supplémentaire : voir le dossier `docs/` :
- `docs/architecture.md` — vue d’ensemble des couches et features.
- `docs/application-layer.md` — logique applicative et serveurs.
- `docs/domain-layer.md` — modèles métier et configuration.
- `docs/infrastructure-layer.md` — intégrations OS (sysinfo, systemd, net).
- `docs/web-security.md` — détails sur l’authentification/rate limiting web.
- `docs/cli.md` — options et flux du binaire `describe-me`.
- `docs/testing.md` — stratégie de tests, benchmarks et fuzzing.
- `docs/logging.md` — conventions de logging structurés.

1) Installation
Depuis les sources
# Cloner
git clone https://github.com/Max-Perso/describe_me
cd describe_me

# Build (lib + tests de base)
cargo build
cargo test

Activer le binaire CLI

Le CLI est derrière la feature cli. Ajoute des features selon tes besoins :

systemd : énumère les services (Linux/systemd)

config : charge un fichier TOML (filtrage services)

net : sockets d’écoute (TCP/UDP)

web : UI & SSE HTTP (Axum), endpoints temps-réel

Exemples :

# CLI seul
cargo build --features "cli"

# CLI + systemd + config + net
cargo build --features "cli systemd config net"

# Tout (incluant serveur web)
cargo build --features "cli systemd config net web"

2) Utilisation rapide (CLI)

Afficher un snapshot JSON lisible :

./target/debug/describe-me


Options courantes :

# Services (systemd requis)
./target/debug/describe-me --with-services

# Disques (agrégé + partitions)
./target/debug/describe-me --disks

# Sockets d’écoute (feature net requise)
./target/debug/describe-me --net-listen

# Charger une config TOML (feature config requise)
./target/debug/describe-me --config ./src/examples/config.toml

# JSON compact / pretty (inclut snapshot complet)
./target/debug/describe-me --json
./target/debug/describe-me --pretty


Astuce : combine librement, ex.
./describe-me --with-services --disks --net-listen --config config.toml --pretty

Exemple de sortie (résumé lisible)
Hostname: srv-app-01
OS: Linux 6.8 (Debian 12)
Uptime: 3j 04h 12m 09s
CPU(s): 8
RAM: 16.0 GiB (utilisée 6.3 GiB)
Disque total: 500 GiB (libre 320 GiB)
Services actifs: nginx, postgresql, ...
Sockets écoute: tcp/0.0.0.0:22, tcp/127.0.0.1:5432, ...

2 bis) Service systemd durci

Un fichier d'unité `systemd` avec durcissement agressif est disponible dans `packaging/systemd/describe-me.service`.

Étapes rapides :

```bash
sudo install -m 0644 packaging/systemd/describe-me.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now describe-me.service
```

Adapte `ExecStart=` selon ton usage (`--web`, jeton, config TOML, etc.). Le service tourne sous un `DynamicUser` jetable, sans capability (`CapabilityBoundingSet=`), et applique `NoNewPrivileges=yes`, `PrivateTmp=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateDevices=yes`, `RestrictNamespaces=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallFilter=@system-service`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `UMask=0027`, `ProtectKernel{Modules,Logs,Tunables}=yes`, `ProtectControlGroups=yes`, `LockPersonality=yes`, `PrivateUsers=yes`, etc.

Seules les écritures explicites vers `/var/lib/describe-me` (créé via `StateDirectory=`) sont autorisées (`ReadWritePaths=`). Un `TemporaryFileSystem=/var/tmp` évite toute interaction avec le `/var/tmp` global. Ajuste `RestrictAddressFamilies=` ou ajoute des exceptions via un `systemctl edit describe-me` si besoin d'autres sockets.

Astuce : grâce au refus d'exécution en root du binaire, lance-le manuellement via `sudo -u describe-me describe-me ...` pour reproduire l'environnement du service.

3) Healthcheck --check (codes 0/1/2)

Permet de scripter des checks (CI/Nagios/Icinga). Retourne le plus sévère rencontré :

0 = OK

1 = WARN

2 = CRIT

Formes supportées :

mem>90%[:warn|:crit]

disk(/point_de_montage)>80%[:warn|:crit]

service=nginx.service:running[:warn|:crit] (nécessite --with-services et feature systemd)

Exemples :

# CRIT si mémoire > 90%
./target/debug/describe-me --check 'mem>90%'

# WARN si /var > 80%
./target/debug/describe-me --check 'disk(/var)>80%:warn' >/dev/null; echo $?

# Service (state contient "running") — nécessite systemd + --with-services
./target/debug/describe-me --with-services --check 'service=ssh.service:running' >/dev/null; echo $?

# Checks multiples : code de sortie = max(WARN/CRIT)
./target/debug/describe-me \
  --with-services \
  --check 'mem>85%:warn' \
  --check 'mem>95%:crit' \
  --check 'disk(/)>90%:crit' \
  >/dev/null; echo $?


Intégration simple Nagios/Icinga (stderr contient les messages) :

/opt/describe-me --with-services \
  --check 'mem>90%:crit' \
  --check 'disk(/var)>80%:warn' \
  >/dev/null

4) Mode Web (SSE temps réel)

Nécessite --features web (et cli côté binaire).

Lancer un mini-serveur SSE avec UI intégrée (HTML/CSS/JS) :

./target/debug/describe-me \
  --web \
  --web-token super-secret \
  --web-interval 2 \
  --web-debug \
  --with-services

Ensuite, ouvrez l'interface sur `http://127.0.0.1:8080/`. L'UI vous demandera le jeton et l'enverra via l'en-tête `Authorization: Bearer` (ou `x-describe-me-token`) pour le flux `/sse`.
Le jeton est mémorisé uniquement dans la session du navigateur et peut être réinitialisé via « Modifier le jeton ».

Pour exposer publiquement, fournissez explicitement l'adresse (ex :`--web 0.0.0.0:8080`) **et** un contrôle d'accès adapté (`--web-token …` et/ou `--web-allow-ip 203.0.113.0/24`).

Les champs sensibles (hostname, version d'OS/noyau, services détaillés, partitions disque) sont masqués par défaut dans le JSON/SSE. Utilisez les flags `--expose-*` / `--web-expose-*` ou la configuration TOML pour les rendre visibles de façon volontaire.


GET / : page HTML (cartes système/mémoire/disque/services)

GET /sse : flux SSE (JSON) émettant périodiquement SystemSnapshot

--web-debug : affiche aussi le JSON brut dans l’UI

Le filtrage des services via config s’applique aussi côté web si --config est fourni

En prod, place-le derrière un reverse proxy/TLS (Nginx/Traefik).
(Roadmap : TLS natif + Basic Auth optionnelle.)

5) Fichier de configuration (optionnel)

Disponible avec --features config.
Actuellement : whitelist des services + configuration du mode web + exposition des champs sensibles.

Exemple minimal config.toml
# Filtrage d’affichage des services (si feature systemd et --with-services)
[services]
include = ["nginx.service", "postgresql.service"]

# Contrôles d'accès web par défaut (optionnels)
[web]
token = "super-secret"
allow_ips = ["127.0.0.1", "10.0.0.0/16"]

[web.exposure]
expose_services = true
expose_disk_partitions = true

# Exposition des champs sensibles pour la sortie CLI/JSON (par défaut: tout masqué)
[exposure]
expose_hostname = true
expose_os = true
expose_kernel = true
redacted = true


Utilisation CLI :

./target/debug/describe-me --with-services --config ./src/examples/config.toml


Utilisation lib :

#[cfg(feature = "config")]
{
    use describe_me::{load_config_from_path, filter_services, SystemSnapshot, CaptureOptions};

    let cfg = load_config_from_path("config.toml")?;
    let mut snap = SystemSnapshot::capture_with(CaptureOptions { with_services: true, with_disk_usage: true })?;
    snap.services_running = filter_services(std::mem::take(&mut snap.services_running), &cfg);
}

6) Utilisation comme bibliothèque
Snapshot système
use describe_me::SystemSnapshot;

fn main() -> anyhow::Result<()> {
    let snap = SystemSnapshot::capture()?;
    println!("CPU: {}", snap.cpu_count);
    println!("RAM totale: {} o", snap.total_memory_bytes);
    Ok(())
}

Usage disque
use describe_me::disk_usage;

let du = disk_usage()?;
println!("Total: {} o, Libre: {} o", du.total_bytes, du.available_bytes);
for p in du.partitions {
    let used = p.total_bytes.saturating_sub(p.available_bytes);
    println!("{}  used={} o / total={} o", p.mount_point, used, p.total_bytes);
}

Sockets d’écoute (feature net)
#[cfg(feature = "net")]
{
    let sockets = describe_me::net_listen()?;
    for s in sockets {
        println!("{} {}:{}", s.proto, s.addr, s.port);
    }
}

Serveur web (feature web, via la lib)
#[cfg(feature = "web")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Même impl que le CLI --web
    describe_me::serve_http(([0,0,0,0], 8080), std::time::Duration::from_secs(2),
        #[cfg(feature = "config")] None,
        /* web_debug = */ false,
        describe_me::WebAccess {
            token: Some("super-secret".into()),
            allow_ips: vec!["127.0.0.1".into()],
        },
        describe_me::Exposure::all(),
    ).await?;
    Ok(())
}

Pour obtenir les détails masqués dans la sortie JSON du CLI, utilisez par exemple `--expose-hostname --expose-services` (ou simplement `--expose-all`). Pour le mode web, utilisez `--web-expose-*` ou la section `[web.exposure]` du fichier de configuration.

7) Matrice des features
Feature	Ce que ça ajoute	Dépendances activées
cli	Binaire describe-me + options ligne de commande	anyhow, clap, serde
systemd	Listing des services systemd	— (Linux/systemd requis)
config	Chargement TOML + filtrage (services.include)	serde, toml
net	Sockets d’écoute (TCP/UDP)	—
web	UI + SSE HTTP (Axum)	axum, tokio, tokio-stream, serde, subtle

Par défaut, aucune feature n’est activée. Active celles dont tu as besoin.

8) Tests & Qualité
# Tests unitaires (sans features)
cargo test

# Avec features clés
cargo test --features "systemd config net web"


Recommandations :

cargo fmt --all et cargo clippy --all-targets -- -D warnings

cargo deny / cargo audit (supply-chain)

Bench local (si besoin) : cargo bench (criterion)

9) Plateformes & limites

Linux : support principal. --with-services nécessite systemd.

Containers CI : certaines infos (disques/partitions) peuvent être partielles.

Droits : lister certains sockets/services peut nécessiter des privilèges.

10) FAQ

Q. Rien pour les services ?
R. Compile avec --features systemd et exécute sur une machine systemd (et utilise --with-services).

Q. --net-listen ne renvoie rien ?
R. Rebuild avec --features net et lance avec des droits suffisants.

Q. Comment faire un healthcheck qui échoue la CI ?
R. Utilise --check puis vérifie le code de sortie (0/1/2). Exemple GitHub Actions :

- name: Healthcheck runner
  run: |
    cargo run --features "cli" --bin describe-me -- \
      --check 'mem>95%:crit' \
      >/dev/null

Licence

Apache-2.0. Voir LICENSE.
