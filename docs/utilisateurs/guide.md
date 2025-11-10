describe_me — Guide utilisateur
================================

Décrit rapidement un serveur (CPU, RAM, OS, uptime, services…), utile aux admins système.
Fonctionne en bibliothèque Rust et en CLI (`describe-me`).

Le binaire refuse volontairement d'être exécuté en root (UID 0). Utilise un compte dédié ou `sudo -u describe-me` pour le lancer.

MSRV : 1.90.0 — Licence : Apache-2.0

Sommaire
--------

1. Installation
2. Utilisation rapide (CLI)
3. Service systemd durci
4. Healthcheck (`--check`)
5. Mode Web (SSE / HTTPS)
6. Configuration TOML
7. Utilisation comme bibliothèque
8. Matrice des features
9. Tests & Qualité
10. FAQ

1. Installation
---------------

```bash
git clone https://github.com/Max-Perso/describe_me
cd describe_me
cargo build
cargo test
```

Activer le binaire CLI : la feature `cli` est nécessaire, ajoute celles dont tu as besoin :

- `systemd` : énumère les services.
- `config` : charge un fichier TOML (filtrage services).
- `net` : sockets d’écoute (TCP/UDP).
- `web` : UI & SSE HTTP (Axum), endpoints temps réel.

Exemples :

```
cargo build --features "cli"
cargo build --features "cli systemd config net"
cargo build --features "cli systemd config net web"
```

2. Utilisation rapide (CLI)
---------------------------

Afficher un snapshot JSON lisible :

```
./target/debug/describe-me
```

Options courantes :

```
./target/debug/describe-me --with-services
./target/debug/describe-me --disks
./target/debug/describe-me --net-listen
./target/debug/describe-me --net-traffic
./target/debug/describe-me --config ./src/examples/config.toml
./target/debug/describe-me --json
./target/debug/describe-me --pretty
```

Astuce : combine librement, ex. `./describe-me --with-services --disks --net-listen --net-traffic --config config.toml --pretty`

Exemple de sortie :

```
Hostname: srv-app-01
OS: Linux 6.8 (Debian 12)
Uptime: 3j 04h 12m 09s
CPU(s): 8
RAM: 16.0 GiB (utilisée 6.3 GiB)
Disque total: 500 GiB (libre 320 GiB)
Services actifs: nginx, postgresql, ...
Sockets écoute: tcp/0.0.0.0:22, tcp/127.0.0.1:5432, ...
Trafic reseau: eth0 Rx 120.5 Go / Tx 95.3 Go, eno1 Rx 4.2 Go / Tx 3.8 Go
```

3. Service systemd durci
------------------------

Un fichier d'unité est fourni (`packaging/systemd/describe-me.service`).

```
sudo install -m 0644 packaging/systemd/describe-me.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now describe-me.service
```

Adapte `ExecStart=` (flags `--web`, jeton, config TOML, etc.). Le service utilise un `DynamicUser` sans capabilities et active les protections (`ProtectSystem=strict`, `RestrictNamespaces=yes`, `MemoryDenyWriteExecute=yes`, etc.). Seules les écritures explicites vers `/var/lib/describe-me` sont autorisées (`StateDirectory=` + `ReadWritePaths=`).

4. Healthcheck (`--check`)
--------------------------

Retourne le code le plus sévère : `0=OK`, `1=WARN`, `2=CRIT`.

Formes supportées :

- `mem>90%[:warn|:crit]`
- `disk(/point_de_montage)>80%[:warn|:crit]`
- `service=nginx.service:running[:warn|:crit]`

Exemples :

```
./target/debug/describe-me --check 'mem>90%'
./target/debug/describe-me --check 'disk(/var)>80%:warn'
./target/debug/describe-me --with-services --check 'service=ssh.service:running'
```

5. Mode Web (SSE / HTTPS)
-------------------------

1. Générer un hash Argon2id du jeton accepté :
   ```
   TOKEN_HASH="$(./target/debug/describe-me --hash-web-token 'super-secret')"
   ```
2. Lancer :
   ```
   ./target/debug/describe-me \
     --web 0.0.0.0:8080 \
     --web-token "$TOKEN_HASH" \
     --web-interval 2 \
     --web-debug \
     --with-services
   ```
3. Ouvrir `http://127.0.0.1:8080/`, saisir le jeton en clair.

Pour produire du HTTPS natif, ajoute un bloc `[web.tls]` (ex. `src/examples/config_tls.toml`) :

```
[web.tls]
cert_path = "./certs/server.pem"
key_path  = "./certs/server-key.pem"
```

Certificat auto-signé rapide :

```
mkdir -p ./certs
openssl req -x509 -nodes -newkey rsa:4096 \
  -keyout ./certs/server-key.pem \
  -out ./certs/server.pem \
  -days 365 \
  -subj "/CN=describe-me.local"
chmod 600 ./certs/server-key.pem
```

6. Configuration TOML
---------------------

Fichier minimal (`src/examples/config.toml`) :

```
[services]
include = ["nginx.service", "postgresql.service"]

[web]
token = "$argon2id$..."
allow_ips = ["127.0.0.1", "10.0.0.0/16"]

[web.exposure]
expose_services = true
expose_disk_partitions = true

[exposure]
expose_hostname = true
expose_os = true
expose_kernel = true
redacted = true
```

> Astuce : pour `allow_ips`, `allow_origins` et `trusted_proxies`, la priorité
> est `--web-*` (CLI) > `[web]` > `[runtime.cli]`. Chaque section définit donc
> ses propres valeurs sans cumul implicite.

Autres variantes :

- `src/examples/config_http.toml` — écoute HTTP (LAN).
- `src/examples/config_tls.toml` — HTTPS complet (certificat/clé).

7. Utilisation comme bibliothèque
---------------------------------

```rust
use describe_me::{SystemSnapshot, CaptureOptions, disk_usage};

fn cli() -> anyhow::Result<()> {
    let snap = SystemSnapshot::capture()?;
    println!("CPU: {}", snap.cpu_count);
    Ok(())
}

fn disks() -> anyhow::Result<()> {
    let du = disk_usage()?;
    println!("Total {}", du.total_bytes);
    Ok(())
}
```

Sockets (`feature = "net"`) :

```rust
#[cfg(feature = "net")]
{
    for sock in describe_me::net_listen()? {
        println!("{} {}:{}", sock.proto, sock.addr, sock.port);
    }
}
```

Serveur web (`feature = "web"`) :

```rust
#[cfg(feature = "web")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    describe_me::serve_http(
        ([0, 0, 0, 0], 8080),
        std::time::Duration::from_secs(2),
        #[cfg(feature = "config")] None,
        false,
        describe_me::WebAccess {
            token: Some("$argon2id$...".into()),
            allow_ips: vec!["127.0.0.1".into()],
            allow_origins: vec![],
            trusted_proxies: vec![],
            tls: None,
        },
        describe_me::Exposure::all(),
    )
    .await?;
    Ok(())
}
```

8. Matrice des features
-----------------------

| Feature | Rôle | Dépendances |
|---------|------|-------------|
| `cli` | Binaire `describe-me`, options Clap | anyhow, clap, serde, nix, argon2, bcrypt, rand_core |
| `systemd` | Listing des services systemd | — |
| `config` | Chargement TOML, filtrage services | serde, toml |
| `net` | Sockets d’écoute (TCP/UDP) | — |
| `web` | UI + SSE (Axum), HTTPS optionnel | axum, tokio, tokio-stream, serde, argon2, bcrypt, rand_core, axum-server |

9. Tests & Qualité
------------------

```
cargo test
cargo test --features "systemd config net web"
cargo fmt --all
cargo clippy --all-targets -- -D warnings
```

Autres outils : `cargo audit`, `cargo deny check`, `cargo crev verify --recursive`, `cargo cyclonedx`.

10. FAQ
-------

- **Rien pour les services ?** Compile avec `--features systemd` et utilise `--with-services`.
- **`--net-listen` vide ?** Active la feature `net` et assure-toi d’avoir les droits.
- **Healthcheck CI ?** Utilise `--check` et lis le code de sortie (0/1/2).
- **HTTPS obligatoire ?** Ajoute `[web.tls]` ou place-le derrière un reverse-proxy.

Licence
-------

Apache-2.0. Voir `LICENSE`.
