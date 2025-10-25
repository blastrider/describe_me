# describe_me

Décrit rapidement un serveur (CPU, RAM, OS, uptime, services…), utile aux admins système.
Fonctionne en **lib Rust** et en **CLI** (binaire `describe-me`).

- MSRV : `1.90.0`
- Licence : Apache-2.0
- Repo : [https://github.com/Max-Perso/describe_me](https://github.com/Max-Perso/describe_me)

## 1) Installation

### Depuis les sources

```bash
# Cloner
git clone https://github.com/Max-Perso/describe_me
cd describe_me

# Build (lib + tests de base)
cargo build
cargo test
```

### Activer le binaire CLI

Le CLI est derrière la feature `cli`. Ajoute des features selon tes besoins :

- `systemd` : énumère les services (Linux systemd)
- `config` : charge un fichier TOML
- `net` : sockets d’écoute (TCP/UDP)
- `web` : expose une API HTTP (via la lib)

Exemples :

```bash
# CLI seul
cargo build --features "cli"

# CLI + systemd + config + net
cargo build --features "cli systemd config net"
```

## 2) Utilisation rapide (CLI)

Afficher un snapshot simple :

```bash
./target/debug/describe-me
```

Options courantes :

```bash
# Services (systemd requis au build)
./target/debug/describe-me --with-services

# Disques (agrégé + partitions)
./target/debug/describe-me --disks

# Sockets d’écoute (feature net requise)
./target/debug/describe-me --net-listen

# Charger une config TOML (feature config requise)
./target/debug/describe-me --config ./src/examples/config.toml
```

> Astuce : combine-les librement, ex.
> `./describe-me --with-services --disks --net-listen --config config.toml`

### Exemple de sortie (résumé)

```
Hostname: srv-app-01
OS: Linux 6.8 (Debian 12)
Uptime: 3d 04:12:09
CPU: 8 cœurs
RAM: 16.0 GiB (utilisée 6.3 GiB)
Disque total: 500 GiB (libre 320 GiB)
Services actifs: nginx, postgresql, ...
Sockets écoute: tcp/0.0.0.0:22, tcp/127.0.0.1:5432, ...
```

## 3) Fichier de configuration (optionnel)

Disponible avec `--features config`.

### Exemple minimal `config.toml`

```toml
# Filtrage d’affichage des services (si feature systemd)
[services]
include = ["nginx", "postgresql"]   # ne montrer que ceux-ci
exclude = ["bluetooth"]             # masquer certains services

# Future extension : règles de sortie, formats, etc.
```

Dans ton code, tu peux aussi charger/filtrer :

```rust
#[cfg(feature = "config")]
{
    use describe_me::{load_config_from_path, filter_services, SystemSnapshot, CaptureOptions};

    let cfg = load_config_from_path("config.toml")?;
    let snap = SystemSnapshot::capture_with(CaptureOptions::default())?;
    let services = filter_services(&cfg, snap.services);
    // ... affiche/exporte comme tu veux
}
```

## 4) Utilisation comme bibliothèque

### Snapshot système

```rust
use describe_me::SystemSnapshot;

fn main() -> anyhow::Result<()> {
    let snap = SystemSnapshot::capture()?;
    println!("CPU: {}", snap.cpu_count);
    println!("RAM totale: {} o", snap.total_memory_bytes);
    Ok(())
}
```

### Usage disque

```rust
use describe_me::disk_usage;

let du = disk_usage()?;
println!("Total: {} o, Libre: {} o", du.total_bytes, du.available_bytes);
for p in du.partitions {
    println!("{}  {} o / {} o", p.mount_point, p.used_bytes, p.total_bytes);
}
```

### Sockets d’écoute (feature `net`)

```rust
#[cfg(feature = "net")]
{
    let sockets = describe_me::net_listen()?;
    for s in sockets {
        println!("{} {}:{}", s.proto, s.addr, s.port);
    }
}
```

### Mini-serveur web (feature `web`)

Pas d’option CLI pour le web à ce stade : tu l’embarques dans ton binaire/app.

```rust
#[cfg(feature = "web")]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Expose quelques endpoints HTTP renvoyant le snapshot (via axum)
    describe_me::serve_http(([0,0,0,0], 8080)).await?;
    Ok(())
}
```

## 5) Matrice des features

| Feature   | Ce que ça ajoute                                  | Dépendances activées                     |
| --------- | ------------------------------------------------- | ---------------------------------------- |
| `cli`     | Binaire `describe-me` + options ligne de commande | `anyhow`, `clap`, `serde`                |
| `systemd` | Listing des services systemd                      | — (Linux/systemd requis)                 |
| `config`  | Chargement TOML + filtrage                        | `serde`, `toml`                          |
| `net`     | Sockets d’écoute (TCP/UDP)                        | —                                        |
| `web`     | Fonctions HTTP (lib) via Axum/Tokio               | `axum`, `tokio`, `tokio-stream`, `serde` |

> Par défaut, **aucune feature** n’est activée. Active celles dont tu as besoin.

## 6) Tests & Qualité

```bash
# Tests unitaires
cargo test

# Avec features
cargo test --features "systemd config net"

# Bench (si tu utilises criterion en local)
cargo bench
```

Recommandations (non bloquantes ici, mais conseillées) :

- `cargo fmt --all` et `cargo clippy --all-targets -- -D warnings`
- `cargo deny` / `cargo audit` pour la supply-chain

## 7) Plateformes & limites

- **Linux** : support principal (systemd requis pour `--with-services`).
- **Containers CI** : certaines infos peuvent être partielles (ex. partitions).
- Droits : pour lister certains sockets/services, il peut falloir des privilèges élevés.

## 8) FAQ

**Q. Rien n’apparaît pour les services ?**
R. Compile avec `--features systemd` et exécute sur une machine systemd.

**Q. L’option `--net-listen` ne marche pas ?**
R. Rebuild avec `--features net`.

**Q. Je veux une API HTTP prête à l’emploi en CLI.**
R. Aujourd’hui, le mode web est exposé côté **lib** (`serve_http`). Intègre-le à ton binaire.

---

## 9) Licence

Apache-2.0. Voir `LICENSE`.

---

**Prêt à l’emploi :**

- CLI « audit rapide » : `cargo build --features "cli systemd config net"` puis `./target/debug/describe-me ...`
- Lib intégrable : `SystemSnapshot::capture()`, `disk_usage()`, `net_listen()`, `serve_http()` (selon features).
