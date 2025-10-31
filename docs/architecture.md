# Architecture Générale

`describe_me` suit une architecture en couches classique :

- **Domain** (`src/domain`) : types métier (snapshot, disque, services),
  erreurs et configuration (TOML). Cette couche est entièrement
  agnostique, sans dépendance système.
- **Application** (`src/application`) : logique orchestrant la capture de
  l’état système, l’exposition des données, le logging, les checks et
  l’UI web. Elle compose les services `domain` et délègue les accès bas
  niveau à `infrastructure`.
- **Infrastructure** (`src/infrastructure`) : interactions avec
  l’OS/bibliothèques (sysinfo, systemd, parsing `/proc`, sockets). Chaque
  backend est isolé pour faciliter les tests et l’évolution.
- **Interface utilisateur** : binaire CLI (`src/bin/describe-me.rs`) et
  serveur web (modules Axum/SSE), activables via des features Cargo.

Les fonctionnalités principales sont pilotées par des **features Cargo**
:

| Feature     | Rôle principal                                                 |
|-------------|----------------------------------------------------------------|
| `cli`       | Binaire `describe-me` et parsing Clap                          |
| `web`       | Serveur Axum + SSE                                             |
| `systemd`   | Intégration systemctl (services actifs)                        |
| `config`    | Chargement TOML et ajustements runtime                         |
| `net`       | Inventaire des sockets TCP/UDP                                 |
| `serde`     | Sérialisation des modèles (`SnapshotView`, `DiskUsage`, …)     |

## Flux principal

1. Le CLI ou le serveur web construit des `CaptureOptions`.
2. `SystemSnapshot::capture` (application) rassemble les informations via
   `infrastructure::sysinfo`, `systemd`, etc.
3. La sortie est redéfinie en `SnapshotView` (exposition/config/redaction).
4. Les modules `health`, `logging`, `web` appliquent les traitements
   spécifiques (checks, SSE, journaux).

## Dossiers complémentaires

- `docs/logging.md` : guide pour émettre des logs structurés.
- `docs/web-security.md` : détails de la sécurité HTTP/SSE.
- `tests/` : scénarios end-to-end et tests systemd.
- `benches/` : benchmark sur la capture de snapshot.
- `fuzz/` : cible libFuzzer pour le parsing `systemctl`.
