# Couche Domain

Le dossier `src/domain/` regroupe les types « métier » indépendants de
l’infrastructure. Ils peuvent être utilisés tant côté bibliothèque que
par des consommateurs externes.

## Modules

- `model.rs`
  - `ServiceInfo` : description d’un service systemd (nom, état, résumé).
  - `SystemSnapshot` : état complet du serveur (hostname, OS, load, mémoire,
    disques, services). Des options (`CaptureOptions`) déterminent si les
    informations disque/services doivent être collectées.
  - `DiskPartition` / `DiskUsage` : modèles partagés entre capture disque,
    sérialisation JSON et web UI.

- `error.rs`
  - `DescribeError` (via `thiserror`) : catégorise les erreurs système,
    externes (systemctl), parsing et configuration.

- `config.rs` (feature `config`)
  - Structures reflétant le fichier TOML (`DescribeConfig`, `WebAccessConfig`,
    `ExposureConfig`, `RuntimeConfig`, `WebSecurityConfig`, etc.).
  - Valeurs par défaut et validation légère (ex. `default_redacted`).

- `mod.rs`
  - Ré-exporte les types clés pour l’API publique : `CaptureOptions`,
    `SystemSnapshot`, `DescribeError`, `DescribeConfig`, `ServiceSelection`,
    etc.

## Sérialisation

La majorité des structures dérivent `Serialize`/`Deserialize` lorsque la
feature `serde` est activée. Cela permet une utilisation flexible
en tant que bibliothèque (ex. exporter des snapshots en JSON dans une
application intégrée).
