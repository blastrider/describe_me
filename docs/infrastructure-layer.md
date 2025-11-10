# Couche Infrastructure

Les modules `src/infrastructure/` manipulent l’OS et les dépendances
externes. Ils sont isolés pour faciliter les tests et limiter les effets
de bord.

## `sysinfo.rs`

- S’appuie sur la crate `sysinfo` pour collecter hostname, uptime, CPU,
  mémoire, load average et espaces disque.
- `SysinfoSnapshot` stocke les informations de base, réutilisées par la
  couche application.
- `gather_disks()` : lit `/proc/self/mountinfo` pour dédupliquer les
  partitions (gestion spéciale de btrfs), skip les pseudo-FS, calcule
  les totaux agrégés.

## `systemd.rs` (feature `systemd`)

- Exécute `systemctl` dans un environnement contrôlé (`PATH`, `LC_ALL`,
  variables effacées).
- `list_systemd_services()` retourne des `ServiceInfo`, avec tolérance
  aux erreurs (absence de systemctl, refus root, parsing).
- Expose également une fonction interne pour les tests/fuzzing
  (`__parse_systemctl_line_for_tests`).

## `net/`

- `linux.rs` (feature `net`) parcourt `/proc/net/{tcp,udp}` et `/proc/<pid>/fd`
  pour associer les sockets LISTEN/UNCONN à leurs PID éventuels.
- Implémente un parsing minimal IPv4 little-endian, extensible vers IPv6.

## `updates.rs`

- Détection best-effort des mises à jour via les gestionnaires de paquets
  (`apt-get -s upgrade`, `dnf check-update`, `checkupdates`, `apk version -l '<'`,
  `pkg version -l '<'`).
- Fournit `gather_updates()` qui retourne `Option<UpdatesInfo>` sans échec fatal
  si l’outil est absent ou échoue.
- Implémente des helpers de parsing (`count_apt_lines`, `count_dnf_updates`)
  couverts par des tests unitaires.

## `storage.rs`

- Initialise la base `redb` (`metadata.redb`) via `MetadataStore` et la
  table `server_metadata`.
- Résout automatiquement le répertoire d’état en respectant (ordre de
  priorité) `DESCRIBE_ME_STATE_DIR`, la variable `STATE_DIRECTORY`
  exposée par systemd, la valeur `[runtime] state_dir` de la configuration,
  puis les emplacements XDG/`LOCALAPPDATA`. Les
  répertoires sont créés à la volée.
- Fournit les primitives `set_description` / `get_description` /
  `clear_description` utilisées pour stocker la description libre du
  serveur, ainsi que `set_tags_raw` / `get_tags_raw` pour la liste de
  tags normalisés.

## Approche commune

- Pas de `unsafe`.
- Manipulation soigneuse des erreurs (`DescribeError`) pour remonter la
  cause précise aux couches supérieures.
- Utilisation d’outils standard (`fs::read_dir`, `read_link`, `HashMap`)
  et de logs (`tracing::debug`) pour faciliter le diagnostic en production.
