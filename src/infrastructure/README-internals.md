# Couche sysinfo/logs : dependances externes

- `btrfs filesystem df -b <mount>` (binaire `btrfs`)
  - Usage : interrogation des volumes Btrfs dans `gather_disks` pour affiner la capacite/usage logique.
  - En cas d'absence/echec : la collecte reste best-effort ; si le binaire manque, renvoie un statut non nul ou une sortie inutilisable, le volume Btrfs est conserve avec les metriques `sysinfo` sans produire d'erreur.
  - Necessite : optionnelle (degradation gracieuse, pas de fallback supplementaire).

- `journalctl` (`/usr/bin/journalctl`, surcharge possible via `DESCRIBE_ME_JOURNALCTL`)
  - Usage : lecture des journaux systeme (`--no-pager --output=short-iso-precise --lines <N>`) dans `tail_journald`.
  - En cas d'absence/echec : renvoie `DescribeError::External` et aucun log n'est retourne (pas de fallback automatique).
  - Necessite : requis pour l'API de logs lorsque la feature `journald` est activee.

- FreeBSD :
  - `sockstat`/`netstat` (PATH `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`) pour les sockets/compteurs.
  - `service` (rc.d) pour la liste des services.
  - `/var/log/messages` (override via `DESCRIBE_ME_SYSLOG_PATH`) pour les logs hote.
