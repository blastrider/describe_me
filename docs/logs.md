# Lecture des logs hôte (journald)

- **CLI** : `describe-me logs --lines 200` lit les dernières lignes journald via `journalctl --output=short-iso-precise`. La commande borne automatiquement la lecture (`HOST_LOGS_MAX_LINES`) et signale si journald est indisponible.
- **Web** : le tableau de bord affiche un aperçu dans une tuile large et un bouton « Détails » vers `/logs` (page dédiée). L’API `GET /api/logs?lines=N` renvoie `{ entries, truncated }` et respecte le même bornage.
- **Conteneur** : montez `/run/systemd/journal/socket:/run/systemd/journal/socket:ro` pour exposer journald à l’image (déjà prévu dans `docker/docker-compose.yml`).
- **Sécurité** : routes soumises à `web.security.logs` (rate limiting) et au jeton/bloqueur IP comme les autres endpoints protégés.
- **Binaire `journalctl` requis** : l’image `scratch` fournie ne l’embarque pas. Pour que la lecture fonctionne en conteneur, fournissez `journalctl` (et ses libs) via une image dérivée ou un bind-mount, puis éventuellement pointez `DESCRIBE_ME_JOURNALCTL=/chemin/journalctl`.

## Mode Docker / lecture des logs de l’hôte

Pour lire les logs du système hôte depuis le conteneur :

- **Image** : l’image par défaut est basée sur `debian:13-slim` et embarque `journalctl`/`libsystemd`.
- **Compose** :
  - `pid: host` pour voir le journal de l’hôte via le socket systemd.
  - Monter le socket journald : `/run/systemd/journal/socket:/run/systemd/journal/socket:ro`.
  - Exécuter en non-root (`HOST_UID`/`HOST_GID`) et ajouter les groupes de lecture journald : `group_add: [systemd-journal, adm]` (ajuster selon la distro).
  - Monter `/proc`, `/sys` et `/etc/machine-id` en lecture seule si besoin d’infos hôte.
  - Définir `DESCRIBE_ME_CONTAINER=1` pour désactiver la collecte des services systemd (sinon `systemctl` échoue dans le conteneur).
- **Limites API** : pour éviter les 429 en dev, relâcher `[web.security.logs]` dans la config (ex. per_ip/per_token élevés, `token_ip_affinity_limit=0`).
- **Troubleshooting** :
  - Vérifier que `journalctl` retourne des lignes sur l’hôte (`journalctl --no-pager --output=short-iso-precise | head`).
  - Confirmer que l’utilisateur du conteneur a les groupes adéquats (`systemd-journal`/`adm`) et que le socket est accessible.
  - Si rien ne s’affiche, regarder les logs du conteneur pour `logs_read` et ajuster montages/groupes en conséquence.
