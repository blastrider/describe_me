# Capture des journaux

- Option CLI : `--capture-logs`
- Config (section `[runtime.cli]`) : `capture_logs = true`

Comportement :
- Si activé, lors d’un snapshot :
  - La sortie journald (dernier boot, tronquée à 500 lignes) est lue via `journalctl -b -n 500 --no-pager`.
  - En mode CLI : les logs sont imprimés sur stderr.
  - En mode web : les logs apparaissent dans la tuile “Journaux”.
- Si journald est indisponible (socket absent), un message explicite est retourné.

Notes :
- Pas de fallback fichiers pour l’instant (journald uniquement).
- Conserve les contrôles d’exposition/ACL déjà en place côté web.
