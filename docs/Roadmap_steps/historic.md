* **Rétention limitée et configurable** — [Inférence] Stocker un ring-buffer de N points par métrique/serveur, configurable, avec purge automatique. Réduit l’impact d’une compromission et la surface de recon, sans coût autre que quelques écritures O(1) par snapshot.

* **Minimisation des données** — [Inférence] Ne conserver que des tuples timestamp + {cpu%, mem%, disk%}, sans détails de services, sockets ou plugins. Limite la quantité d’information exploitable par un attaquant et réduit l’empreinte mémoire/disk.

* **Alignement avec les flags d’exposition** — [Inférence] L’historique doit respecter `ExposureConfig`/`expose-*` et le mode `redacted`. Si le disque ou la mémoire sont masqués dans le snapshot courant, ne pas exposer leurs séries dans l’UI ni le `history`.

* **Contrôle d’accès unifié** — [Inférence] Réutiliser le même garde `AuthGuard`, token, allowlist IP et affinité token/IP pour les endpoints history. Optionnellement appliquer des limites plus strictes que sur `/` et `/sse` pour éviter le scraping massif.

* **Rate limiting et DoS** — [Inférence] Ajouter des quotas spécifiques `RouteLimitConfig` pour l’API history (requêtes + plage temporelle max par appel), afin d’éviter les scans intensifs tout en gardant des requêtes O(1)/O(log N) côté stockage.

* **Stockage durci** — [Inférence] Réutiliser `state_dir` (mode 0700) et redb pour stocker l’historique. Éviter tout chemin configurable non root-owned, prévoir un mode “no-persist-history” pour des environnements très sensibles.

* **Option de chiffrement au repos** — [Inférence] Prévoir une abstraction permettant, plus tard, un backend chiffré (clé fournie via variable d’environnement ou agent externe) sans changer l’API. Ne pas l’imposer pour éviter le coût CPU par défaut.

* **Séparation des responsabilités** — [Inférence] Isoler le module time-series (lecture/écriture) du module d’auth, des plugins et de l’UI. Réduit le risque de couplage dangereux (ex: plugin injectant des données malformées consommées directement par l’UI).

* **Hygiène des logs** — [Inférence] Journaliser uniquement des métriques agrégées (count, range temporelle, erreurs), jamais les valeurs brutes de l’historique ni des identifiants sensibles. Permet la détection d’abus sans transformer les logs en canal d’exfiltration.

* **UI tendances et XSS** — [Inférence] L’endpoint fournissant les sparklines doit renvoyer un JSON strict, parsé et non interpolé dans le DOM via `innerHTML`. Tout se fait via canvas/SVG programmatique pour éliminer les risques de XSS issus des données.

* **Fenêtre temporelle stricte par requête** — [Inférence] Imposer une plage max (ex: 1 h) et refuser les requêtes trop larges. Un attaquant doit multiplier les appels pour reconstituer l’historique complet, ce qui rend le scraping lent et visible.

* **Pagination et tri imposés côté serveur** — [Inférence] Forcer un ordre (par timestamp) et une pagination fixe, sans tri arbitraire. Un attaquant ne peut pas optimiser ses requêtes pour extraire des patterns précis rapidement, il doit tout balayer séquentiellement.

* **Quota par token / IP avec backoff** — [Inférence] Définir un budget de requêtes `history` par minute et par jour. Au-delà : backoff exponentiel ou HTTP 429 prolongé. La collecte agressive devient fastidieuse alors que l’usage normal reste fluide.

* **Dégradation ciblée sous suspicion** — [Inférence] En cas de pattern suspect (scan séquentiel, saturation quotas), augmenter ponctuellement la latence uniquement pour l’endpoint history. L’attaquant est ralenti sans impacter fortement la consultation standard ou le SSE.

* **Granularité dégradée pour les grosses fenêtres** — [Inférence] Plus la période demandée est longue, plus les points sont agrégés (min/max/avg). L’attaquant ne peut pas obtenir à la fois large horizon et haute résolution, ce qui complique l’analyse fine de charge.

* **Brouillage partiel des timestamps** — [Inférence] Pour l’historique côté UI seulement, arrondir les timestamps (ex: à la minute). L’attaquant obtient moins de précision temporelle pour corréler avec d’autres événements, l’admin conserve une lecture suffisante via les tendances.

* **Clés logiques par serveur difficilement devinables** — [Inférence] Ne jamais exposer d’identifiants séquentiels simples dans les routes history. Utiliser des IDs pseudo-aléatoires dérivés (hash stable) pour chaque serveur, rendant le balayage des IDs moins trivial.

* **Désactivation d’export brut** — [Inférence] Ne pas proposer de “download all history” en CSV/JSON depuis l’UI. Forcer l’attaquant à paginer et reconstituer manuellement, alors que l’admin a de toute façon les données résumées visibles via sparklines.

* **Mode paranoïaque activable** — [Inférence] Prévoir un mode runtime `--paranoid-history` : quotas plus bas, fenêtres plus courtes, pas d’historique persistant. Activable lors d’un incident pour transformer l’historique en source minimale, difficile à exploiter.

* **Monitoring spécifique des requêtes history** — [Inférence] Journaliser les patterns d’appel (nombre, IP, token, plage temporelle) et brancher un alerting minimal. Savoir que l’attaquant est ralenti est aussi important que le ralentir.

Intégrité de l’historique — [Inférence] Facultatif : chaînage de hash par serveur (H(n) incluant H(n-1)) stocké dans redb. Rend les suppressions/altérations massives détectables sans surcoût majeur, surtout si tu ne fais la vérif qu’à la demande.

Durcissement côté CLI history — [Inférence] Le binaire local ne doit lire l’historique que via les mêmes contrôles (permissions fichiers, owner root, pas de world-read). Éviter toute option --raw-json ou --export côté CLI pour ne pas offrir de canal d’exfil direct.

Safe defaults + profils — [Inférence] Rendre l’historique désactivé ou très court par défaut (N faible, pas de persistance longue), avec quelques profils préconfigurés : default, ops, paranoid. Ça évite les mauvaises surprises en prod et simplifie la posture globale.

---

## Étapes de design proposées

1. [x] **Surface de configuration & profils** — Étendre `domain::config` avec un bloc `[history]` (retention_points, max_window_seconds, aggregation_strategy, paranoid_mode) plus des profils prédéfinis (`default`, `ops`, `paranoid`). Les valeurs alimentent aussi la CLI (`--history-profile`, `--history-disabled`) pour respecter le flag « safe defaults + profils ».
2. [x] **Module stockage time-series** — Créer `src/infrastructure/history.rs` gérant un ring-buffer redb par serveur/metric (`cpu`, `mem`, `disk`). Chaque entrée = `{ts_sec, cpu_pct, mem_pct, disk_pct, hash_chain}` afin de préparer l’option d’intégrité. L’API expose `append_snapshot(server_id, data)` et `query(server_id_hash, window, limit)` avec purge O(1).
3. [x] **IDs serveurs opaques** — Introduire un identifiant stable dérivé (`server_id_hash = blake3(hostname+salt)`) stocké avec les métadonnées. Les endpoints history consomment uniquement cet ID pour éviter les séquences devinables.
4. [x] **Pipeline d’ingestion** — Lors de chaque snapshot (module `application::snapshot`), appeler `history::append_snapshot` après avoir calculé CPU/Mem/Disk normalisés. Respecter `ExposureConfig` et `history_disabled`, sinon skip. Appliquer un arrondi temporel (minute) côté stockage UI mais conserver l’horodatage exact pour la CLI (sous contrôle d’accès).
5. [x] **Aggregation adaptative** — Ajouter dans `history::query` un mode downsampling (par bucket de taille dynamique) dès que la fenêtre demandée dépasse `history.max_window_seconds/4`. Retourner min/max/avg par bucket pour respecter « granularité dégradée ».
6. [x] **Rate limiting dédié** — Étendre `web.security` avec un bloc `history` (per_ip/per_token/global/payload caps) et brancher `HistoryGuard` dans les nouvelles routes. Réutiliser `AuthGuard`, allowlist IP, affinité token/IP, plus un budget par token/IP journalier pour respecter quotas/backoff.
7. [x] **API & CLI history** — Côté HTTP, ajouter `GET /api/history?server=ID&window=900` → JSON strict `{points:[{ts,cpu,mem,disk}]}` + métadonnées (`aggregated:true`, `precision:"minute"`). Côté CLI, implémenter `describe-me history --server default --since 30m --json` qui lit via le module local (pas via HTTP) en vérifiant permissions fichiers (state_dir 0700).
8. [x] **UI tendances** — Dans `web/templates` + `assets/js/ui.js`, créer une carte « Tendances » qui fetch `/api/history` via `fetch` (pas d’innerHTML) et dessine les sparklines (CPU/Mem/Disk) avec `<canvas>` ou `<svg>` généré. Aucun export CSV/JSON complet, uniquement affichage graphique + valeurs agrégées.
9. [x] **Journalisation & alerting** — Ajout d’événements `LogEvent::HistoryQuery` (ip, token hash, window, points) sans données sensibles. Brancher un compteur/alerte minimal (ex: `history_suspicious_pattern`) déclenché quand une IP dépasse X requêtes ou scanne séquentiellement les IDs.
10. [x] **Mode paranoïaque** — Implémenter `history.paranoid = true` : ring-buffer en mémoire uniquement, N très faible, pas d’écriture disque, quotas divisés par 2 et `history` désactivé côté UI (CLI accessible uniquement localement). Permet de répondre au flag « mode paranoïaque activable ».

ensuite l’API + quotas + journaux,
puis la CLI,
enfin l’UI tendances et le mode paranoïaque.
