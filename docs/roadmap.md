# Roadmap Describe_me

## 1. Backends metadata alternatifs (Postgres/MariaDB/Mongo)

- Finaliser l’interface `MetadataBackend` avec une couche de config (URI, credentials, migrations).
- Fournir au moins un backend SQL et un NoSQL avec tests d’intégration.
- Documenter comment brancher ces backends et migrer les données redb existantes.

## 2. Vue multi-serveurs & navigation

- Ajouter une API/listing qui expose plusieurs snapshots (clé serveur, alias).
- Côté UI : un sélecteur ou vue tableau pour passer de « default » à un autre serveur, avec persistance dans les préférences utilisateur.

## 3. Recherche/tri dynamique (services, sockets, tags)

- Implémenter un panneau de filtres (texte, statut, tag) qui agit en temps réel côté front.
- Ajouter une API de pagination côté CLI/web pour éviter de charger des listes massives.

## 4. Export & automatisation des snapshots

- Offrir une commande/endpoint « push » vers un collecteur (HTTP webhook, MQTT, syslog).
- Possibilité de planifier un export périodique (cron-like) et d’ajouter des hooks personnalisés.

## 5. Alerting & notifications légères

- Sur la base des health checks, exposer un moteur simple d’alertes (mail/webhook quand un seuil passe à CRIT).
- Historiser les dernières alertes et afficher un bandeau/centre de notifications dans l’UI.

## 6. Historique léger / mini time-series

- Conserver N snapshots récents par serveur (configurable) pour tracer CPU/mémoire/disk.
- Ajouter une carte « tendances » dans l’interface (sparklines) et une commande CLI `history`.

## 7. Sécurité granulaire & multi-utilisateurs

- Étendre `web.security` pour gérer des rôles (lecture seule, édition description/tags, admin).
- Gestion des tokens multiples, audit des actions (écriture description/tags).

## 8. Extensions / plugins de collecte

- Définir un SDK minimal pour ajouter des collecteurs (ex : vérifier certificats, services custom).
- Interface CLI `describe-me plugin run` et routage des métriques supplémentaires vers l’UI.

## 9. Mode mobile & accessibilité

- Revoir le layout CSS pour un rendu fluide < 600 px, gestures pour masquer des sections, thèmes accessibles (contraste, focus).
- Ajouter des tests Lighthouse/axe intégrés dans la CI.

## 10. Synchronisation config CLI ↔ web

- Permettre au serveur web de pousser une config recommandée (services, exposure) vers les clients CLI.
- Ajouter une commande `describe-me sync` qui récupère les préférences serveur et met à jour le fichier local.
