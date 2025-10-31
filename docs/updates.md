# Détection des mises à jour système

Ce document décrit le fonctionnement de la collecte des mises à jour
disponibles ainsi que l’exposition du statut dans `describe_me`.

## Modèle de données

- `UpdatesInfo` (dans `domain::model`) stocke :
  - `pending` : nombre estimé de paquets en attente d’installation.
  - `reboot_required` : booléen indiquant si un redémarrage est conseillé.
- `SystemSnapshot::updates` est un `Option<UpdatesInfo>` :
  - `None` signifie que la détection n’a pas pu être effectuée (outil absent,
    OS non pris en charge, erreur d’exécution).
  - `Some` signale qu’une estimation a été calculée avec les heuristiques
    décrites ci-dessous.

`SnapshotView` relaie directement la valeur vers :

- la sortie JSON (`--json`/`--pretty`),
- le flux SSE et l’interface web,
- la ligne de résumé CLI (`--summary`).

## Collecte (`infrastructure::updates`)

Le module `src/infrastructure/updates.rs` effectue une détection « best-effort »
en appelant les outils systèmes disponibles. Aucun privilège root n’est requis.

| Plateforme | Commande principale | Comptage | Détection reboot |
|------------|--------------------|----------|------------------|
| Debian/Ubuntu | `apt-get -s upgrade` | lignes `Inst ...` | fichiers `/var/run/reboot-required` ou `/run/reboot-required` |
| RHEL/CentOS/Fedora & co | `dnf -q check-update` | sorties « package version repo » (ignore les sections `Security:`, `Obsoleting Packages`, etc.) | `needs-restarting -r` (si dispo) + fichiers reboot |
| Arch Linux | `checkupdates` | nombre de lignes non vides (ignore code 2 = erreur) | fichiers reboot si présents |
| Alpine | `apk version -l '<'` | lignes non vides | fichier `/run/reboot-required` si présent |
| FreeBSD | `pkg version -l '<'` | lignes non vides | non supporté (toujours `false`) |

Si la commande est absente ou retourne un code inattendu, le module tente le
backend suivant (ex. `dnf` → `checkupdates` → `apk`). En cas d’échec total,
`SystemSnapshot::updates` reste à `None` et aucune erreur n’est remontée.

## Consommation

- **CLI** : `--summary` ajoute `updates=<N> reboot=<yes|no|unknown>` sur une
  ligne avant la sortie principale. La JSON/pretty contiennent le champ
  `updates`. L’affichage détaillé peut être contrôlé par `--expose-updates`
  (ou via la clef TOML `expose_updates`).
- **Interface web** : carte « Mises à jour » affiche « Aucune mise à jour » ou le
  nombre détecté, avec une coloration (vert=à jour, jaune=actions requises). La
  tuile est rendue visible uniquement si `Exposure.updates` est activé (CLI,
  config ou `--web-expose-updates`).
- **API JSON / SSE** : incluent le champ `updates` lorsqu’il est disponible.

## Tests

Des helpers de parsing (`count_apt_lines`, `count_dnf_updates`) sont couverts
par des tests unitaires pour garantir la robustesse face aux variations de
sortie.
