# Partage des données volumineuses

Certaines structures (services systemd, sockets, partitions disque) peuvent
être sérialisées plusieurs fois après une capture (`SnapshotView` clonée pour
le JSON, SSE, etc.). Copier systématiquement les `Vec<T>` gonfle inutilement
la consommation mémoire.

Le module `src/shared.rs` introduit `SharedSlice<T>` :

- encapsule un `Arc<Vec<T>>` pour partager les éléments sans recopier ;
- fournit `from_vec` (consomme un `Vec<T>` existant) et `from_slice` (clone une
  fois une tranche) ;
- implémente `Deref<Target = [T]>` et `Serialize` pour rester transparent côté
  API.

`SystemSnapshot` et `SnapshotView` stockent désormais
`SharedSlice<ServiceInfo>`, `SharedSlice<ListeningSocket>` et
`SharedSlice<DiskPartition>`. Ainsi, un clone se limite à incrémenter un
compteur de références, et les réutilisations (CLI + SSE, web + JSON brut) ne
déclenchent plus de copies intégrales.
