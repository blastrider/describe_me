# Fuzzing

Ce dossier est initialisé avec `cargo-fuzz`. Les cibles couvrent les parseurs sensibles aux entrées hostiles :

| Target | Description |
| --- | --- |
| `parse_proc_net` | `/proc/net/tcp` & `/proc/net/udp` (`parse_table`) |
| `parse_apt_line` | `apt list --upgradable` (`parse_apt_upgradable_line`) |
| `parse_dnf_output` | `dnf check-update` (`count_dnf_updates`) |
| `parse_apk_output` | `apk version -l <` (`count_apk_updates`) |
| `parse_mountinfo` | `/proc/self/mountinfo` (`parse_mountinfo_for_tests`) |
| `parse_systemd_line` | `systemctl list-units` (`__parse_systemctl_line_for_tests`) |

## Utilisation

1. Installer `cargo-fuzz` (si besoin) :
   ```bash
   cargo install cargo-fuzz
   ```
2. Lancer un fuzz :
   ```bash
   cd fuzz
   cargo fuzz run parse_proc_net
   ```
   (remplacez `parse_proc_net` par la cible voulue).

> Les cibles utilisent la feature `internals` pour atteindre les parseurs ; elles ne sont pas activées en build normal.
