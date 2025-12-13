# Packaging FreeBSD (binaire autonome)

Prerequis :
- FreeBSD 13/14 avec `rust`, `cargo` et `gmake` (`pkg install rust gmake pkgconf openssl`).
- Compilation lancee **depuis une machine FreeBSD** (pas de cross-compilation fournie ici).

Build :

```sh
gmake freebsd-build          # features cli web config net
ls dist/freebsd/             # describe_me-freebsd-amd64, rc.describe_me, README
```

Installation manuelle best-effort :

```sh
sudo install -m 0755 dist/freebsd/describe_me-freebsd-amd64 /usr/local/bin/describe-me
sudo install -m 0644 packaging/freebsd/describe_me /usr/local/etc/rc.d/describe_me
# config par defaut : /usr/local/etc/describe_me/config.toml (copiez votre fichier)
sudo sysrc describe_me_enable=YES
sudo service describe_me start
```

Notes :
- Le script `rc.d` utilise `/usr/sbin/daemon` et attend un utilisateur `describe_me` (cree le si besoin).
- Le backend logs lit `/var/log/messages` (override : `DESCRIBE_ME_SYSLOG_PATH`).
- Les services rc.d, le trafic reseau (netstat) et les sockets (sockstat) sont detectes automatiquement.
