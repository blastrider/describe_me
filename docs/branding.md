# Personnalisation du logo web

La page web est servie depuis l'application elle‑même. Le logo par défaut est embarqué dans `src/application/web/assets/logo.svg` et exposé en lecture seule à l'URL fixe `/assets/logo.svg`.

## Modifier le logo

1. Remplacez le contenu de `src/application/web/assets/logo.svg` par votre propre SVG statique. Aucune interpolation n'est effectuée : le fichier est inclus au moment de la compilation.
2. Conservez un SVG « passif » (sans `<script>` ni attributs d'événement) afin de ne pas introduire d'exécution de script dans le navigateur.
3. Recompilez ou redéployez l'application. La route `/assets/logo.svg` servira automatiquement le nouveau contenu.

La directive CSP reste limitée à `img-src 'self'`, ce qui empêche le chargement d'images distantes ou de `data:` URI. Le chemin reste maîtrisé et ne dépend d'aucune entrée utilisateur.

## Via la configuration (`web.logo_path`)

Lorsque la feature `config` est activée, vous pouvez déléguer le logo à un fichier externe en ajoutant dans votre TOML :

```toml
[web]
logo_path = "/etc/describe-me/logo.svg"
```

Contraintes de sécurité :

- chemin absolu uniquement (pas de `~` ni de chemins relatifs) ;
- taille maximale : 128 KiB ;
- contenu UTF-8 contenant une balise `<svg>` ;
- balises `<script>` et attributs d'événements (`onload=`, `onclick=`, etc.) interdits ;
- les URLs `javascript:` sont bloquées.

Au démarrage, le serveur lit et valide le fichier. Si la validation échoue, le lancement est stoppé et un message explicite est renvoyé. Le fichier est ensuite servi tel quel depuis `/assets/logo.svg`, toujours sous la même CSP (`img-src 'self'`).
