Ajouter une crate describe_me_plugin_sdk (lib + macro) fournissant Plugin, PluginOutput (basé sur BTreeMap<String, serde_json::Value>), PluginError et describe_me_plugin_main!(MyPlugin) qui sérialise l’output JSON stable sur stdout.
Exposer describe_me_plugin_sdk dans le workspace via un path dependency et fournir PluginPayload dans describe_me (SystemSnapshot gagne extensions: HashMap<String, PluginOutput>).
Étendre DescribeConfig avec extensions.plugins = [{ name, cmd, args?, timeout_secs? }] pour lister les collecteurs automatiques et ajouter exposure.expose_extensions.
Créer application::extensions qui lit cette config, exécute chaque plugin (Command + timeout + stdout JSON), namespacé sous extensions.<plugin_name>, et agrège les erreurs dans LogEvent.
Ajouter describe-me plugin run --cmd <plugin> [--arg ...] [--timeout <s>] qui réutilise le runner et affiche PluginOutput ou les erreurs explicites (exit code ≠0, timeout, JSON invalide).
Modifier la capture (capture_snapshot_with_view) pour déclencher automatiquement les plugins configurés et alimenter SnapshotView.extensions (géré via exposition/config).
Étendre l’UI web: types JSON incluent extensions: HashMap<String, PluginOutput>, SSE relaie ce champ, l’HTML obtient un nouveau panneau listant les plugins et leurs clés/valeurs.
Ajouter des tests unitaires pour le SDK (macro, sérialisation), le runner CLI (commande factice) et l’exécution configurée (mise en cache des erreurs/timeouts).
Documenter la config (docs, README, packaging/config) et fournir au moins un plugin minimal dans plugin-examples/certificates utilisant la macro.
Garantir que l’intégration reste optionnelle (aucun plugin par défaut) et que les erreurs ne bloquent ni la capture ni le serveur web.