# Captures de la réalisation

Les captures ci-dessous documentent le déroulé sous Kali. Elles montrent des sorties locales de laboratoire ; les scénarios synthétiques restent simulés.

| Étape | Capture | Contenu |
|---:|---|---|
| 01 | [`01-docker-compose-floci-config.png`](01-docker-compose-floci-config.png) | Configuration Docker Compose pour Floci |
| 02 | [`02-docker-compose-first-command-error.png`](02-docker-compose-first-command-error.png) | Première commande Compose erronée |
| 03 | [`03-install-docker-compose-plugin-kali.png`](03-install-docker-compose-plugin-kali.png) | Installation du plugin Docker Compose |
| 04 | [`04-verify-compose-config-and-iam-enforcement.png`](04-verify-compose-config-and-iam-enforcement.png) | Configuration et activation IAM enforcement |
| 05 | [`05-docker-daemon-permission-denied.png`](05-docker-daemon-permission-denied.png) | Permission Docker daemon refusée |
| 06 | [`06-pull-and-start-floci.png`](06-pull-and-start-floci.png) | Téléchargement et démarrage de Floci |
| 07 | [`07-check-floci-container-starting.png`](07-check-floci-container-starting.png) | État initial du conteneur |
| 08 | [`08-recreate-floci-with-iam-enforcement.png`](08-recreate-floci-with-iam-enforcement.png) | Redémarrage avec IAM enforcement |
| 09 | [`09-confirm-floci-healthy.png`](09-confirm-floci-healthy.png) | Conteneur Floci healthy |
| 10 | [`10-verify-local-sts-identity.png`](10-verify-local-sts-identity.png) | Identité STS locale |
| 11 | [`11-upload-sample-finance-and-backup-files.png`](11-upload-sample-finance-and-backup-files.png) | Envoi des fichiers d’exemple |
| 12 | [`12-create-s3-lab-buckets.png`](12-create-s3-lab-buckets.png) | Création des buckets S3 |
| 13 | [`13-list-buckets-and-sample-objects.png`](13-list-buckets-and-sample-objects.png) | Vérification des buckets et objets |
| 14 | [`14-verify-iam-users-and-devpolicy.png`](14-verify-iam-users-and-devpolicy.png) | Utilisateurs IAM et DevPolicy de Bob |
| 15 | [`15-create-bob-access-key.png`](15-create-bob-access-key.png) | Création de la clé de Bob |
| 16 | [`16-test-bob-permissions-after-escalation.png`](16-test-bob-permissions-after-escalation.png) | Vérification des permissions après élévation |
| 17 | [`17-restore-operator-credentials.png`](17-restore-operator-credentials.png) | Retour aux identifiants opérateur |
| 18 | [`18-confirm-admin-policy-detached.png`](18-confirm-admin-policy-detached.png) | Nettoyage de la policy administrateur |
| 19 | [`19-confirm-bob-access-denied-after-cleanup.png`](19-confirm-bob-access-denied-after-cleanup.png) | Refus de ListUsers après nettoyage |
| 20 | [`20-create-cloudtrail-trail-and-s3-selectors.png`](20-create-cloudtrail-trail-and-s3-selectors.png) | Création du trail et des sélecteurs S3 |
| 21 | [`21-start-trail-and-check-status.png`](21-start-trail-and-check-status.png) | Démarrage et état du trail |
| 22 | [`22-generate-s3-object-events.png`](22-generate-s3-object-events.png) | Opérations S3 de test |
| 23 | [`23-collect-native-cloudtrail-files.png`](23-collect-native-cloudtrail-files.png) | Collecte des journaux natifs |
| 24 | [`24-inspect-native-cloudtrail-records.png`](24-inspect-native-cloudtrail-records.png) | Inspection des événements CloudTrail natifs |
| 25 | [`25-run-s3-operations-as-bob.png`](25-run-s3-operations-as-bob.png) | Opérations S3 exécutées par Bob |
| 26 | [`26-verify-bob-events-in-native-logs.png`](26-verify-bob-events-in-native-logs.png) | Vérification des événements de Bob |
| 27 | [`27-preserve-native-evidence.png`](27-preserve-native-evidence.png) | Conservation des preuves natives |
| 28 | [`28-generate-synthetic-scenarios.png`](28-generate-synthetic-scenarios.png) | Génération des scénarios synthétiques |
| 29 | [`29-check-synthetic-event-uniqueness.png`](29-check-synthetic-event-uniqueness.png) | Vérification des eventID uniques |
| 30 | [`30-shell-parse-error-during-category-check.png`](30-shell-parse-error-during-category-check.png) | Erreur de syntaxe pendant une vérification jq |
| 31 | [`31-verify-s3-event-categories.png`](31-verify-s3-event-categories.png) | Vérification de la catégorie des événements S3 |
| 32 | [`32-analyze-synthetic-and-native-data.png`](32-analyze-synthetic-and-native-data.png) | Analyse des données natives et synthétiques |
| 33 | [`33-count-alerts-by-detection-rule.png`](33-count-alerts-by-detection-rule.png) | Nombre d’alertes par règle |
| 34 | [`34-read-synthetic-analysis-report.png`](34-read-synthetic-analysis-report.png) | Lecture du rapport synthétique |
| 35 | [`35-export-alert-timeline.png`](35-export-alert-timeline.png) | Export de la chronologie |
| 36 | [`36-export-synthetic-cloudtrail-s3-layout.png`](36-export-synthetic-cloudtrail-s3-layout.png) | Création de l’arborescence CloudTrail synthétique |
| 37 | [`37-upload-synthetic-files-to-floci.png`](37-upload-synthetic-files-to-floci.png) | Envoi du jeu synthétique vers le bucket Floci |
| 38 | [`38-download-and-analyze-synthetic-files.png`](38-download-and-analyze-synthetic-files.png) | Récupération puis analyse du jeu synthétique |
| 39 | [`39-verify-collected-alert-distribution.png`](39-verify-collected-alert-distribution.png) | Vérification de la répartition des alertes |
