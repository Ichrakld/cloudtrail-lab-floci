# Guide d’exécution pas à pas

Toutes les commandes AWS de ce guide ciblent Floci avec `--endpoint-url`. Les identifiants sont factices et réservés à ce laboratoire.

## 1. Démarrer Floci

Depuis la racine du dépôt :

```bash
sudo docker compose config
sudo docker compose up -d
sudo docker compose ps
sudo docker exec floci-cloudtrail printenv | grep FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED
```

Attendre que le statut du conteneur soit `healthy`. La dernière commande doit afficher `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true`.

## 2. Configurer l’AWS CLI et vérifier l’identité locale

Dans le terminal Kali :

```bash
export AWS_ENDPOINT_URL=http://127.0.0.1:4566
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=eu-west-3

aws --endpoint-url "$AWS_ENDPOINT_URL" sts get-caller-identity
```

Le compte `000000000000` confirme que l’appel atteint Floci.

## 3. Créer les buckets et les objets d’exemple

```bash
for bucket in corp-app-data corp-backups-prod corp-finance-secrets corp-cloudtrail-logs; do
  aws --endpoint-url "$AWS_ENDPOINT_URL" s3 mb "s3://$bucket"
done

mkdir -p data config
printf 'id;montant\n1;4200\n' > data/payroll.csv
printf 'sauvegarde de test\n' > data/db.dump

aws --endpoint-url "$AWS_ENDPOINT_URL" s3 cp data/payroll.csv \
  s3://corp-finance-secrets/2026/payroll.csv
aws --endpoint-url "$AWS_ENDPOINT_URL" s3 cp data/db.dump \
  s3://corp-backups-prod/daily/db.dump
```

Vérifie les buckets et objets :

```bash
aws --endpoint-url "$AWS_ENDPOINT_URL" s3 ls
aws --endpoint-url "$AWS_ENDPOINT_URL" s3 ls s3://corp-finance-secrets/ --recursive
aws --endpoint-url "$AWS_ENDPOINT_URL" s3 ls s3://corp-backups-prod/ --recursive
```

Si un bucket existe déjà, ne relance pas sa création ; passe directement aux commandes d’envoi.

## 4. Créer les utilisateurs et la policy de Bob

```bash
for user in alice bob carol svc-backup; do
  aws --endpoint-url "$AWS_ENDPOINT_URL" iam create-user --user-name "$user"
done
```

La policy `config/dev-policy.json` est volontairement trop permissive : elle autorise Bob à gérer S3 et à attacher des policies IAM ou créer des clés.

```bash
DEV_POLICY_ARN=$(aws --endpoint-url "$AWS_ENDPOINT_URL" iam create-policy \
  --policy-name DevPolicy \
  --policy-document file://config/dev-policy.json \
  --query 'Policy.Arn' --output text)

aws --endpoint-url "$AWS_ENDPOINT_URL" iam attach-user-policy \
  --user-name bob --policy-arn "$DEV_POLICY_ARN"
```

Vérifie les utilisateurs et la policy attachée :

```bash
aws --endpoint-url "$AWS_ENDPOINT_URL" iam list-users \
  --query 'Users[].UserName' --output table
aws --endpoint-url "$AWS_ENDPOINT_URL" iam list-attached-user-policies \
  --user-name bob
```

## 5. Rejouer le test S2 d’élévation IAM

Crée une clé de laboratoire pour Bob et conserve-la uniquement dans les variables du terminal :

```bash
BOB_JSON=$(aws --endpoint-url "$AWS_ENDPOINT_URL" iam create-access-key \
  --user-name bob --output json)
export BOB_KEY_ID=$(printf '%s' "$BOB_JSON" | jq -r '.AccessKey.AccessKeyId')
export BOB_SECRET=$(printf '%s' "$BOB_JSON" | jq -r '.AccessKey.SecretAccessKey')
```

Teste d’abord `ListUsers` sous l’identité de Bob. Le refus `AccessDenied` est le résultat attendu avant l’élévation :

```bash
AWS_ACCESS_KEY_ID="$BOB_KEY_ID" AWS_SECRET_ACCESS_KEY="$BOB_SECRET" \
aws --endpoint-url "$AWS_ENDPOINT_URL" iam list-users
```

Puis tente d’attacher `AdministratorAccess` à Bob avec sa propre clé :

```bash
AWS_ACCESS_KEY_ID="$BOB_KEY_ID" AWS_SECRET_ACCESS_KEY="$BOB_SECRET" \
aws --endpoint-url "$AWS_ENDPOINT_URL" iam attach-user-policy \
  --user-name bob \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

Refais `iam list-users` avec la clé de Bob : cette fois, l’appel devrait réussir. Cela illustre un gain de permissions dans Floci, pas dans AWS réel.

Nettoie ensuite l’élévation en revenant aux identifiants opérateur :

```bash
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
aws --endpoint-url "$AWS_ENDPOINT_URL" iam detach-user-policy \
  --user-name bob \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws --endpoint-url "$AWS_ENDPOINT_URL" iam list-attached-user-policies --user-name bob
```

Le résultat attendu après nettoyage est uniquement `DevPolicy`. Le test `ListUsers` avec Bob doit de nouveau être refusé.

## 6. Créer et démarrer le trail natif

`config/s3-selectors.json` cible les opérations de lecture et d’écriture sur les objets des buckets sensibles.

```bash
aws --endpoint-url "$AWS_ENDPOINT_URL" cloudtrail create-trail \
  --name corp-trail --s3-bucket-name corp-cloudtrail-logs
aws --endpoint-url "$AWS_ENDPOINT_URL" cloudtrail put-event-selectors \
  --trail-name corp-trail --event-selectors file://config/s3-selectors.json
aws --endpoint-url "$AWS_ENDPOINT_URL" cloudtrail start-logging --name corp-trail
aws --endpoint-url "$AWS_ENDPOINT_URL" cloudtrail get-trail-status --name corp-trail
```

Vérifie que `IsLogging` vaut `true`. La configuration et les sélecteurs définissent quelles opérations l’émulateur est censé collecter.

## 7. Générer et collecter des événements S3 natifs

```bash
printf 'fichier pour le test CloudTrail\n' > data/test-trail.txt
aws --endpoint-url "$AWS_ENDPOINT_URL" s3 cp data/test-trail.txt \
  s3://corp-backups-prod/audit/test-trail.txt
aws --endpoint-url "$AWS_ENDPOINT_URL" s3 cp \
  s3://corp-backups-prod/audit/test-trail.txt data/recupere.txt
aws --endpoint-url "$AWS_ENDPOINT_URL" s3 rm \
  s3://corp-backups-prod/audit/test-trail.txt

sleep 15
mkdir -p data/collected-native
aws --endpoint-url "$AWS_ENDPOINT_URL" s3 sync \
  s3://corp-cloudtrail-logs/ data/collected-native/
find data/collected-native -type f -name '*.json.gz'
```

Inspecte les enregistrements puis conserve les preuves utiles :

```bash
find data/collected-native -type f -name '*.json.gz' -print0 |
while IFS= read -r -d '' file; do
  zcat "$file" | jq -r '.Records[] | [.eventTime, .eventName,
    .userIdentity.userName, .sourceIPAddress, (.errorCode // "OK"),
    .requestParameters.key] | @tsv'
done | sort

mkdir -p evidence/native
cp -a data/collected-native/. evidence/native/
```

Ces objets sont les journaux natifs observés dans Floci. Leur absence d’alerte ne prouve pas qu’AWS se comporterait de la même façon.

## 8. Générer et analyser les scénarios synthétiques

```bash
python3 src/generate_events.py
jq '{total: (.Records | length), unique: ([.Records[].eventID] | unique | length)}' \
  data/synthetic/dataset_synthetic.json
python3 src/analyze_logs.py data/synthetic/dataset_synthetic.json
```

Le jeu attendu contient 20 événements uniques. Le rapport direct attendu contient 12 alertes, réparties sur R01 à R09. Ce sont des résultats de simulation.

## 9. Exporter, envoyer et récupérer le jeu synthétique

```bash
python3 src/export_s3_layout.py
find data/synthetic-layout -type f -name '*.json.gz' | wc -l

aws --endpoint-url "$AWS_ENDPOINT_URL" s3 mb \
  s3://corp-cloudtrail-logs-synthetic
aws --endpoint-url "$AWS_ENDPOINT_URL" s3 sync \
  data/synthetic-layout/ s3://corp-cloudtrail-logs-synthetic/

mkdir -p data/collected-synthetic
aws --endpoint-url "$AWS_ENDPOINT_URL" s3 sync \
  s3://corp-cloudtrail-logs-synthetic/ data/collected-synthetic/
find data/collected-synthetic -type f -name '*.json.gz' | wc -l
python3 src/analyze_logs.py data/collected-synthetic
```

Le résultat attendu de l’export est 14 fichiers gzip. Après récupération, l’analyse doit retrouver 20 événements uniques et 12 alertes. Le bucket `corp-cloudtrail-logs-synthetic` est distinct de `corp-cloudtrail-logs`.

## 10. Vérifier le projet

```bash
python3 -m unittest discover -s tests -v
jq -r 'group_by(.rule)[] | [.[0].rule, length, .[0].severity] | @tsv' \
  reports/collected-synthetic/findings.json
```

Les captures associées à chaque étape sont listées dans [`screenshots/README.md`](screenshots/README.md).
