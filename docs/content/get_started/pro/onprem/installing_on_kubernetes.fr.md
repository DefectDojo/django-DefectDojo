---
title: Guide d'installation de DefectDojo Pro
description: Installez DefectDojo Pro sur Kubernetes à l'aide du chart Helm, en couvrant
  l'infrastructure, les secrets et l'installation elle-même
draft: false
weight: 13
audience: pro
---

<!--
  Généré à partir du dépôt du chart Helm DefectDojo Pro.
  Source : docs/INSTALLATION_GUIDE.md à la version de chart 3.1.304.
  Modifiez le guide source, pas ce fichier. Les modifications locales sont écrasées
  lors de la prochaine publication du chart.
-->
Couvre le déploiement sur AWS EKS et OpenShift (ROSA). Le déroulement est le même
dans les deux cas : configurer l'infrastructure, créer les secrets, installer le chart.

---

## Liste de contrôle avant installation

Rassemblez les informations suivantes avant de commencer. Les avoir sous la main évite
des retards pendant le processus d'installation.

### Détails de l'infrastructure

| Élément | Exemple | Où le trouver |
|------|---------|-------------------|
| **Hôte PostgreSQL** | `mydb.abc123.us-east-1.rds.amazonaws.com` | Console AWS RDS ou `aws rds describe-db-instances` |
| **Port PostgreSQL** | `5432` | Généralement 5432, sauf personnalisation |
| **Nom de la base de données PostgreSQL** | `dojodb` | Votre DBA ou les sorties Terraform/CloudFormation — doit être créée avant l'installation (voir la remarque ci-dessous) |
| **Base de données de l'orchestrateur** | `dojodb-ddorch` | Accordez le rôle `CREATEDB` au rôle applicatif, ou pré-créez `<dbname>-ddorch` — voir [Vérification préalable : base de données de l'orchestrateur (ddorch)](#pre-flight-orchestrator-ddorch-database) |
| **Nom d'utilisateur PostgreSQL** | `defectdojo` | `aws rds describe-db-instances --query 'DBInstances[].MasterUsername'` |
| **Mot de passe PostgreSQL** | — | AWS Secrets Manager, l'état Terraform, ou votre DBA |
| **Point de terminaison Redis/ElastiCache** | `my-redis.abc123.use1.cache.amazonaws.com` | `aws elasticache describe-cache-clusters --show-cache-node-info` |
| **Mot de passe Redis** | — | À omettre si l'authentification est désactivée (VPC uniquement). Vérifiez avec : `aws elasticache describe-replication-groups --query 'ReplicationGroups[].AuthTokenEnabled'` |
| **ID du système de fichiers EFS** | `fs-0abc123def456` | `aws efs describe-file-systems --region <region>` |
| **ID du point d'accès EFS** (le cas échéant) | `fsap-0abc123def456` | `aws efs describe-access-points --file-system-id <fs-id>` |
| **UID/GID du point d'accès EFS** | UID `1001`, GID `1337` | Doit correspondre au contexte de sécurité du conteneur (voir la remarque ci-dessous) |
| **Nom de domaine (FQDN)** | `dojo.example.com` | Votre administrateur DNS (voir les remarques spécifiques à la plateforme ci-dessous) |
| **ARN du certificat ACM** (EKS avec HTTPS) | `arn:aws:acm:...` | `aws acm list-certificates --region <region>` |
| **Domaine des applications OpenShift** (ROSA uniquement) | `apps.abc123.p1.openshiftapps.com` | `oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'` |
| **fsGroup de l'espace de noms OpenShift** (ROSA uniquement) | `1001070000` | `oc get namespace <ns> -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'` — utilisez la valeur de départ |
| **Fichier de licence** | `onprem-dojopro.lic` | Fourni par le support DefectDojo |

> **Créez les bases de données avant l'installation.** Le chart ne crée pas
> de bases de données sur un serveur PostgreSQL externe. Créez les deux bases suivantes sur
> votre serveur de base de données, appartenant à l'utilisateur applicatif, avant d'exécuter
> `helm install` :
>
> - `dojodb` — la base de données principale de DefectDojo
> - `dojodb-ddorch` — la base de données de l'orchestrateur (ddorch), toujours nommée d'après
>   la base de données principale avec le suffixe `-ddorch`. Vous pouvez aussi accorder au
>   rôle applicatif le privilège `CREATEDB` ; ddorch crée alors cette base lui-même au premier
>   démarrage.
>
> Voir [Vérification préalable : vérifier la connectivité à la base de données](#pre-flight-verify-database-connectivity)
> et [Vérification préalable : base de données de l'orchestrateur (ddorch)](#pre-flight-orchestrator-ddorch-database)
> pour des commandes `CREATE DATABASE` prêtes à l'emploi.

> **UID/GID du point d'accès EFS :** Si votre système de fichiers EFS utilise un point d'accès,
> sa configuration d'utilisateur POSIX **doit** utiliser l'UID `1001` et le GID `1337` pour correspondre
> au contexte de sécurité du conteneur DefectDojo. Une incohérence provoque des erreurs `Permission
> denied` pendant l'initialisation, lorsque les conteneurs tentent de créer
> les sous-répertoires media. Vérifiez avec :
>
> ```bash
> aws efs describe-access-points --file-system-id <fs-id> --region <region> \
>   --query 'AccessPoints[].{Id:AccessPointId,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
>   --output table
> ```

> **OpenShift/ROSA FQDN :** Sur ROSA, les Routes génèrent automatiquement des noms d'hôte selon le
> modèle `<release-name>-<namespace>.apps.<cluster-domain>`. Par exemple, si
> votre release s'appelle `dojopro` dans l'espace de noms `dojopro`, le nom d'hôte de la Route sera
> `dojopro-dojopro.apps.abc123.p1.openshiftapps.com`. Déterminez le domaine des applications
> de votre cluster avec :
>
> ```bash
> oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
> ```

>
> Utilisez le FQDN obtenu pour `dojo.fqdn`, `dojo.url`, et `dojo.hosts.main`.

> **OpenShift/ROSA fsGroup :** Vous aurez besoin de la valeur de départ des supplemental-groups
> de votre espace de noms pour `securityContext.openshift.fsGroup`. Recherchez-la dès maintenant pour éviter
> d'avoir à modifier votre fichier de valeurs plus tard :
>
> ```bash
> oc get namespace <your-namespace> \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Output example: 1001070000/10000 — use 1001070000 as fsGroup
> ```

### Secrets à générer

Les secrets suivants doivent être générés spécifiquement pour votre déploiement. Utilisez les
commandes indiquées pour créer des valeurs aléatoires cryptographiquement sûres :

| Secret | Clé dans le Secret K8s | Générer avec |
|--------|-------------------|---------------|
| Clé secrète Django | `DD_SECRET_KEY` | `openssl rand -hex 25` |
| Clé de chiffrement AES-256 | `DD_CREDENTIAL_AES_256_KEY` | `openssl rand -hex 16` |
| Secret du portail cloud | `CLOUD_PORTAL_SECRET_KEY` | `openssl rand -hex 25` |
| Secret partagé des connecteurs | `DD_CONNECTORS_SHARED_SECRET` | Utilisez la même valeur que `CLOUD_PORTAL_SECRET_KEY` |
| Mot de passe administrateur | `DD_ADMIN_PASSWORD` | `openssl rand -base64 16` |
| Mot de passe des métriques | `METRICS_HTTP_AUTH_PASSWORD` | `openssl rand -hex 16` |

### Secrets provenant de votre infrastructure

Ces valeurs proviennent de votre infrastructure existante — ne les générez pas :

| Secret | Clé dans le Secret K8s | Source |
|--------|-------------------|--------|
| Mot de passe de la base de données | `DD_DATABASE_PASSWORD` | Votre mot de passe PostgreSQL |
| URL de connexion à la base de données | `DD_DATABASE_URL` | `postgresql://<user>:<password>@<host>:<port>/<dbname>` |
| Mot de passe Redis | `redis-password` (dans le secret séparé `dojopro-redis`) | Votre mot de passe Redis, ou à omettre en l'absence d'authentification |
| URL du service d'e-mail | `DD_EMAIL_URL` | `consolemail://` pour les tests, ou votre URL SMTP |

### Facultatif (laisser vide pour désactiver)

| Secret | Clé dans le Secret K8s | Objectif |
|--------|-------------------|---------|
| Clé du bucket EPSS | `DD_PRO_ENHANCEMENTS_EPSS_BUCKET_KEY` | Enrichissement du score EPSS |

> **Astuce :** Copiez `secrets-template.yaml` et renseignez les valeurs ci-dessus. Voir
> [Générer les secrets](#generate-secrets) pour des instructions détaillées sur la création
> du Secret Kubernetes.

---

## Prérequis

```bash
# Required tools
brew install awscli helm kubectl jq openssl eksctl

# Verify AWS access
aws sts get-caller-identity
```

Pour OpenShift/ROSA, installez également :
```bash
brew install rosa openshift-cli
```

### Exigences de connectivité sortante

Dans les environnements réseau restreints, les connexions sortantes suivantes doivent être
autorisées avant l'installation. Les règles de pare-feu peuvent nécessiter des demandes de
changement anticipées — vérifiez qu'elles sont en place avant de poursuivre.

**Registre de conteneurs (obligatoire)**

Tous les nœuds du cluster doivent pouvoir joindre le registre de conteneurs DefectDojo sur le port 443 :

```
host us-south1-docker.pkg.dev
# us-south1-docker.pkg.dev is an alias for googlecode.l.googleusercontent.com
```

> Pour les environnements isolés (air-gapped), voir
> [Registre privé / environnements isolés](#private-registry-air-gapped-environments).

**Base de données (obligatoire)**

Des nœuds du cluster vers votre instance PostgreSQL, généralement le port 5432.

- RDS dans le même VPC : assurez-vous que le groupe de sécurité des nœuds EKS autorise le trafic entrant
  sur le port 5432
- RDS dans un VPC ou un compte différent : peering VPC ou Transit Gateway requis
- Externe/sur site : le chemin VPN ou Direct Connect doit autoriser le port 5432

**Mises à jour EPSS (recommandé)**

```
host api.first.org
# api.first.org has address 151.101.1.91
# api.first.org has address 151.101.193.91
# api.first.org has address 151.101.129.91
# api.first.org has address 151.101.65.91
# Port 443
```

**Flux KEV (recommandé)**

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

host www.cisa.gov
# www.cisa.gov is an alias for www.cisa.gov.edgekey.net (Akamai CDN — IPs vary)
# Port 443
```

**Services AWS (EKS uniquement, obligatoire)**

Le pilote EBS CSI et le contrôleur ALB nécessitent un accès aux points de terminaison de l'API AWS sur
le port 443 :

- `sts.amazonaws.com`
- `ec2.amazonaws.com`
- `elasticloadbalancing.amazonaws.com`
- `elasticfilesystem.amazonaws.com` (si vous utilisez EFS)

### Prérequis AWS EKS

Les composants suivants doivent être installés dans votre cluster EKS avant de déployer
DefectDojo Pro. Le déploiement échouera sans eux.

**Pilote EBS CSI** (requis uniquement avec le profil minimal utilisant PostgreSQL et Redis
embarqués — non nécessaire si vous utilisez RDS et ElastiCache externes) :

```bash
# Associate IAM OIDC provider
eksctl utils associate-iam-oidc-provider \
  --cluster <your-cluster> --region <region> --approve

# Create IAM role for EBS CSI
eksctl create iamserviceaccount \
  --name ebs-csi-controller-sa \
  --namespace kube-system \
  --cluster <your-cluster> \
  --region <region> \
  --role-name AmazonEKS_EBS_CSI_DriverRole \
  --role-only \
  --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy \
  --approve

# Install the add-on
eksctl create addon \
  --name aws-ebs-csi-driver \
  --cluster <your-cluster> \
  --region <region> \
  --service-account-role-arn arn:aws:iam::<account-id>:role/AmazonEKS_EBS_CSI_DriverRole \
  --force
```

**Pilote EFS CSI** (requis lorsque vous utilisez le stockage EFS — le backend de stockage
recommandé pour les déploiements EKS multi-répliques) :

```bash
# Create IAM role for EFS CSI
eksctl create iamserviceaccount \
  --name efs-csi-controller-sa \
  --namespace kube-system \
  --cluster <your-cluster> \
  --region <region> \
  --role-name AmazonEKS_EFS_CSI_DriverRole \
  --role-only \
  --attach-policy-arn arn:aws:iam::aws:policy/service-role/AmazonEFSCSIDriverPolicy \
  --approve

# Install the add-on
eksctl create addon \
  --name aws-efs-csi-driver \
  --cluster <your-cluster> \
  --region <region> \
  --service-account-role-arn arn:aws:iam::<account-id>:role/AmazonEKS_EFS_CSI_DriverRole \
  --force
```

**AWS Load Balancer Controller** (requis pour l'ingress ALB) :

Les instructions d'installation varient selon la version d'EKS. Suivez le
[guide d'installation officiel d'AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/deploy/installation/).

---

## Extraire le package du chart

Le chart est fourni sous forme d'un zip contenant un package Helm `.tgz`. Extrayez les deux avant de
poursuivre. Utilisez un chemin d'extraction versionné pour éviter d'écraser silencieusement des
préréglages lorsque vous extrayez une version plus récente du chart par la suite :

```bash
unzip helm-chart-<version>.zip -d /tmp/dojopro-extract
cd /tmp/dojopro-extract
mkdir -p dojopro-<version>
tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
```

Définissez une variable `CHART` pointant vers le répertoire du chart extrait. Toutes les
commandes `helm` suivantes de ce guide utilisent `$CHART` :

```bash
CHART="dojopro-<version>/dojopro"
# e.g. CHART="dojopro-2.55.4/dojopro"
```

> **Pourquoi l'extraction est nécessaire pour les utilisateurs de la CLI :** Les fichiers de préréglages
> (`presets/platforms/*.yaml`, `presets/profiles/*.yaml`) sont inclus dans le package
> `.tgz`. `helm install -f` nécessite des fichiers présents sur le système de fichiers local — il
> ne peut pas lire des fichiers à l'intérieur d'un `.tgz` empaqueté. Vous devez extraire le chart
> pour accéder aux préréglages.
>
> **Les utilisateurs d'ArgoCD n'ont pas besoin d'extraire.** ArgoCD lit les `valueFiles` directement
> depuis l'intérieur du package du chart. Voir [Déployer avec ArgoCD](#deploy-with-argocd).

---

## Préparer votre fichier de valeurs

Le modèle de configuration client (`template.yaml`) et le modèle de secrets
(`secrets-template.yaml`) sont disponibles séparément sur le portail de support DefectDojo,
ou auprès de support@defectdojo.com. Ils ne sont pas inclus dans le `.tgz` du chart.
Une fois que vous disposez du modèle, copiez-le et renseignez vos informations :

```bash
cp template.yaml my-company.yaml
```

Configurez au minimum les éléments suivants :

| Paramètre | Description |
|---------|-------------|
| `dojo.fqdn` | Votre nom de domaine (ROSA : voir la [remarque sur le FQDN](#infrastructure-details) ci-dessus) |
| `dojo.url` | URL complète avec le protocole (par exemple, `https://dojo.example.com`) |
| `dojo.hosts.main` | Doit correspondre à votre FQDN |
| `dojo.secureCookies` | Réglez sur `false` sous **OpenShift/ROSA** (voir l'avertissement ci-dessous) |
| `dojo.admin.*` | `user`, `email`, `firstName`, `lastName` — compte administrateur |
| `database.host`, `.port`, `.name`, `.user` | Détails de connexion PostgreSQL (le mot de passe va dans les secrets) |
| `celery.broker.host` | Votre point de terminaison Redis/ElastiCache |
| `redis.enabled` | **Doit être `false`** lorsque vous utilisez un Redis externe (voir l'avertissement ci-dessous) |
| `storage.type` | Backend de stockage — voir les remarques spécifiques à la plateforme |
| `certificates.*` | Configuration du certificat TLS |
| `django.ingress.*` ou `django.route.*` | Ingress (EKS) ou Route (OpenShift) — le préréglage définit des valeurs par défaut |
| `securityContext.openshift.fsGroup` | **ROSA uniquement** — valeur de départ des supplemental-groups de l'espace de noms |

> **AVERTISSEMENT — `redis.enabled` doit être explicitement réglé sur `false` lorsque vous utilisez
> un Redis/ElastiCache externe.** Les préréglages de profil `standard` et `performance`
> définissent `redis.enabled: true` par défaut. Si votre fichier de valeurs ne remplace pas
> ce paramètre, le chart déploiera un Redis in-cluster **en plus** de votre broker
> externe, ce qui produira une configuration défectueuse. Ajoutez ceci à votre fichier de valeurs :
>
> ```yaml
> redis:
>   enabled: false
> ```

> **AVERTISSEMENT — `dojo.secureCookies` doit être `false` sous OpenShift/ROSA.** Lorsque vous
> utilisez des Routes OpenShift avec terminaison TLS en périphérie (edge), `secureCookies: true`
> (la valeur par défaut dans `template.yaml`) provoque des boucles de redirection et un échec de connexion.
> Ce n'est pas facultatif — les Routes à terminaison en périphérie nécessitent :
>
> ```yaml
> dojo:
>   secureCookies: false
> ```

**Remarques sur le stockage :**
- **EKS :** Utilisez EFS, pas EBS. Les volumes EBS ne peuvent pas être partagés entre les nœuds, ce qui provoque
  des erreurs `Multi-Attach`. Voir [Problèmes connus](#known-issues-chart-version-2.57.1).
  Si votre EFS utilise un point d'accès, définissez aussi `storage.efs.accessPointId` —
  voir [Points d'accès EFS](#efs-access-points).
- **OpenShift/ROSA :** Le préréglage de la plateforme utilise par défaut `storage.type: "pvc"` avec
  `createNew: true`, ce qui utilise la StorageClass par défaut du cluster. Pour
  les déploiements multi-nœuds, utilisez NFS via EFS (`storage.type: "nfs"`).

Vous pouvez également définir la verbosité des journaux :
- `config.logLevel` — niveau de journalisation de l'application Django (par défaut : `"INFO"`)
- `celery.logLevel` — niveau de journalisation du worker/beat Celery (par défaut : `"INFO"`)

Réglez l'un ou l'autre sur `"DEBUG"` pour le dépannage. Voir [Verbosité des journaux](#log-verbosity)
pour savoir comment basculer ce réglage à l'exécution sans modifier votre fichier de valeurs.

Ne placez pas de secrets ni le contenu de la licence dans ce fichier. Ces éléments sont traités dans les
deux sections suivantes.

Consultez `template.yaml` pour la liste complète des options.

### Vérification préalable : vérifier la connectivité à la base de données

Confirmez que votre base de données est accessible avant de poursuivre — cela vous fera gagner beaucoup
de temps de dépannage par la suite. Démarrez un pod temporaire avec `psql` :

```bash
kubectl run psql-test --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -d dojodb -U defectdojo \
     -c "SELECT version();"
```

Une connexion réussie ressemble à ceci :

```
                                                version
--------------------------------------------------------------------------------------------------------
 PostgreSQL 16.x on x86_64-pc-linux-gnu, compiled by gcc ...
(1 row)

pod "psql-test" deleted
```

Si cela échoue avec `database "dojodb" does not exist`, votre instance RDS est
accessible mais la base de données n'a pas encore été créée. Créez-la :

```bash
kubectl run psql-create-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c "CREATE DATABASE dojodb OWNER <your-db-user>;"
```

Relancez ensuite la vérification de connectivité ci-dessus pour confirmer.

Si l'échec a une autre cause, vérifiez :
- **Les règles de groupe de sécurité / pare-feu** — le port 5432 doit être ouvert du cluster
  vers l'hôte de la base de données
- **Les privilèges de l'utilisateur de la base de données** — l'utilisateur doit disposer des permissions
  CREATE, ALTER et SELECT sur la base de données cible, ainsi que soit `CREATEDB`, soit une
  base de données de l'orchestrateur pré-créée (voir la section suivante)

> Le chart inclut également des vérifications intégrées : un conteneur d'initialisation qui attend la
> connectivité TCP à la base de données, et `helm test`, qui valide une connexion PostgreSQL
> complète après le déploiement. Cette étape de vérification préalable permet de détecter les problèmes avant
> d'investir du temps à créer les secrets et à exécuter `helm install`.

### Vérification préalable : base de données de l'orchestrateur (ddorch)

L'orchestrateur (`ddorch`, activé par défaut) stocke l'état de ses workflows dans une
**seconde base de données**, en plus de la base de données principale de DefectDojo. Au démarrage, il récupère
le nom de la base de données depuis `DD_DATABASE_URL`, y ajoute `-ddorch`, et crée cette
base de données si elle n'existe pas — une base de données principale `dojodb` signifie que
l'orchestrateur utilise `dojodb-ddorch`.

Si le rôle applicatif n'est pas autorisé à créer des bases de données, le pod ddorch
échoue au démarrage avec :

```
ERROR: permission denied to create database (SQLSTATE 42501)
```

Remplissez **l'une** des conditions suivantes avant l'installation :

**Option A — accordez `CREATEDB` au rôle applicatif** et laissez ddorch créer
sa base de données au premier démarrage :

```sql
ALTER ROLE defectdojo CREATEDB;
```

**Option B — pré-créez la base de données de l'orchestrateur**, nommée d'après votre
base de données principale avec le suffixe `-ddorch`, et appartenant au même utilisateur applicatif. Le
trait d'union dans le nom nécessite des guillemets doubles en SQL :

```sql
CREATE DATABASE "dojodb-ddorch" OWNER defectdojo;
```

En utilisant la même approche de pod temporaire que pour la vérification de connectivité ci-dessus :

```bash
kubectl run psql-create-ddorch-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c 'CREATE DATABASE "dojodb-ddorch" OWNER <your-db-user>;'
```

---

## Générer les secrets

Deux options ici.

### Option A : Secret externe (recommandé pour GitOps)

Créez un Secret Kubernetes contenant les 12 clés requises avant d'installer le chart.
Utilisez le fichier `secrets-template.yaml` fourni par le support DefectDojo comme point de
départ (voir [Préparer votre fichier de valeurs](#prepare-your-values-file) pour savoir comment
l'obtenir) :

```bash
cp secrets-template.yaml /tmp/dojopro-secrets.yaml
```

Modifiez le fichier, remplacez toutes les valeurs d'espace réservé, puis appliquez :
```bash
kubectl apply -f /tmp/dojopro-secrets.yaml -n <your-namespace>
```

Le secret peut également être géré par External Secrets Operator, Sealed Secrets, ou
tout autre outil qui crée des Secrets Kubernetes. Peu importe pour le chart la manière dont le
secret a été créé — il suffit de définir `dojo.existingSecret` avec son nom.

Au moment de l'installation :
```bash
--set dojo.existingSecret=dojopro-secrets
```

Le chart évite automatiquement de générer son Secret intégré lorsque
`dojo.existingSecret` est défini — aucun indicateur supplémentaire n'est nécessaire.

Si votre Redis externe nécessite une authentification, `secrets-template.yaml` inclut
également un Secret `dojopro-redis` séparé. Le chart lit les identifiants Redis depuis
`redis.auth.existingSecret` (par défaut : `dojopro-redis`). Si votre Redis n'a pas de
mot de passe (par exemple, ElastiCache VPC uniquement), vous pouvez l'omettre.

### Option B : secrets en ligne (plus simple, mais peu adapté à GitOps)

Transmettez les valeurs des secrets directement dans un fichier de valeurs :

```yaml
dojo:
  secretKey: ""                    # openssl rand -hex 25
  credentialAES256Key: ""          # openssl rand -hex 16
  cloudPortalSecretKey: ""         # openssl rand -hex 25
  connectorsSharedSecret: ""       # openssl rand -hex 25 (or reuse cloudPortalSecretKey)
  admin:
    password: ""                   # openssl rand -base64 16
  emailUrl: "consolemail://"
  proEnhancementsEpssBucketKey: "" # leave empty if not using EPSS

database:
  password: ""                     # your PostgreSQL password

redis:
  auth:
    password: ""                   # your Redis password (omit if Redis has no auth)

monitoring:
  password: ""                     # openssl rand -hex 16
```

Enregistrez ceci sous `my-secrets.yaml` et transmettez-le avec `-f` au moment de l'installation.

> Ne validez pas les fichiers de secrets dans le contrôle de version.

---

## Créer les certificats TLS internes

Le chart a besoin de certificats TLS internes pour la communication service à service.

Créez deux Secrets TLS Kubernetes dans votre espace de noms avant l'installation :

1. `dojopro-internal-tls` — un Secret TLS avec `tls.crt` et `tls.key` pour
   le chiffrement service à service (nginx ↔ connectors, etc.)
2. `dojopro-internal-ca` — un Secret contenant le certificat CA sous la
   clé `ca.crt`, utilisé par les connecteurs pour valider le certificat TLS interne

Vous pouvez générer une CA auto-signée et un certificat serveur avec `openssl`, ou
utiliser la CA interne de votre organisation. Le CN/SAN du certificat serveur **doit** couvrir
le nom du service nginx interne utilisé par la release Helm. Par défaut, il s'agit de
`<release-name>-nginx` (par exemple, `dojopro-nginx` si votre release s'appelle
`dojopro`).

Exemple de génération d'une CA auto-signée et d'un certificat serveur :
```bash
RELEASE_NAME="dojopro"
NAMESPACE="dojopro"

# Generate CA
# basicConstraints + keyUsage MUST be set explicitly. Without them the CA may
# be rejected as not a valid CA (e.g. "x509: certificate signed by unknown
# authority" / missing keyUsage) depending on your local openssl defaults.
openssl req -x509 -newkey rsa:2048 -keyout ca.key -out ca.crt \
  -days 365 -nodes -subj "/CN=${RELEASE_NAME}-internal-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign"

# Generate server cert with correct SANs and usage extensions
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes \
  -subj "/CN=${RELEASE_NAME}-nginx" \
  -addext "subjectAltName=DNS:${RELEASE_NAME}-nginx,DNS:${RELEASE_NAME}-nginx.${NAMESPACE}.svc.cluster.local" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out server.crt -days 365 -copy_extensions copyall

# Create the Kubernetes secrets
kubectl create secret tls dojopro-internal-tls \
  --cert=server.crt --key=server.key \
  -n $NAMESPACE

kubectl create secret generic dojopro-internal-ca \
  --from-file=ca.crt=ca.crt \
  -n $NAMESPACE
```

> **Erreur courante :** utiliser `nginx-internal` comme CN/SAN au lieu de
> `<release-name>-nginx`. Le pod connectors valide le certificat TLS
> par rapport au nom de service réel (`<release-name>-nginx.<namespace>.svc.cluster.local`),
> et échouera avec une erreur `x509: certificate is valid for ... not ...` si
> le SAN ne correspond pas.

Définissez ensuite dans votre fichier de valeurs :
```yaml
certificates:
  generation:
    enabled: false
  internal:
    source: "secret"
    secretName: "dojopro-internal-tls"
    caBundle:
      secretName: "dojopro-internal-ca"
      key: "ca.crt"
```

### Certificats mTLS ddorch

En plus des Secrets TLS internes ci-dessus, l'orchestrateur `ddorch`
nécessite un trio de certificats mTLS distinct, utilisé par le serveur ddorch et par tous les
workers qui communiquent avec lui (`ddorch-workers`, `integrators`). Ceux-ci sont
fournis au chart au moment de l'installation via `--set-file` (ils ne sont **pas**
lus depuis un Secret Kubernetes préexistant) :

- `orch_tls_root.ca` — certificat CA
- `orch_tls.crt` — certificat serveur
- `orch_tls.key` — clé privée du serveur

Sans ces trois fichiers, `helm install` échoue avec
`ddorch.tls.rootCa is required`.

Le SAN du certificat serveur **doit** inclure tous les noms d'hôte que les workers utilisent
pour joindre ddorch :

- `ddorch` — nom court du service in-cluster
- `<release-name>-ddorch` — nom de service complet (par exemple, `dojopro-ddorch`)
- `<release-name>-ddorch.<namespace>.svc.cluster.local` — FQDN du cluster
- `nginx` — le `SERVER_TLS_SERVER_NAME` par défaut utilisé par les workers de type hatchet
- `localhost`, `127.0.0.1` — pour les workers du même pod joignant ddorch via la boucle locale hostAlias

Exemple de génération du trio :

```bash
RELEASE_NAME="dojopro"
NAMESPACE="dojopro"

# ddorch CA
# As with the internal CA, set basicConstraints + keyUsage explicitly so the
# generated cert is a valid signing CA regardless of local openssl defaults.
openssl req -x509 -newkey rsa:2048 -keyout orch_ca.key -out orch_ca.crt \
  -days 365 -nodes -subj "/CN=${RELEASE_NAME}-ddorch-ca" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyCertSign,cRLSign"

# ddorch server cert
openssl req -newkey rsa:2048 -keyout orch_server.key -out orch_server.csr -nodes \
  -subj "/CN=ddorch" \
  -addext "subjectAltName=DNS:ddorch,DNS:${RELEASE_NAME}-ddorch,DNS:${RELEASE_NAME}-ddorch.${NAMESPACE}.svc.cluster.local,DNS:nginx,DNS:localhost,IP:127.0.0.1" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth"

openssl x509 -req -in orch_server.csr -CA orch_ca.crt -CAkey orch_ca.key \
  -CAcreateserial -out orch_server.crt -days 365 -copy_extensions copyall
```

Transmettez-les à `helm install` / `helm template` :

```bash
--set-file ddorch.tls.rootCa=orch_ca.crt \
--set-file ddorch.tls.cert=orch_server.crt \
--set-file ddorch.tls.key=orch_server.key
```

> Le script utilitaire `scripts/bootstrap-aws-eks.sh` génère et réutilise ces certificats
> automatiquement via `dojopro-orch-certs-configmap` — si vous utilisez
> ce script, vous n'avez pas besoin de les créer manuellement.

---

## Licence

Le chart nécessite une licence DefectDojo Pro.

### Inspecter votre licence

Avant de déployer, vérifiez que votre licence est valide et n'a pas expiré :

```bash
sed -n '/^[[:space:]]*ey/,/-----END/p' license.lic \
  | sed '$d' | tr -d ' ' | base64 -d | jq .
```

Ceci affiche les métadonnées de la licence, notamment :
- `not_after` — date d'expiration de la licence
- `license_package` — confirme votre palier (tier)

> **Secrets de pull d'images :** Lorsque `images.pullSecrets.extractFromLicense: true`
> est défini (valeur par défaut dans les préréglages de plateforme), le chart extrait automatiquement
> le compte de service GCP intégré à votre fichier de licence et crée le secret de pull d'images
> nécessaire pour récupérer les images DefectDojo depuis le registre de conteneurs. Aucune
> extraction ni décodage manuel n'est requis. Si vous utilisez plutôt un registre privé,
> réglez `extractFromLicense: false` et fournissez votre propre secret de pull —
> voir [Registre privé / environnements isolés](#private-registry-air-gapped-environments).

### Option 1 : --set-file (installation Helm standard)

Transmettez le fichier de licence au moment de l'installation :
```bash
--set-file license.contents=/path/to/license.lic
```

### Option 2 : Secret existant (GitOps / ArgoCD)

Créez un Secret Kubernetes contenant la licence, puis indiquez au chart de l'utiliser.
Cela évite d'avoir besoin de `--set-file` ou de stocker la licence dans git.

```bash
kubectl create secret generic dojopro-license \
  --namespace $NAMESPACE \
  --from-file=dojopro.lic=/path/to/license.lic
```

Puis dans votre fichier de valeurs ou vos indicateurs helm :
```yaml
license:
  existingSecret: "dojopro-license"
```

Le secret peut être géré par External Secrets Operator, Sealed Secrets, ou simplement kubectl.

> **Important :** `license.existingSecret` n'est **pas compatible** avec le
> paramètre par défaut `images.pullSecrets.extractFromLicense: true`. Le chart a besoin
> que le contenu de la licence soit disponible au moment du rendu pour extraire les
> identifiants de registre de conteneurs intégrés. Si vous utilisez `license.existingSecret`, vous
> devez également désactiver l'extraction automatique du secret de pull et fournir le vôtre :
>
> ```yaml
> images:
>   pullSecrets:
>     extractFromLicense: false
>     existingSecrets:
>       - "my-registry-pull-secret"
> ```

>
> Si vous souhaitez que le chart extraie automatiquement les secrets de pull depuis la licence
> (comportement par défaut), utilisez plutôt l'**Option 1** (`--set-file license.contents=`).


---

## Mode FIPS 140-3 (facultatif)

Pour les environnements soumis à FedRAMP **SC-13** ou équivalent, le chart peut déployer
les variantes d'image `-fips`, dont la cryptographie est assurée par le **fournisseur
OpenSSL FIPS 3.1.2** (certificat NIST CMVP **#4985**) et, pour les services Go,
le **Go Cryptographic Module v1.0.0** (CMVP **#5247**).

L'application se fait à l'intérieur du conteneur, donc aucun noyau hôte compatible FIPS n'est
requis — c'est ce qui rend cela viable sur des runtimes managés où le
système d'exploitation hôte n'est pas sous votre contrôle.

Désactivé par défaut ; le rendu généré est inchangé lorsque c'est désactivé.

```yaml
fips:
  enabled: true
  validate: true    # refuse to render a partly-FIPS deployment (see below)
```

Les images taguées `-fips` doivent être disponibles dans votre registre. Contactez
hello@defectdojo.com pour y avoir accès.

### Composants sans variante FIPS

Sensei et le PostgreSQL/Redis **embarqués** n'ont pas de build FIPS — l'image
valkey fournie est basée sur Alpine, qui ne dispose pas d'OpenSSL validé FIPS. Une installation
FIPS doit donc utiliser des magasins de données externes et laisser Sensei désactivé :

```yaml
fips:
  enabled: true
sensei:
  enabled: false
postgresql:
  enabled: false    # point at an external FIPS-compliant database
redis:
  enabled: false    # point at an external FIPS-compliant cache
```

Avec `fips.validate: true` (valeur par défaut), le chart **échoue au rendu** si vous
activez FIPS en même temps que l'un de ces composants, en nommant les responsables :

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei, redis (embedded). Disable them, or set fips.validate=false to accept
that they run non-validated cryptography.
```

C'est voulu. Un déploiement où la plupart des services utilisent une cryptographie
validée, mais où un ou deux ne le font pas discrètement, est pire qu'un échec évident :
il paraît conforme et le problème ne se révèle que lors d'un audit. Ne réglez
`fips.validate: false` que si vous avez explicitement accepté ce risque.

### Vérifier après le déploiement

Chaque pod exécute une vérification de démarrage en mode fail-closed — si le fournisseur
validé n'est pas actif, le conteneur s'arrête au lieu de servir des requêtes. Les preuves
qu'il affiche sont généralement ce qu'un auditeur recherche :

```bash
kubectl -n $NAMESPACE logs deploy/dojopro-django | grep FIPS
kubectl -n $NAMESPACE exec deploy/dojopro-django -- openssl list -providers
kubectl -n $NAMESPACE exec deploy/dojopro-django -- python3 /verify_fips.py
```

Les changements de comportement à anticiper (le hachage des mots de passe passe à PBKDF2,
ChaCha20 est retiré de la liste des suites de chiffrement TLS) sont détaillés dans la page
Mode FIPS 140-3 de la documentation du produit.

---

## Pre-flight : valider les modèles

Avant l'installation, exécutez `helm template` pour générer et valider tous les manifestes
sans toucher au cluster. Cela permet de détecter les erreurs de valeurs, les champs requis
manquants et les problèmes YAML avant de vous engager dans `helm install` :

```bash
helm template dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/<platform>.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  > /dev/null
```

Utilisez les mêmes indicateurs que ceux que vous prévoyez de transmettre à `helm install`. Si
la commande se termine sans erreur, vos valeurs sont valides. En cas d'échec, le message d'erreur
identifiera le champ manquant ou invalide — corrigez votre fichier de valeurs et relancez la
commande jusqu'à ce qu'elle réussisse.

---

## Déployer

Combinez votre surcouche de plateforme, votre profil de ressources, vos valeurs client, ainsi que
les choix de secrets et de licence effectués ci-dessus.

### AWS EKS

> **Il est fortement recommandé d'utiliser HTTPS pour l'accès navigateur sur EKS.**
> Lorsque le TLS d'ingress est actif, le chart active automatiquement
> `SECURE_SSL_REDIRECT` et définit les cookies CSRF/session sur `Secure`, ce qui signifie
> que la connexion via navigateur échouera sans écouteur HTTPS sur l'ALB. Configurez un
> certificat ACM avant le déploiement pour une expérience optimale.
>
> Si vous devez fonctionner sans HTTPS, consultez
> [Déploiement sans HTTPS (non recommandé)](#deploying-without-https-not-recommended)
> ci-dessous.

```bash
NAMESPACE="dojopro"
kubectl create namespace $NAMESPACE
```

> **Cohérence de l'espace de noms :** la valeur de l'espace de noms doit correspondre dans toutes
> les ressources : votre YAML de secrets (`metadata.namespace`), `kubectl create namespace`,
> et `helm install -n`. Si vous utilisez un espace de noms personnalisé au lieu de `dojopro`,
> remplacez-le de manière cohérente dans toutes les commandes et tous les manifestes de secrets.

**Secrets externes + secret de licence (GitOps) :**

Appliquez vos secrets si ce n'est pas déjà fait (voir [Générer les secrets](#generate-secrets)),
puis installez :

```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/aws-eks.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

**Secrets en ligne + fichier de licence (plus simple) :**
```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/aws-eks.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

#### Déploiement sans HTTPS (non recommandé)

> **Avertissement :** exécuter l'application sans HTTPS signifie que les cookies de session sont
> envoyés en clair et que la protection CSRF via des cookies sécurisés est désactivée. N'utilisez
> pas cette configuration en production.

Si vous devez déployer temporairement sans HTTPS (par exemple, pour des tests initiaux sans
certificat ACM), appliquez **tous** les changements suivants dans votre fichier de valeurs :

```yaml
dojo:
  url: "http://dojo.example.com"       # must be http://, not https://
  secureCookies: false                  # disable Secure flag on session/CSRF cookies

django:
  ingress:
    tls:
      enabled: false
    annotations:
      # HTTP-only listener — remove the HTTPS listener entirely
      alb.ingress.kubernetes.io/listen-ports: '[{"HTTP": 80}]'
      # Do NOT include the ssl-redirect annotation — it causes a redirect
      # loop when no HTTPS listener exists (see BUG-17 in Known Issues)
      # alb.ingress.kubernetes.io/ssl-redirect: "443"   # REMOVE this line
```

Les quatre changements sont tous requis. L'omission de l'un d'entre eux entraînera des boucles
de redirection ou un échec de connexion. Lorsque vous êtes prêt à activer HTTPS, annulez ces
changements et configurez un certificat ACM.

### OpenShift / ROSA

```bash
NAMESPACE="dojopro"
oc new-project $NAMESPACE
# Or, if the namespace already exists:
# oc project $NAMESPACE
```

> **Rappel :** vous devriez déjà disposer de la valeur `fsGroup` de votre espace de noms grâce à
> la [liste de contrôle pré-installation](#infrastructure-details). Si ce n'est pas le cas,
> récupérez-la maintenant :
>
> ```bash
> oc get namespace $NAMESPACE \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Use the start value (e.g., 1001070000) as securityContext.openshift.fsGroup
> ```

**Secrets externes + secret de licence (GitOps) :**

Appliquez vos secrets si ce n'est pas déjà fait (voir [Générer les secrets](#generate-secrets)),
puis installez :

```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/openshift.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

**Secrets en ligne + fichier de licence (plus simple) :**
```bash
helm install dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/openshift.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

---

## Déployer avec ArgoCD

DefectDojo Pro est entièrement compatible avec ArgoCD. Le chart inclut des préréglages de
plateforme et de profil qu'ArgoCD peut référencer directement en tant que `valueFiles`.

### Prérequis

Avant de créer l'Application ArgoCD, les ressources Kubernetes suivantes doivent exister
dans l'espace de noms cible :

- Les secrets de l'application (voir [Générer les secrets](#generate-secrets))
- Le secret de licence (voir [Licence](#license))
- Les secrets TLS internes, si vous n'utilisez pas la génération automatique (voir [Créer les certificats TLS internes](#create-internal-tls-certificates))
- Le matériel mTLS de ddorch (voir [Certificats mTLS ddorch](#ddorch-mtls-certificates)). ArgoCD ne dispose pas d'équivalent à `--set-file` ; transmettez donc les trois contenus PEM via des paramètres d'Application (`ddorch.tls.rootCa` / `ddorch.tls.cert` / `ddorch.tls.key`). Utilisez un plugin de gestion des secrets ArgoCD (Sealed Secrets, External Secrets ou un plugin ConfigMap) plutôt que de valider la clé en texte clair.

### Fonctionnement

ArgoCD référence les fichiers de préréglages par rapport à la racine du chart. Votre
spécification d'Application a besoin de trois éléments :

1. Les préréglages de plateforme et de profil en tant que `valueFiles`
2. Votre configuration spécifique à l'environnement (via `valueFiles`, des `values` en ligne, ou les deux)
3. Les références de secrets et de licence en tant que `parameters`

```yaml
helm:
  valueFiles:
    - presets/platforms/aws-eks.yaml       # or openshift
    - presets/profiles/standard.yaml       # or minimal, performance
  values: |
    # Your environment-specific configuration goes here.
    # This is applied last and overrides the presets above.
    dojo:
      fqdn: dojo.example.com
      admin:
        user: admin
        email: admin@example.com
    database:
      host: your-db-host.example.com
    # ... see template.yaml for all options
  parameters:
    - name: dojo.existingSecret
      value: dojopro-secrets
    - name: license.existingSecret
      value: dojopro-license
```

### Fournir votre configuration

Il existe plusieurs façons de fournir vos valeurs spécifiques à l'environnement à ArgoCD :

- Des `values` en ligne dans la spécification d'Application — approche la plus simple, sans
  fichier ni dépôt supplémentaire nécessaire. Fonctionne bien lorsque votre configuration est
  simple.
- Un fichier de valeurs dans un dépôt git distinct — utilisez la fonctionnalité multi-source
  d'ArgoCD (v2.6+) avec une variable `$ref` pour récupérer votre fichier de valeurs aux côtés
  du chart. Recommandé lors de l'utilisation d'un chart publié en OCI.
- Un fichier de valeurs dans le même dépôt git que le chart — référencez-le dans `valueFiles`
  avec un chemin relatif au répertoire du chart (par exemple, `../../overrides/customers/my-company.yaml`).

Les trois approches suivent la même superposition : préréglage de plateforme → préréglage
de profil → votre configuration. Les valeurs les plus récentes remplacent les précédentes.

### Mise à niveau

Lorsque le chart est publié dans un registre OCI, la mise à niveau se résume à une seule
modification de `targetRevision` dans votre spécification d'Application. Les préréglages de
plateforme et de profil sont versionnés avec le chart, ils sont donc mis à jour automatiquement.

Pour tous les détails sur la prise en charge de Helm par ArgoCD, consultez la
[documentation Helm d'ArgoCD](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/).

---

## Vérifier

```bash
# Check the initializer job completed successfully (required for first install)
kubectl get jobs -n $NAMESPACE
# The initializer job must show 1/1 COMPLETIONS. If it shows 0/1, the
# database migrations did not run and the application will not work.
# Check its logs:
#   kubectl logs -n $NAMESPACE -l app.kubernetes.io/component=initializer
# To retry: delete the failed job and run helm upgrade with the same flags:
#   kubectl delete job -n $NAMESPACE -l app.kubernetes.io/component=initializer
#   helm upgrade dojopro <chart> ... (same flags as install)

# Check all pods are running
kubectl get pods -n $NAMESPACE
# Expected components (chart 2.57+): django, celery-worker, celery-beat,
# connectors, nginx, ddorch, ddorch-workers, integrators, mcp-server, plus
# redis and postgresql if you are using the bundled copies, plus psirt and
# sensei if you enabled them (psirt.enabled, sensei.enabled).
# Note: ddorch-workers replaces the legacy kairos, rulesengine, and
# hatchet-integrators workers.

# Check ingress (EKS) or route (OpenShift)
kubectl get ingress -n $NAMESPACE    # EKS
oc get route -n $NAMESPACE           # OpenShift

# Run built-in helm tests
helm test dojopro -n $NAMESPACE --logs --timeout 5m

# Health check
# EKS (use https:// if TLS is configured, http:// otherwise):
ALB=$(kubectl get ingress -n $NAMESPACE -o jsonpath='{.items[0].status.loadBalancer.ingress[0].hostname}')
curl -sk "https://${ALB}/api/v2/health_check/light/"
# or for HTTP-only deployments:
# curl -s "http://${ALB}/api/v2/health_check/light/"

# OpenShift:
ROUTE=$(oc get route -n $NAMESPACE -o jsonpath='{.items[0].spec.host}')
curl -sk "https://${ROUTE}/api/v2/health_check/light/"
```

### Tests Helm intégrés

Le chart est fourni avec quatre tests qui s'exécutent sous forme de pods Kubernetes lorsque vous
lancez `helm test`. Ils valident les points d'intégration critiques entre DefectDojo et ses
services sous-jacents :

| Test | Ce qui est vérifié |
|------|----------------|
| `test-database` | Se connecte à PostgreSQL avec les identifiants configurés, exécute `SELECT version()`, et confirme que la base de données accepte les requêtes. Réessaie pendant jusqu'à 60 secondes. |
| `test-redis-broker` | Se connecte au broker Redis/Valkey, envoie un `PING`, puis effectue un cycle set/get/delete pour vérifier l'accès en lecture-écriture. |
| `test-django-health` | Interroge le point de terminaison `/api/v2/health_check/light/` sur le service nginx interne et confirme une réponse HTTP 2xx/3xx. S'exécute après les tests de base de données et de broker (hook-weight 10). |
| `test-storage` | Monte le volume média et effectue un cycle d'écriture/lecture/suppression pour confirmer que le backend de stockage est accessible et modifiable par l'application. S'exécute en dernier (hook-weight 15). |

Les tests s'exécutent dans l'ordre du hook-weight — d'abord les tests d'infrastructure (base
de données, broker), puis les tests au niveau applicatif (santé, stockage). Si un test précédent
échoue, les tests suivants peuvent tout de même s'exécuter, mais échoueront probablement aussi.

Pour relancer les tests après un échec de déploiement ou un changement de configuration :
```bash
helm test dojopro -n $NAMESPACE --logs --timeout 5m
```

Les pods de test sont automatiquement nettoyés avant chaque exécution (politique de suppression
`before-hook-creation`). Pour inspecter manuellement les journaux d'un pod de test en échec :

```bash
kubectl logs -n $NAMESPACE dojopro-test-database
kubectl logs -n $NAMESPACE dojopro-test-redis-broker
kubectl logs -n $NAMESPACE dojopro-test-django-health
kubectl logs -n $NAMESPACE dojopro-test-storage
```

### Récupérer le mot de passe administrateur

Le mot de passe administrateur initial est stocké dans le secret de l'application. Récupérez-le
avec :

```bash
kubectl get secret dojopro-secrets -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

Si vous avez utilisé des secrets en ligne au lieu d'un secret externe, le mot de passe se
trouve dans le secret géré par le chart :

```bash
kubectl get secret dojopro-defectdojo -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

Connectez-vous à l'URL configurée avec le nom d'utilisateur administrateur (par défaut :
`admin`) et ce mot de passe. Changez le mot de passe après la première connexion.

---

## Opérations

### Verbosité des journaux

Le chart expose deux paramètres de niveau de journalisation, tous deux définis par défaut sur
`INFO` :

| Paramètre | Contrôle | Variable d'environnement |
|---------|----------|---------|
| `config.logLevel` | Journalisation de l'application Django | `DD_LOG_LEVEL` |
| `celery.logLevel` | Journalisation des workers et du beat Celery | `DD_CELERY_LOG_LEVEL` |

Pour augmenter la verbosité à des fins de dépannage, définissez l'un ou l'autre (ou les deux)
sur `DEBUG` dans votre fichier de valeurs, puis exécutez `helm upgrade` :

```yaml
config:
  logLevel: "DEBUG"
celery:
  logLevel: "DEBUG"
```

```bash
helm upgrade dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/<platform>.yaml \
  -f $CHART/presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set config.logLevel=DEBUG \
  --set celery.logLevel=DEBUG \
  --wait --timeout 15m
```

Les indicateurs `--set` remplacent les paramètres du fichier de valeurs, ce qui vous permet
d'activer ou de désactiver la journalisation de débogage sans modifier de fichiers. Une fois le
problème résolu, exécutez à nouveau `helm upgrade` sans les indicateurs `--set` pour revenir à
votre configuration par défaut.

Le déploiement Django prend également en charge `django.uwsgi.enableDebug: true`, qui définit
`DD_DEBUG=True` pour un débogage de plus bas niveau du framework. Cela produit nettement plus de
sorties et ne devrait être utilisé que pour de courtes investigations.

### Isolation des imports de scans

Les imports de scans (`/api/v2/import-scan/` et `/api/v2/reimport-scan/`) sont analysés de
manière synchrone et peuvent consommer d'importantes quantités de mémoire des workers. Par
défaut, le chart exécute un déploiement `django-import` dédié (uwsgi sur le port 3032 derrière
son propre Service), et le nginx du pod Django lui achemine les points de terminaison d'import.
Un import volumineux ne peut donc pas épuiser (ni provoquer un OOM sur) les workers web
interactifs, et le pool d'importeurs (writers) évolue indépendamment des pods web (readers).

Paramètres ajustables sous `django.uwsgiImport` :

```yaml
django:
  uwsgiImport:
    enabled: true          # false routes imports back to the main uwsgi pool
    replicas: 2            # importer pods (ignored when autoscaling is on)
    maxBodySizeMb: null    # client_max_body_size on the import routes; null
                           # derives dojo.scanMaxFileSize + 5 (multipart
                           # overhead), so raising scanMaxFileSize just works.
                           # Set an integer to override.
    performance:
      processes: 2         # concurrent imports per pod = processes x threads
      threads: 4
    resources:
      requests:
        cpu: "100m"
        memory: "512Mi"
      limits:
        memory: "4Gi"
    terminationGracePeriodSeconds: 60   # raise toward 1800 to let in-flight
                                        # imports finish on rollouts/drains
    autoscaling:
      enabled: false       # scale importers on their own CPU signal
    horizontalpodautoscaler:
      minReplicas: 2
      maxReplicas: 5
      averageUtilization: 60
```

Notes opérationnelles :

- Les pods importeurs montent le volume média partagé ; ils ont donc besoin d'un stockage
  compatible ReadWriteMany pour pouvoir être planifiés librement sur tous les nœuds. Les backends
  de stockage du chart (`efs`, `filestore`, `gcsfuse`, `nfs`, et le PVC média RWX par défaut)
  conviennent tous ; un PVC ReadWriteOnce ne convient pas.
- L'autoscaling des importeurs est désactivé par défaut, car une réduction d'échelle expulse
  l'import en cours d'exécution sur ce pod dès que `terminationGracePeriodSeconds` expire. Si
  vous l'activez, augmentez la période de grâce pour permettre aux imports en cours de se
  terminer.
- Un PodDisruptionBudget (`podDisruptionBudget.djangoImport`) protège le pool d'importeurs
  pendant les interruptions volontaires dès que plus d'un importeur est en cours d'exécution.

Le profil `minimal` désactive le déploiement importeur pour limiter l'empreinte ; les imports
partagent alors le pool uwsgi unique comme auparavant.

### Moteur d'avis PSIRT (optionnel)

Le chart peut déployer le PSIRT Advisory Engine, un service permettant de rédiger et de publier
des avis de sécurité à partir des constatations DefectDojo. Il est désactivé par défaut. Une fois
activé, il apparaît sous `/psirt/` sur votre hôte DefectDojo principal — le sidecar nginx le
proxifie, donc aucune entrée ingress ou DNS supplémentaire n'est nécessaire.

```yaml
psirt:
  enabled: true
  # REQUIRED: full async connection URL. Use a dedicated database (its
  # migrations must not share DefectDojo's database).
  databaseUrl: "postgresql+asyncpg://pae:<password>@<host>:5432/pae"
  # Pre-shared secret for autonomous advisory publishing. The scheduler sends
  # it to DefectDojo as an X-Psirt-Secret header (no minted token, no UI step);
  # the chart injects the SAME value into the DefectDojo pods so they accept it.
  # Optional — omit to disable autonomous publishing (the pod still boots).
  psirtSharedSecret: "<high-entropy secret>"
  # Strongly recommended: pin both secrets. Left empty they are re-generated
  # on every helm upgrade, which logs out active sessions and invalidates
  # stored DefectDojo tokens.
  sessionSecretKey: ""   # any 64-character string
  fernetSaltB64: ""      # python -c "import secrets; print(secrets.token_urlsafe(32))"
```

`psirtSharedSecret` est une simple valeur que vous choisissez — aucun utilisateur DefectDojo ni
jeton généré n'est impliqué. Définissez une chaîne à haute entropie (par exemple
`python -c "import secrets; print(secrets.token_urlsafe(48))"`). Le chart la connecte à la fois
au Secret du moteur psirt et aux pods DefectDojo, de sorte qu'une seule valeur permet une
publication autonome dès l'installation, sans étape post-démarrage. Rotation : changez-la puis
exécutez `helm upgrade`.

Configuration de la base de données : pointez `databaseUrl` vers le même hôte PostgreSQL que
celui utilisé par DefectDojo (ou tout autre hôte accessible), avec un nom de base de données de
votre choix. Le pod crée la base de données au premier démarrage si elle n'existe pas, ce qui
nécessite une autorisation ponctuelle en tant que superutilisateur postgres :

```sql
ALTER ROLE pae CREATEDB;
```

Notes opérationnelles :

- Conservez `psirt.replicas` à 1. Le service exécute son propre planificateur de tâches
  interne, et une seconde réplique exécuterait chaque tâche planifiée deux fois.
- Le pod monte le volume média partagé (les pièces jointes des avis se trouvent sous
  `<media>/pae/uploads`), les mêmes recommandations de stockage ReadWriteMany que pour le pool
  d'importeurs s'appliquent donc.
- Le HTTPS sortant est requis pour les flux d'avis et les recherches NVD. Avec
  `networkPolicy.profile=aggressive`, la liste des CIDR autorisés
  (`networkPolicy.externalAPIs.allowedCidrs`) doit couvrir ces points de terminaison.
- Un `psirt.nvdApiKey` optionnel augmente la limite de débit NVD de 5 à 50 requêtes par 30
  secondes.

### Moteur de scan/correction Sensei (optionnel)

Le chart peut déployer le moteur Sensei, le service à l'origine des tâches de scan côté serveur
et de correction automatique (fix). Il est désactivé par défaut et ne nécessite aucune
configuration supplémentaire pour démarrer :

```yaml
sensei:
  enabled: true
```

Le moteur ne conserve aucun secret persistant. Les identifiants de scan/correction et les URL de
point de terminaison circulent avec chaque tâche, transmis depuis la configuration chiffrée des
workers de DefectDojo. django et celery atteignent le moteur au sein du cluster
(`SENSEI_ENGINE_URL` est connecté automatiquement au configmap partagé), aucune entrée ingress
ou DNS n'est donc nécessaire.

Notes opérationnelles :

- Par défaut, le moteur rappelle DefectDojo à l'URL publique de votre site (`dojo.url`).
  Définissez `sensei.ddCallbackUrl` pour la remplacer — pour un trafic purement intra-cluster,
  pointez-la vers l'écouteur nginx interne, mais le moteur doit alors faire confiance à
  l'autorité de certification interne de DefectDojo.
- Les identifiants LLM pour les tâches de correction sont normalement définis dans
  l'application (Paramètres du modèle IA) et transmis à chaque tâche. Ne définissez
  `sensei.llm.*` que lorsque le moteur doit lire la clé depuis son propre environnement ;
  privilégiez `sensei.llm.existingSecret` plutôt que `sensei.llm.apiKey` en texte clair.
- Pour exécuter le moteur avec Google Vertex AI au lieu d'une clé API de fournisseur,
  définissez `sensei.llm.provider: vertex` et `sensei.llm.vertexProject` sur le projet GCP
  hébergeant Vertex (`sensei.llm.vertexRegion` vaut généralement `global`). Le pod
  s'authentifie avec les Application Default Credentials ; attribuez-lui donc un compte de
  service GCP via `sensei.serviceAccountName` + Workload Identity, ou montez un fichier de clé
  avec `sensei.extraVolumesRaw` et `sensei.extraVolumeMounts`, puis pointez
  `GOOGLE_APPLICATION_CREDENTIALS` vers celui-ci via `sensei.extraEnv`.
- `sensei.llm.fallbackChain` accepte une liste d'entrées `provider` ou `provider:model`
  séparées par des virgules, vers lesquelles le moteur bascule lorsque le fournisseur principal
  renvoie un échec pouvant être réessayé. Terminer la chaîne sur un fournisseur différent (par
  exemple `vertex-gemini:gemini-2.5-pro`) permet aux tâches de correction de continuer à
  s'exécuter pendant une panne du fournisseur principal.
- L'image du scanner est volumineuse. `sensei.maxConcurrentJobs` (3 par défaut) limite le
  nombre de tâches parallèles par pod, et les ressources par défaut (requête 1Gi / limite 4Gi)
  sont dimensionnées pour cette limite — augmentez les deux ensemble.
- Un HPA basé sur le CPU (1 à 4 répliques) est activé par défaut. Définissez
  `sensei.hpa.maxReplicas` égal à `sensei.hpa.minReplicas` pour figer plutôt le nombre sur
  `sensei.replicas`.
- Le HTTPS sortant est requis pour les clonages de dépôt, les API d'hébergement git et les API
  des fournisseurs LLM. Avec `networkPolicy.profile=aggressive`, la liste des CIDR autorisés
  (`networkPolicy.externalAPIs.allowedCidrs`) doit couvrir ces points de terminaison.

### Rotation des certificats TLS

Le chart utilise deux catégories de certificats TLS, chacune avec une procédure de rotation
différente.

#### TLS interne (service à service)

Il s'agit des secrets `dojopro-internal-tls` et `dojopro-internal-ca` utilisés pour la
communication entre nginx, connectors, et les autres services internes.

```bash
# Replace the existing secret with new cert/key
kubectl create secret tls dojopro-internal-tls \
  --cert=new-server.crt \
  --key=new-server.key \
  -n $NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

# Replace the CA bundle
kubectl create secret generic dojopro-internal-ca \
  --from-file=ca.crt=new-ca.crt \
  -n $NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

# Restart affected pods to pick up new certs
kubectl rollout restart deployment -n $NAMESPACE
```

#### TLS d'ingress (externe/côté navigateur)

La rotation dépend de la manière dont vous avez configuré le TLS :

- **Géré par ACM (EKS) :** le renouvellement est automatique — aucune action requise.
- **cert-manager :** le renouvellement est automatique selon les paramètres `duration` et
  `renewBefore` (valeurs par défaut : 2160h / 720h).
- **Certificats gérés GKE :** le renouvellement est automatique — aucune action requise.
- **Certificat manuel via un secret Kubernetes :** mettez à jour le secret référencé par
  l'ingress en utilisant le même schéma `kubectl create secret tls ... --dry-run=client`
  présenté ci-dessus.
- **Certificats internes générés automatiquement :** le chart peut les régénérer avec
  `helm upgrade` si `certificates.generation.enabled: true`.

> Dans Kubernetes, la source de vérité est l'objet Secret — la rotation des certificats
> consiste à mettre à jour le secret puis à effectuer un rollout du déploiement.

> Si vous utilisez External Secrets Operator ou Sealed Secrets pour gérer les secrets TLS, la
> rotation est gérée à ce niveau et les secrets Kubernetes se mettent à jour automatiquement —
> aucune étape manuelle `kubectl` n'est nécessaire.

---

## Superposition des fichiers de valeurs

Le chart empile les fichiers de valeurs. Les fichiers les plus récents l'emportent :

```
presets/platforms/<platform>.yaml       # Platform defaults (aws-eks or openshift)
presets/profiles/<size>.yaml            # Resource profiles (minimal, standard, performance)
overrides/customers/<company>.yaml      # Your config (domain, DB, storage, certs)
```

Les préréglages de plateforme et de profil sont fournis à l'intérieur du chart
(`dojopro/presets/`). Ils sont inclus dans le `.tgz` packagé et versionnés avec le chart. Les
clients n'ont pas besoin de les modifier.

Lorsque vous utilisez `helm install` à partir du chart extrait, référencez-les en utilisant la
variable `$CHART` définie lors de l'[extraction](#extract-the-chart-package) :
```
-f $CHART/presets/platforms/aws-eks.yaml
```

Lorsque vous utilisez ArgoCD, référencez-les par rapport à la racine du chart :
```
valueFiles:
  - presets/platforms/aws-eks.yaml
```

Ne placez pas de limites de ressources dans les fichiers client, ni de configuration de
plateforme dans les fichiers de profil. Gardez chaque couche centrée sur une seule chose.

> **Versionnage des préréglages — ArgoCD vs CLI :** ArgoCD référence les préréglages à
> l'intérieur du package du chart, ils se mettent donc à jour automatiquement lorsque vous
> modifiez `targetRevision`. Les utilisateurs de la CLI doivent réextraire les préréglages lors
> d'une mise à niveau vers une nouvelle version du chart pour bénéficier des éventuels
> changements des valeurs par défaut de plateforme ou de profil. Utilisez un chemin
> d'extraction versionné (par exemple, `dojopro-2.55.4/`) pour éviter toute confusion entre les
> versions de chart — voir [Extraire le package du chart](#extract-the-chart-package).

---

## Personnalisation et extensibilité

Au-delà des fichiers de valeurs plateforme/profil/client, le chart offre des points d'extension
de premier ordre pour connecter votre propre infrastructure — sidecars, conteneurs
d'initialisation, variables d'environnement, volumes, comptes de service, contraintes
d'ordonnancement, et des manifestes supplémentaires arbitraires — sans avoir à forker le chart :

- **Points d'accroche par composant** — `extraEnv`, `extraEnvFrom`, `extraVolumesRaw`,
  `extraVolumeMounts`, `extraInitContainers`, `extraContainers`, `hostAliases`,
  `priorityClassName`, `topologySpreadConstraints`, `dnsConfig`, et `serviceAccountName` sur
  chaque charge de travail (django, celery worker/beat, connectors, ddorch, ddorch-workers,
  integrators, mcp-server, psirt).
- **`extraManifests` de premier niveau** — permet de générer du YAML arbitraire fourni par
  l'utilisateur (ConfigMaps, Secrets, NetworkPolicies, etc.) aux côtés du chart, traité via le
  `tpl` de Helm avec le contexte racine du chart.
- **Utilisation en chart parapluie (umbrella-chart)** — `dojopro` peut être intégré comme
  sous-chart via une dépendance `file://` ou OCI, ce qui est utile pour livrer des offres
  groupées client qui superposent des ressources supplémentaires autour du chart.
- **Validation basée sur un schéma** — `values.schema.json` couvre chaque point d'accroche, ce
  qui permet aux éditeurs de bénéficier de l'autocomplétion et à `helm lint`/`helm install` de
  valider vos surcharges.

Consultez le guide d'extensibilité BYO — inclus sous forme d'**Annexe : Bring Your Own
Infrastructure (BYO)** dans l'édition PDF — pour les modèles, exemples et garanties de
stabilité lors des mises à niveau.

---

## Politiques réseau

Le chart fournit des NetworkPolicies pour chaque composant, activées par défaut
(`networkPolicy.enabled: true`). Une base de refus par défaut est limitée aux pods de cette
version (via les labels `app.kubernetes.io/name` + `app.kubernetes.io/instance`), elle n'affecte
donc jamais les autres charges de travail partageant l'espace de noms.

Le degré de rigueur des règles est contrôlé par **`networkPolicy.profile`** :

| Profil | Sortie (Egress) | Entrée pod-à-pod | Entrée externe |
|---------|--------|--------------------|------------------|
| `standard` (par défaut) | Toute sortie autorisée (`0.0.0.0/0`) | Tout le trafic entre les propres pods de cette version est autorisé | Restreinte au contrôleur d'ingress / à l'équilibreur de charge |
| `aggressive` | Liste d'autorisation granulaire par composant (DNS, base de données/broker, services internes spécifiques au cluster, API externes explicitement autorisées uniquement) | Liste d'autorisation granulaire par composant | Restreinte au contrôleur d'ingress / à l'équilibreur de charge |

- **`standard`** est recommandé pour la plupart des clusters. Il évite les ruptures dues aux
  dépendances de sortie spécifiques au cluster (le serveur de métadonnées GKE, NodeLocal
  DNSCache, les points de terminaison de stockage cloud/API) et aux appels de service
  intra-application, tout en maintenant l'entrée externe verrouillée sur le chemin d'ingress :
  la version fait confiance à ses propres pods, mais l'extérieur passe toujours par la porte
  d'entrée.
- **`aggressive`** impose une liste d'autorisation stricte dans les deux sens. Si vous
  l'utilisez, vous devrez peut-être ajuster les dérogations sous `networkPolicy` pour votre
  cluster :
  - `nodeLocalDns` — autorise le résolveur NodeLocal DNSCache (link-local `169.254.20.10`
    par défaut, sur le port 53). Requis sur les clusters exécutant NodeLocal DNSCache (par
    exemple, l'add-on GKE), sinon la résolution DNS échoue.
  - `dnsSelectors` — remplace la cible de sortie DNS pour une configuration DNS
    personnalisée.
  - `allowExternalAPIs` / `externalAPIs` — contrôle la sortie vers les API HTTPS externes et
    les CIDR bloqués (par exemple, les métadonnées cloud).

Définissez le profil dans n'importe quel fichier de valeurs, par exemple :

```yaml
networkPolicy:
  profile: aggressive
```

> **Les contrôles de santé GKE** sont pris en charge dans les deux profils — les plages de
> sondage de l'équilibreur de charge GCE (`130.211.0.0/22`, `35.191.0.0/16`) sont toujours
> autorisées à atteindre le backend django sur GKE. Voir [GCP GKE](#gcp-gke).

### Accès au contrôleur d'ingress (502 Bad Gateway)

Sur les clusters autres que GKE/OpenShift, la NetworkPolicy django autorise l'entrée du
contrôleur d'ingress en sélectionnant son espace de noms via le label
`kubernetes.io/metadata.name` que Kubernetes applique automatiquement à chaque espace de noms.
Par défaut, cela suppose que le contrôleur se trouve dans un espace de noms nommé
**`ingress-nginx`**, avec des pods de contrôleur portant `app.kubernetes.io/name: ingress-nginx`
(valeur par défaut du chart ingress-nginx).

Si votre contrôleur d'ingress se trouve dans un espace de noms au nom différent, utilise des
labels de pod différents, ou est un contrôleur entièrement différent (Traefik, un ALB, etc.), la
politique rejettera silencieusement son trafic et les requêtes renverront **502 Bad Gateway**
(`connect() failed (110: Operation timed out)` dans les journaux du contrôleur). Pointez la
politique vers votre véritable source d'ingress avec `networkPolicy.ingressSource` :

```yaml
networkPolicy:
  ingressSource:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: <ingress-namespace>
      podSelector:
        matchLabels:
          app.kubernetes.io/name: <controller-label>
```

Ou ajustez `networkPolicy.ingressNamespace` / `networkPolicy.ingressControllerLabel` si seuls
les noms diffèrent. Consultez les commentaires sous `networkPolicy` dans `values.yaml` pour
d'autres exemples d'`ingressSource` (Traefik, routeur OpenShift, ALB AWS).

---

## Mise à niveau

Le chemin de mise à niveau recommandé récupère le chart directement depuis le registre OCI de
DefectDojo — aucune extraction de fichier zip n'est requise :

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

Voici à quoi ressemble une mise à niveau OCI typique (mêmes fichiers de valeurs et mêmes
indicateurs `--set` que l'installation d'origine) :

```bash
VERSION="<chart-version>"   # e.g. 2.57.2

helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --wait --timeout 15m
```

Le flux de travail à base de zip packagé utilisé lors de l'installation fonctionne également
pour les mises à niveau — substituez `helm upgrade` à `helm install` sur le chemin `$CHART`
extrait.

Consultez le [guide de mise à niveau](/get_started/pro/onprem/upgrading_on_kubernetes/) — inclus
sous forme d'**Annexe : Mise à niveau de DefectDojo Pro** dans l'édition PDF — pour
l'authentification, les mises à niveau ArgoCD, la vérification, le rollback et le dépannage.

---

## Désinstallation

```bash
helm uninstall dojopro -n $NAMESPACE
kubectl delete namespace $NAMESPACE
```

> Les PVC, les bases de données externes et les secrets externes ne sont pas supprimés.
> Nettoyez-les séparément.

### Nettoyage des PersistentVolumes

Les PersistentVolumes dotés d'une politique de récupération `Retain` sont **à l'échelle du cluster** — ils
ne sont pas supprimés par `helm uninstall` ni par la suppression de l'espace de noms. Si vous réinstallez
DefectDojo dans un espace de noms différent, les métadonnées de propriété du PV orphelin entreront en
conflit avec la nouvelle installation et bloqueront `helm install`.

Vérifiez la présence de PV orphelins après la désinstallation :

```bash
kubectl get pv | grep dojopro
```

S'il en reste, supprimez-les :

```bash
kubectl delete pv dojopro-media-pv
```

> **Remarque :** La suppression du PV retire la référence du volume Kubernetes, mais les données
> sous-jacentes persistent sur le backend de stockage (par exemple, le système de fichiers EFS). Cette
> opération est sûre si vous prévoyez de réinstaller, mais elle doit être effectuée intentionnellement.

---

## Tests locaux avec PostgreSQL et Redis intégrés

> **Cette configuration est destinée uniquement aux tests locaux et à l'évaluation. N'utilisez pas
> PostgreSQL ou Redis intégrés en production.** Les déploiements de production doivent utiliser des
> services gérés (par exemple, RDS, ElastiCache) pour la fiabilité, les sauvegardes et la mise à
> l'échelle. Le support DefectDojo ne couvre pas les problèmes liés aux bases de données intégrées dans
> les environnements de production.

Le chart peut déployer son propre PostgreSQL et Redis pour des tests locaux rapides à l'aide du profil
`minimal`. Cela évite d'avoir besoin d'une infrastructure de base de données et de broker externe.

Ajoutez ce qui suit à votre fichier de values :

```yaml
# Enable embedded PostgreSQL (instead of external RDS)
postgresql:
  enabled: true
  database:
    password: "your-password"   # required — must match DD_DATABASE_PASSWORD in your secrets

database:
  external: false

# Enable embedded Redis (instead of external ElastiCache)
redis:
  enabled: true

celery:
  broker:
    external: false
```

> **Important : `postgresql.database.password` est obligatoire** lorsque `postgresql.enabled` vaut true
> et que `database.existingSecret` n'est pas défini. Le chart ne pourra pas se rendre sans cela. Ce mot
> de passe doit correspondre à la valeur `DD_DATABASE_PASSWORD` dans les secrets de votre application.

> **Identifiants par défaut de PostgreSQL intégré :** Les valeurs par défaut du chart pour PostgreSQL
> intégré sont le nom d'utilisateur `dojodbusr` et le nom de base de données `dojodb` (définis dans le
> `values.yaml` du chart). Votre `DD_DATABASE_URL` dans les secrets de l'application doit utiliser ces
> valeurs, et non les placeholders de base de données externe présents dans `secrets-template.yaml`.
> Par exemple :
>
> ```
> DD_DATABASE_URL: "postgresql://dojodbusr:<password>@<release>-postgresql:5432/dojodb"
> ```

Le profil `minimal` (`dojopro/presets/profiles/minimal.yaml`) définit des demandes de ressources
réduites adaptées à un cluster de test à nœud unique, mais ne bascule pas ces indicateurs de base de
données/broker — vous devez les définir vous-même.

> **Remarque sur les privilèges des conteneurs :** Les conteneurs PostgreSQL et Redis intégrés ne
> s'exécutent **pas** en tant que root — PostgreSQL s'exécute avec l'UID 999 et Redis avec l'UID 1001.
> La seule exception est le **init container** de PostgreSQL (`init-chmod-data`), qui s'exécute en tant
> que root (UID 0) pour définir la propriété du répertoire sur le volume de données avant le démarrage
> du processus principal. Il s'agit d'un modèle courant pour les StatefulSets avec stockage persistant.
> Si votre cluster impose un Pod Security Standard `restricted` ou une SCC OpenShift qui interdit les
> init containers root, désactivez-le avec `postgresql.initContainer.enabled: false` (voir
> [Problèmes connus](#known-issues-chart-version-2.57.1)).

Lorsque vous utilisez PostgreSQL intégré sur EKS, vous aurez également besoin du pilote CSI EBS (voir
[Prérequis AWS EKS](#aws-eks-prerequisites)) et devrez peut-être ajuster les valeurs de stockage par
défaut (voir [Problèmes connus](#known-issues-chart-version-2.57.1)).

Validez vos values avant l'installation — le chemin minimal nécessite davantage de surcharges et est
plus susceptible de rencontrer des erreurs de rendu :

```bash
helm template dojopro $CHART \
  -n $NAMESPACE \
  -f $CHART/presets/platforms/aws-eks.yaml \
  -f $CHART/presets/profiles/minimal.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  > /dev/null
```

Si cette commande se termine sans erreur, poursuivez avec `helm install` en utilisant les mêmes
indicateurs.

> **Utilisez `--timeout 30m` pour les installations minimales/base de données neuve.** Le PostgreSQL
> intégré dispose de ressources réduites, et l'initializer doit exécuter toutes les migrations de base
> de données à partir de zéro sur une nouvelle base de données. Lors des tests, cela a pris environ 23
> minutes, ce qui dépasse le `--timeout 15m` utilisé dans les exemples d'installation standard. Un
> dépassement de délai entraîne l'affichage par `helm install` de `INSTALLATION FAILED`, même si le
> déploiement se termine correctement en arrière-plan. L'utilisation de `--timeout 30m` évite ce faux
> échec et le statut de release `failed` qui en résulte.

---

## Registre privé / environnements isolés (air-gapped)

Si votre cluster ne peut pas récupérer les images depuis le registre DefectDojo par défaut, mettez en
miroir les images vers votre propre registre et configurez le chart pour l'utiliser.

### Option 1 : surcharge globale du registre

Définissez `global.imageRegistry` pour rediriger toutes les récupérations d'images. Le chart retire le
registre d'origine de `images.prefix` et ajoute le vôtre :

```yaml
global:
  imageRegistry: "my-registry.example.com"
```

Cela affecte toutes les images (django, nginx, celery, connectors, redis, etc.).

### Option 2 : surcharges par image

Pour un contrôle plus fin, définissez `images.registry` (affecte les images de l'application
principale) et surchargez les images individuellement :

```yaml
images:
  registry: "my-registry.example.com"
  prefix: "defectdojo/"          # path within your registry
  tag: "2.53.0"
  connectors:
    registry: "my-registry.example.com"
    repository: "defectdojo/connectors"
    tag: "2.53.0"
  redis:
    registry: "my-registry.example.com"
    repository: "defectdojo/redis"
    tag: "7.2.4"
```

### Secrets de pull d'images pour les registres privés

Si votre registre nécessite une authentification, créez un secret de pull et référencez-le :

```yaml
images:
  pullSecrets:
    existingSecrets:
      - "my-registry-pull-secret"
```

Ou laissez le chart en créer un à partir d'identifiants explicites :

```yaml
images:
  pullSecrets:
    create: true
    registry: "my-registry.example.com"
    # Provide credentials via a Kubernetes docker-registry secret
```

Le comportement par défaut (`extractFromLicense: true`) extrait les identifiants de compte de service
GCP du fichier de licence pour effectuer le pull depuis le registre de DefectDojo. Désactivez cette
option lorsque vous utilisez votre propre registre :

```yaml
images:
  pullSecrets:
    create: true
    extractFromLicense: false
    existingSecrets:
      - "my-registry-pull-secret"
```

---

## Surcharge des annotations de plateforme

Le chart injecte automatiquement des annotations spécifiques à la plateforme sur l'Ingress et le
Service en fonction de `cloudProvider` (par exemple, des annotations ALB pour EKS, des annotations GCE
pour GKE). Si vous avez besoin d'un contrôle total sur les annotations — par exemple, pour utiliser un
contrôleur d'ingress nginx sur EKS au lieu d'ALB — définissez `platformAnnotations.enabled: false` et
fournissez les vôtres :

```yaml
django:
  ingress:
    platformAnnotations:
      enabled: false
    annotations:
      nginx.ingress.kubernetes.io/proxy-body-size: "500m"
      nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
  service:
    platformAnnotations:
      enabled: false
    annotations: {}
```

Lorsque `platformAnnotations.enabled` vaut `true` (valeur par défaut), le chart fusionne les
annotations de plateforme avec vos annotations personnalisées. Vos annotations sont prioritaires en cas
de conflit de clé, mais vous ne pouvez pas supprimer une annotation de plateforme sans cet indicateur.

### Limite de taille de téléversement de l'Ingress

Par défaut, le chart définit `nginx.ingress.kubernetes.io/proxy-body-size: "2400m"` sur l'Ingress afin
que les téléversements volumineux de résultats de scan et les rapports PDF passent par nginx-ingress
sans provoquer d'erreur `413 Request Entity Too Large`. Surchargez via :

```yaml
django:
  ingress:
    maxBodySize: "100m"     # set "" to omit the annotation entirely
```

Cela s'applique chaque fois que nginx-ingress est le contrôleur — y compris nginx-ingress exécuté sur
EKS, GKE ou AKS. Les contrôleurs autres que nginx ignorent cette annotation et doivent être réglés via
leurs propres mécanismes (limites d'inspection du corps AWS WAF, `request-body-limit` d'AppGW,
`tuningOptions` de HAProxy pour les Routes OpenShift).

---

## Remarques spécifiques à la plateforme

### AWS EKS

- Nécessite l'AWS Load Balancer Controller pour l'ingress ALB
- Nécessite le pilote CSI EFS si vous utilisez le stockage EFS
- Le TLS se termine au niveau de l'ALB via des certificats ACM
- Définissez `certificates.ingress.source: "acm"` et fournissez `acmCertArn`
- `dojo.secureCookies: true` fonctionne correctement puisque l'ALB gère le HTTPS

#### Points d'accès EFS

Si votre système de fichiers EFS est configuré avec un **point d'accès** (recommandé pour imposer la
propriété UID/GID sur le montage), vous **devez** définir `storage.efs.accessPointId` dans votre
fichier de values. Sans cela, le PV monte la racine EFS avec une propriété root, et les conteneurs
DefectDojo (exécutés avec l'UID 1001) ne peuvent pas créer de sous-répertoires media — ce qui provoque
l'échec de l'initializer avec des erreurs `Permission denied`.

Vérifiez vos points d'accès EFS :

```bash
aws efs describe-access-points --file-system-id <your-fs-id> --region <region> \
  --query 'AccessPoints[].{Id:AccessPointId,Path:RootDirectory.Path,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
  --output table
```

Si un point d'accès existe, ajoutez-le à votre fichier de values :

```yaml
storage:
  type: "efs"
  efs:
    enabled: true
    fileSystemId: "fs-REPLACE_EFS_ID"
    accessPointId: "fsap-REPLACE_EFS_ACCESS_POINT_ID"
    region: "REPLACE_AWS_REGION"
```

> **Important :** Le champ `volumeHandle` du PersistentVolume est **immuable** après sa création. Si
> vous installez initialement sans point d'accès et devez en ajouter un par la suite, vous devez
> supprimer le PV et le PVC existants avant d'exécuter `helm upgrade` :
>
> ```bash
> kubectl delete pvc defectdojo-media -n $NAMESPACE
> kubectl delete pv dojopro-media-pv
> helm upgrade dojopro $CHART ... (same flags as install)
> ```
>
> Cette opération est sûre — la suppression du PV ne retire que la référence Kubernetes ; les données
> sur le système de fichiers EFS ne sont pas affectées.

#### StorageClasses sur les clusters renforcés / gouvernés par GitOps

Deux hypothèses relatives aux StorageClasses posent problème sur les clusters ayant une nomenclature de
StorageClass personnalisée ou où les ressources à l'échelle du cluster sont gérées en dehors du chart
applicatif.

**Les PVC provisionnés dynamiquement utilisent par défaut `gp3` sur EKS.** Tout PVC provisionné
dynamiquement par le chart — le volume Redis intégré (`redis.enabled: true`) et le volume media
`storage.type: "pvc"` — résout sa StorageClass vers la valeur par défaut de la plateforme, qui est
`gp3` sur EKS. Si votre cluster ne possède aucune StorageClass nommée `gp3` (cas fréquent sur les
clusters renforcés avec une nomenclature personnalisée), le PVC reste en état `Pending` avec un
événement `storageclass.storage.k8s.io "gp3" not found`, et les pods ne démarrent jamais.

Surchargez-la de l'une des deux façons suivantes :

- **Globalement (recommandé)** — un seul levier pour tous les PVC provisionnés par le chart :

  ```yaml
  storage:
    defaultStorageClass: "your-ebs-storageclass"   # or "" for the cluster default
  ```

- **Par composant**, si vous avez besoin de classes différentes :

  ```yaml
  redis:
    redisVolume:
      pvc:
        storageClassName: "your-ebs-storageclass"
  storage:
    pvc:
      storageClassName: "your-ebs-storageclass"    # only for storage.type: "pvc"
  ```

  L'ordre de résolution est : valeur par composant → `storage.defaultStorageClass` → valeur par défaut
  de la plateforme (`gp3`). Définissez une valeur sur `""` pour revenir à la StorageClass par défaut du
  cluster. Cela ne s'applique **pas** au chemin media EFS par défaut (voir ci-dessous), qui n'utilise
  aucune StorageClass.

**Le volume media EFS par défaut ne nécessite aucune StorageClass.** Lorsque `storage.type: "efs"`, le
chart lie le PV media de manière statique via le `volumeHandle` du système de fichiers EFS et un
`claimRef` — le PV comme le PVC utilisent un `storageClassName` vide. La StorageClass `efs-sc` n'a
**pas** besoin d'exister pour que le PVC media se lie.

Le chart ne crée une StorageClass `efs-sc` à l'échelle du cluster que si vous optez explicitement pour
le provisionnement **dynamique** d'EFS avec `storageClasses.efs.enabled: true` (valeur par défaut :
`false`). Sur les clusters où les ressources à l'échelle du cluster sont gérées en dehors du chart
applicatif (GitOps), laissez la valeur par défaut `false` — le chemin EFS statique décrit ci-dessus ne
nécessite aucune StorageClass ni aucun objet à l'échelle du cluster provenant de ce chart. Si vous
souhaitez malgré tout un provisionnement EFS dynamique sous GitOps, créez la StorageClass hors bande et
conservez `storageClasses.efs.enabled: false`.

### GCP GKE

- Utilise le contrôleur d'ingress GCE (`className: "gce"`) avec une terminaison TLS au niveau du load
  balancer Google Cloud
- Le préréglage `gcp-gke.yaml` attache automatiquement une `FrontendConfig` (redirection HTTP→HTTPS +
  politique SSL) et une `BackendConfig` à l'ingress
- Le load balancer GCE effectue des vérifications de santé sur le backend django directement depuis
  les plages IP de Google (`130.211.0.0/22`, `35.191.0.0/16`). Les NetworkPolicies du chart les
  autorisent automatiquement sur GKE pour les deux valeurs de `networkPolicy.profile`, de sorte que la
  sonde `/nginx_health` réussit et que le backend se signale comme sain — voir
  [Politiques réseau](#network-policies)

#### TLS géré par Google ou apporté par vous (BYO)

Le préréglage `gcp-gke.yaml` utilise par défaut les **certificats gérés par Google**. Choisissez l'une
des deux approches suivantes :

- **Géré par Google (par défaut) :** GCP provisionne et renouvelle le certificat. Il suffit de lister
  vos domaines — aucun secret TLS Kubernetes n'est nécessaire :

  ```yaml
  certificates:
    ingress:
      source: "google-managed"
      googleManaged:
        domains:
          - defectdojo.example.com
  ```

- **Apporté par vous (BYO) :** Fournissez un secret TLS Kubernetes existant dans l'espace de noms de
  la release et pointez l'ingress vers celui-ci :

  ```yaml
  certificates:
    ingress:
      source: "secret"
      secretName: wildcard-example-com   # kubectl create secret tls ...
  ```

  Cela génère `spec.tls[].secretName` sur l'ingress et omet l'annotation
  `networking.gke.io/managed-certificates`.

> **Prise en charge du script de bootstrap :** `scripts/bootstrap/bootstrap-gcp-gke.sh` ne couvre que
> les flux de certificats natifs GCP (`google-managed` et `pre-shared`). Pour le chemin BYO `secret`,
> installez directement avec `helm` (créez d'abord le secret TLS, puis passez
> `certificates.ingress.source=secret` et `certificates.ingress.secretName=<your-secret>`).

> Le renouvellement des certificats gérés par Google est automatique — voir
> [Rotation des certificats TLS](#rotating-tls-certificates).

### OpenShift / ROSA

- Utilise les Routes par défaut (`django.route.enabled: true`), mais l'Ingress est également pris en
  charge
- Pour utiliser l'Ingress à la place : définissez `django.ingress.enabled: true` et
  `django.route.enabled: false`
- Un seul des deux peut être activé à la fois (le chart valide l'exclusivité mutuelle)
- **`dojo.secureCookies` doit être `false`** lors de l'utilisation de Routes à terminaison edge
  (comportement par défaut). Ceci est obligatoire, pas optionnel. Voir l'
  [avertissement dans Préparer votre fichier de values](#prepare-your-values-file).
- `securityContext.openshift.fsGroup` doit correspondre à la plage de groupes supplémentaires de votre
  espace de noms (voir la [liste de contrôle pré-installation](#infrastructure-details) pour savoir
  comment la trouver)
- NFS via EFS fonctionne bien — utilisez `storage.type: "nfs"` avec le nom DNS EFS comme serveur

#### Utiliser l'Ingress au lieu des Routes sur OpenShift

OpenShift est livré avec un contrôleur d'ingress basé sur HAProxy par défaut. Si vous préférez
l'Ingress aux Routes (par exemple, pour la cohérence avec d'autres clusters ou pour utiliser un
contrôleur d'ingress personnalisé), configurez vos values comme suit :

```yaml
django:
  ingress:
    enabled: true
    className: "openshift-default"   # or your custom ingress class
    platformAnnotations:
      enabled: false                 # recommended — provide your own annotations
    pathType: "Prefix"
    path: "/"
    tls:
      enabled: true
    annotations: {}                  # add your ingress controller annotations here
  route:
    enabled: false
  nginx:
    tls:
      enabled: false
      generateCertificate: false
```

Les helpers de plateforme du chart continueront de gérer correctement les contextes de sécurité, le
résolveur DNS et les valeurs de stockage par défaut pour OpenShift, quelle que soit la méthode
d'exposition choisie.

---

## Problèmes connus (version de chart 2.57.1)

Il s'agit de bugs confirmés dans le chart actuel. Des solutions de contournement sont documentées ici
jusqu'à la publication d'une version corrigée.

### Installation minimale avec PostgreSQL ou Redis locaux uniquement

Les problèmes suivants ne s'appliquent que si vous utilisez le PostgreSQL ou le Redis intégrés au chart
(`postgresql.enabled: true` ou `broker.external: false`). Ils n'affectent pas les déploiements de
production utilisant des bases de données et des brokers externes.

**N'utilisez pas EBS pour le volume media (BUG-14, BUG-15)**

Les volumes EBS ne prennent en charge que `ReadWriteOnce` — ils ne peuvent être attachés qu'à un seul
nœud à la fois. DefectDojo exige que le volume media soit partagé entre plusieurs pods (django,
celery-worker, initializer, connectors), qui peuvent être planifiés sur des nœuds différents. Lorsque
cela se produit, les pods restent bloqués en état `ContainerCreating` avec une erreur
`Multi-Attach error`, car EBS ne peut pas monter le volume sur plus d'un nœud simultanément. Cela
affecte également `helm test`, où le pod test-storage peut être planifié sur un nœud différent des
pods applicatifs.

**Utilisez EFS (ou un autre backend de stockage compatible `ReadWriteMany`) au lieu d'EBS pour le
volume media.** EFS prend en charge l'accès concurrent depuis tous les nœuds du cluster et constitue
le backend de stockage recommandé pour les déploiements EKS.

Si vous devez utiliser EBS pour des tests sur un cluster à nœud unique, surchargez les valeurs par
défaut :

```yaml
storage:
  pvc:
    accessMode: "ReadWriteOnce"
    selector: null
    storageClassName: "gp3"
```

Sachez que même avec cette surcharge, EBS cessera de fonctionner dès que des pods seront planifiés sur
plusieurs nœuds (par exemple lors d'une mise à l'échelle, d'un remplacement de nœud ou d'un
`helm test`). EFS évite entièrement ce problème.

**Le init container PostgreSQL entre en conflit avec un contexte de sécurité non-root (BUG-16)**

Désactivez-le si vous rencontrez `CreateContainerConfigError` :

```yaml
postgresql:
  initContainer:
    enabled: false
```

### Tous les déploiements

**Le pod connectors redémarre en boucle pendant l'exécution de l'initializer (comportement attendu)**

Lors de la première installation, le pod connectors entrera en état `CrashLoopBackOff` pendant que le
job initializer exécute les migrations de base de données. Ce comportement est attendu — le pod
connectors tente d'appeler l'API Django (`/api/connectors/v1/config/`), qui renvoie une erreur 500 car
le schéma de base de données n'est pas encore entièrement migré. Une fois que le job initializer se
termine avec succès (affichant `1/1 COMPLETIONS` dans `kubectl get jobs`), le pod connectors se
rétablira lors de son prochain cycle de redémarrage. Aucune intervention manuelle n'est requise.

**Un plantage de l'initializer après les migrations laisse la base de données dans un état
irrécupérable (BUG-18)**

Si le job initializer plante **après** l'exécution des migrations de base de données mais **avant**
l'insertion des données initiales (par exemple en raison d'erreurs de permissions de stockage ou de
limites de ressources), la base de données reste dans un état partiellement initialisé — les tables
existent mais la table `dojo_system_settings` est vide. Lors des redémarrages suivants, l'initializer
échoue immédiatement avec :

```
CommandError: Failed to read system settings from database: 'NoneType' object is not iterable
```

Cela crée une boucle de plantage sans récupération automatique. **Solution de contournement :**
réinitialisez le schéma de base de données et relancez l'initializer :

```bash
# Drop and recreate the public schema
kubectl run psql-reset --rm -i --tty=false --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -d <your-db-name> -U <your-db-user> \
     -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public; GRANT ALL ON SCHEMA public TO <your-db-user>;"

# Delete the failed initializer job and trigger a new one
kubectl delete job -n $NAMESPACE -l app.kubernetes.io/component=initializer
helm upgrade dojopro $CHART ... (same flags as install)
```

> **Prévention :** assurez-vous que les permissions de stockage (en particulier les points d'accès EFS
> — voir [Points d'accès EFS](#efs-access-points)) et les limites de ressources sont correctement
> configurées **avant** la première installation. Exécutez `helm template` pour valider vos values, et
> vérifiez si possible les permissions de montage EFS à l'aide d'un pod de test.

**Avertissement concernant le token Hatchet dans les logs (informatif)**

Lorsque `hatchet.enabled: false` (valeur par défaut), les pods consignent l'avertissement suivant au
démarrage :

```
Could not create Hatchet handle; all future Hatchet invocations will fail.
Error: ... Token must be set
```

Ce comportement est **attendu et sans danger**. Depuis le chart 2.57, l'exécution des workflows en
arrière-plan a été consolidée dans `ddorch` + `ddorch-workers`, qui remplacent les anciens workers
basés sur Hatchet (`kairos`, `rulesengine`, `hatchet-integrators`). Le code client Hatchet est toujours
initialisé au démarrage, l'avertissement continue donc d'apparaître lorsque Hatchet est désactivé, mais
rien n'en dépend. Cet avertissement peut être ignoré sans risque.

### HTTPS non configuré

**L'annotation ssl-redirect de l'ALB nécessite un listener HTTPS (BUG-17)**

Le préréglage EKS inclut une annotation `ssl-redirect` qui suppose l'existence d'un listener HTTPS sur
l'ALB. Si vous n'avez pas configuré de certificat ACM ni de listener HTTPS, cette annotation provoque
une boucle de redirection. Configurez le HTTPS (recommandé) ou consultez
[Déployer sans HTTPS (non recommandé)](#deploying-without-https-not-recommended) pour l'ensemble
complet des modifications requises.

---

## Dépannage

### Pods bloqués en CrashLoopBackOff

Vérifiez les logs :
```bash
kubectl logs -n $NAMESPACE <pod-name> --previous
```

Il s'agit généralement de l'un des cas suivants : secrets manquants ou incorrects (vérifiez les 12
clés), base de données inaccessible (vérifiez `database.host` et les groupes de sécurité), ou
certificat TLS interne manquant (vérifiez que le secret `dojopro-internal-tls` existe).

### Mélange de secrets externes et en ligne

```
dojo.existingSecret is set to 'X', but the following inline secret values are also provided: [...]
```

Choisissez une seule approche. Si vous utilisez `dojo.existingSecret`, retirez toutes les valeurs de
secrets en ligne (`dojo.secretKey`, `dojo.admin.password`, `monitoring.password`, etc.) de vos fichiers
de values.

### Le schéma indique que admin.password est requis

Définissez `dojo.existingSecret` — le schéma supprime l'exigence de mot de passe lorsqu'un secret
externe est configuré.

### Erreurs de permission fsGroup sur OpenShift

Si des pods échouent avec des erreurs de permission sur des volumes NFS, vérifiez que
`securityContext.openshift.fsGroup` se situe dans la plage de groupes supplémentaires de votre espace
de noms. Voir la recherche de fsGroup dans [Déploiement → OpenShift / ROSA](#openshift-rosa).

### L'ALB n'apparaît pas (EKS)

Vérifiez que l'AWS Load Balancer Controller est en cours d'exécution :
```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

Vérifiez les événements de l'ingress :
```bash
kubectl describe ingress -n $NAMESPACE
```

---

## Annexe : modèle de configuration client

Le modèle complet (`template.yaml`) est disponible sur le portail de support DefectDojo ou auprès de
support@defectdojo.com. Copiez-le, remplacez les placeholders `REPLACE_*`, et supprimez les sections
qui ne s'appliquent pas à votre plateforme. Le modèle inclut des exemples commentés pour :

- L'identification de la plateforme (`cloudProvider`)
- La configuration des secrets de pull d'images
- La configuration de l'Ingress et de la Route (Ingress pour EKS/GKE/OpenShift, Route pour OpenShift)
- Les options de stockage EFS et NFS
- La configuration des certificats et du TLS
- Les contextes de sécurité (uwsgi, nginx, fsGroup OpenShift)
- Les politiques réseau
- Les options de fourniture de la licence (fichier, secret, en ligne)

---

## Historique des révisions

| Date       | Version | Modifications                                                        |
|------------|---------|----------------------------------------------------------------------|
| 2026-07-09 | 3.1.0   | Ajout du PSIRT Advisory Engine optionnel (`psirt.enabled`) : servi sous `/psirt/` via le sidecar nginx, base de données dédiée via `psirt.databaseUrl`, recommandations d'épinglage de secrets, règles de politique réseau, hooks BYO |
| 2026-04-17 | 2.57.1  | Documentation de `ddorch` + `ddorch-workers` (nouvelle paire d'orchestrateurs remplaçant kairos/rulesengine/hatchet-integrators) ; ajout des indicateurs `--set-file` `ddorch.tls.rootCa/cert/key` aux commandes de pré-vérification et de déploiement ; nouvelle section sur les certificats mTLS ddorch avec exigences SAN ; mcp-server ajouté à la liste des pods attendus ; ajout de PDB pour ddorch (singleton) et ddorch-workers ; note sur les prérequis ArgoCD concernant la livraison des certificats ddorch ; mise à jour de l'avertissement Hatchet pour refléter la consolidation des workers |
| 2026-03-25 | 2.55.4  | Ajout de la documentation sur les points d'accès EFS et du champ de modèle correspondant ; documentation de la récupération après plantage de l'initializer (BUG-18) ; documentation du crashloop attendu des connectors pendant l'initialisation ; clarification de l'innocuité de l'avertissement du token Hatchet ; correction d'une ancre obsolète dans les problèmes connus ; chemin d'extraction du chart versionné ; consolidation des recommandations sans HTTPS ; nettoyage des PV lors de la désinstallation ; note sur la cohérence des espaces de noms ; remarque sur le versionnement des préréglages ArgoCD vs CLI |
| 2026-03-11 | 2.53.0  | Correction des chemins des commandes helm ; ajout de l'extraction du chart, des prérequis EKS, de la vérification préalable de la base de données, de l'avis HTTPS, de la rotation TLS, de la section des problèmes connus |
