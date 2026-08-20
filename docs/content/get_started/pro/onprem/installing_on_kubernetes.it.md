---
title: Guida all'installazione di DefectDojo Pro
description: Installare DefectDojo Pro su Kubernetes utilizzando il chart Helm, trattando
  infrastruttura, secret e l'installazione vera e propria
draft: false
weight: 13
audience: pro
---

<!--
  Generated from the DefectDojo Pro Helm chart repository.
  Source: docs/INSTALLATION_GUIDE.md at chart version 3.1.304.
  Edit the source guide, not this file. Local edits are overwritten
  the next time the chart is released.
-->
Copre la distribuzione su AWS EKS e OpenShift (ROSA). Il flusso di lavoro è lo stesso
per entrambe: configurare l'infrastruttura, creare i secret, installare il chart.

---

## Checklist pre-installazione

Raccogliere le seguenti informazioni prima di iniziare. Averle già pronte evita
ritardi durante il processo di installazione.

### Dettagli dell'infrastruttura

| Voce | Esempio | Dove trovarla |
|------|---------|-------------------|
| **Host PostgreSQL** | `mydb.abc123.us-east-1.rds.amazonaws.com` | Console AWS RDS oppure `aws rds describe-db-instances` |
| **Porta PostgreSQL** | `5432` | Solitamente 5432, salvo personalizzazioni |
| **Nome del database PostgreSQL** | `dojodb` | Il proprio DBA o gli output di Terraform/CloudFormation — deve essere creato prima dell'installazione (vedere la nota seguente) |
| **Database dell'orchestrator** | `dojodb-ddorch` | Concedere al ruolo applicativo `CREATEDB` oppure pre-creare `<dbname>-ddorch` — vedere [Pre-flight: database dell'orchestrator (ddorch)](#pre-flight-orchestrator-ddorch-database) |
| **Nome utente PostgreSQL** | `defectdojo` | `aws rds describe-db-instances --query 'DBInstances[].MasterUsername'` |
| **Password PostgreSQL** | — | AWS Secrets Manager, lo stato di Terraform o il proprio DBA |
| **Endpoint Redis/ElastiCache** | `my-redis.abc123.use1.cache.amazonaws.com` | `aws elasticache describe-cache-clusters --show-cache-node-info` |
| **Password Redis** | — | Omettere se l'autenticazione è disabilitata (solo VPC). Verificare con: `aws elasticache describe-replication-groups --query 'ReplicationGroups[].AuthTokenEnabled'` |
| **ID del filesystem EFS** | `fs-0abc123def456` | `aws efs describe-file-systems --region <region>` |
| **ID dell'access point EFS** (se applicabile) | `fsap-0abc123def456` | `aws efs describe-access-points --file-system-id <fs-id>` |
| **UID/GID dell'access point EFS** | UID `1001`, GID `1337` | Deve corrispondere al security context del container (vedere la nota seguente) |
| **Nome di dominio (FQDN)** | `dojo.example.com` | Il proprio amministratore DNS (vedere le note specifiche per piattaforma di seguito) |
| **ARN del certificato ACM** (EKS con HTTPS) | `arn:aws:acm:...` | `aws acm list-certificates --region <region>` |
| **Dominio delle app OpenShift** (solo ROSA) | `apps.abc123.p1.openshiftapps.com` | `oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'` |
| **fsGroup del namespace OpenShift** (solo ROSA) | `1001070000` | `oc get namespace <ns> -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'` — utilizzare il valore iniziale |
| **File di licenza** | `onprem-dojopro.lic` | Fornito dal supporto DefectDojo |

> **Creare i database prima di installare.** Il chart non crea
> database su un server PostgreSQL esterno. Creare entrambi i seguenti
> sul proprio server di database, di proprietà dell'utente applicativo, prima di eseguire
> `helm install`:
>
> - `dojodb` — il database principale di DefectDojo
> - `dojodb-ddorch` — il database dell'orchestrator (ddorch), sempre denominato a partire dal
>   nome del database principale con il suffisso `-ddorch`. In alternativa, concedere al
>   ruolo applicativo `CREATEDB` e ddorch creerà questo database autonomamente al primo
>   avvio.
>
> Vedere [Pre-flight: verifica della connettività al database](#pre-flight-verify-database-connectivity)
> e [Pre-flight: database dell'orchestrator (ddorch)](#pre-flight-orchestrator-ddorch-database)
> per i comandi `CREATE DATABASE` pronti all'uso.

> **UID/GID dell'access point EFS:** se il filesystem EFS utilizza un access point,
> la relativa configurazione utente POSIX **deve** usare UID `1001` e GID `1337` per corrispondere
> al security context del container DefectDojo. Una mancata corrispondenza causa errori `Permission
> denied` durante l'inizializzazione, quando i container tentano di creare
> le sottodirectory dei media. Verificare con:
>
> ```bash
> aws efs describe-access-points --file-system-id <fs-id> --region <region> \
>   --query 'AccessPoints[].{Id:AccessPointId,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
>   --output table
> ```

> **FQDN OpenShift/ROSA:** su ROSA, le Route generano automaticamente gli hostname usando lo
> schema `<release-name>-<namespace>.apps.<cluster-domain>`. Ad esempio, se
> la release si chiama `dojopro` nel namespace `dojopro`, l'hostname della Route sarà
> `dojopro-dojopro.apps.abc123.p1.openshiftapps.com`. Determinare il dominio delle app
> del cluster con:
>
> ```bash
> oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
> ```
>
> Usare l'FQDN risultante per `dojo.fqdn`, `dojo.url` e `dojo.hosts.main`.

> **fsGroup OpenShift/ROSA:** sarà necessario il valore iniziale dei supplemental-groups
> del namespace per `securityContext.openshift.fsGroup`. Individuarlo ora per evitare
> di dover modificare in seguito il file values:
>
> ```bash
> oc get namespace <your-namespace> \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Output example: 1001070000/10000 — use 1001070000 as fsGroup
> ```

### Secret da generare

I seguenti secret devono essere generati appositamente per la propria distribuzione. Utilizzare i
comandi mostrati per creare valori casuali crittograficamente sicuri:

| Secret | Chiave nel Secret K8s | Generare con |
|--------|-------------------|---------------|
| Chiave segreta di Django | `DD_SECRET_KEY` | `openssl rand -hex 25` |
| Chiave di cifratura AES-256 | `DD_CREDENTIAL_AES_256_KEY` | `openssl rand -hex 16` |
| Secret del portale cloud | `CLOUD_PORTAL_SECRET_KEY` | `openssl rand -hex 25` |
| Secret condiviso dei connector | `DD_CONNECTORS_SHARED_SECRET` | Usare lo stesso valore di `CLOUD_PORTAL_SECRET_KEY` |
| Password amministratore | `DD_ADMIN_PASSWORD` | `openssl rand -base64 16` |
| Password delle metriche | `METRICS_HTTP_AUTH_PASSWORD` | `openssl rand -hex 16` |

### Secret dalla propria infrastruttura

Provengono dall'infrastruttura già esistente — non generarli:

| Secret | Chiave nel Secret K8s | Origine |
|--------|-------------------|--------|
| Password del database | `DD_DATABASE_PASSWORD` | La propria password PostgreSQL |
| URL di connessione al database | `DD_DATABASE_URL` | `postgresql://<user>:<password>@<host>:<port>/<dbname>` |
| Password Redis | `redis-password` (in un secret separato `dojopro-redis`) | La propria password Redis, oppure omettere se non è prevista l'autenticazione |
| URL del servizio email | `DD_EMAIL_URL` | `consolemail://` per i test, oppure l'URL SMTP in uso |

### Facoltativi (lasciare vuoto per disabilitare)

| Secret | Chiave nel Secret K8s | Scopo |
|------|-------------------|---------|
| Chiave del bucket EPSS | `DD_PRO_ENHANCEMENTS_EPSS_BUCKET_KEY` | Arricchimento del punteggio EPSS |

> **Suggerimento:** copiare `secrets-template.yaml` e compilare i valori indicati sopra. Vedere
> [Generare i secret](#generate-secrets) per istruzioni dettagliate sulla creazione
> del Secret Kubernetes.

---

## Prerequisiti

```bash
# Required tools
brew install awscli helm kubectl jq openssl eksctl

# Verify AWS access
aws sts get-caller-identity
```

Per OpenShift/ROSA, installare anche:
```bash
brew install rosa openshift-cli
```

### Requisiti di connettività in uscita

Negli ambienti di rete con restrizioni, le seguenti connessioni in uscita devono essere
consentite prima dell'installazione. Le regole del firewall potrebbero richiedere richieste
di change anticipate — verificare che siano già in vigore prima di procedere.

**Registro dei container (obbligatorio)**

Tutti i nodi del cluster devono poter raggiungere il registro dei container di DefectDojo sulla porta 443:

```
host us-south1-docker.pkg.dev
# us-south1-docker.pkg.dev is an alias for googlecode.l.googleusercontent.com
```

> Per gli ambienti air-gapped, vedere
> [Registro privato / ambienti air-gapped](#private-registry-air-gapped-environments).

**Database (obbligatorio)**

Dai nodi del cluster alla propria istanza PostgreSQL, in genere sulla porta 5432.

- RDS nella stessa VPC: assicurarsi che il security group dei nodi EKS consenta il traffico in
  ingresso sulla porta 5432
- RDS in una VPC o un account diverso: è necessario il VPC peering o una Transit Gateway
- Esterno/on-premises: il percorso VPN o Direct Connect deve consentire la porta 5432

**Aggiornamenti EPSS (consigliato)**

```
host api.first.org
# api.first.org has address 151.101.1.91
# api.first.org has address 151.101.193.91
# api.first.org has address 151.101.129.91
# api.first.org has address 151.101.65.91
# Port 443
```

**Feed KEV (consigliato)**

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

host www.cisa.gov
# www.cisa.gov is an alias for www.cisa.gov.edgekey.net (Akamai CDN — IPs vary)
# Port 443
```

**Servizi AWS (solo EKS, obbligatorio)**

Il driver EBS CSI e l'ALB Controller richiedono l'accesso agli endpoint dell'API AWS sulla
porta 443:

- `sts.amazonaws.com`
- `ec2.amazonaws.com`
- `elasticloadbalancing.amazonaws.com`
- `elasticfilesystem.amazonaws.com` (se si utilizza EFS)

### Prerequisiti AWS EKS

I seguenti componenti devono essere installati nel proprio cluster EKS prima di distribuire
DefectDojo Pro. Senza di essi la distribuzione avrà esito negativo.

**Driver EBS CSI** (necessario solo quando si utilizza il profilo minimal con PostgreSQL
e Redis incorporati — non necessario se si utilizzano RDS ed ElastiCache esterni):

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

**Driver EFS CSI** (necessario quando si utilizza lo storage EFS — il backend di storage
consigliato per le distribuzioni EKS multi-replica):

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

**AWS Load Balancer Controller** (necessario per l'ingress ALB):

Le istruzioni di installazione variano in base alla versione di EKS. Seguire la
[guida ufficiale all'installazione di AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/deploy/installation/).

---

## Estrarre il pacchetto del chart

Il chart viene distribuito come file zip contenente un pacchetto Helm `.tgz`. Estrarre
entrambi prima di procedere. Utilizzare un percorso di estrazione con versione per evitare
di sovrascrivere silenziosamente i preset quando in seguito si estrae una versione più
recente del chart:

```bash
unzip helm-chart-<version>.zip -d /tmp/dojopro-extract
cd /tmp/dojopro-extract
mkdir -p dojopro-<version>
tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
```

Impostare una variabile `CHART` che punti alla directory del chart estratto. Tutti i comandi
`helm` successivi in questa guida utilizzano `$CHART`:

```bash
CHART="dojopro-<version>/dojopro"
# e.g. CHART="dojopro-2.55.4/dojopro"
```

> **Perché l'estrazione è necessaria per chi usa la CLI:** i file dei preset
> (`presets/platforms/*.yaml`, `presets/profiles/*.yaml`) sono inclusi all'interno del
> pacchetto `.tgz`. `helm install -f` richiede file presenti sul filesystem locale — non
> può leggere file dall'interno di un `.tgz` pacchettizzato. È necessario estrarre il chart
> per accedere ai preset.
>
> **Chi utilizza ArgoCD non deve estrarre nulla.** ArgoCD legge `valueFiles` direttamente
> dall'interno del pacchetto del chart. Vedere [Distribuzione con ArgoCD](#deploy-with-argocd).

---

## Preparare il file values

Il modello di configurazione per il cliente (`template.yaml`) e il modello dei secret
(`secrets-template.yaml`) sono disponibili separatamente sul portale di supporto DefectDojo,
oppure scrivendo a support@defectdojo.com. Non sono inclusi nel `.tgz` del chart. Una volta
ottenuto il modello, copiarlo e compilarlo con i propri dati:

```bash
cp template.yaml my-company.yaml
```

Come minimo, impostare quanto segue:

| Impostazione | Descrizione |
|---------|-------------|
| `dojo.fqdn` | Il proprio nome di dominio (ROSA: vedere la [nota sull'FQDN](#infrastructure-details) sopra) |
| `dojo.url` | URL completo, protocollo incluso (ad es. `https://dojo.example.com`) |
| `dojo.hosts.main` | Deve corrispondere al proprio FQDN |
| `dojo.secureCookies` | Impostare `false` su **OpenShift/ROSA** (vedere l'avviso seguente) |
| `dojo.admin.*` | `user`, `email`, `firstName`, `lastName` — account amministratore |
| `database.host`, `.port`, `.name`, `.user` | Dettagli di connessione a PostgreSQL (la password va nei secret) |
| `celery.broker.host` | Il proprio endpoint Redis/ElastiCache |
| `redis.enabled` | **Deve essere `false`** quando si utilizza un Redis esterno (vedere l'avviso seguente) |
| `storage.type` | Backend di storage — vedere le note specifiche per piattaforma |
| `certificates.*` | Configurazione dei certificati TLS |
| `django.ingress.*` oppure `django.route.*` | Ingress (EKS) o Route (OpenShift) — il preset imposta i valori predefiniti |
| `securityContext.openshift.fsGroup` | **Solo ROSA** — valore iniziale dei supplemental-groups del namespace |

> **AVVISO — `redis.enabled` deve essere impostato esplicitamente su `false` quando si usa
> un Redis/ElastiCache esterno.** I preset dei profili `standard` e `performance`
> impostano `redis.enabled: true` per impostazione predefinita. Se il proprio file values non
> esegue l'override di questo valore, il chart distribuirà un Redis in-cluster **insieme**
> al broker esterno, con conseguente configurazione non funzionante. Aggiungere quanto segue
> al proprio file values:
>
> ```yaml
> redis:
>   enabled: false
> ```

> **AVVISO — `dojo.secureCookies` deve essere `false` su OpenShift/ROSA.** Quando
> si utilizzano Route OpenShift con terminazione TLS edge, `secureCookies: true`
> (il valore predefinito in `template.yaml`) causa loop di redirect e accessi non funzionanti.
> Non è facoltativo — le Route con terminazione edge richiedono:
>
> ```yaml
> dojo:
>   secureCookies: false
> ```

**Note sullo storage:**
- **EKS:** utilizzare EFS, non EBS. I volumi EBS non possono essere condivisi tra i nodi, il che
  causa errori `Multi-Attach`. Vedere [Problemi noti](#known-issues-chart-version-2.57.1).
  Se il proprio EFS utilizza un access point, impostare anche `storage.efs.accessPointId` —
  vedere [Access point EFS](#efs-access-points).
- **OpenShift/ROSA:** il preset della piattaforma imposta per impostazione predefinita
  `storage.type: "pvc"` con `createNew: true`, che utilizza la StorageClass predefinita del
  cluster. Per distribuzioni multi-nodo, utilizzare NFS tramite EFS (`storage.type: "nfs"`).

Facoltativamente, impostare il livello di dettaglio dei log:
- `config.logLevel` — livello di log dell'applicazione Django (predefinito: `"INFO"`)
- `celery.logLevel` — livello di log di Celery worker/beat (predefinito: `"INFO"`)

Impostare uno dei due su `"DEBUG"` per la risoluzione dei problemi. Vedere [Livello di dettaglio
dei log](#log-verbosity) per sapere come attivarlo in fase di runtime senza modificare il file values.

Non inserire secret o contenuti della licenza in questo file. Sono gestiti nelle prossime due
sezioni.

Vedere `template.yaml` per l'elenco completo delle opzioni.

### Pre-flight: verifica della connettività al database

Verificare che il database sia raggiungibile prima di procedere: questo farà risparmiare molto
tempo nella risoluzione dei problemi in seguito. Avviare un pod temporaneo con `psql`:

```bash
kubectl run psql-test --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -d dojodb -U defectdojo \
     -c "SELECT version();"
```

Una connessione riuscita ha un aspetto simile a questo:

```
                                                version
--------------------------------------------------------------------------------------------------------
 PostgreSQL 16.x on x86_64-pc-linux-gnu, compiled by gcc ...
(1 row)

pod "psql-test" deleted
```

Se l'operazione ha esito negativo con `database "dojodb" does not exist`, l'istanza RDS è
raggiungibile ma il database non è stato ancora creato. Crearlo:

```bash
kubectl run psql-create-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c "CREATE DATABASE dojodb OWNER <your-db-user>;"
```

Quindi rieseguire il controllo di connettività sopra riportato per confermare.

Se l'operazione ha esito negativo per altri motivi, verificare quanto segue:
- **Regole del security group / firewall** — la porta 5432 deve essere aperta dal cluster
  verso l'host del database
- **Privilegi dell'utente del database** — l'utente deve disporre dei permessi CREATE, ALTER
  e SELECT sul database di destinazione, oltre a `CREATEDB` oppure a un database
  dell'orchestrator pre-creato (vedere la sezione successiva)

> Il chart include anche controlli integrati: un init container che attende la connettività TCP
> al database, e `helm test`, che convalida una connessione PostgreSQL completa
> dopo la distribuzione. Questo passaggio pre-flight individua i problemi prima di
> investire tempo nella creazione dei secret e nell'esecuzione di `helm install`.

### Pre-flight: database dell'orchestrator (ddorch)

L'orchestrator (`ddorch`, abilitato per impostazione predefinita) memorizza lo stato dei propri
workflow in un **secondo database**, accanto al database principale di DefectDojo. All'avvio,
ricava il nome del database da `DD_DATABASE_URL`, aggiunge `-ddorch` e crea tale database se non
esiste già — con database principale `dojodb`, l'orchestrator utilizza `dojodb-ddorch`.

Se al ruolo applicativo non è consentito creare database, il pod ddorch ha esito negativo
all'avvio con:

```
ERROR: permission denied to create database (SQLSTATE 42501)
```

Soddisfare **una** delle seguenti condizioni prima di installare:

**Opzione A — concedere `CREATEDB` al ruolo applicativo** e lasciare che ddorch crei il proprio
database al primo avvio:

```sql
ALTER ROLE defectdojo CREATEDB;
```

**Opzione B — pre-creare il database dell'orchestrator**, denominato a partire dal nome del
database principale con il suffisso `-ddorch` e di proprietà dello stesso utente applicativo.
Il trattino nel nome richiede le virgolette doppie in SQL:

```sql
CREATE DATABASE "dojodb-ddorch" OWNER defectdojo;
```

Utilizzando lo stesso approccio con pod temporaneo del controllo di connettività sopra riportato:

```bash
kubectl run psql-create-ddorch-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c 'CREATE DATABASE "dojodb-ddorch" OWNER <your-db-user>;'
```

---

## Generare i secret

Due opzioni disponibili.

### Opzione A: Secret esterno (consigliata per GitOps)

Creare un Secret Kubernetes con le 12 chiavi richieste prima di installare il chart.
Utilizzare `secrets-template.yaml` fornito dal supporto DefectDojo come punto di partenza
(vedere [Preparare il file values](#prepare-your-values-file) per sapere come ottenerlo):

```bash
cp secrets-template.yaml /tmp/dojopro-secrets.yaml
```

Modificare il file, sostituire tutti i valori segnaposto, quindi applicare:
```bash
kubectl apply -f /tmp/dojopro-secrets.yaml -n <your-namespace>
```

Il secret può anche essere gestito da External Secrets Operator, Sealed Secrets o qualsiasi
altro strumento in grado di creare Secret Kubernetes. Al chart non importa come il secret sia
arrivato lì — basta impostare `dojo.existingSecret` con il suo nome.

Al momento dell'installazione:
```bash
--set dojo.existingSecret=dojopro-secrets
```

Il chart salta automaticamente il rendering del proprio Secret integrato quando
`dojo.existingSecret` è impostato — non sono necessari flag aggiuntivi.

Se il proprio Redis esterno richiede l'autenticazione, `secrets-template.yaml` include anche
un Secret separato `dojopro-redis`. Il chart legge le credenziali Redis da
`redis.auth.existingSecret` (valore predefinito: `dojopro-redis`). Se il proprio Redis non ha
password (ad es. ElastiCache solo VPC), è possibile ometterlo.

### Opzione B: secret inline (più semplice, non adatta a GitOps)

Passare i valori dei secret direttamente in un file values:

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

Salvare questo file come `my-secrets.yaml` e passarlo con `-f` al momento dell'installazione.

> Non eseguire il commit dei file dei secret nel controllo di versione.

---

## Creare i certificati TLS interni

Il chart necessita di certificati TLS interni per la comunicazione service-to-service.

Creare due secret TLS Kubernetes nel proprio namespace prima di installare:

1. `dojopro-internal-tls` — un secret TLS con `tls.crt` e `tls.key` per
   la cifratura service-to-service (nginx ↔ connector, ecc.)
2. `dojopro-internal-ca` — un secret contenente il certificato CA sotto la
   chiave `ca.crt`, utilizzato dai connector per convalidare il certificato TLS interno

È possibile generare una CA e un certificato server self-signed con `openssl`, oppure
utilizzare la CA interna della propria organizzazione. Il CN/SAN del certificato server
**deve** coprire il nome del servizio nginx interno utilizzato dalla release Helm. Per
impostazione predefinita, è `<release-name>-nginx` (ad es. `dojopro-nginx` se la release
si chiama `dojopro`).

Esempio di generazione di una CA e di un certificato server self-signed:
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

> **Errore comune:** usare `nginx-internal` come CN/SAN invece di
> `<release-name>-nginx`. Il pod dei connector convalida il certificato TLS
> rispetto al nome effettivo del servizio (`<release-name>-nginx.<namespace>.svc.cluster.local`),
> e l'operazione avrà esito negativo con un errore `x509: certificate is valid for ... not ...` se
> il SAN non corrisponde.

Quindi impostare nel proprio file values:
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

### Certificati mTLS di ddorch

Oltre ai secret TLS interni sopra indicati, l'orchestrator `ddorch` richiede una terna separata
di certificati mTLS, utilizzata dal server ddorch e da ogni worker che comunica con esso
(`ddorch-workers`, `integrators`). Questi vengono forniti al chart al momento dell'installazione
tramite `--set-file` (**non** vengono letti da un secret Kubernetes preesistente):

- `orch_tls_root.ca` — certificato CA
- `orch_tls.crt` — certificato server
- `orch_tls.key` — chiave privata del server

Senza questi tre file, `helm install` ha esito negativo con `ddorch.tls.rootCa is required`.

Il SAN del certificato server **deve** includere tutti gli hostname utilizzati dai worker per
raggiungere ddorch:

- `ddorch` — nome breve del servizio in-cluster
- `<release-name>-ddorch` — nome completo del servizio (ad es. `dojopro-ddorch`)
- `<release-name>-ddorch.<namespace>.svc.cluster.local` — FQDN del cluster
- `nginx` — il valore predefinito di `SERVER_TLS_SERVER_NAME` utilizzato dai worker in stile hatchet
- `localhost`, `127.0.0.1` — worker nello stesso pod che raggiungono ddorch tramite il loopback hostAlias

Esempio di generazione della terna:

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

Passarli a `helm install` / `helm template`:

```bash
--set-file ddorch.tls.rootCa=orch_ca.crt \
--set-file ddorch.tls.cert=orch_server.crt \
--set-file ddorch.tls.key=orch_server.key
```

> Lo script di supporto `scripts/bootstrap-aws-eks.sh` genera e riutilizza automaticamente
> questi elementi tramite `dojopro-orch-certs-configmap` — se si utilizza
> questo script, non è necessario crearli manualmente.

---

## Licenza

Il chart necessita di una licenza DefectDojo Pro.

### Analisi della propria licenza

Prima di distribuire, verificare che la propria licenza sia valida e non sia scaduta:

```bash
sed -n '/^[[:space:]]*ey/,/-----END/p' license.lic \
  | sed '$d' | tr -d ' ' | base64 -d | jq .
```

Questo mostra i metadati della licenza, tra cui:
- `not_after` — data di scadenza della licenza
- `license_package` — conferma il piano di licenza

> **Secret per il pull delle immagini:** quando `images.pullSecrets.extractFromLicense: true`
> è impostato (il valore predefinito nei preset di piattaforma), il chart estrae
> automaticamente l'account di servizio GCP incorporato nel file di licenza e crea il secret
> per il pull delle immagini necessario per scaricare le immagini DefectDojo dal registro dei
> container. Non è richiesta alcuna estrazione o decodifica manuale. Se invece si utilizza un
> registro privato, impostare `extractFromLicense: false` e fornire il proprio secret per il
> pull — vedere [Registro privato / ambienti air-gapped](#private-registry-air-gapped-environments).

### Opzione 1: --set-file (installazione Helm standard)

Passare il file di licenza al momento dell'installazione:
```bash
--set-file license.contents=/path/to/license.lic
```

### Opzione 2: Secret esistente (GitOps / ArgoCD)

Creare un Secret Kubernetes contenente la licenza, quindi indicare al chart di utilizzarlo.
In questo modo si evita di dover usare `--set-file` o di memorizzare la licenza in git.

```bash
kubectl create secret generic dojopro-license \
  --namespace $NAMESPACE \
  --from-file=dojopro.lic=/path/to/license.lic
```

Quindi, nel proprio file values o nei flag di helm:
```yaml
license:
  existingSecret: "dojopro-license"
```

Il secret può essere gestito da External Secrets Operator, Sealed Secrets o semplicemente da kubectl.

> **Importante:** `license.existingSecret` **non è compatibile** con l'impostazione
> predefinita `images.pullSecrets.extractFromLicense: true`. Il chart ha bisogno
> del contenuto della licenza disponibile al momento del rendering per estrarre le credenziali
> del registro dei container incorporate. Se si utilizza `license.existingSecret`, è
> necessario disabilitare anche l'estrazione automatica del pull secret e fornirne uno proprio:
>
> ```yaml
> images:
>   pullSecrets:
>     extractFromLicense: false
>     existingSecrets:
>       - "my-registry-pull-secret"
> ```
>
> Se invece si desidera che il chart estragga automaticamente il pull secret dalla licenza
> (comportamento predefinito), utilizzare invece l'**Opzione 1** (`--set-file license.contents=`).


---

## Modalità FIPS 140-3 (opzionale)

Per gli ambienti soggetti a FedRAMP **SC-13** o requisiti analoghi, il chart può distribuire
le varianti immagine `-fips`, la cui crittografia è basata su **OpenSSL FIPS Provider 3.1.2**
(certificato NIST CMVP **#4985**) e, per i servizi Go, su **Go Cryptographic Module v1.0.0**
(CMVP **#5247**).

L'applicazione avviene all'interno del container, quindi non è richiesto un kernel host
abilitato FIPS — ed è proprio questo che rende la soluzione praticabile sui runtime gestiti
in cui non si ha il controllo del sistema operativo host.

Disabilitata per impostazione predefinita; quando è disattivata, l'output renderizzato rimane
invariato.

```yaml
fips:
  enabled: true
  validate: true    # refuse to render a partly-FIPS deployment (see below)
```

Le immagini con tag `-fips` devono essere disponibili nel proprio registro. Contattare
hello@defectdojo.com per richiedere l'accesso.

### Componenti privi di una variante FIPS

Sensei e PostgreSQL/Redis **incorporati** non dispongono di una build FIPS — l'immagine
valkey inclusa è basata su Alpine, che non dispone di un OpenSSL convalidato FIPS.
Un'installazione FIPS deve quindi utilizzare datastore esterni e lasciare Sensei disabilitato:

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

Con `fips.validate: true` (valore predefinito) il chart **non riesce a completare il
rendering** se si abilita FIPS insieme a uno qualsiasi di questi componenti, indicando quali
sono i responsabili:

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei, redis (embedded). Disable them, or set fips.validate=false to accept
that they run non-validated cryptography.
```

Si tratta di una scelta intenzionale. Una distribuzione in cui la maggior parte dei servizi
utilizza crittografia convalidata mentre uno o due la aggirano silenziosamente è peggiore di
un errore evidente: sembra conforme e il problema emerge solo durante una valutazione.
Impostare `fips.validate: false` solo se si è accettato esplicitamente questo rischio.

### Verifica dopo la distribuzione

Ogni pod esegue un controllo di avvio fail-closed — se il provider convalidato non è attivo,
il container termina anziché servire le richieste. Le evidenze che stampa sono in genere ciò
che un valutatore desidera:

```bash
kubectl -n $NAMESPACE logs deploy/dojopro-django | grep FIPS
kubectl -n $NAMESPACE exec deploy/dojopro-django -- openssl list -providers
kubectl -n $NAMESPACE exec deploy/dojopro-django -- python3 /verify_fips.py
```

I cambiamenti di comportamento di cui tenere conto (l'hashing delle password passa a PBKDF2,
ChaCha20 viene rimosso dall'elenco di cipher TLS) sono trattati nella pagina Modalità FIPS
140-3 della documentazione del prodotto.

---

## Pre-flight: convalida dei template

Prima di procedere con l'installazione, eseguire `helm template` per generare e convalidare tutti i manifest senza intervenire sul cluster. In questo modo si individuano errori nei values, campi obbligatori mancanti e problemi YAML prima di eseguire `helm install`:

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

Utilizzare gli stessi flag che si intende passare a `helm install`. Se il comando termina senza errori, i values sono validi. Se fallisce, il messaggio di errore indicherà il campo mancante o non valido: correggere il file values e rieseguire il comando finché non viene completato correttamente.

---

## Deploy

Combinare l'overlay della piattaforma, il profilo delle risorse, i values del cliente e le scelte su secret e licenza effettuate in precedenza.

### AWS EKS

> **Per l'accesso da browser su EKS è vivamente consigliato l'uso di HTTPS.**
> Quando il TLS dell'ingress è attivo, il chart abilita automaticamente
> `SECURE_SSL_REDIRECT` e imposta i cookie CSRF/sessione su `Secure`: questo
> significa che l'accesso da browser non funzionerà senza un listener HTTPS
> sull'ALB. Per un'esperienza ottimale, configurare un certificato ACM prima
> del deploy.
>
> Per l'esecuzione senza HTTPS, vedere
> [Distribuzione senza HTTPS (sconsigliata)](#deploying-without-https-not-recommended)
> di seguito.

```bash
NAMESPACE="dojopro"
kubectl create namespace $NAMESPACE
```

> **Coerenza del namespace:** il valore del namespace deve corrispondere in
> tutte le risorse: il file YAML dei secret (`metadata.namespace`),
> `kubectl create namespace` e `helm install -n`. Se si utilizza un namespace
> personalizzato al posto di `dojopro`, sostituirlo in modo coerente in tutti
> i comandi e i manifest dei secret.

**Secret esterni + secret di licenza (GitOps):**

Applicare i secret, se non è già stato fatto (vedere [Genera i secret](#generate-secrets)),
quindi procedere con l'installazione:

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

**Secret inline + file di licenza (più semplice):**
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

#### Distribuzione senza HTTPS (sconsigliata)

> **Attenzione:** l'esecuzione senza HTTPS comporta l'invio dei cookie di
> sessione in chiaro e la disabilitazione della protezione CSRF tramite
> cookie sicuri. Non utilizzare questa configurazione in produzione.

Se è necessario eseguire temporaneamente il deploy senza HTTPS (ad esempio per
test iniziali senza un certificato ACM), applicare **tutte** le seguenti
modifiche nel file values:

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

Tutte e quattro le modifiche sono obbligatorie. Se anche una sola viene
omessa, si verificheranno loop di redirect o un accesso non funzionante. Una
volta pronti ad abilitare HTTPS, ripristinare queste modifiche e configurare
un certificato ACM.

### OpenShift / ROSA

```bash
NAMESPACE="dojopro"
oc new-project $NAMESPACE
# Or, if the namespace already exists:
# oc project $NAMESPACE
```

> **Promemoria:** il valore `fsGroup` del namespace dovrebbe già essere
> disponibile dalla [Checklist pre-installazione](#infrastructure-details).
> In caso contrario, recuperarlo ora:
>
> ```bash
> oc get namespace $NAMESPACE \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Use the start value (e.g., 1001070000) as securityContext.openshift.fsGroup
> ```

**Secret esterni + secret di licenza (GitOps):**

Applicare i secret, se non è già stato fatto (vedere [Genera i secret](#generate-secrets)),
quindi procedere con l'installazione:

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

**Secret inline + file di licenza (più semplice):**
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

## Deploy con ArgoCD

DefectDojo Pro è pienamente compatibile con ArgoCD. Il chart include preset di
piattaforma e di profilo che ArgoCD può referenziare direttamente come
`valueFiles`.

### Prerequisiti

Prima di creare l'Application di ArgoCD, le seguenti risorse Kubernetes
devono già esistere nel namespace di destinazione:

- I secret dell'applicazione (vedere [Genera i secret](#generate-secrets))
- Il secret di licenza (vedere [Licenza](#license))
- I secret TLS interni, se non si utilizza la generazione automatica (vedere [Crea i certificati TLS interni](#create-internal-tls-certificates))
- Il materiale mTLS di ddorch (vedere [Certificati mTLS di ddorch](#ddorch-mtls-certificates)). ArgoCD non ha un equivalente di `--set-file`, quindi passare i tre contenuti PEM tramite i parametri dell'Application (`ddorch.tls.rootCa` / `ddorch.tls.cert` / `ddorch.tls.key`). Utilizzare un plugin di gestione dei secret di ArgoCD (Sealed Secrets, External Secrets o un plugin ConfigMap) piuttosto che includere la chiave in chiaro.

### Come funziona

ArgoCD referenzia i file di preset in modo relativo alla radice del chart. La
spec dell'Application richiede tre elementi:

1. I preset di piattaforma e di profilo come `valueFiles`
2. La configurazione specifica dell'ambiente (tramite `valueFiles`, `values` inline, o entrambi)
3. I riferimenti a secret e licenza come `parameters`

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

### Come fornire la propria configurazione

Esistono diversi modi per fornire ad ArgoCD i values specifici del proprio
ambiente:

- `values` inline nella spec dell'Application — l'approccio più semplice,
  senza bisogno di file o repository aggiuntivi. Funziona bene quando la
  configurazione è semplice.
- Un file values in un repository Git separato — utilizzare la funzionalità
  multi-source di ArgoCD (v2.6+) con una variabile `$ref` per recuperare il
  file values insieme al chart. Consigliato quando si utilizza un chart
  pubblicato via OCI.
- Un file values nello stesso repository Git del chart — referenziarlo in
  `valueFiles` con un percorso relativo alla directory del chart
  (ad esempio, `../../overrides/customers/my-company.yaml`).

Tutti e tre gli approcci seguono la stessa stratificazione: preset di
piattaforma → preset di profilo → configurazione personalizzata. I values
successivi sovrascrivono quelli precedenti.

### Aggiornamento

Quando il chart è pubblicato su un registry OCI, l'aggiornamento richiede una
singola modifica a `targetRevision` nella spec dell'Application. I preset di
piattaforma e di profilo sono versionati insieme al chart, quindi si
aggiornano automaticamente.

Per i dettagli completi sul supporto Helm di ArgoCD, vedere la
[documentazione Helm di ArgoCD](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/).

---

## Verifica

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

### Test Helm integrati

Il chart include quattro test che vengono eseguiti come pod Kubernetes quando
si esegue `helm test`. Questi test verificano i punti di integrazione critici
tra DefectDojo e i servizi di backend:

| Test | Cosa verifica |
|------|----------------|
| `test-database` | Si connette a PostgreSQL usando le credenziali configurate, esegue `SELECT version()` e conferma che il database accetta query. Riprova per un massimo di 60 secondi. |
| `test-redis-broker` | Si connette al broker Redis/Valkey, invia un `PING`, quindi esegue un ciclo di set/get/delete per verificare l'accesso in lettura e scrittura. |
| `test-django-health` | Interroga l'endpoint `/api/v2/health_check/light/` sul servizio nginx interno e conferma una risposta HTTP 2xx/3xx. Viene eseguito dopo i test su database e broker (hook-weight 10). |
| `test-storage` | Monta il volume dei media ed esegue un ciclo di scrittura/lettura/eliminazione per confermare che il backend di storage sia accessibile e scrivibile dall'applicazione. Viene eseguito per ultimo (hook-weight 15). |

I test vengono eseguiti in ordine di hook-weight: prima i test
infrastrutturali (database, broker), poi i test a livello applicativo
(health, storage). Se un test precedente fallisce, i test successivi possono
comunque essere eseguiti, ma è probabile che falliscano a loro volta.

Per rieseguire i test dopo un deploy non riuscito o una modifica alla
configurazione:
```bash
helm test dojopro -n $NAMESPACE --logs --timeout 5m
```

I pod di test vengono ripuliti automaticamente prima di ogni esecuzione
(policy di eliminazione `before-hook-creation`). Per esaminare manualmente i
log di un pod di test non riuscito:
```bash
kubectl logs -n $NAMESPACE dojopro-test-database
kubectl logs -n $NAMESPACE dojopro-test-redis-broker
kubectl logs -n $NAMESPACE dojopro-test-django-health
kubectl logs -n $NAMESPACE dojopro-test-storage
```

### Recuperare la password di amministratore

La password di amministratore iniziale è memorizzata nel secret
dell'applicazione. Recuperarla con:

```bash
kubectl get secret dojopro-secrets -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

Se sono stati usati secret inline invece di un secret esterno, la password si
trova nel secret gestito dal chart:

```bash
kubectl get secret dojopro-defectdojo -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

Accedere all'URL configurato con il nome utente amministratore (predefinito:
`admin`) e questa password. Cambiare la password dopo il primo accesso.

---

## Operazioni

### Verbosità dei log

Il chart espone due impostazioni per il livello di log, entrambe con valore
predefinito `INFO`:

| Impostazione | Controlla | Variabile d'ambiente |
|---------|----------|---------|
| `config.logLevel` | Logging dell'applicazione Django | `DD_LOG_LEVEL` |
| `celery.logLevel` | Logging di Celery worker e beat | `DD_CELERY_LOG_LEVEL` |

Per aumentare la verbosità a fini di troubleshooting, impostare l'una o
l'altra (o entrambe) su `DEBUG` nel file values ed eseguire `helm upgrade`:

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

I flag `--set` sovrascrivono le impostazioni del file values, quindi è
possibile attivare il logging di debug senza modificare i file. Una volta
risolto il problema, eseguire di nuovo `helm upgrade` senza i flag `--set`
per tornare alle impostazioni predefinite configurate.

Il deployment Django supporta anche `django.uwsgi.enableDebug: true`, che
imposta `DD_DEBUG=True` per un debug di livello framework più approfondito.
Questo produce un output molto più corposo e dovrebbe essere usato solo per
indagini di breve durata.

### Isolamento delle importazioni di scansione

Le importazioni di scansione (`/api/v2/import-scan/` e
`/api/v2/reimport-scan/`) vengono analizzate in modo sincrono e possono
consumare grandi quantità di memoria dei worker. Per impostazione predefinita
il chart esegue un deployment `django-import` dedicato (uwsgi sulla porta
3032 dietro il proprio Service) e l'nginx del pod Django instrada verso di
esso gli endpoint di importazione. Un'importazione pesante non può esaurire
(né causare un OOM su) i worker web interattivi, e il pool di importer (in
scrittura) scala in modo indipendente rispetto ai pod web (in lettura).

Parametri configurabili sotto `django.uwsgiImport`:

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

Note operative:

- I pod di importer montano il volume dei media condiviso, quindi necessitano
  di storage compatibile con ReadWriteMany per essere pianificati liberamente
  tra i nodi. I backend di storage del chart (`efs`, `filestore`, `gcsfuse`,
  `nfs` e la PVC RWX predefinita per i media) soddisfano tutti questo
  requisito; una PVC ReadWriteOnce no.
- L'autoscaling degli importer è disattivato per impostazione predefinita,
  perché uno scale-down elimina qualsiasi importazione in corso su quel pod
  non appena scade `terminationGracePeriodSeconds`. Se lo si abilita, aumentare
  il periodo di grazia in modo che le importazioni in corso possano
  completarsi.
- Un PodDisruptionBudget (`podDisruptionBudget.djangoImport`) protegge il pool
  di importer durante le interruzioni volontarie, ogni volta che è in
  esecuzione più di un importer.

Il profilo `minimal` disabilita il deployment dell'importer per mantenere
ridotto l'ingombro; le importazioni condividono quindi il pool uwsgi singolo
come in precedenza.

### Motore Advisory PSIRT (opzionale)

Il chart può distribuire il motore Advisory PSIRT, un servizio per la
creazione e la pubblicazione di advisory di sicurezza a partire dai riscontri
di DefectDojo. È disattivato per impostazione predefinita. Quando è attivo,
compare sotto `/psirt/` sul proprio host DefectDojo principale: il sidecar
nginx lo espone tramite proxy, quindi non è necessario alcun ingress o voce
DNS aggiuntivi.

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

`psirtSharedSecret` è un valore semplice a propria scelta: non è coinvolto
alcun utente DefectDojo né un token generato. Impostare una stringa ad alta
entropia (ad esempio `python -c "import secrets; print(secrets.token_urlsafe(48))"`).
Il chart la inserisce sia nel Secret del motore psirt sia nei pod DefectDojo,
quindi un singolo valore abilita la pubblicazione automatica su
un'installazione pulita senza alcun passaggio successivo all'avvio. Rotazione:
modificarlo ed eseguire `helm upgrade`.

Configurazione del database: puntare `databaseUrl` allo stesso host
PostgreSQL usato da DefectDojo (o a qualsiasi altro host raggiungibile) con un
nome di database a propria scelta. Il pod crea il database al primo avvio se
non esiste già, il che richiede una concessione una tantum come superuser di
postgres:

```sql
ALTER ROLE pae CREATEDB;
```

Note operative:

- Mantenere `psirt.replicas` a 1. Il servizio esegue un proprio scheduler di
  job interno, e una seconda replica eseguirebbe due volte ogni job
  pianificato.
- Il pod monta il volume dei media condiviso (gli allegati degli advisory
  risiedono sotto `<media>/pae/uploads`), quindi si applicano le stesse
  indicazioni di storage ReadWriteMany valide per il pool di importer.
- È richiesto HTTPS in uscita per i feed di advisory e le ricerche NVD. Con
  `networkPolicy.profile=aggressive`, l'elenco di CIDR consentiti
  (`networkPolicy.externalAPIs.allowedCidrs`) deve coprire questi endpoint.
- Un `psirt.nvdApiKey` opzionale aumenta il rate limit di NVD da 5 a 50
  richieste ogni 30 secondi.

### Motore di scansione/fix Sensei (opzionale)

Il chart può distribuire il motore Sensei, il servizio alla base delle
scansioni lato server e dei job di correzione automatica (fix). È
disattivato per impostazione predefinita e non richiede alcuna
configurazione aggiuntiva per l'avvio:

```yaml
sensei:
  enabled: true
```

Il motore non conserva alcun secret di lunga durata. Le credenziali di
scansione/fix e gli URL degli endpoint viaggiano con ciascun job, distribuiti
a partire dalla configurazione worker cifrata di DefectDojo. django e celery
raggiungono il motore all'interno del cluster (`SENSEI_ENGINE_URL` viene
inserito automaticamente nella configmap condivisa), quindi non è necessario
alcun ingress o voce DNS.

Note operative:

- Il motore richiama DefectDojo all'URL pubblico del sito (`dojo.url`) per
  impostazione predefinita. Impostare `sensei.ddCallbackUrl` per
  sovrascriverlo: per il traffico puramente interno al cluster, puntarlo al
  listener nginx interno, ma in tal caso il motore deve considerare
  attendibile la CA interna di DefectDojo.
- Le credenziali LLM per i job di fix sono normalmente impostate all'interno
  dell'applicazione (Impostazioni modello IA) e trasportate per ogni job.
  Impostare `sensei.llm.*` solo quando il motore deve leggere la chiave dal
  proprio ambiente; preferire `sensei.llm.existingSecret` rispetto alla
  chiave in chiaro `sensei.llm.apiKey`.
- Per eseguire il motore su Google Vertex AI invece che con una chiave API di
  un provider, impostare `sensei.llm.provider: vertex` e
  `sensei.llm.vertexProject` sul progetto GCP che ospita Vertex
  (`sensei.llm.vertexRegion` di norma è `global`). Il pod si autentica con le
  Application Default Credentials, quindi fornirgli un service account GCP
  tramite `sensei.serviceAccountName` + Workload Identity, oppure montare un
  file di chiave con `sensei.extraVolumesRaw` e `sensei.extraVolumeMounts`, e
  quindi puntare `GOOGLE_APPLICATION_CREDENTIALS` su di esso tramite
  `sensei.extraEnv`.
- `sensei.llm.fallbackChain` accetta un elenco separato da virgole di voci
  `provider` o `provider:model` a cui il motore ricorre quando il provider
  primario restituisce un errore ripetibile. Terminare la catena con un
  vendor diverso (ad esempio `vertex-gemini:gemini-2.5-pro`) mantiene i job
  di fix in esecuzione anche durante un'interruzione del provider primario.
- L'immagine dello scanner è pesante. `sensei.maxConcurrentJobs` (valore
  predefinito 3) limita i job paralleli per pod, e le risorse predefinite
  (richiesta 1Gi / limite 4Gi) sono dimensionate per questo limite: aumentarle
  entrambe insieme.
- Un HPA basato sulla CPU (da 1 a 4 repliche) è attivo per impostazione
  predefinita. Impostare `sensei.hpa.maxReplicas` uguale a
  `sensei.hpa.minReplicas` per fissare il numero a `sensei.replicas`.
- È richiesto HTTPS in uscita per i clone dei repository, le API di hosting
  Git e le API dei provider LLM. Con `networkPolicy.profile=aggressive`,
  l'elenco di CIDR consentiti (`networkPolicy.externalAPIs.allowedCidrs`)
  deve coprire questi endpoint.

### Rotazione dei certificati TLS

Il chart utilizza due categorie di certificati TLS, ciascuna con una
procedura di rotazione diversa.

#### TLS interno (da servizio a servizio)

Questi sono i secret `dojopro-internal-tls` e `dojopro-internal-ca` usati per
la comunicazione tra nginx, connectors e altri servizi interni.

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

#### TLS per l'ingress (esterno/rivolto al browser)

La rotazione dipende da come è stato configurato il TLS:

- **Gestito da ACM (EKS):** il rinnovo è automatico, nessuna azione richiesta.
- **cert-manager:** il rinnovo è automatico in base alle impostazioni
  `duration` e `renewBefore` (valori predefiniti: 2160h / 720h).
- **Certificati gestiti GKE:** il rinnovo è automatico, nessuna azione
  richiesta.
- **Certificato manuale tramite secret Kubernetes:** aggiornare il secret
  referenziato dall'ingress usando lo stesso schema
  `kubectl create secret tls ... --dry-run=client` mostrato sopra.
- **Certificati interni generati automaticamente:** il chart può rigenerarli
  con `helm upgrade` se `certificates.generation.enabled: true`.

> In Kubernetes la fonte di verità è l'oggetto Secret: aggiornare il secret e
> far ripartire il deployment è il modo in cui funziona la rotazione dei
> certificati.

> Se si utilizza External Secrets Operator o Sealed Secrets per gestire i
> secret TLS, la rotazione viene gestita a quel livello e i secret Kubernetes
> si aggiornano automaticamente: non sono necessari passaggi manuali con
> `kubectl`.

---

## Stratificazione dei file values

Il chart sovrappone più file values. I file successivi prevalgono:

```
presets/platforms/<platform>.yaml       # Platform defaults (aws-eks or openshift)
presets/profiles/<size>.yaml            # Resource profiles (minimal, standard, performance)
overrides/customers/<company>.yaml      # Your config (domain, DB, storage, certs)
```

I preset di piattaforma e di profilo sono inclusi all'interno del chart
(`dojopro/presets/`). Sono compresi nel `.tgz` pacchettizzato e versionati
insieme al chart. I clienti non devono modificarli.

Quando si usa `helm install` a partire dal chart estratto, referenziarli
usando la variabile `$CHART` impostata durante l'[estrazione](#extract-the-chart-package):
```
-f $CHART/presets/platforms/aws-eks.yaml
```

Quando si usa ArgoCD, referenziarli in modo relativo alla radice del chart:
```
valueFiles:
  - presets/platforms/aws-eks.yaml
```

Non inserire i limiti di risorse nei file dei clienti né la configurazione di
piattaforma nei file di profilo. Mantenere ogni livello focalizzato su un
unico aspetto.

> **Versionamento dei preset — ArgoCD vs CLI:** ArgoCD referenzia i preset
> dall'interno del pacchetto del chart, quindi si aggiornano automaticamente
> quando si modifica `targetRevision`. Gli utenti CLI devono ri-estrarre i
> preset quando eseguono l'upgrade a una nuova versione del chart, per
> recepire eventuali modifiche ai valori predefiniti di piattaforma o
> profilo. Usare un percorso di estrazione versionato (ad esempio,
> `dojopro-2.55.4/`) per evitare confusione tra le versioni del chart —
> vedere [Estrarre il pacchetto del chart](#extract-the-chart-package).

---

## Personalizzazione ed estensibilità

Oltre ai file values di piattaforma/profilo/cliente, il chart offre punti di
estensione di prim'ordine per collegare la propria infrastruttura — sidecar,
init container, variabili d'ambiente, volumi, service account, vincoli di
scheduling e manifest aggiuntivi arbitrari — senza dover eseguire un fork del
chart:

- **Hook per singolo componente** — `extraEnv`, `extraEnvFrom`,
  `extraVolumesRaw`, `extraVolumeMounts`, `extraInitContainers`,
  `extraContainers`, `hostAliases`, `priorityClassName`,
  `topologySpreadConstraints`, `dnsConfig` e `serviceAccountName` su ogni
  workload (django, celery worker/beat, connectors, ddorch, ddorch-workers,
  integrators, mcp-server, psirt).
- **`extraManifests` di primo livello** — genera YAML arbitrario fornito
  dall'utente (ConfigMap, Secret, NetworkPolicy, ecc.) insieme al chart,
  passato attraverso `tpl` di Helm con il contesto radice del chart.
- **Utilizzo come umbrella chart** — `dojopro` può essere incorporato come
  subchart tramite dipendenza `file://` o OCI, utile per distribuire bundle
  per i clienti che sovrappongono risorse aggiuntive intorno al chart.
- **Validazione basata su schema** — `values.schema.json` copre ogni hook,
  quindi gli editor offrono l'autocompletamento e `helm lint`/`helm install`
  convalidano le proprie personalizzazioni.

Consultare la guida BYO Extensibility — inclusa come **Appendice: Bring Your
Own Infrastructure (BYO)** nell'edizione PDF — per pattern, esempi e garanzie
di stabilità degli aggiornamenti.

---

## Network Policy

Il chart include NetworkPolicy per ogni componente, attive per impostazione
predefinita (`networkPolicy.enabled: true`). Una baseline default-deny è
delimitata ai pod di questa release (tramite le etichette
`app.kubernetes.io/name` + `app.kubernetes.io/instance`), quindi non
influisce mai su altri workload che condividono il namespace.

Il livello di rigore delle regole è controllato da
**`networkPolicy.profile`**:

| Profilo | Egress | Ingress pod-to-pod | Ingress esterno |
|---------|--------|--------------------|------------------|
| `standard` (predefinito) | Tutto il traffico in uscita consentito (`0.0.0.0/0`) | Tutto il traffico tra i pod di questa release è consentito | Limitato all'ingress controller / load balancer |
| `aggressive` | Allowlist granulare per componente (DNS, database/broker, servizi specifici nel cluster, solo API esterne esplicitamente consentite) | Allowlist granulare per componente | Limitato all'ingress controller / load balancer |

- **`standard`** è consigliato per la maggior parte dei cluster. Evita
  interruzioni dovute a dipendenze di egress specifiche del cluster (il
  metadata server di GKE, NodeLocal DNSCache, endpoint di storage/API cloud) e
  alle chiamate tra i servizi interni dell'applicazione, pur mantenendo
  l'ingress esterno vincolato al solo percorso dell'ingress: la release si
  fida dei propri pod, ma dall'esterno si continua a passare dalla porta
  principale.
- **`aggressive`** applica un'allowlist rigorosa in entrambe le direzioni. Se
  la si utilizza, potrebbe essere necessario regolare le eccezioni sotto
  `networkPolicy` per il proprio cluster:
  - `nodeLocalDns` — consente il resolver NodeLocal DNSCache (link-local
    `169.254.20.10` per impostazione predefinita, sulla porta 53).
    Obbligatorio sui cluster che eseguono NodeLocal DNSCache (ad esempio
    l'addon GKE), altrimenti la risoluzione DNS fallisce.
  - `dnsSelectors` — sovrascrive il target di egress DNS per una
    configurazione DNS personalizzata.
  - `allowExternalAPIs` / `externalAPIs` — controlla l'egress verso le API
    HTTPS esterne e quali CIDR sono bloccati (ad esempio i metadata cloud).

Impostare il profilo in un qualsiasi file values, ad esempio:

```yaml
networkPolicy:
  profile: aggressive
```

> **I controlli di integrità di GKE** sono gestiti in entrambi i profili: gli
> intervalli di probe del load balancer GCE (`130.211.0.0/22`,
> `35.191.0.0/16`) possono sempre raggiungere il backend django su GKE.
> Vedere [GCP GKE](#gcp-gke).

### Accesso dell'ingress controller (502 Bad Gateway)

Sui cluster non GKE/non OpenShift, la NetworkPolicy di django consente
l'ingresso dell'ingress controller selezionandone il namespace tramite
l'etichetta `kubernetes.io/metadata.name` che Kubernetes applica
automaticamente a ogni namespace. Per impostazione predefinita, questo
presuppone che il controller si trovi in un namespace denominato
**`ingress-nginx`**, con i pod del controller che portano l'etichetta
`app.kubernetes.io/name: ingress-nginx` (il valore predefinito del chart
ingress-nginx).

Se il proprio ingress controller si trova in un namespace con un nome
diverso, usa etichette dei pod diverse, oppure è un controller
completamente diverso (Traefik, un ALB, ecc.), la policy scarterà
silenziosamente il suo traffico e le richieste restituiranno **502 Bad
Gateway** (`connect() failed (110: Operation timed out)` nei log del
controller). Puntare la policy alla propria sorgente di ingress reale con
`networkPolicy.ingressSource`:

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

Oppure regolare `networkPolicy.ingressNamespace` /
`networkPolicy.ingressControllerLabel` se cambiano solo i nomi. Vedere i
commenti sotto `networkPolicy` in `values.yaml` per altri esempi di
`ingressSource` (Traefik, router OpenShift, AWS ALB).

---

## Aggiornamento

Il percorso di aggiornamento consigliato preleva il chart direttamente dal
registry OCI di DefectDojo, senza bisogno di estrarre alcuno zip:

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

Un tipico aggiornamento OCI ha questo aspetto (stessi file values e stessi
flag `--set` dell'installazione originale):

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

Il flusso di lavoro con zip pacchettizzato usato al momento dell'installazione
funziona anche per gli aggiornamenti: sostituire `helm install` con
`helm upgrade` puntando al percorso `$CHART` estratto.

Vedere la [Guida all'aggiornamento](/get_started/pro/onprem/upgrading_on_kubernetes/) — inclusa
come **Appendice: aggiornamento di DefectDojo Pro** nell'edizione PDF — per
autenticazione, aggiornamenti ArgoCD, verifica, rollback e risoluzione dei
problemi.

---

## Disinstallazione

```bash
helm uninstall dojopro -n $NAMESPACE
kubectl delete namespace $NAMESPACE
```

> I PVC, i database esterni e i secret esterni non vengono eliminati.
> Vanno ripuliti separatamente.

### Pulizia dei PersistentVolume

I PersistentVolume con criterio di recupero (reclaim policy) `Retain` hanno **ambito cluster**: non
vengono rimossi da `helm uninstall` né dall'eliminazione del namespace. Se si reinstalla
DefectDojo in un namespace diverso, i metadati di proprietà del PV orfano entreranno
in conflitto con la nuova installazione e bloccheranno `helm install`.

Verificare la presenza di PV orfani dopo la disinstallazione:

```bash
kubectl get pv | grep dojopro
```

Se ne restano alcuni, eliminarli:

```bash
kubectl delete pv dojopro-media-pv
```

> **Nota:** l'eliminazione del PV rimuove il riferimento al volume Kubernetes, ma i
> dati sottostanti restano sul backend di storage (ad es. il file system EFS). Questo
> è sicuro se si intende reinstallare, ma va fatto in modo intenzionale.

---

## Test in locale con PostgreSQL e Redis integrati

> **Questa configurazione è solo per test in locale e valutazione. Non usare
> PostgreSQL o Redis integrati in produzione.** Negli ambienti di produzione occorre
> usare servizi gestiti (ad es. RDS, ElastiCache) per affidabilità, backup e
> scalabilità. Il supporto DefectDojo non copre i problemi con i database integrati in
> ambienti di produzione.

Il chart può distribuire un proprio PostgreSQL e Redis per test rapidi in locale usando
il profilo `minimal`. Questo evita la necessità di un'infrastruttura esterna di
database e broker.

Aggiungere quanto segue al file dei valori:

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

> **Importante: `postgresql.database.password` è obbligatorio** quando
> `postgresql.enabled` è true e `database.existingSecret` non è impostato. Il
> chart non riuscirà a effettuare il rendering senza questo valore. Questa password deve corrispondere al
> valore `DD_DATABASE_PASSWORD` nei secret dell'applicazione.

> **Credenziali predefinite di PostgreSQL integrato:** i valori predefiniti del chart per
> PostgreSQL integrato sono nome utente `dojodbusr` e nome database `dojodb`
> (definiti nel `values.yaml` del chart). Il `DD_DATABASE_URL` nei
> secret dell'applicazione deve usare questi valori, non i placeholder per il database
> esterno presenti in `secrets-template.yaml`. Ad esempio:
>
> ```
> DD_DATABASE_URL: "postgresql://dojodbusr:<password>@<release>-postgresql:5432/dojodb"
> ```

Il profilo `minimal` (`dojopro/presets/profiles/minimal.yaml`) imposta richieste di
risorse ridotte, adatte a un cluster di test a singolo nodo, ma non attiva questi
flag di database/broker: vanno impostati manualmente.

> **Nota sui privilegi dei container:** i container di PostgreSQL e Redis integrati
> **non** vengono eseguiti come root — PostgreSQL viene eseguito come UID 999 e Redis come UID 1001.
> L'unica eccezione è l'**init container** di PostgreSQL (`init-chmod-data`),
> che viene eseguito come root (UID 0) per impostare la proprietà della directory sul volume dei dati
> prima dell'avvio del processo principale. Si tratta di un pattern comune per gli StatefulSet
> con storage persistente. Se il cluster applica uno standard Pod Security `restricted`
> o un SCC di OpenShift che vieta gli init container come root, disabilitarlo con
> `postgresql.initContainer.enabled: false` (vedere [Problemi noti](#known-issues-chart-version-2.57.1)).

Quando si usa PostgreSQL integrato su EKS, è necessario anche l'EBS CSI driver
(vedere [Prerequisiti AWS EKS](#aws-eks-prerequisites)) e potrebbe essere necessario adeguare
i valori predefiniti di storage (vedere [Problemi noti](#known-issues-chart-version-2.57.1)).

Convalidare i valori prima dell'installazione: il percorso minimal richiede più
override ed è più soggetto a errori di rendering:

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

Se questo comando termina senza errori, procedere con `helm install` usando gli stessi flag.

> **Usare `--timeout 30m` per le installazioni minimal/con database nuovo.** Con risorse
> ridotte per PostgreSQL integrato, l'initializer deve eseguire da zero tutte le migrazioni
> del database su un nuovo database. Nei test ciò ha richiesto circa 23 minuti,
> un tempo che supera il `--timeout 15m` usato negli esempi di installazione standard.
> Un timeout fa sì che `helm install` segnali `INSTALLATION FAILED` anche se
> la distribuzione si completa correttamente in background. Usare `--timeout 30m`
> evita il falso errore e lo stato di release `failed` che ne deriverebbe.

---

## Registro privato / Ambienti air-gapped

Se il cluster non riesce a effettuare il pull dal registro DefectDojo predefinito, effettuare il mirror delle
immagini sul proprio registro e configurare il chart per usarlo.

### Opzione 1: override globale del registro

Impostare `global.imageRegistry` per reindirizzare tutti i pull delle immagini. Il chart rimuove il
registro originale da `images.prefix` e antepone il proprio:

```yaml
global:
  imageRegistry: "my-registry.example.com"
```

Questo interessa tutte le immagini (django, nginx, celery, connectors, redis, ecc.).

### Opzione 2: override per singola immagine

Per un controllo più granulare, impostare `images.registry` (interessa le immagini principali dell'app) e
sovrascrivere le singole immagini:

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

### Secret di pull delle immagini per i registri privati

Se il registro richiede l'autenticazione, creare un pull secret e farvi riferimento:

```yaml
images:
  pullSecrets:
    existingSecrets:
      - "my-registry-pull-secret"
```

Oppure lasciare che il chart ne crei uno a partire da credenziali esplicite:

```yaml
images:
  pullSecrets:
    create: true
    registry: "my-registry.example.com"
    # Provide credentials via a Kubernetes docker-registry secret
```

Il comportamento predefinito (`extractFromLicense: true`) estrae le credenziali dell'account di servizio GCP
dal file di licenza per effettuare il pull dal registro di DefectDojo. Disabilitare
questa opzione quando si usa un registro proprio:

```yaml
images:
  pullSecrets:
    create: true
    extractFromLicense: false
    existingSecrets:
      - "my-registry-pull-secret"
```

---

## Override delle annotazioni della piattaforma

Il chart inietta automaticamente annotazioni specifiche per piattaforma su Ingress e Service,
in base a `cloudProvider` (ad es. annotazioni ALB per EKS, annotazioni GCE per
GKE). Se è necessario il controllo completo sulle annotazioni — ad esempio usando un controller
ingress nginx su EKS invece di ALB — impostare `platformAnnotations.enabled: false`
e fornire le proprie:

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

Quando `platformAnnotations.enabled` è `true` (impostazione predefinita), il chart unisce
le annotazioni della piattaforma con le annotazioni personalizzate. In caso di conflitto sulle chiavi,
prevalgono le annotazioni personalizzate, ma senza questa opzione non è possibile rimuovere
un'annotazione di piattaforma.

### Limite di dimensione degli upload dell'Ingress

Per impostazione predefinita il chart imposta `nginx.ingress.kubernetes.io/proxy-body-size: "2400m"`
sull'Ingress, in modo che gli upload di grandi risultati di scansione e i report PDF passino
attraverso nginx-ingress senza un errore `413 Request Entity Too Large`. Eseguire l'override con:

```yaml
django:
  ingress:
    maxBodySize: "100m"     # set "" to omit the annotation entirely
```

Questo vale ogni volta che il controller è nginx-ingress — incluso nginx-ingress
eseguito sopra EKS, GKE o AKS. I controller non nginx ignorano
l'annotazione e vanno regolati tramite i propri meccanismi (limiti di ispezione del body
di AWS WAF, request-body-limit di AppGW, `tuningOptions` di HAProxy per le Route di OpenShift).

---

## Note specifiche per piattaforma

### AWS EKS

- Richiede l'AWS Load Balancer Controller per l'ingress ALB
- Richiede l'EFS CSI driver se si usa lo storage EFS
- Il TLS termina sull'ALB tramite certificati ACM
- Impostare `certificates.ingress.source: "acm"` e fornire `acmCertArn`
- `dojo.secureCookies: true` funziona correttamente poiché l'ALB gestisce l'HTTPS

#### Punti di accesso EFS

Se il file system EFS è configurato con un **punto di accesso** (consigliato per
imporre la proprietà UID/GID sul mount), è **necessario** impostare
`storage.efs.accessPointId` nel file dei valori. In caso contrario, il PV monta la
radice EFS di proprietà di root e i container DefectDojo (eseguiti come UID 1001)
non possono creare le sottodirectory dei media — causando il fallimento dell'initializer con
errori `Permission denied`.

Verificare i punti di accesso EFS:

```bash
aws efs describe-access-points --file-system-id <your-fs-id> --region <region> \
  --query 'AccessPoints[].{Id:AccessPointId,Path:RootDirectory.Path,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
  --output table
```

Se esiste un punto di accesso, aggiungerlo al file dei valori:

```yaml
storage:
  type: "efs"
  efs:
    enabled: true
    fileSystemId: "fs-REPLACE_EFS_ID"
    accessPointId: "fsap-REPLACE_EFS_ACCESS_POINT_ID"
    region: "REPLACE_AWS_REGION"
```

> **Importante:** il campo `volumeHandle` del PersistentVolume è
> **immutabile** dopo la creazione. Se inizialmente si installa senza un punto
> di accesso e in seguito è necessario aggiungerne uno, occorre eliminare il PV e la PVC esistenti
> prima di eseguire `helm upgrade`:
>
> ```bash
> kubectl delete pvc defectdojo-media -n $NAMESPACE
> kubectl delete pv dojopro-media-pv
> helm upgrade dojopro $CHART ... (same flags as install)
> ```
>
> Questa operazione è sicura — l'eliminazione del PV rimuove solo il riferimento Kubernetes; i dati
> sul file system EFS non vengono interessati.

#### StorageClass su cluster hardened / gestiti tramite GitOps

Due assunzioni relative alle storage class creano problemi nei cluster con naming
personalizzato delle StorageClass o in cui le risorse a livello di cluster sono gestite al di fuori del chart applicativo.

**Le PVC con provisioning dinamico usano `gp3` come impostazione predefinita su EKS.** Qualsiasi PVC che il chart
provisiona dinamicamente — il volume Redis integrato (`redis.enabled: true`) e
il volume media `storage.type: "pvc"` — risolve la propria StorageClass in base al
valore predefinito della piattaforma, che su EKS è `gp3`. Se il cluster non ha una StorageClass
denominata `gp3` (comune nei cluster hardened con naming personalizzato), la PVC resta
in stato `Pending` con un evento `storageclass.storage.k8s.io "gp3" not found` e i
pod non si avviano mai.

Eseguire l'override in uno dei due modi seguenti:

- **Globalmente (consigliato)** — un'unica leva per ogni PVC provisionata dal chart:

  ```yaml
  storage:
    defaultStorageClass: "your-ebs-storageclass"   # or "" for the cluster default
  ```

- **Per singolo componente**, se sono necessarie classi diverse:

  ```yaml
  redis:
    redisVolume:
      pvc:
        storageClassName: "your-ebs-storageclass"
  storage:
    pvc:
      storageClassName: "your-ebs-storageclass"    # only for storage.type: "pvc"
  ```

  L'ordine di risoluzione è: valore per componente → `storage.defaultStorageClass` →
  valore predefinito della piattaforma (`gp3`). Impostare un valore su `""` per tornare alla
  StorageClass predefinita del cluster. Questo **non** si applica al percorso media EFS predefinito
  (vedere sotto), che non usa alcuna StorageClass.

**Il volume media EFS predefinito non richiede alcuna StorageClass.** Quando
`storage.type: "efs"`, il chart associa il PV media in modo statico tramite il `volumeHandle`
del file system EFS e un `claimRef` — sia il PV che la PVC usano uno
`storageClassName` vuoto. La StorageClass `efs-sc` **non** deve esistere perché
la PVC media si associ.

Il chart crea una StorageClass `efs-sc` a livello di cluster solo se si sceglie esplicitamente
il provisioning EFS **dinamico** con `storageClasses.efs.enabled: true`
(predefinito: `false`). Nei cluster in cui le risorse a livello di cluster sono gestite
al di fuori del chart applicativo (GitOps), lasciarlo al valore predefinito `false` — il
percorso EFS statico descritto sopra non richiede alcuna StorageClass né oggetti a livello di cluster
da questo chart. Se invece si desidera il provisioning EFS dinamico sotto GitOps, creare
la StorageClass fuori banda e mantenere `storageClasses.efs.enabled: false`.

### GCP GKE

- Usa il controller ingress GCE (`className: "gce"`), con il TLS che termina sul
  bilanciatore di carico di Google Cloud
- Il preset `gcp-gke.yaml` collega automaticamente all'ingress un `FrontendConfig`
  (redirect HTTP→HTTPS + policy SSL) e un `BackendConfig`
- Il bilanciatore di carico GCE esegue gli health check sul backend django direttamente dagli
  intervalli di Google (`130.211.0.0/22`, `35.191.0.0/16`). Le NetworkPolicy del chart li consentono
  automaticamente su GKE con entrambi i valori di `networkPolicy.profile`, quindi
  il probe `/nginx_health` va a buon fine e il backend risulta healthy — vedere
  [Politiche di rete](#network-policies)

#### TLS gestito da Google o BYO

Il preset `gcp-gke.yaml` usa per impostazione predefinita i **certificati gestiti da Google**. Scegliere
uno dei due approcci:

- **Gestito da Google (predefinito):** GCP crea e rinnova il certificato. Basta
  elencare i propri domini — non è necessario alcun secret TLS Kubernetes:

  ```yaml
  certificates:
    ingress:
      source: "google-managed"
      googleManaged:
        domains:
          - defectdojo.example.com
  ```

- **Bring your own (BYO):** fornire un secret TLS Kubernetes già esistente nel
  namespace di release e fare puntare l'ingress ad esso:

  ```yaml
  certificates:
    ingress:
      source: "secret"
      secretName: wildcard-example-com   # kubectl create secret tls ...
  ```

  Questo genera `spec.tls[].secretName` sull'ingress e omette l'annotazione
  `networking.gke.io/managed-certificates`.

> **Supporto script di bootstrap:** `scripts/bootstrap/bootstrap-gcp-gke.sh` copre
> solo i flussi di certificati nativi GCP (`google-managed` e `pre-shared`). Per il
> percorso BYO `secret`, installare direttamente con `helm` (creare prima il secret TLS,
> poi passare `certificates.ingress.source=secret` e
> `certificates.ingress.secretName=<your-secret>`).

> Il rinnovo dei certificati gestiti da Google è automatico — vedere
> [Rotazione dei certificati TLS](#rotating-tls-certificates).

### OpenShift / ROSA

- Usa le Route per impostazione predefinita (`django.route.enabled: true`), ma è supportato anche Ingress
- Per usare Ingress: impostare `django.ingress.enabled: true` e `django.route.enabled: false`
- Se ne può abilitare solo uno alla volta (il chart valida la mutua esclusività)
- **`dojo.secureCookies` deve essere `false`** quando si usano Route con terminazione edge (l'impostazione predefinita).
  Questo è obbligatorio, non facoltativo. Vedere l'[avviso in Preparare il file dei valori](#prepare-your-values-file).
- `securityContext.openshift.fsGroup` deve corrispondere all'intervallo di supplemental-groups del namespace
  (vedere la [Checklist pre-installazione](#infrastructure-details) per sapere come ricavarlo)
- NFS tramite EFS funziona bene — usare `storage.type: "nfs"` con il nome DNS EFS come server

#### Usare Ingress invece delle Route su OpenShift

OpenShift fornisce di serie un controller ingress basato su HAProxy. Se si preferisce
Ingress rispetto alle Route (ad es. per coerenza con altri cluster o per usare un
controller ingress personalizzato), configurare i valori così:

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

Gli helper di piattaforma del chart continuano comunque a gestire correttamente i security context, il resolver DNS
e i valori predefiniti di storage per OpenShift, indipendentemente dal metodo di
esposizione scelto.

---

## Problemi noti (versione chart 2.57.1)

Si tratta di bug confermati nel chart attuale. Le soluzioni alternative sono documentate
qui finché non viene rilasciata una versione corretta.

### Installazione minimal con solo PostgreSQL o Redis locali

I problemi seguenti si applicano solo se si usano PostgreSQL o Redis integrati nel chart
(`postgresql.enabled: true` oppure `broker.external: false`).
Non interessano le distribuzioni in produzione che usano database e broker esterni.

**Non usare EBS per il volume media (BUG-14, BUG-15)**

I volumi EBS supportano solo `ReadWriteOnce` — possono collegarsi a un solo
nodo alla volta. DefectDojo richiede che il volume media sia condiviso tra
più pod (django, celery-worker, initializer, connectors), che potrebbero essere
pianificati su nodi diversi. Quando ciò accade, i pod restano bloccati in
`ContainerCreating` con un `Multi-Attach error`, perché EBS non può montare il
volume su più di un nodo contemporaneamente. Questo interessa anche `helm test`,
dove il pod test-storage potrebbe essere pianificato su un nodo diverso rispetto ai
pod dell'applicazione.

**Usare EFS (o un altro backend di storage compatibile con `ReadWriteMany`) al posto di EBS
per il volume media.** EFS supporta l'accesso concorrente da tutti i nodi del
cluster ed è il backend di storage consigliato per le distribuzioni EKS.

Se è necessario usare EBS per i test su un cluster a singolo nodo, sovrascrivere i
valori predefiniti:

```yaml
storage:
  pvc:
    accessMode: "ReadWriteOnce"
    selector: null
    storageClassName: "gp3"
```

Tenere presente che, anche con questo override, EBS smetterà di funzionare non appena i pod verranno
pianificati su più nodi (ad es. durante lo scaling, la sostituzione di un nodo o
`helm test`). EFS evita del tutto questo problema.

**L'init container di PostgreSQL entra in conflitto con un security context non root (BUG-16)**

Disabilitarlo se si riscontra `CreateContainerConfigError`:

```yaml
postgresql:
  initContainer:
    enabled: false
```

### Tutti i deployment

**Il pod connectors va in crashloop mentre l'initializer è in esecuzione (comportamento previsto)**

Durante la prima installazione, il pod connectors entra in `CrashLoopBackOff`
mentre il job initializer esegue le migrazioni del database. Questo è previsto —
il pod connectors tenta di chiamare l'API Django (`/api/connectors/v1/config/`),
che restituisce un 500 perché lo schema del database non è ancora completamente migrato.
Una volta che il job initializer si completa correttamente (mostra `1/1 COMPLETIONS` in
`kubectl get jobs`), il pod connectors si riprende al successivo ciclo di riavvio.
Non è richiesto alcun intervento manuale.

**Un crash dell'initializer dopo le migrazioni lascia il database in uno stato non recuperabile (BUG-18)**

Se il job initializer va in crash **dopo** aver eseguito le migrazioni del database ma
**prima** di popolare i dati iniziali (ad es. per errori di permessi sullo storage o
limiti di risorse), il database resta in uno stato parzialmente inizializzato — le tabelle
esistono, ma la tabella `dojo_system_settings` è vuota. Ai riavvii successivi,
l'initializer fallisce immediatamente con:

```
CommandError: Failed to read system settings from database: 'NoneType' object is not iterable
```

Questo genera un crash loop senza ripristino automatico. **Soluzione alternativa:** reimpostare
lo schema del database e rieseguire l'initializer:

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

> **Prevenzione:** assicurarsi che i permessi di storage (in particolare i punti di accesso EFS —
> vedere [Punti di accesso EFS](#efs-access-points)) e i limiti di risorse siano configurati
> correttamente **prima** della prima installazione. Eseguire `helm template` per convalidare i
> valori e verificare, se possibile, i permessi di mount EFS con un pod di test.

**Avviso sul token Hatchet nei log (informativo)**

Quando `hatchet.enabled: false` (impostazione predefinita), i pod registrano nei log il seguente
avviso all'avvio:

```
Could not create Hatchet handle; all future Hatchet invocations will fail.
Error: ... Token must be set
```

Questo è **previsto e innocuo**. A partire dal chart 2.57, l'esecuzione dei workflow
in background è stata consolidata in `ddorch` + `ddorch-workers`, che
sostituiscono i worker basati su Hatchet ormai legacy (`kairos`, `rulesengine`,
`hatchet-integrators`). Il codice client di Hatchet viene comunque inizializzato
all'avvio, quindi l'avviso continua a comparire quando Hatchet è disabilitato, ma nulla
dipende da esso. L'avviso può essere tranquillamente ignorato.

### HTTPS non configurato

**L'annotazione ssl-redirect dell'ALB richiede un listener HTTPS (BUG-17)**

Il preset EKS include un'annotazione `ssl-redirect` che presuppone l'esistenza di un listener
HTTPS sull'ALB. Se non è stato configurato un certificato ACM e un listener
HTTPS, questa annotazione causa un loop di redirect. Configurare l'HTTPS
(consigliato) oppure vedere
[Distribuzione senza HTTPS (sconsigliata)](#deploying-without-https-not-recommended)
per l'elenco completo delle modifiche necessarie.

---

## Risoluzione dei problemi

### Pod bloccati in CrashLoopBackOff

Controllare i log:
```bash
kubectl logs -n $NAMESPACE <pod-name> --previous
```

Di solito si tratta di uno di questi casi: secret mancanti o errati (controllare tutte e 12 le chiavi), database
non raggiungibile (controllare `database.host` e i security group), oppure certificato TLS interno mancante
(verificare che esista il secret `dojopro-internal-tls`).

### Combinare secret esterni e inline

```
dojo.existingSecret is set to 'X', but the following inline secret values are also provided: [...]
```

Scegliere un solo approccio. Se si usa `dojo.existingSecret`, rimuovere tutti i valori
di secret inline (`dojo.secretKey`, `dojo.admin.password`, `monitoring.password`, ecc.)
dai file dei valori.

### Lo schema indica che admin.password è obbligatorio

Impostare `dojo.existingSecret` — lo schema elimina l'obbligo della password quando
è configurato un secret esterno.

### Errori di permessi fsGroup su OpenShift

Se i pod falliscono con errori di permessi sui volumi NFS, verificare che
`securityContext.openshift.fsGroup` rientri nell'intervallo di supplemental-groups
del namespace. Vedere come ricavare il valore fsGroup in
[Distribuzione → OpenShift / ROSA](#openshift-rosa).

### ALB non visualizzato (EKS)

Verificare che l'AWS Load Balancer Controller sia in esecuzione:
```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

Controllare gli eventi dell'ingress:
```bash
kubectl describe ingress -n $NAMESPACE
```

---

## Appendice: modello di configurazione per il cliente

Il modello completo (`template.yaml`) è disponibile tramite il portale di supporto
DefectDojo o all'indirizzo support@defectdojo.com. Copiarlo, sostituire i
placeholder `REPLACE_*` e rimuovere le sezioni non applicabili alla propria piattaforma. Il
modello include esempi commentati per:

- Identificazione della piattaforma (`cloudProvider`)
- Configurazione dei pull secret delle immagini
- Configurazione di Ingress e Route (Ingress per EKS/GKE/OpenShift, Route per OpenShift)
- Opzioni di storage EFS e NFS
- Configurazione dei certificati e del TLS
- Security context (uwsgi, nginx, fsGroup di OpenShift)
- Politiche di rete
- Opzioni di consegna della licenza (file, secret, inline)

---

## Cronologia delle revisioni

| Data       | Versione | Modifiche                                                              |
|------------|---------|----------------------------------------------------------------------|
| 2026-07-09 | 3.1.0   | Aggiunto il PSIRT Advisory Engine opzionale (`psirt.enabled`): servito su `/psirt/` tramite il sidecar nginx, database dedicato tramite `psirt.databaseUrl`, indicazioni sul pinning dei secret, regole di network policy, hook BYO |
| 2026-04-17 | 2.57.1  | Documentati `ddorch` + `ddorch-workers` (nuova coppia di orchestratori che sostituisce kairos/rulesengine/hatchet-integrators); aggiunti i flag `ddorch.tls.rootCa/cert/key` `--set-file` ai comandi di pre-flight e deploy; nuova sezione sui certificati mTLS di ddorch con i requisiti SAN; mcp-server elencato tra i pod previsti; aggiunti i PDB per ddorch (singleton) e ddorch-workers; nota sui prerequisiti ArgoCD relativa alla consegna dei certificati ddorch; aggiornato l'avviso su Hatchet per riflettere il consolidamento dei worker |
| 2026-03-25 | 2.55.4  | Aggiunta la documentazione sugli access point EFS e il relativo campo del template; documentato il ripristino da crash dell'initializer (BUG-18); documentato il crashloop dei connectors durante l'init come comportamento previsto; chiarito che l'avviso sul token Hatchet è innocuo; corretta un'ancora obsoleta dei problemi noti; percorso di estrazione del chart con versione; consolidate le indicazioni per l'assenza di HTTPS; pulizia dei PV nella disinstallazione; nota sulla coerenza del namespace; nota su ArgoCD rispetto al versionamento dei preset da CLI |
| 2026-03-11 | 2.53.0  | Corretti i percorsi dei comandi helm; aggiunti estrazione del chart, prerequisiti EKS, controllo del database pre-flight, avviso HTTPS, rotazione TLS, sezione dei problemi noti |
