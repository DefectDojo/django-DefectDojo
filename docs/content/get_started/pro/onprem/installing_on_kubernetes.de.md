---
title: DefectDojo Pro Installationsleitfaden
description: 'DefectDojo Pro mit dem Helm-Chart auf Kubernetes installieren: Infrastruktur,
  Secrets und die Installation selbst'
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
Behandelt die Bereitstellung auf AWS EKS und OpenShift (ROSA). Der Ablauf ist
für beide identisch: Infrastruktur einrichten, Secrets erstellen, Chart installieren.

---

## Checkliste vor der Installation

Stellen Sie die folgenden Informationen zusammen, bevor Sie beginnen. Wenn Sie
diese bereithalten, vermeiden Sie Verzögerungen während der Installation.

### Infrastrukturdetails

| Angabe | Beispiel | Wo Sie sie finden |
|------|---------|-------------------|
| **PostgreSQL-Host** | `mydb.abc123.us-east-1.rds.amazonaws.com` | AWS-RDS-Konsole oder `aws rds describe-db-instances` |
| **PostgreSQL-Port** | `5432` | Üblicherweise 5432, sofern nicht angepasst |
| **Name der PostgreSQL-Datenbank** | `dojodb` | Ihr DBA oder die Ausgaben von Terraform/CloudFormation — muss vor der Installation erstellt werden (siehe Hinweis unten) |
| **Orchestrator-Datenbank** | `dojodb-ddorch` | Entweder der Anwendungsrolle `CREATEDB` gewähren oder `<dbname>-ddorch` vorab erstellen — siehe [Pre-flight: Orchestrator-Datenbank (ddorch)](#pre-flight-orchestrator-ddorch-database) |
| **PostgreSQL-Benutzername** | `defectdojo` | `aws rds describe-db-instances --query 'DBInstances[].MasterUsername'` |
| **PostgreSQL-Passwort** | — | AWS Secrets Manager, Terraform-State oder Ihr DBA |
| **Redis-/ElastiCache-Endpunkt** | `my-redis.abc123.use1.cache.amazonaws.com` | `aws elasticache describe-cache-clusters --show-cache-node-info` |
| **Redis-Passwort** | — | Entfällt, wenn die Authentifizierung deaktiviert ist (nur VPC). Prüfen mit: `aws elasticache describe-replication-groups --query 'ReplicationGroups[].AuthTokenEnabled'` |
| **EFS-Dateisystem-ID** | `fs-0abc123def456` | `aws efs describe-file-systems --region <region>` |
| **EFS-Access-Point-ID** (falls zutreffend) | `fsap-0abc123def456` | `aws efs describe-access-points --file-system-id <fs-id>` |
| **UID/GID des EFS-Access-Points** | UID `1001`, GID `1337` | Muss zum Security-Context des Containers passen (siehe Hinweis unten) |
| **Domainname (FQDN)** | `dojo.example.com` | Ihr DNS-Administrator (siehe plattformspezifische Hinweise unten) |
| **ACM-Zertifikats-ARN** (EKS mit HTTPS) | `arn:aws:acm:...` | `aws acm list-certificates --region <region>` |
| **OpenShift-Apps-Domain** (nur ROSA) | `apps.abc123.p1.openshiftapps.com` | `oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'` |
| **fsGroup des OpenShift-Namespace** (nur ROSA) | `1001070000` | `oc get namespace <ns> -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'` — verwenden Sie den Startwert |
| **Lizenzdatei** | `onprem-dojopro.lic` | Wird vom DefectDojo-Support bereitgestellt |

> **Erstellen Sie die Datenbanken vor der Installation.** Das Chart erstellt auf
> einem externen PostgreSQL-Server keine Datenbanken. Erstellen Sie beide der
> folgenden Datenbanken auf Ihrem Datenbankserver im Besitz des
> Anwendungsbenutzers, bevor Sie `helm install` ausführen:
>
> - `dojodb` — die Hauptdatenbank von DefectDojo
> - `dojodb-ddorch` — die Orchestrator-Datenbank (ddorch), stets benannt nach der
>   Hauptdatenbank mit dem Suffix `-ddorch`. Alternativ gewähren Sie der
>   Anwendungsrolle `CREATEDB`, dann erstellt ddorch diese Datenbank beim ersten
>   Start selbst.
>
> Siehe [Pre-flight: Datenbankverbindung prüfen](#pre-flight-verify-database-connectivity)
> und [Pre-flight: Orchestrator-Datenbank (ddorch)](#pre-flight-orchestrator-ddorch-database)
> für direkt ausführbare `CREATE DATABASE`-Befehle.

> **UID/GID des EFS-Access-Points:** Wenn Ihr EFS-Dateisystem einen Access Point
> verwendet, **muss** dessen POSIX-Benutzerkonfiguration UID `1001` und GID `1337`
> verwenden, damit sie zum Security-Context des DefectDojo-Containers passt. Eine
> Abweichung führt während der Initialisierung zu `Permission denied`-Fehlern,
> wenn die Container versuchen, Media-Unterverzeichnisse zu erstellen. Prüfen mit:
>
> ```bash
> aws efs describe-access-points --file-system-id <fs-id> --region <region> \
>   --query 'AccessPoints[].{Id:AccessPointId,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
>   --output table
> ```

> **OpenShift-/ROSA-FQDN:** Auf ROSA erzeugen Routes Hostnamen automatisch nach
> dem Muster `<release-name>-<namespace>.apps.<cluster-domain>`. Lautet Ihr
> Release beispielsweise `dojopro` im Namespace `dojopro`, ist der Route-Hostname
> `dojopro-dojopro.apps.abc123.p1.openshiftapps.com`. Die Apps-Domain Ihres
> Clusters ermitteln Sie mit:
>
> ```bash
> oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
> ```
>
> Verwenden Sie den resultierenden FQDN für `dojo.fqdn`, `dojo.url` und `dojo.hosts.main`.

> **OpenShift-/ROSA-fsGroup:** Sie benötigen den Startwert der
> supplemental-groups Ihres Namespace für `securityContext.openshift.fsGroup`.
> Ermitteln Sie ihn jetzt, damit Sie Ihre Values-Datei später nicht anpassen müssen:
>
> ```bash
> oc get namespace <your-namespace> \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Output example: 1001070000/10000 — use 1001070000 as fsGroup
> ```

### Zu erzeugende Secrets

Die folgenden Secrets müssen für Ihre Bereitstellung neu erzeugt werden.
Verwenden Sie die angegebenen Befehle, um kryptografisch zufällige Werte zu erstellen:

| Secret | Schlüssel im K8s-Secret | Erzeugen mit |
|--------|-------------------|---------------|
| Django-Secret-Key | `DD_SECRET_KEY` | `openssl rand -hex 25` |
| AES-256-Verschlüsselungsschlüssel | `DD_CREDENTIAL_AES_256_KEY` | `openssl rand -hex 16` |
| Cloud-Portal-Secret | `CLOUD_PORTAL_SECRET_KEY` | `openssl rand -hex 25` |
| Gemeinsames Secret der Connectors | `DD_CONNECTORS_SHARED_SECRET` | Denselben Wert wie `CLOUD_PORTAL_SECRET_KEY` verwenden |
| Admin-Passwort | `DD_ADMIN_PASSWORD` | `openssl rand -base64 16` |
| Metrics-Passwort | `METRICS_HTTP_AUTH_PASSWORD` | `openssl rand -hex 16` |

### Secrets aus Ihrer Infrastruktur

Diese stammen aus Ihrer bestehenden Infrastruktur — erzeugen Sie sie nicht selbst:

| Secret | Schlüssel im K8s-Secret | Quelle |
|--------|-------------------|--------|
| Datenbankpasswort | `DD_DATABASE_PASSWORD` | Ihr PostgreSQL-Passwort |
| Datenbank-Verbindungs-URL | `DD_DATABASE_URL` | `postgresql://<user>:<password>@<host>:<port>/<dbname>` |
| Redis-Passwort | `redis-password` (im separaten Secret `dojopro-redis`) | Ihr Redis-Passwort, oder überspringen, wenn keine Authentifizierung genutzt wird |
| URL des E-Mail-Dienstes | `DD_EMAIL_URL` | `consolemail://` zum Testen, oder Ihre SMTP-URL |

### Optional (leer lassen, um es zu deaktivieren)

| Secret | Schlüssel im K8s-Secret | Zweck |
|--------|-------------------|---------|
| EPSS-Bucket-Key | `DD_PRO_ENHANCEMENTS_EPSS_BUCKET_KEY` | Anreicherung mit EPSS-Scores |

> **Tipp:** Kopieren Sie `secrets-template.yaml` und tragen Sie die oben genannten
> Werte ein. Ausführliche Anweisungen zum Erstellen des Kubernetes-Secrets finden
> Sie unter [Secrets erzeugen](#generate-secrets).

---

## Voraussetzungen

```bash
# Required tools
brew install awscli helm kubectl jq openssl eksctl

# Verify AWS access
aws sts get-caller-identity
```

Für OpenShift/ROSA installieren Sie zusätzlich:
```bash
brew install rosa openshift-cli
```

### Anforderungen an ausgehende Verbindungen

In eingeschränkten Netzwerkumgebungen müssen die folgenden ausgehenden
Verbindungen vor der Installation freigegeben sein. Firewall-Regeln erfordern
möglicherweise vorab beantragte Änderungen — stellen Sie sicher, dass sie
eingerichtet sind, bevor Sie fortfahren.

**Container-Registry (erforderlich)**

Alle Cluster-Knoten müssen die DefectDojo-Container-Registry über Port 443 erreichen:

```
host us-south1-docker.pkg.dev
# us-south1-docker.pkg.dev is an alias for googlecode.l.googleusercontent.com
```

> Für Air-Gapped-Umgebungen siehe
> [Private Registry / Air-Gapped-Umgebungen](#private-registry-air-gapped-environments).

**Datenbank (erforderlich)**

Von den Cluster-Knoten zu Ihrer PostgreSQL-Instanz, üblicherweise Port 5432.

- RDS im selben VPC: Stellen Sie sicher, dass die Security Group der EKS-Knoten
  eingehend auf Port 5432 freigegeben ist
- RDS in einem anderen VPC oder Konto: VPC-Peering oder Transit Gateway erforderlich
- Extern/On-Premises: Der VPN- oder Direct-Connect-Pfad muss Port 5432 zulassen

**EPSS-Updates (empfohlen)**

```
host api.first.org
# api.first.org has address 151.101.1.91
# api.first.org has address 151.101.193.91
# api.first.org has address 151.101.129.91
# api.first.org has address 151.101.65.91
# Port 443
```

**KEV-Feed (empfohlen)**

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

host www.cisa.gov
# www.cisa.gov is an alias for www.cisa.gov.edgekey.net (Akamai CDN — IPs vary)
# Port 443
```

**AWS-Dienste (nur EKS, erforderlich)**

Der EBS-CSI-Treiber und der ALB-Controller benötigen Zugriff auf AWS-API-Endpunkte
über Port 443:

- `sts.amazonaws.com`
- `ec2.amazonaws.com`
- `elasticloadbalancing.amazonaws.com`
- `elasticfilesystem.amazonaws.com` (bei Verwendung von EFS)

### Voraussetzungen für AWS EKS

Die folgenden Komponenten müssen in Ihrem EKS-Cluster installiert sein, bevor Sie
DefectDojo Pro bereitstellen. Ohne sie schlägt die Bereitstellung fehl.

**EBS-CSI-Treiber** (nur erforderlich beim Minimal-Profil mit eingebettetem
PostgreSQL und Redis — nicht nötig, wenn Sie externes RDS und ElastiCache nutzen):

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

**EFS-CSI-Treiber** (erforderlich bei Verwendung von EFS-Speicher — dem
empfohlenen Speicher-Backend für EKS-Bereitstellungen mit mehreren Replicas):

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

**AWS Load Balancer Controller** (erforderlich für ALB-Ingress):

Die Installationsanweisungen unterscheiden sich je nach EKS-Version. Folgen Sie
der [offiziellen Installationsanleitung für den AWS Load Balancer Controller](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/deploy/installation/).

---

## Chart-Paket entpacken

Das Chart wird als ZIP-Datei ausgeliefert, die ein `.tgz`-Helm-Paket enthält.
Entpacken Sie beides, bevor Sie fortfahren. Verwenden Sie einen versionierten
Entpackungspfad, damit Presets nicht unbemerkt überschrieben werden, wenn Sie
später eine neuere Chart-Version entpacken:

```bash
unzip helm-chart-<version>.zip -d /tmp/dojopro-extract
cd /tmp/dojopro-extract
mkdir -p dojopro-<version>
tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
```

Setzen Sie eine Variable `CHART`, die auf das entpackte Chart-Verzeichnis zeigt.
Alle folgenden `helm`-Befehle in dieser Anleitung verwenden `$CHART`:

```bash
CHART="dojopro-<version>/dojopro"
# e.g. CHART="dojopro-2.55.4/dojopro"
```

> **Warum CLI-Nutzer entpacken müssen:** Die Preset-Dateien
> (`presets/platforms/*.yaml`, `presets/profiles/*.yaml`) sind im `.tgz`-Paket
> enthalten. `helm install -f` benötigt Dateien im lokalen Dateisystem — es kann
> keine Dateien aus einem gepackten `.tgz` lesen. Sie müssen das Chart entpacken,
> um auf die Presets zugreifen zu können.
>
> **ArgoCD-Nutzer müssen nicht entpacken.** ArgoCD liest `valueFiles` direkt aus
> dem Chart-Paket. Siehe [Mit ArgoCD bereitstellen](#deploy-with-argocd).

---

## Values-Datei vorbereiten

Die Konfigurationsvorlage für Kunden (`template.yaml`) und die Secrets-Vorlage
(`secrets-template.yaml`) sind separat über das DefectDojo-Support-Portal oder
per Anfrage an support@defectdojo.com verfügbar. Sie sind nicht im Chart-`.tgz`
enthalten. Sobald Sie die Vorlage haben, kopieren Sie sie und tragen Ihre Daten ein:

```bash
cp template.yaml my-company.yaml
```

Setzen Sie mindestens:

| Einstellung | Beschreibung |
|---------|-------------|
| `dojo.fqdn` | Ihr Domainname (ROSA: siehe [FQDN-Hinweis](#infrastructure-details) oben) |
| `dojo.url` | Vollständige URL inklusive Protokoll (z. B. `https://dojo.example.com`) |
| `dojo.hosts.main` | Muss zu Ihrem FQDN passen |
| `dojo.secureCookies` | Unter **OpenShift/ROSA** auf `false` setzen (siehe Warnung unten) |
| `dojo.admin.*` | `user`, `email`, `firstName`, `lastName` — Administratorkonto |
| `database.host`, `.port`, `.name`, `.user` | PostgreSQL-Verbindungsdaten (das Passwort gehört in die Secrets) |
| `celery.broker.host` | Ihr Redis-/ElastiCache-Endpunkt |
| `redis.enabled` | **Muss `false` sein**, wenn Sie externes Redis verwenden (siehe Warnung unten) |
| `storage.type` | Speicher-Backend — siehe plattformspezifische Hinweise |
| `certificates.*` | Konfiguration der TLS-Zertifikate |
| `django.ingress.*` oder `django.route.*` | Ingress (EKS) oder Route (OpenShift) — das Preset setzt Standardwerte |
| `securityContext.openshift.fsGroup` | **Nur ROSA** — Startwert der supplemental-groups des Namespace |

> **WARNUNG — `redis.enabled` muss bei Verwendung von externem Redis/ElastiCache
> ausdrücklich auf `false` gesetzt werden.** Die Presets der Profile `standard`
> und `performance` setzen `redis.enabled: true` als Standard. Wenn Ihre
> Values-Datei dies nicht überschreibt, stellt das Chart ein clusterinternes
> Redis **neben** Ihrem externen Broker bereit, was zu einer fehlerhaften
> Konfiguration führt. Ergänzen Sie Ihre Values-Datei um:
>
> ```yaml
> redis:
>   enabled: false
> ```

> **WARNUNG — `dojo.secureCookies` muss unter OpenShift/ROSA `false` sein.**
> Bei Verwendung von OpenShift Routes mit Edge-TLS-Terminierung führt
> `secureCookies: true` (der Standard in `template.yaml`) zu Redirect-Schleifen
> und einem defekten Login. Das ist nicht optional — Routes mit
> Edge-Terminierung erfordern:
>
> ```yaml
> dojo:
>   secureCookies: false
> ```

**Hinweise zum Speicher:**
- **EKS:** Verwenden Sie EFS — nicht EBS. EBS-Volumes können nicht knotenübergreifend
  geteilt werden, was `Multi-Attach`-Fehler verursacht. Siehe [Bekannte Probleme](#known-issues-chart-version-2.57.1).
  Wenn Ihr EFS einen Access Point verwendet, setzen Sie zusätzlich `storage.efs.accessPointId` —
  siehe [EFS-Access-Points](#efs-access-points).
- **OpenShift/ROSA:** Das Plattform-Preset verwendet standardmäßig `storage.type: "pvc"`
  mit `createNew: true` und damit die Standard-StorageClass des Clusters. Für
  Bereitstellungen über mehrere Knoten nutzen Sie NFS über EFS (`storage.type: "nfs"`).

Optional können Sie die Log-Ausführlichkeit festlegen:
- `config.logLevel` — Log-Level der Django-Anwendung (Standard: `"INFO"`)
- `celery.logLevel` — Log-Level von Celery Worker/Beat (Standard: `"INFO"`)

Setzen Sie einen der Werte zur Fehlersuche auf `"DEBUG"`. Unter
[Log-Ausführlichkeit](#log-verbosity) erfahren Sie, wie Sie dies zur Laufzeit
umschalten, ohne Ihre Values-Datei zu bearbeiten.

Legen Sie keine Secrets oder Lizenzinhalte in dieser Datei ab. Diese werden in
den nächsten beiden Abschnitten behandelt.

Die vollständige Liste der Optionen finden Sie in `template.yaml`.

### Pre-flight: Datenbankverbindung prüfen

Vergewissern Sie sich vor dem Fortfahren, dass Ihre Datenbank erreichbar ist —
das erspart später viel Zeit bei der Fehlersuche. Starten Sie einen temporären
Pod mit `psql`:

```bash
kubectl run psql-test --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -d dojodb -U defectdojo \
     -c "SELECT version();"
```

Eine erfolgreiche Verbindung sieht so aus:

```
                                                version
--------------------------------------------------------------------------------------------------------
 PostgreSQL 16.x on x86_64-pc-linux-gnu, compiled by gcc ...
(1 row)

pod "psql-test" deleted
```

Schlägt dies mit `database "dojodb" does not exist` fehl, ist Ihre RDS-Instanz
erreichbar, die Datenbank wurde aber noch nicht erstellt. Erstellen Sie sie:

```bash
kubectl run psql-create-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c "CREATE DATABASE dojodb OWNER <your-db-user>;"
```

Führen Sie anschließend die obige Verbindungsprüfung erneut aus, um es zu bestätigen.

Schlägt sie aus anderen Gründen fehl, prüfen Sie:
- **Security-Group-/Firewall-Regeln** — Port 5432 muss vom Cluster zum
  Datenbank-Host geöffnet sein
- **Berechtigungen des Datenbankbenutzers** — der Benutzer benötigt CREATE-,
  ALTER- und SELECT-Rechte auf der Zieldatenbank sowie entweder `CREATEDB` oder
  eine vorab erstellte Orchestrator-Datenbank (siehe nächster Abschnitt)

> Das Chart enthält außerdem eigene Prüfungen: einen Init-Container, der auf die
> TCP-Verbindung zur Datenbank wartet, und `helm test`, das nach der
> Bereitstellung eine vollständige PostgreSQL-Verbindung validiert. Dieser
> Pre-flight-Schritt findet Probleme, bevor Sie Zeit in das Erstellen von Secrets
> und den Aufruf von `helm install` investieren.

### Pre-flight: Orchestrator-Datenbank (ddorch)

Der Orchestrator (`ddorch`, standardmäßig aktiviert) speichert seinen
Workflow-Status in einer **zweiten Datenbank** neben der Hauptdatenbank von
DefectDojo. Beim Start entnimmt er den Datenbanknamen aus `DD_DATABASE_URL`,
hängt `-ddorch` an und erstellt diese Datenbank, falls sie nicht existiert — bei
der Hauptdatenbank `dojodb` verwendet der Orchestrator also `dojodb-ddorch`.

Darf die Anwendungsrolle keine Datenbanken erstellen, schlägt der ddorch-Pod beim
Start fehl mit:

```
ERROR: permission denied to create database (SQLSTATE 42501)
```

Erfüllen Sie **eine** der folgenden Bedingungen vor der Installation:

**Option A — der Anwendungsrolle `CREATEDB` gewähren** und ddorch seine Datenbank
beim ersten Start selbst erstellen lassen:

```sql
ALTER ROLE defectdojo CREATEDB;
```

**Option B — die Orchestrator-Datenbank vorab erstellen**, benannt nach Ihrer
Hauptdatenbank mit dem Suffix `-ddorch` und im Besitz desselben
Anwendungsbenutzers. Der Bindestrich im Namen erfordert doppelte Anführungszeichen
in SQL:

```sql
CREATE DATABASE "dojodb-ddorch" OWNER defectdojo;
```

Mit demselben Ansatz über einen temporären Pod wie bei der Verbindungsprüfung oben:

```bash
kubectl run psql-create-ddorch-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c 'CREATE DATABASE "dojodb-ddorch" OWNER <your-db-user>;'
```

---

## Secrets erzeugen

Hier haben Sie zwei Möglichkeiten.

### Option A: Externes Secret (empfohlen für GitOps)

Erstellen Sie vor der Installation des Charts ein Kubernetes-Secret mit den 12
erforderlichen Schlüsseln. Verwenden Sie die vom DefectDojo-Support
bereitgestellte `secrets-template.yaml` als Ausgangspunkt (wie Sie sie erhalten,
steht unter [Values-Datei vorbereiten](#prepare-your-values-file)):

```bash
cp secrets-template.yaml /tmp/dojopro-secrets.yaml
```

Bearbeiten Sie die Datei, ersetzen Sie alle Platzhalterwerte und wenden Sie sie an:
```bash
kubectl apply -f /tmp/dojopro-secrets.yaml -n <your-namespace>
```

Das Secret kann auch vom External Secrets Operator, von Sealed Secrets oder von
jedem anderen Werkzeug verwaltet werden, das Kubernetes-Secrets erstellt. Dem
Chart ist es gleich, wie das Secret dorthin gelangt ist — setzen Sie lediglich
`dojo.existingSecret` auf dessen Namen.

Bei der Installation:
```bash
--set dojo.existingSecret=dojopro-secrets
```

Das Chart überspringt das Rendern seines eingebauten Secrets automatisch, wenn
`dojo.existingSecret` gesetzt ist — weitere Flags sind nicht nötig.

Wenn Ihr externes Redis eine Authentifizierung erfordert, enthält
`secrets-template.yaml` außerdem ein separates Secret `dojopro-redis`. Das Chart
liest die Redis-Zugangsdaten aus `redis.auth.existingSecret` (Standard:
`dojopro-redis`). Hat Ihr Redis kein Passwort (z. B. ElastiCache nur im VPC),
können Sie dies überspringen.

### Option B: Inline-Secrets (einfacher, aber nicht GitOps-freundlich)

Übergeben Sie die Secret-Werte direkt in einer Values-Datei:

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

Speichern Sie dies als `my-secrets.yaml` und übergeben Sie es bei der
Installation mit `-f`.

> Committen Sie keine Secret-Dateien in die Versionsverwaltung.

---

## Interne TLS-Zertifikate erstellen

Das Chart benötigt interne TLS-Zertifikate für die Kommunikation zwischen den
Diensten.

Erstellen Sie vor der Installation zwei Kubernetes-TLS-Secrets in Ihrem Namespace:

1. `dojopro-internal-tls` — ein TLS-Secret mit `tls.crt` und `tls.key` für die
   Verschlüsselung zwischen den Diensten (nginx ↔ Connectors usw.)
2. `dojopro-internal-ca` — ein Secret mit dem CA-Zertifikat unter dem Schlüssel
   `ca.crt`, mit dem die Connectors das interne TLS-Zertifikat validieren

Sie können eine selbst signierte CA und ein Serverzertifikat mit `openssl`
erzeugen oder die interne CA Ihrer Organisation verwenden. CN/SAN des
Serverzertifikats **muss** den Namen des internen nginx-Service abdecken, den das
Helm-Release verwendet. Standardmäßig ist das `<release-name>-nginx` (z. B.
`dojopro-nginx`, wenn Ihr Release `dojopro` heißt).

Beispiel für das Erzeugen einer selbst signierten CA und eines Serverzertifikats:
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

> **Häufiger Fehler:** `nginx-internal` als CN/SAN zu verwenden statt
> `<release-name>-nginx`. Der Connectors-Pod validiert das TLS-Zertifikat gegen
> den tatsächlichen Service-Namen (`<release-name>-nginx.<namespace>.svc.cluster.local`)
> und schlägt mit einem Fehler `x509: certificate is valid for ... not ...` fehl,
> wenn der SAN nicht passt.

Setzen Sie dann in Ihrer Values-Datei:
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

### mTLS-Zertifikate für ddorch

Zusätzlich zu den internen TLS-Secrets oben benötigt der Orchestrator `ddorch`
ein separates mTLS-Zertifikatstrio, das vom ddorch-Server und von jedem Worker
verwendet wird, der mit ihm kommuniziert (`ddorch-workers`, `integrators`). Diese
werden dem Chart bei der Installation über `--set-file` übergeben (sie werden
**nicht** aus einem bereits vorhandenen Kubernetes-Secret gelesen):

- `orch_tls_root.ca` — CA-Zertifikat
- `orch_tls.crt` — Serverzertifikat
- `orch_tls.key` — privater Serverschlüssel

Ohne diese drei Dateien schlägt `helm install` mit
`ddorch.tls.rootCa is required` fehl.

Der SAN des Serverzertifikats **muss** alle Hostnamen enthalten, über die die
Worker ddorch erreichen:

- `ddorch` — clusterinterner Kurzname des Service
- `<release-name>-ddorch` — vollqualifizierter Service-Name (z. B. `dojopro-ddorch`)
- `<release-name>-ddorch.<namespace>.svc.cluster.local` — Cluster-FQDN
- `nginx` — der standardmäßige `SERVER_TLS_SERVER_NAME`, den Worker im Hatchet-Stil verwenden
- `localhost`, `127.0.0.1` — Worker im selben Pod, die ddorch über das hostAlias-Loopback erreichen

Beispiel für das Erzeugen des Trios:

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

Übergeben Sie sie an `helm install` / `helm template`:

```bash
--set-file ddorch.tls.rootCa=orch_ca.crt \
--set-file ddorch.tls.cert=orch_server.crt \
--set-file ddorch.tls.key=orch_server.key
```

> Das Hilfsskript `scripts/bootstrap-aws-eks.sh` erzeugt diese Dateien
> automatisch über die `dojopro-orch-certs-configmap` und verwendet sie wieder —
> wenn Sie dieses Skript nutzen, müssen Sie sie nicht manuell erstellen.

---

## Lizenz

Das Chart benötigt eine DefectDojo-Pro-Lizenz.

### Ihre Lizenz prüfen

Vergewissern Sie sich vor der Bereitstellung, dass Ihre Lizenz gültig und nicht
abgelaufen ist:

```bash
sed -n '/^[[:space:]]*ey/,/-----END/p' license.lic \
  | sed '$d' | tr -d ' ' | base64 -d | jq .
```

Damit werden die Lizenz-Metadaten angezeigt, darunter:
- `not_after` — Ablaufdatum der Lizenz
- `license_package` — bestätigt Ihre Stufe

> **Image-Pull-Secrets:** Wenn `images.pullSecrets.extractFromLicense: true`
> gesetzt ist (der Standard in den Plattform-Presets), extrahiert das Chart
> automatisch das eingebettete GCP-Servicekonto aus Ihrer Lizenzdatei und
> erstellt das Image-Pull-Secret, das zum Abrufen der DefectDojo-Images aus der
> Container-Registry benötigt wird. Ein manuelles Extrahieren oder Dekodieren ist
> nicht erforderlich. Wenn Sie stattdessen eine private Registry verwenden, setzen
> Sie `extractFromLicense: false` und stellen Ihr eigenes Pull-Secret bereit —
> siehe [Private Registry / Air-Gapped-Umgebungen](#private-registry-air-gapped-environments).

### Option 1: --set-file (Standard-Helm-Installation)

Übergeben Sie die Lizenzdatei bei der Installation:
```bash
--set-file license.contents=/path/to/license.lic
```

### Option 2: Vorhandenes Secret (GitOps / ArgoCD)

Erstellen Sie ein Kubernetes-Secret mit der Lizenz und weisen Sie das Chart an,
es zu verwenden. So benötigen Sie kein `--set-file` und müssen die Lizenz nicht in
Git ablegen.

```bash
kubectl create secret generic dojopro-license \
  --namespace $NAMESPACE \
  --from-file=dojopro.lic=/path/to/license.lic
```

Dann in Ihrer Values-Datei oder in den Helm-Flags:
```yaml
license:
  existingSecret: "dojopro-license"
```

Das Secret kann vom External Secrets Operator, von Sealed Secrets oder mit
einfachem kubectl verwaltet werden.

> **Wichtig:** `license.existingSecret` ist **nicht kompatibel** mit der
> Standardeinstellung `images.pullSecrets.extractFromLicense: true`. Das Chart
> benötigt den Lizenzinhalt zum Zeitpunkt des Renderings, um die eingebetteten
> Zugangsdaten für die Container-Registry zu extrahieren. Wenn Sie
> `license.existingSecret` verwenden, müssen Sie außerdem das automatische
> Extrahieren des Pull-Secrets deaktivieren und ein eigenes bereitstellen:
>
> ```yaml
> images:
>   pullSecrets:
>     extractFromLicense: false
>     existingSecrets:
>       - "my-registry-pull-secret"
> ```
>
> Wenn das Chart die Pull-Secrets automatisch aus der Lizenz extrahieren soll
> (der Standard), verwenden Sie stattdessen **Option 1**
> (`--set-file license.contents=`).


---

## FIPS-140-3-Modus (optional)

Für Umgebungen, die FedRAMP **SC-13** oder Ähnlichem unterliegen, kann das Chart
die `-fips`-Image-Varianten bereitstellen, deren Kryptografie vom **OpenSSL FIPS
Provider 3.1.2** (NIST-CMVP-Zertifikat **#4985**) und, für die Go-Dienste, vom
**Go Cryptographic Module v1.0.0** (CMVP **#5247**) ausgeführt wird.

Die Durchsetzung erfolgt innerhalb des Containers, sodass kein FIPS-fähiger
Host-Kernel erforderlich ist — genau das macht diesen Ansatz auf verwalteten
Laufzeitumgebungen praktikabel, in denen Sie das Host-Betriebssystem nicht
kontrollieren.

Standardmäßig deaktiviert; die gerenderte Ausgabe bleibt unverändert, solange er
ausgeschaltet ist.

```yaml
fips:
  enabled: true
  validate: true    # refuse to render a partly-FIPS deployment (see below)
```

Images mit dem Tag `-fips` müssen in Ihrer Registry verfügbar sein. Für den
Zugang wenden Sie sich an hello@defectdojo.com.

### Komponenten ohne FIPS-Variante

Für Sensei und das **eingebettete** PostgreSQL/Redis gibt es keinen FIPS-Build —
das mitgelieferte valkey-Image basiert auf Alpine, für das kein FIPS-validiertes
OpenSSL existiert. Eine FIPS-Installation muss daher externe Datenspeicher
verwenden und Sensei deaktiviert lassen:

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

Mit `fips.validate: true` (dem Standard) **schlägt das Rendern des Charts fehl**,
wenn Sie FIPS zusammen mit einer dieser Komponenten aktivieren; die betroffenen
Dienste werden benannt:

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei, redis (embedded). Disable them, or set fips.validate=false to accept
that they run non-validated cryptography.
```

Das ist Absicht. Eine Bereitstellung, in der die meisten Dienste validierte
Kryptografie nutzen und einer oder zwei still und heimlich nicht, ist schlechter
als ein offensichtlicher Fehler: Sie sieht konform aus und fällt erst bei einer
Prüfung auf. Setzen Sie `fips.validate: false` nur, wenn Sie dieses Risiko
ausdrücklich akzeptiert haben.

### Prüfung nach der Bereitstellung

Jeder Pod führt beim Start eine Prüfung nach dem Fail-Closed-Prinzip aus — ist
der validierte Provider nicht aktiv, beendet sich der Container, anstatt Anfragen
zu bedienen. Die ausgegebenen Nachweise sind meist genau das, was ein Prüfer
sehen möchte:

```bash
kubectl -n $NAMESPACE logs deploy/dojopro-django | grep FIPS
kubectl -n $NAMESPACE exec deploy/dojopro-django -- openssl list -providers
kubectl -n $NAMESPACE exec deploy/dojopro-django -- python3 /verify_fips.py
```

Verhaltensänderungen, die Sie einplanen sollten (das Passwort-Hashing wechselt zu
PBKDF2, ChaCha20 entfällt in der TLS-Cipher-Liste), sind auf der Seite zum
FIPS-140-3-Modus in der Produktdokumentation beschrieben.

---

## Pre-flight: Templates validieren

Führen Sie vor der Installation `helm template` aus, um alle Manifeste zu rendern
und zu validieren, ohne den Cluster anzufassen. Damit finden Sie Fehler in den
Values, fehlende Pflichtfelder und YAML-Probleme, bevor Sie sich auf
`helm install` festlegen:

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

Verwenden Sie dieselben Flags, die Sie später an `helm install` übergeben wollen.
Wenn der Befehl ohne Fehler endet, sind Ihre Values gültig. Schlägt er fehl,
benennt die Fehlermeldung das fehlende oder ungültige Feld — korrigieren Sie Ihre
Values-Datei und wiederholen Sie den Aufruf, bis er durchläuft.

---

## Bereitstellen

Kombinieren Sie Ihr Plattform-Overlay, das Ressourcenprofil, Ihre Kunden-Values
und die oben getroffenen Entscheidungen zu Secrets und Lizenz.

### AWS EKS

> **Für den Browserzugriff auf EKS wird HTTPS nachdrücklich empfohlen.**
> Wenn Ingress-TLS aktiv ist, aktiviert das Chart automatisch
> `SECURE_SSL_REDIRECT` und setzt CSRF-/Session-Cookies auf `Secure`. Das
> bedeutet, dass der Browser-Login ohne HTTPS-Listener am ALB fehlschlägt.
> Konfigurieren Sie für das beste Ergebnis ein ACM-Zertifikat, bevor Sie
> bereitstellen.
>
> Wenn Sie ohne HTTPS arbeiten müssen, siehe
> [Bereitstellung ohne HTTPS (nicht empfohlen)](#deploying-without-https-not-recommended)
> weiter unten.

```bash
NAMESPACE="dojopro"
kubectl create namespace $NAMESPACE
```

> **Konsistenz des Namespace:** Der Namespace-Wert muss über alle Ressourcen
> hinweg übereinstimmen: in Ihrem Secrets-YAML (`metadata.namespace`), bei
> `kubectl create namespace` und bei `helm install -n`. Wenn Sie einen eigenen
> Namespace anstelle von `dojopro` verwenden, ersetzen Sie ihn konsistent in allen
> Befehlen und Secret-Manifesten.

**Externe Secrets + Lizenz-Secret (GitOps):**

Wenden Sie Ihre Secrets an, falls noch nicht geschehen (siehe
[Secrets erzeugen](#generate-secrets)), und installieren Sie dann:

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

**Inline-Secrets + Lizenzdatei (einfacher):**
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

#### Bereitstellung ohne HTTPS (nicht empfohlen)

> **Warnung:** Ohne HTTPS werden Session-Cookies im Klartext übertragen und der
> CSRF-Schutz über Secure-Cookies ist deaktiviert. Verwenden Sie diese
> Konfiguration nicht in der Produktion.

Wenn Sie vorübergehend ohne HTTPS bereitstellen müssen (z. B. für erste Tests ohne
ACM-Zertifikat), nehmen Sie **alle** der folgenden Änderungen in Ihrer
Values-Datei vor:

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

Alle vier Änderungen sind erforderlich. Fehlt eine davon, kommt es zu
Redirect-Schleifen oder einem defekten Login. Wenn Sie HTTPS aktivieren möchten,
machen Sie diese Änderungen rückgängig und konfigurieren ein ACM-Zertifikat.

### OpenShift / ROSA

```bash
NAMESPACE="dojopro"
oc new-project $NAMESPACE
# Or, if the namespace already exists:
# oc project $NAMESPACE
```

> **Erinnerung:** Den `fsGroup`-Wert Ihres Namespace sollten Sie bereits aus der
> [Checkliste vor der Installation](#infrastructure-details) haben. Falls nicht,
> ermitteln Sie ihn jetzt:
>
> ```bash
> oc get namespace $NAMESPACE \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Use the start value (e.g., 1001070000) as securityContext.openshift.fsGroup
> ```

**Externe Secrets + Lizenz-Secret (GitOps):**

Wenden Sie Ihre Secrets an, falls noch nicht geschehen (siehe
[Secrets erzeugen](#generate-secrets)), und installieren Sie dann:

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

**Inline-Secrets + Lizenzdatei (einfacher):**
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

## Mit ArgoCD bereitstellen

DefectDojo Pro ist vollständig mit ArgoCD kompatibel. Das Chart enthält
Plattform- und Profil-Presets, die ArgoCD direkt als `valueFiles` referenzieren
kann.

### Voraussetzungen

Vor dem Erstellen der ArgoCD-Application müssen die folgenden
Kubernetes-Ressourcen im Ziel-Namespace vorhanden sein:

- Die Anwendungs-Secrets (siehe [Secrets erzeugen](#generate-secrets))
- Das Lizenz-Secret (siehe [Lizenz](#license))
- Die internen TLS-Secrets, sofern Sie keine automatische Erzeugung nutzen (siehe [Interne TLS-Zertifikate erstellen](#create-internal-tls-certificates))
- Das mTLS-Material für ddorch (siehe [mTLS-Zertifikate für ddorch](#ddorch-mtls-certificates)). ArgoCD hat kein Äquivalent zu `--set-file`, übergeben Sie die drei PEM-Inhalte daher über Application-Parameter (`ddorch.tls.rootCa` / `ddorch.tls.cert` / `ddorch.tls.key`). Verwenden Sie ein ArgoCD-Plugin zur Secret-Verwaltung (Sealed Secrets, External Secrets oder ein ConfigMap-Plugin), anstatt den Schlüssel im Klartext zu committen.

### So funktioniert es

ArgoCD referenziert Preset-Dateien relativ zum Chart-Root. Ihre Application-Spec
benötigt drei Dinge:

1. Plattform- und Profil-Presets als `valueFiles`
2. Ihre umgebungsspezifische Konfiguration (über `valueFiles`, inline in `values` oder beides)
3. Verweise auf Secret und Lizenz als `parameters`

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

### Ihre Konfiguration bereitstellen

Es gibt mehrere Wege, ArgoCD Ihre umgebungsspezifischen Values zu übergeben:

- Inline in `values` in der Application-Spec — der einfachste Ansatz, es sind
  keine zusätzlichen Dateien oder Repositories nötig. Funktioniert gut, wenn Ihre
  Konfiguration überschaubar ist.
- Eine Values-Datei in einem separaten Git-Repository — nutzen Sie die
  Multi-Source-Funktion von ArgoCD (ab v2.6) mit einer `$ref`-Variablen, um Ihre
  Values-Datei zusammen mit dem Chart zu laden. Empfohlen bei einem über OCI
  veröffentlichten Chart.
- Eine Values-Datei im selben Git-Repository wie das Chart — referenzieren Sie sie
  in `valueFiles` mit einem Pfad relativ zum Chart-Verzeichnis
  (z. B. `../../overrides/customers/my-company.yaml`).

Alle drei Ansätze folgen derselben Schichtung: Plattform-Preset → Profil-Preset →
Ihre Konfiguration. Später gesetzte Values überschreiben frühere.

### Aktualisieren

Wenn das Chart in einer OCI-Registry veröffentlicht ist, genügt für ein Upgrade
eine einzige Änderung an `targetRevision` in Ihrer Application-Spec. Die
Plattform- und Profil-Presets sind mit dem Chart versioniert und werden daher
automatisch aktualisiert.

Alle Details zur Helm-Unterstützung von ArgoCD finden Sie in der
[ArgoCD-Helm-Dokumentation](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/).

---

## Überprüfen

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

### Integrierte Helm-Tests

Das Chart bringt vier Tests mit, die als Kubernetes-Pods laufen, wenn Sie
`helm test` ausführen. Sie validieren die kritischen Integrationspunkte zwischen
DefectDojo und den zugrunde liegenden Diensten:

| Test | Was geprüft wird |
|------|----------------|
| `test-database` | Verbindet sich mit den konfigurierten Zugangsdaten zu PostgreSQL, führt `SELECT version()` aus und bestätigt, dass die Datenbank Abfragen annimmt. Wiederholt den Versuch bis zu 60 Sekunden. |
| `test-redis-broker` | Verbindet sich mit dem Redis-/Valkey-Broker, sendet ein `PING` und führt anschließend einen Zyklus aus Set/Get/Delete aus, um den Lese- und Schreibzugriff zu prüfen. |
| `test-django-health` | Ruft den Endpunkt `/api/v2/health_check/light/` am internen nginx-Service auf und bestätigt eine HTTP-2xx-/3xx-Antwort. Läuft nach den Tests für Datenbank und Broker (hook-weight 10). |
| `test-storage` | Bindet das Media-Volume ein und führt einen Zyklus aus Schreiben/Lesen/Löschen aus, um zu bestätigen, dass das Speicher-Backend erreichbar und für die Anwendung beschreibbar ist. Läuft zuletzt (hook-weight 15). |

Die Tests laufen in der Reihenfolge ihres hook-weight — zuerst die
Infrastrukturtests (Datenbank, Broker), dann die Tests auf Anwendungsebene
(Health, Storage). Schlägt ein früherer Test fehl, laufen spätere Tests
möglicherweise trotzdem, scheitern aber wahrscheinlich ebenfalls.

So führen Sie die Tests nach einer fehlgeschlagenen Bereitstellung oder einer
Konfigurationsänderung erneut aus:
```bash
helm test dojopro -n $NAMESPACE --logs --timeout 5m
```

Test-Pods werden vor jedem Lauf automatisch aufgeräumt (Delete-Policy
`before-hook-creation`). So prüfen Sie die Logs eines fehlgeschlagenen Test-Pods
manuell:
```bash
kubectl logs -n $NAMESPACE dojopro-test-database
kubectl logs -n $NAMESPACE dojopro-test-redis-broker
kubectl logs -n $NAMESPACE dojopro-test-django-health
kubectl logs -n $NAMESPACE dojopro-test-storage
```

### Das Admin-Passwort abrufen

Das initiale Admin-Passwort ist im Anwendungs-Secret gespeichert. Abrufen mit:

```bash
kubectl get secret dojopro-secrets -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

Wenn Sie Inline-Secrets anstelle eines externen Secrets verwendet haben, steht das
Passwort im vom Chart verwalteten Secret:

```bash
kubectl get secret dojopro-defectdojo -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

Melden Sie sich unter Ihrer konfigurierten URL mit dem Admin-Benutzernamen
(Standard: `admin`) und diesem Passwort an. Ändern Sie das Passwort nach der
ersten Anmeldung.

---

## Betrieb

### Log-Ausführlichkeit

Das Chart stellt zwei Einstellungen für das Log-Level bereit, die beide
standardmäßig auf `INFO` stehen:

| Einstellung | Steuert | Umgebungsvariable |
|---------|----------|---------|
| `config.logLevel` | Logging der Django-Anwendung | `DD_LOG_LEVEL` |
| `celery.logLevel` | Logging von Celery Worker und Beat | `DD_CELERY_LOG_LEVEL` |

Um die Ausführlichkeit zur Fehlersuche zu erhöhen, setzen Sie einen oder beide
Werte in Ihrer Values-Datei auf `DEBUG` und führen `helm upgrade` aus:

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

Die `--set`-Flags überschreiben die Einstellungen aus der Values-Datei, sodass Sie
das Debug-Logging umschalten können, ohne Dateien zu bearbeiten. Sobald das
Problem behoben ist, führen Sie `helm upgrade` erneut ohne die `--set`-Flags aus,
um zu Ihren konfigurierten Standardwerten zurückzukehren.

Das Django-Deployment unterstützt außerdem `django.uwsgi.enableDebug: true`, was
`DD_DEBUG=True` setzt und ein tiefergehendes Framework-Debugging ermöglicht. Das
erzeugt deutlich mehr Ausgaben und sollte nur für kurze Untersuchungen verwendet
werden.

### Isolierung von Scan-Importen

Scan-Importe (`/api/v2/import-scan/` und `/api/v2/reimport-scan/`) werden synchron
geparst und können viel Worker-Speicher beanspruchen. Standardmäßig betreibt das
Chart ein eigenes `django-import`-Deployment (uwsgi auf Port 3032 hinter einem
eigenen Service), und der nginx im Django-Pod leitet die Import-Endpunkte dorthin
weiter. Ein umfangreicher Import kann so die interaktiven Web-Worker nicht
erschöpfen (oder in ein OOM treiben), und der Importer-Pool (Schreiber) skaliert
unabhängig von den Web-Pods (Leser).

Einstellbare Werte unter `django.uwsgiImport`:

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

Hinweise für den Betrieb:

- Die Importer-Pods binden das gemeinsame Media-Volume ein und benötigen daher
  ReadWriteMany-fähigen Speicher, um frei über die Knoten hinweg eingeplant werden
  zu können. Die Speicher-Backends des Charts (`efs`, `filestore`, `gcsfuse`,
  `nfs` sowie das standardmäßige RWX-Media-PVC) erfüllen dies; ein
  ReadWriteOnce-PVC nicht.
- Das Autoscaling der Importer ist standardmäßig aus, weil ein Scale-down den
  gerade laufenden Import des betroffenen Pods abbricht, sobald
  `terminationGracePeriodSeconds` abgelaufen ist. Wenn Sie es aktivieren, erhöhen
  Sie die Grace Period, damit laufende Importe abgeschlossen werden können.
- Ein PodDisruptionBudget (`podDisruptionBudget.djangoImport`) schützt den
  Importer-Pool bei freiwilligen Unterbrechungen, sobald mehr als ein Importer
  läuft.

Das Profil `minimal` deaktiviert das Importer-Deployment, um den Footprint klein
zu halten; Importe teilen sich dann wie früher den einzigen uwsgi-Pool.

### PSIRT Advisory Engine (optional)

Das Chart kann die PSIRT Advisory Engine bereitstellen, einen Dienst zum
Erstellen und Veröffentlichen von Sicherheitshinweisen aus DefectDojo-Befunden.
Sie ist standardmäßig deaktiviert. Aktiviert erscheint sie unter `/psirt/` auf
Ihrem Haupt-DefectDojo-Host — der nginx-Sidecar arbeitet als Proxy dafür, sodass
kein zusätzlicher Ingress- oder DNS-Eintrag nötig ist.

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

`psirtSharedSecret` ist ein einfacher, von Ihnen gewählter Wert — es ist kein
DefectDojo-Benutzer und kein ausgestellter Token beteiligt. Setzen Sie eine
Zeichenkette mit hoher Entropie (z. B.
`python -c "import secrets; print(secrets.token_urlsafe(48))"`). Das Chart
verdrahtet sie sowohl im Secret der PSIRT-Engine als auch in den
DefectDojo-Pods, sodass ein einziger Wert das automatische Veröffentlichen bei
einer Neuinstallation ohne weiteren Schritt nach dem Start ermöglicht. Rotation:
Wert ändern und `helm upgrade` ausführen.

Datenbank einrichten: Richten Sie `databaseUrl` auf denselben PostgreSQL-Host, den
DefectDojo verwendet (oder auf einen anderen erreichbaren Host), mit einem
Datenbanknamen Ihrer Wahl. Der Pod erstellt die Datenbank beim ersten Start,
falls sie nicht existiert; das erfordert eine einmalige Berechtigung als
postgres-Superuser:

```sql
ALTER ROLE pae CREATEDB;
```

Hinweise für den Betrieb:

- Belassen Sie `psirt.replicas` bei 1. Der Dienst betreibt einen eigenen internen
  Job-Scheduler, und eine zweite Replica würde jeden geplanten Job doppelt
  ausführen.
- Der Pod bindet das gemeinsame Media-Volume ein (Anhänge zu Hinweisen liegen
  unter `<media>/pae/uploads`), sodass dieselben Empfehlungen zu
  ReadWriteMany-Speicher gelten wie für den Importer-Pool.
- Ausgehendes HTTPS ist für Advisory-Feeds und NVD-Abfragen erforderlich. Mit
  `networkPolicy.profile=aggressive` muss die Liste der erlaubten CIDRs
  (`networkPolicy.externalAPIs.allowedCidrs`) diese Endpunkte abdecken.
- Ein optionaler `psirt.nvdApiKey` erhöht das NVD-Rate-Limit von 5 auf 50
  Anfragen pro 30 Sekunden.

### Sensei-Engine für Scan/Fix (optional)

Das Chart kann die Sensei-Engine bereitstellen, den Dienst hinter serverseitigem
Scannen und automatischer Behebung (Fix-Jobs). Sie ist standardmäßig deaktiviert
und benötigt für den Start keine zusätzliche Konfiguration:

```yaml
sensei:
  enabled: true
```

Die Engine hält keine langlebigen Secrets. Zugangsdaten und Endpunkt-URLs für
Scan/Fix werden mit jedem Job übergeben und aus der verschlüsselten
Worker-Konfiguration von DefectDojo verteilt. django und celery erreichen die
Engine clusterintern (`SENSEI_ENGINE_URL` wird automatisch in die gemeinsame
ConfigMap eingetragen), sodass kein Ingress- oder DNS-Eintrag nötig ist.

Hinweise für den Betrieb:

- Die Engine ruft DefectDojo standardmäßig unter Ihrer öffentlichen Site-URL
  (`dojo.url`) zurück. Setzen Sie `sensei.ddCallbackUrl`, um das zu
  überschreiben — für ausschließlich clusterinternen Verkehr richten Sie sie auf
  den internen nginx-Listener, die Engine muss dann jedoch der internen CA von
  DefectDojo vertrauen.
- LLM-Zugangsdaten für Fix-Jobs werden normalerweise in der Anwendung gesetzt
  (AI Model Settings) und pro Job mitgegeben. Setzen Sie `sensei.llm.*` nur,
  wenn die Engine den Schlüssel aus ihrer eigenen Umgebung lesen muss; bevorzugen
  Sie `sensei.llm.existingSecret` gegenüber dem Klartext-Wert
  `sensei.llm.apiKey`.
- Um die Engine mit Google Vertex AI statt mit einem Provider-API-Key zu
  betreiben, setzen Sie `sensei.llm.provider: vertex` und
  `sensei.llm.vertexProject` auf das GCP-Projekt, in dem Vertex läuft
  (`sensei.llm.vertexRegion` ist üblicherweise `global`). Der Pod authentifiziert
  sich über Application Default Credentials; geben Sie ihm also ein
  GCP-Servicekonto über `sensei.serviceAccountName` + Workload Identity, oder
  binden Sie eine Schlüsseldatei mit `sensei.extraVolumesRaw` und
  `sensei.extraVolumeMounts` ein und richten `GOOGLE_APPLICATION_CREDENTIALS`
  über `sensei.extraEnv` darauf.
- `sensei.llm.fallbackChain` nimmt eine kommagetrennte Liste von Einträgen der
  Form `provider` oder `provider:model` auf, auf die die Engine zurückfällt, wenn
  der primäre Provider einen wiederholbaren Fehler zurückgibt. Endet die Kette
  bei einem anderen Anbieter (zum Beispiel `vertex-gemini:gemini-2.5-pro`),
  laufen Fix-Jobs auch bei einem Ausfall des primären Providers weiter.
- Das Scanner-Image ist ressourcenintensiv. `sensei.maxConcurrentJobs`
  (Standard 3) begrenzt die parallelen Jobs pro Pod, und die Standardressourcen
  (1Gi Request / 4Gi Limit) sind auf diese Grenze ausgelegt — erhöhen Sie beides
  gemeinsam.
- Ein CPU-basierter HPA (1 bis 4 Replicas) ist standardmäßig aktiv. Setzen Sie
  `sensei.hpa.maxReplicas` gleich `sensei.hpa.minReplicas`, um die Anzahl
  stattdessen auf `sensei.replicas` festzunageln.
- Ausgehendes HTTPS ist für Repository-Klone, APIs von Git-Hostern und
  LLM-Provider-APIs erforderlich. Mit `networkPolicy.profile=aggressive` muss die
  Liste der erlaubten CIDRs (`networkPolicy.externalAPIs.allowedCidrs`) diese
  Endpunkte abdecken.

### TLS-Zertifikate rotieren

Das Chart verwendet zwei Kategorien von TLS-Zertifikaten, jede mit einem eigenen
Rotationsverfahren.

#### Internes TLS (zwischen Diensten)

Dies sind die Secrets `dojopro-internal-tls` und `dojopro-internal-ca`, die für
die Kommunikation zwischen nginx, Connectors und anderen internen Diensten
verwendet werden.

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

#### Ingress-TLS (extern / browserseitig)

Die Rotation hängt davon ab, wie Sie TLS konfiguriert haben:

- **ACM-verwaltet (EKS):** Die Erneuerung erfolgt automatisch — keine Aktion nötig.
- **cert-manager:** Die Erneuerung erfolgt automatisch anhand der Einstellungen
  `duration` und `renewBefore` (Standardwerte: 2160h / 720h).
- **Von GKE verwaltete Zertifikate:** Die Erneuerung erfolgt automatisch — keine
  Aktion nötig.
- **Manuelles Zertifikat über ein Kubernetes-Secret:** Aktualisieren Sie das
  Secret, auf das der Ingress verweist, mit demselben Muster
  `kubectl create secret tls ... --dry-run=client` wie oben gezeigt.
- **Automatisch erzeugte interne Zertifikate:** Das Chart kann diese mit
  `helm upgrade` neu erzeugen, wenn `certificates.generation.enabled: true` gesetzt ist.

> In Kubernetes ist das Secret-Objekt die maßgebliche Quelle — das Aktualisieren
> des Secrets und ein Rollout des Deployments ist die Art, wie
> Zertifikatsrotation funktioniert.

> Wenn Sie den External Secrets Operator oder Sealed Secrets zur Verwaltung der
> TLS-Secrets einsetzen, wird die Rotation auf dieser Ebene erledigt und die
> Kubernetes-Secrets werden automatisch aktualisiert — manuelle `kubectl`-Schritte
> sind nicht nötig.

---

## Schichtung der Values-Dateien

Das Chart stapelt Values-Dateien. Spätere Dateien gewinnen:

```
presets/platforms/<platform>.yaml       # Platform defaults (aws-eks or openshift)
presets/profiles/<size>.yaml            # Resource profiles (minimal, standard, performance)
overrides/customers/<company>.yaml      # Your config (domain, DB, storage, certs)
```

Plattform- und Profil-Presets werden im Chart mitgeliefert (`dojopro/presets/`).
Sie sind im gepackten `.tgz` enthalten und mit dem Chart versioniert. Kunden
müssen sie nicht anpassen.

Wenn Sie `helm install` aus dem entpackten Chart verwenden, referenzieren Sie sie
über die beim [Entpacken](#extract-the-chart-package) gesetzte Variable `$CHART`:
```
-f $CHART/presets/platforms/aws-eks.yaml
```

Bei ArgoCD referenzieren Sie sie relativ zum Chart-Root:
```
valueFiles:
  - presets/platforms/aws-eks.yaml
```

Legen Sie keine Ressourcenlimits in Kundendateien und keine
Plattformkonfiguration in Profildateien ab. Halten Sie jede Schicht auf eine Sache
fokussiert.

> **Versionierung der Presets — ArgoCD vs. CLI:** ArgoCD referenziert Presets aus
> dem Chart-Paket heraus, sie werden also automatisch aktualisiert, wenn Sie
> `targetRevision` ändern. CLI-Nutzer müssen die Presets beim Upgrade auf eine
> neue Chart-Version erneut entpacken, um Änderungen an den Plattform- oder
> Profilstandards zu übernehmen. Verwenden Sie einen versionierten
> Entpackungspfad (z. B. `dojopro-2.55.4/`), um Verwechslungen zwischen
> Chart-Versionen zu vermeiden — siehe [Chart-Paket entpacken](#extract-the-chart-package).

---

## Anpassung und Erweiterbarkeit

Über Plattform-, Profil- und Kunden-Values-Dateien hinaus bietet das Chart
vollwertige Erweiterungspunkte, um Ihre eigene Infrastruktur einzubinden —
Sidecars, Init-Container, Umgebungsvariablen, Volumes, Servicekonten,
Scheduling-Einschränkungen und beliebige zusätzliche Manifeste — ohne das Chart zu
forken:

- **Hooks pro Komponente** — `extraEnv`, `extraEnvFrom`, `extraVolumesRaw`,
  `extraVolumeMounts`, `extraInitContainers`, `extraContainers`, `hostAliases`,
  `priorityClassName`, `topologySpreadConstraints`, `dnsConfig` und
  `serviceAccountName` bei jedem Workload (django, celery worker/beat,
  connectors, ddorch, ddorch-workers, integrators, mcp-server, psirt).
- **`extraManifests` auf oberster Ebene** — rendert beliebiges, von Ihnen
  bereitgestelltes YAML (ConfigMaps, Secrets, NetworkPolicies usw.) neben dem
  Chart, durchgeleitet über Helms `tpl` mit dem Root-Kontext des Charts.
- **Verwendung als Umbrella-Chart** — `dojopro` kann über eine `file://`- oder
  OCI-Abhängigkeit als Subchart eingebettet werden, nützlich für
  Kundenbündel, die zusätzliche Ressourcen um das Chart legen.
- **Schema-basierte Validierung** — `values.schema.json` deckt jeden Hook ab,
  sodass Editoren Autovervollständigung bieten und `helm lint` / `helm install`
  Ihre Overrides validieren.

Muster, Beispiele und Garantien zur Upgrade-Stabilität finden Sie im
BYO-Erweiterbarkeitsleitfaden — in der PDF-Ausgabe als
**Appendix: Bring Your Own Infrastructure (BYO)** enthalten.

---

## Network Policies

Das Chart liefert NetworkPolicies für jede Komponente mit, standardmäßig
aktiviert (`networkPolicy.enabled: true`). Eine Default-Deny-Basislinie ist auf
die Pods dieses Releases beschränkt (über die Labels `app.kubernetes.io/name` +
`app.kubernetes.io/instance`), sodass sie andere Workloads im selben Namespace
nie beeinträchtigt.

Wie streng die Regeln sind, steuert **`networkPolicy.profile`**:

| Profil | Egress | Pod-zu-Pod-Ingress | Externer Ingress |
|---------|--------|--------------------|------------------|
| `standard` (Standard) | Jeder Egress erlaubt (`0.0.0.0/0`) | Jeglicher Verkehr zwischen den eigenen Pods dieses Releases erlaubt | Auf den Ingress-Controller / Load Balancer beschränkt |
| `aggressive` | Feingranulare Allowlist pro Komponente (DNS, Datenbank/Broker, bestimmte clusterinterne Dienste, nur ausdrücklich erlaubte externe APIs) | Feingranulare Allowlist pro Komponente | Auf den Ingress-Controller / Load Balancer beschränkt |

- **`standard`** ist für die meisten Cluster empfohlen. Es vermeidet Störungen
  durch clusterspezifische Egress-Abhängigkeiten (den GKE-Metadatenserver,
  NodeLocal DNSCache, Cloud-Storage-/API-Endpunkte) und durch anwendungsinterne
  Serviceaufrufe, hält den externen Ingress aber weiterhin auf den Ingress-Pfad
  begrenzt: Das Release vertraut seinen eigenen Pods, von außen geht es aber
  weiterhin nur durch die Vordertür.
- **`aggressive`** erzwingt eine strikte Allowlist in beiden Richtungen. Wenn Sie
  es verwenden, müssen Sie unter `networkPolicy` möglicherweise die Ausnahmen für
  Ihren Cluster anpassen:
  - `nodeLocalDns` — erlaubt den NodeLocal-DNSCache-Resolver (standardmäßig
    link-local `169.254.20.10`, auf Port 53). Erforderlich auf Clustern, die
    NodeLocal DNSCache betreiben (z. B. das GKE-Add-on), andernfalls schlägt die
    DNS-Auflösung fehl.
  - `dnsSelectors` — überschreibt das DNS-Egress-Ziel für ein eigenes DNS-Setup.
  - `allowExternalAPIs` / `externalAPIs` — steuert den Egress zu externen
    HTTPS-APIs und welche CIDRs blockiert werden (z. B. Cloud-Metadaten).

Setzen Sie das Profil in einer beliebigen Values-Datei, z. B.:

```yaml
networkPolicy:
  profile: aggressive
```

> **GKE-Health-Checks** werden in beiden Profilen berücksichtigt — die
> Probe-Bereiche des GCE-Load-Balancers (`130.211.0.0/22`, `35.191.0.0/16`)
> dürfen auf GKE stets das django-Backend erreichen. Siehe [GCP GKE](#gcp-gke).

### Zugriff des Ingress-Controllers (502 Bad Gateway)

Auf Clustern, die nicht GKE oder OpenShift sind, lässt die NetworkPolicy von
django den Ingress-Controller herein, indem sie dessen Namespace über das Label
`kubernetes.io/metadata.name` auswählt, das Kubernetes automatisch an jeden
Namespace anhängt. Standardmäßig wird der Controller dabei in einem Namespace
namens **`ingress-nginx`** erwartet, dessen Controller-Pods das Label
`app.kubernetes.io/name: ingress-nginx` tragen (der Standard des
ingress-nginx-Charts).

Wenn Ihr Ingress-Controller in einem anders benannten Namespace liegt, andere
Pod-Labels verwendet oder ein völlig anderer Controller ist (Traefik, ein ALB
usw.), verwirft die Policy dessen Verkehr stillschweigend und Anfragen laufen in
**502 Bad Gateway** (`connect() failed (110: Operation timed out)` in den Logs
des Controllers). Richten Sie die Policy mit `networkPolicy.ingressSource` auf
Ihre tatsächliche Ingress-Quelle:

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

Oder passen Sie `networkPolicy.ingressNamespace` /
`networkPolicy.ingressControllerLabel` an, wenn nur die Namen abweichen. Weitere
`ingressSource`-Beispiele (Traefik, OpenShift-Router, AWS ALB) finden Sie in den
Kommentaren unter `networkPolicy` in `values.yaml`.

---

## Aktualisieren

Der empfohlene Upgrade-Pfad bezieht das Chart direkt aus der
DefectDojo-OCI-Registry — ein Entpacken der ZIP-Datei ist nicht erforderlich:

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

Ein typisches OCI-Upgrade sieht so aus (mit denselben Values-Dateien und
`--set`-Flags wie bei der ursprünglichen Installation):

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

Der bei der Installation genutzte Weg über die gepackte ZIP-Datei funktioniert
auch für Upgrades — verwenden Sie `helm upgrade` statt `helm install` gegen den
entpackten `$CHART`-Pfad.

Informationen zu Authentifizierung, ArgoCD-Upgrades, Überprüfung, Rollback und
Fehlersuche finden Sie im [Upgrade-Leitfaden](/get_started/pro/onprem/upgrading_on_kubernetes/) — in der PDF-Ausgabe als
**Appendix: Upgrading DefectDojo Pro** enthalten.

---

## Deinstallieren

```bash
helm uninstall dojopro -n $NAMESPACE
kubectl delete namespace $NAMESPACE
```

> PVCs, externe Datenbanken und externe Secrets werden nicht gelöscht.
> Räumen Sie diese separat auf.

### PersistentVolumes aufräumen

PersistentVolumes mit der Reclaim-Policy `Retain` sind **clusterweit** — sie
werden weder von `helm uninstall` noch vom Löschen des Namespace entfernt. Wenn
Sie DefectDojo in einem anderen Namespace neu installieren, kollidieren die
Besitzmetadaten des verwaisten PV mit der neuen Installation und blockieren
`helm install`.

Prüfen Sie nach der Deinstallation auf verwaiste PVs:

```bash
kubectl get pv | grep dojopro
```

Falls welche übrig sind, löschen Sie sie:

```bash
kubectl delete pv dojopro-media-pv
```

> **Hinweis:** Das Löschen des PV entfernt die Kubernetes-Volume-Referenz, die
> zugrunde liegenden Daten bleiben aber im Speicher-Backend erhalten (z. B. im
> EFS-Dateisystem). Das ist unproblematisch, wenn Sie neu installieren wollen,
> sollte aber bewusst erfolgen.

---

## Lokales Testen mit eingebettetem PostgreSQL und Redis

> **Diese Konfiguration ist ausschließlich für lokale Tests und Evaluierungen
> gedacht. Verwenden Sie eingebettetes PostgreSQL oder Redis nicht in der
> Produktion.** Produktivbereitstellungen sollten verwaltete Dienste (z. B. RDS,
> ElastiCache) nutzen, um Zuverlässigkeit, Backups und Skalierung zu
> gewährleisten. Der DefectDojo-Support deckt Probleme mit eingebetteten
> Datenbanken in Produktionsumgebungen nicht ab.

Das Chart kann für schnelle lokale Tests mit dem Profil `minimal` sein eigenes
PostgreSQL und Redis bereitstellen. Damit entfällt der Bedarf an externer
Datenbank- und Broker-Infrastruktur.

Ergänzen Sie Ihre Values-Datei um Folgendes:

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

> **Wichtig: `postgresql.database.password` ist erforderlich**, wenn
> `postgresql.enabled` auf true steht und `database.existingSecret` nicht gesetzt
> ist. Ohne diesen Wert lässt sich das Chart nicht rendern. Dieses Passwort muss
> mit dem Wert `DD_DATABASE_PASSWORD` in Ihren Anwendungs-Secrets übereinstimmen.

> **Standard-Zugangsdaten des eingebetteten PostgreSQL:** Die Chart-Standardwerte
> für das eingebettete PostgreSQL sind der Benutzername `dojodbusr` und der
> Datenbankname `dojodb` (definiert in der `values.yaml` des Charts). Ihr
> `DD_DATABASE_URL` in den Anwendungs-Secrets muss diese Werte verwenden, nicht
> die Platzhalter für die externe Datenbank aus `secrets-template.yaml`. Zum
> Beispiel:
>
> ```
> DD_DATABASE_URL: "postgresql://dojodbusr:<password>@<release>-postgresql:5432/dojodb"
> ```

Das Profil `minimal` (`dojopro/presets/profiles/minimal.yaml`) setzt reduzierte
Ressourcenanforderungen, die für einen Testcluster mit einem einzigen Knoten
angemessen sind, schaltet diese Datenbank-/Broker-Flags aber nicht um — die
müssen Sie selbst setzen.

> **Hinweis zu Container-Privilegien:** Die Container des eingebetteten
> PostgreSQL und Redis laufen **nicht** als root — PostgreSQL läuft als UID 999
> und Redis als UID 1001. Die einzige Ausnahme ist der **Init-Container** von
> PostgreSQL (`init-chmod-data`), der als root (UID 0) läuft, um vor dem Start des
> Hauptprozesses die Verzeichnisrechte auf dem Datenvolume zu setzen. Das ist ein
> verbreitetes Muster für StatefulSets mit persistentem Speicher. Wenn Ihr Cluster
> einen `restricted` Pod Security Standard oder eine OpenShift-SCC erzwingt, die
> root-Init-Container verbietet, deaktivieren Sie ihn mit
> `postgresql.initContainer.enabled: false` (siehe [Bekannte Probleme](#known-issues-chart-version-2.57.1)).

Wenn Sie eingebettetes PostgreSQL auf EKS verwenden, benötigen Sie außerdem den
EBS-CSI-Treiber (siehe [Voraussetzungen für AWS EKS](#aws-eks-prerequisites)) und
müssen möglicherweise die Speicherstandards anpassen (siehe
[Bekannte Probleme](#known-issues-chart-version-2.57.1)).

Validieren Sie Ihre Values vor der Installation — der minimale Weg erfordert mehr
Overrides und führt eher zu Rendering-Fehlern:

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

Wenn der Befehl ohne Fehler endet, fahren Sie mit `helm install` und denselben
Flags fort.

> **Verwenden Sie `--timeout 30m` bei minimalen Installationen oder frischen
> Datenbanken.** Das eingebettete PostgreSQL hat reduzierte Ressourcen, und der
> Initializer muss auf einer neuen Datenbank alle Datenbankmigrationen von Null an
> ausführen. In Tests dauerte das etwa 23 Minuten und überschritt damit das in den
> Standardbeispielen verwendete `--timeout 15m`. Ein Timeout führt dazu, dass
> `helm install` `INSTALLATION FAILED` meldet, obwohl die Bereitstellung im
> Hintergrund erfolgreich abgeschlossen wird. Mit `--timeout 30m` vermeiden Sie
> diese falsche Fehlermeldung und den daraus resultierenden Release-Status
> `failed`.

---

## Private Registry / Air-Gapped-Umgebungen

Wenn Ihr Cluster nicht aus der Standard-DefectDojo-Registry ziehen kann, spiegeln
Sie die Images in Ihre eigene Registry und konfigurieren das Chart entsprechend.

### Option 1: Globales Registry-Override

Setzen Sie `global.imageRegistry`, um alle Image-Pulls umzuleiten. Das Chart
entfernt die ursprüngliche Registry aus `images.prefix` und stellt Ihre davor:

```yaml
global:
  imageRegistry: "my-registry.example.com"
```

Das betrifft alle Images (django, nginx, celery, connectors, redis usw.).

### Option 2: Overrides pro Image

Für feinere Kontrolle setzen Sie `images.registry` (betrifft die
Haupt-Anwendungsimages) und überschreiben einzelne Images:

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

### Image-Pull-Secrets für private Registries

Wenn Ihre Registry eine Authentifizierung erfordert, erstellen Sie ein
Pull-Secret und referenzieren es:

```yaml
images:
  pullSecrets:
    existingSecrets:
      - "my-registry-pull-secret"
```

Oder lassen Sie das Chart eines aus ausdrücklich angegebenen Zugangsdaten erstellen:

```yaml
images:
  pullSecrets:
    create: true
    registry: "my-registry.example.com"
    # Provide credentials via a Kubernetes docker-registry secret
```

Das Standardverhalten (`extractFromLicense: true`) extrahiert die Zugangsdaten des
GCP-Servicekontos aus der Lizenzdatei, um aus der Registry von DefectDojo zu
ziehen. Deaktivieren Sie dies, wenn Sie Ihre eigene Registry verwenden:

```yaml
images:
  pullSecrets:
    create: true
    extractFromLicense: false
    existingSecrets:
      - "my-registry-pull-secret"
```

---

## Plattform-Annotationen überschreiben

Das Chart fügt auf Basis von `cloudProvider` automatisch plattformspezifische
Annotationen an Ingress und Service ein (z. B. ALB-Annotationen für EKS,
GCE-Annotationen für GKE). Wenn Sie die vollständige Kontrolle über die
Annotationen benötigen — zum Beispiel bei Verwendung eines
nginx-Ingress-Controllers auf EKS anstelle von ALB — setzen Sie
`platformAnnotations.enabled: false` und geben Ihre eigenen an:

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

Wenn `platformAnnotations.enabled` auf `true` steht (der Standard), führt das
Chart die Plattform-Annotationen mit Ihren eigenen zusammen. Bei
Schlüsselkonflikten haben Ihre Annotationen Vorrang, eine Plattform-Annotation
können Sie ohne diesen Schalter jedoch nicht entfernen.

### Größenlimit für Uploads am Ingress

Standardmäßig setzt das Chart `nginx.ingress.kubernetes.io/proxy-body-size: "2400m"`
am Ingress, damit große Uploads von Scan-Ergebnissen und PDF-Berichte den
nginx-Ingress ohne `413 Request Entity Too Large` passieren. Überschreiben Sie es mit:

```yaml
django:
  ingress:
    maxBodySize: "100m"     # set "" to omit the annotation entirely
```

Das gilt immer dann, wenn nginx-ingress der Controller ist — auch für
nginx-ingress, das auf EKS, GKE oder AKS läuft. Andere Controller ignorieren die
Annotation und müssen über ihre eigenen Mechanismen eingestellt werden (Limits der
Body-Inspection in AWS WAF, request-body-limit beim AppGW, `tuningOptions` der
HAProxy-basierten OpenShift Route).

---

## Plattformspezifische Hinweise

### AWS EKS

- Benötigt den AWS Load Balancer Controller für ALB-Ingress
- Benötigt den EFS-CSI-Treiber, wenn EFS-Speicher verwendet wird
- TLS wird am ALB über ACM-Zertifikate terminiert
- Setzen Sie `certificates.ingress.source: "acm"` und geben `acmCertArn` an
- `dojo.secureCookies: true` funktioniert problemlos, da der ALB HTTPS übernimmt

#### EFS-Access-Points

Wenn Ihr EFS-Dateisystem mit einem **Access Point** konfiguriert ist (empfohlen,
um UID/GID-Besitz auf dem Mount zu erzwingen), **müssen** Sie
`storage.efs.accessPointId` in Ihrer Values-Datei setzen. Ohne diesen Wert bindet
das PV den EFS-Root als root-eigen ein, und die DefectDojo-Container (die als
UID 1001 laufen) können keine Media-Unterverzeichnisse erstellen — der Initializer
schlägt dann mit `Permission denied`-Fehlern fehl.

Prüfen Sie Ihre EFS-Access-Points:

```bash
aws efs describe-access-points --file-system-id <your-fs-id> --region <region> \
  --query 'AccessPoints[].{Id:AccessPointId,Path:RootDirectory.Path,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
  --output table
```

Wenn ein Access Point existiert, ergänzen Sie ihn in Ihrer Values-Datei:

```yaml
storage:
  type: "efs"
  efs:
    enabled: true
    fileSystemId: "fs-REPLACE_EFS_ID"
    accessPointId: "fsap-REPLACE_EFS_ACCESS_POINT_ID"
    region: "REPLACE_AWS_REGION"
```

> **Wichtig:** Das Feld `volumeHandle` am PersistentVolume ist nach der Erstellung
> **unveränderlich**. Wenn Sie zunächst ohne Access Point installieren und später
> einen hinzufügen müssen, müssen Sie das bestehende PV und PVC löschen, bevor Sie
> `helm upgrade` ausführen:
>
> ```bash
> kubectl delete pvc defectdojo-media -n $NAMESPACE
> kubectl delete pv dojopro-media-pv
> helm upgrade dojopro $CHART ... (same flags as install)
> ```
>
> Das ist unproblematisch — beim Löschen des PV entfällt nur die
> Kubernetes-Referenz; die Daten im EFS-Dateisystem sind nicht betroffen.

#### StorageClasses auf gehärteten / per GitOps verwalteten Clustern

Zwei Annahmen zu StorageClasses bringen Cluster mit eigener
StorageClass-Benennung oder mit clusterweiten Ressourcen, die außerhalb des
Anwendungs-Charts verwaltet werden, ins Stolpern.

**Dynamisch provisionierte PVCs verwenden auf EKS standardmäßig `gp3`.** Jedes
PVC, das das Chart dynamisch provisioniert — das Volume des eingebetteten Redis
(`redis.enabled: true`) und das Media-Volume bei `storage.type: "pvc"` — löst
seine StorageClass auf den Plattformstandard auf, und der ist auf EKS `gp3`. Wenn
Ihr Cluster keine StorageClass namens `gp3` hat (üblich auf gehärteten Clustern
mit eigener Benennung), bleibt das PVC im Status `Pending` mit dem Ereignis
`storageclass.storage.k8s.io "gp3" not found`, und die Pods starten nie.

Sie können das auf zwei Wegen überschreiben:

- **Global (empfohlen)** — ein Hebel für jedes vom Chart provisionierte PVC:

  ```yaml
  storage:
    defaultStorageClass: "your-ebs-storageclass"   # or "" for the cluster default
  ```

- **Pro Komponente**, wenn Sie unterschiedliche Klassen benötigen:

  ```yaml
  redis:
    redisVolume:
      pvc:
        storageClassName: "your-ebs-storageclass"
  storage:
    pvc:
      storageClassName: "your-ebs-storageclass"    # only for storage.type: "pvc"
  ```

  Die Auflösungsreihenfolge ist: Wert der Komponente → `storage.defaultStorageClass` →
  Plattformstandard (`gp3`). Setzen Sie einen Wert auf `""`, um auf die
  Standard-StorageClass des Clusters zurückzufallen. Das gilt **nicht** für den
  standardmäßigen EFS-Media-Pfad (siehe unten), der keine StorageClass verwendet.

**Das standardmäßige EFS-Media-Volume benötigt keine StorageClass.** Bei
`storage.type: "efs"` bindet das Chart das Media-PV statisch über den
`volumeHandle` des EFS-Dateisystems und eine `claimRef` — PV und PVC verwenden
beide einen leeren `storageClassName`. Die StorageClass `efs-sc` muss **nicht**
existieren, damit das Media-PVC bindet.

Das Chart erstellt nur dann eine clusterweite StorageClass `efs-sc`, wenn Sie sich
ausdrücklich für **dynamische** EFS-Provisionierung mit
`storageClasses.efs.enabled: true` entscheiden (Standard: `false`). Auf Clustern,
auf denen clusterweite Ressourcen außerhalb des Anwendungs-Charts verwaltet werden
(GitOps), belassen Sie es beim Standard `false` — der oben beschriebene statische
EFS-Pfad benötigt keine StorageClass und keine clusterweiten Objekte aus diesem
Chart. Wenn Sie dynamische EFS-Provisionierung unter GitOps dennoch wünschen,
erstellen Sie die StorageClass außerhalb des Charts und lassen
`storageClasses.efs.enabled: false`.

### GCP GKE

- Verwendet den GCE-Ingress-Controller (`className: "gce"`), wobei TLS am
  Google-Cloud-Load-Balancer terminiert wird
- Das Preset `gcp-gke.yaml` hängt automatisch eine `FrontendConfig`
  (HTTP→HTTPS-Weiterleitung + SSL-Policy) und eine `BackendConfig` an den Ingress
- Der GCE-Load-Balancer prüft das django-Backend direkt aus Googles Bereichen
  (`130.211.0.0/22`, `35.191.0.0/16`). Die NetworkPolicies des Charts erlauben
  diese auf GKE automatisch unter beiden Werten von `networkPolicy.profile`,
  sodass die Probe `/nginx_health` erfolgreich ist und das Backend als gesund
  gemeldet wird — siehe [Network Policies](#network-policies)

#### Von Google verwaltet vs. BYO-TLS

Das Preset `gcp-gke.yaml` verwendet standardmäßig **von Google verwaltete
Zertifikate**. Wählen Sie einen der beiden Ansätze:

- **Von Google verwaltet (Standard):** GCP stellt das Zertifikat bereit und
  erneuert es. Sie listen lediglich Ihre Domains auf — ein Kubernetes-TLS-Secret
  ist nicht nötig:

  ```yaml
  certificates:
    ingress:
      source: "google-managed"
      googleManaged:
        domains:
          - defectdojo.example.com
  ```

- **Eigenes Zertifikat (BYO):** Stellen Sie ein vorhandenes
  Kubernetes-TLS-Secret im Release-Namespace bereit und richten den Ingress darauf:

  ```yaml
  certificates:
    ingress:
      source: "secret"
      secretName: wildcard-example-com   # kubectl create secret tls ...
  ```

  Damit wird `spec.tls[].secretName` am Ingress gerendert und die Annotation
  `networking.gke.io/managed-certificates` weggelassen.

> **Unterstützung durch das Bootstrap-Skript:**
> `scripts/bootstrap/bootstrap-gcp-gke.sh` deckt nur die GCP-eigenen
> Zertifikatswege ab (`google-managed` und `pre-shared`). Für den BYO-Weg über
> `secret` installieren Sie direkt mit `helm` (erstellen Sie zuerst das
> TLS-Secret, übergeben Sie dann `certificates.ingress.source=secret` und
> `certificates.ingress.secretName=<your-secret>`).

> Die Erneuerung von Google-verwalteten Zertifikaten erfolgt automatisch — siehe
> [TLS-Zertifikate rotieren](#rotating-tls-certificates).

### OpenShift / ROSA

- Verwendet standardmäßig Routes (`django.route.enabled: true`), Ingress wird aber ebenfalls unterstützt
- Um stattdessen Ingress zu verwenden: setzen Sie `django.ingress.enabled: true` und `django.route.enabled: false`
- Es kann jeweils nur eines aktiviert sein (das Chart prüft die gegenseitige Ausschließlichkeit)
- **`dojo.secureCookies` muss `false` sein**, wenn Routes mit Edge-Terminierung verwendet werden (der Standard).
  Das ist erforderlich — nicht optional. Siehe die [Warnung unter „Values-Datei vorbereiten“](#prepare-your-values-file).
- `securityContext.openshift.fsGroup` muss zum supplemental-groups-Bereich Ihres Namespace passen
  (wie Sie ihn ermitteln, steht in der [Checkliste vor der Installation](#infrastructure-details))
- NFS über EFS funktioniert gut — verwenden Sie `storage.type: "nfs"` mit dem EFS-DNS-Namen als Server

#### Ingress statt Routes unter OpenShift verwenden

OpenShift bringt einen standardmäßigen, HAProxy-basierten Ingress-Controller mit.
Wenn Sie Ingress gegenüber Routes bevorzugen (z. B. aus Konsistenzgründen mit
anderen Clustern oder um einen eigenen Ingress-Controller zu nutzen),
konfigurieren Sie Ihre Values so:

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

Die Plattform-Helper des Charts behandeln Security-Contexts, DNS-Resolver und
Speicherstandards für OpenShift weiterhin korrekt, unabhängig davon, welche
Expositionsmethode Sie wählen.

---

## Bekannte Probleme (Chart-Version 2.57.1)

Dies sind bestätigte Fehler im aktuellen Chart. Die Workarounds sind hier
dokumentiert, bis eine korrigierte Version veröffentlicht wird.

### Minimale Installation nur mit lokalem PostgreSQL oder Redis

Die folgenden Probleme treten nur auf, wenn Sie das im Chart enthaltene
PostgreSQL oder Redis verwenden (`postgresql.enabled: true` oder
`broker.external: false`). Produktivbereitstellungen mit externen Datenbanken und
Brokern sind nicht betroffen.

**Verwenden Sie EBS nicht für das Media-Volume (BUG-14, BUG-15)**

EBS-Volumes unterstützen nur `ReadWriteOnce` — sie können jeweils nur an einen
Knoten angebunden werden. DefectDojo benötigt das Media-Volume gemeinsam für
mehrere Pods (django, celery-worker, initializer, connectors), die auf
unterschiedlichen Knoten eingeplant werden können. Tritt das ein, bleiben Pods mit
einem `Multi-Attach error` im Status `ContainerCreating` hängen, weil EBS das
Volume nicht gleichzeitig auf mehr als einem Knoten einbinden kann. Das betrifft
auch `helm test`, bei dem der test-storage-Pod auf einem anderen Knoten als die
Anwendungs-Pods eingeplant werden kann.

**Verwenden Sie EFS (oder ein anderes `ReadWriteMany`-fähiges Speicher-Backend)
anstelle von EBS für das Media-Volume.** EFS unterstützt den gleichzeitigen
Zugriff von allen Knoten des Clusters und ist das empfohlene Speicher-Backend für
EKS-Bereitstellungen.

Wenn Sie für Tests auf einem Single-Node-Cluster unbedingt EBS verwenden müssen,
überschreiben Sie die Standardwerte:

```yaml
storage:
  pvc:
    accessMode: "ReadWriteOnce"
    selector: null
    storageClassName: "gp3"
```

Beachten Sie, dass EBS auch mit diesem Override sofort ausfällt, sobald Pods über
mehrere Knoten verteilt eingeplant werden (z. B. beim Skalieren, beim Austausch
eines Knotens oder bei `helm test`). EFS vermeidet das vollständig.

**Der PostgreSQL-Init-Container kollidiert mit einem Non-root-Security-Context (BUG-16)**

Deaktivieren Sie ihn, wenn Sie auf `CreateContainerConfigError` stoßen:

```yaml
postgresql:
  initContainer:
    enabled: false
```

### Alle Bereitstellungen

**Der Connectors-Pod läuft in einen Crashloop, während der Initializer läuft (erwartetes Verhalten)**

Während der ersten Installation geht der Connectors-Pod in `CrashLoopBackOff`,
während der Initializer-Job die Datenbankmigrationen ausführt. Das ist zu
erwarten — der Connectors-Pod versucht, die Django-API
(`/api/connectors/v1/config/`) aufzurufen, die einen 500er zurückgibt, weil das
Datenbankschema noch nicht vollständig migriert ist. Sobald der Initializer-Job
erfolgreich abgeschlossen ist (`1/1 COMPLETIONS` in `kubectl get jobs`), erholt
sich der Connectors-Pod beim nächsten Neustartzyklus. Ein manuelles Eingreifen ist
nicht erforderlich.

**Ein Absturz des Initializers nach den Migrationen hinterlässt einen nicht wiederherstellbaren Datenbankzustand (BUG-18)**

Wenn der Initializer-Job **nach** dem Ausführen der Datenbankmigrationen, aber
**vor** dem Einspielen der Initialdaten abstürzt (z. B. wegen
Speicherberechtigungsfehlern oder Ressourcenlimits), bleibt die Datenbank in einem
teilweise initialisierten Zustand zurück — die Tabellen existieren, aber die
Tabelle `dojo_system_settings` ist leer. Bei nachfolgenden Neustarts schlägt der
Initializer sofort fehl mit:

```
CommandError: Failed to read system settings from database: 'NoneType' object is not iterable
```

Daraus entsteht ein Crashloop ohne automatische Erholung. **Workaround:** Setzen
Sie das Datenbankschema zurück und führen den Initializer erneut aus:

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

> **Vorbeugung:** Stellen Sie sicher, dass Speicherberechtigungen (insbesondere
> bei EFS-Access-Points — siehe [EFS-Access-Points](#efs-access-points)) und
> Ressourcenlimits **vor** der ersten Installation korrekt konfiguriert sind.
> Führen Sie `helm template` aus, um Ihre Values zu validieren, und prüfen Sie die
> EFS-Mount-Berechtigungen wenn möglich mit einem Test-Pod.

**Hatchet-Token-Warnung in den Logs (informativ)**

Wenn `hatchet.enabled: false` gesetzt ist (der Standard), protokollieren die Pods
beim Start die folgende Warnung:

```
Could not create Hatchet handle; all future Hatchet invocations will fail.
Error: ... Token must be set
```

Das ist **erwartet und harmlos**. Seit Chart 2.57 wurde die Ausführung von
Hintergrund-Workflows in `ddorch` + `ddorch-workers` zusammengeführt, die die
früheren Hatchet-basierten Worker (`kairos`, `rulesengine`,
`hatchet-integrators`) ersetzen. Der Hatchet-Client-Code wird beim Start weiterhin
initialisiert, sodass die Warnung bei deaktiviertem Hatchet noch erscheint, es
hängt aber nichts davon ab. Die Warnung kann gefahrlos ignoriert werden.

### HTTPS nicht konfiguriert

**Die ALB-Annotation ssl-redirect setzt einen HTTPS-Listener voraus (BUG-17)**

Das EKS-Preset enthält eine `ssl-redirect`-Annotation, die davon ausgeht, dass am
ALB ein HTTPS-Listener existiert. Wenn Sie kein ACM-Zertifikat und keinen
HTTPS-Listener konfiguriert haben, führt diese Annotation zu einer
Redirect-Schleife. Konfigurieren Sie entweder HTTPS (empfohlen) oder sehen Sie
sich unter
[Bereitstellung ohne HTTPS (nicht empfohlen)](#deploying-without-https-not-recommended)
alle dafür erforderlichen Änderungen an.

---

## Fehlersuche

### Pods hängen in CrashLoopBackOff

Logs prüfen:
```bash
kubectl logs -n $NAMESPACE <pod-name> --previous
```

In der Regel liegt eines davon vor: fehlende oder falsche Secrets (prüfen Sie alle
12 Schlüssel), die Datenbank ist nicht erreichbar (prüfen Sie `database.host` und
die Security Groups) oder das interne TLS-Zertifikat fehlt (prüfen Sie, ob das
Secret `dojopro-internal-tls` existiert).

### Externe und Inline-Secrets vermischt

```
dojo.existingSecret is set to 'X', but the following inline secret values are also provided: [...]
```

Entscheiden Sie sich für einen Ansatz. Wenn Sie `dojo.existingSecret` verwenden,
entfernen Sie alle Inline-Secret-Werte (`dojo.secretKey`, `dojo.admin.password`,
`monitoring.password` usw.) aus Ihren Values-Dateien.

### Das Schema verlangt admin.password

Setzen Sie `dojo.existingSecret` — das Schema lässt die Passwortanforderung
entfallen, wenn ein externes Secret konfiguriert ist.

### fsGroup-Berechtigungsfehler unter OpenShift

Wenn Pods mit Berechtigungsfehlern auf NFS-Volumes fehlschlagen, prüfen Sie, ob
`securityContext.openshift.fsGroup` innerhalb des supplemental-groups-Bereichs
Ihres Namespace liegt. Siehe die fsGroup-Ermittlung unter
[Bereitstellen → OpenShift / ROSA](#openshift-rosa).

### Der ALB erscheint nicht (EKS)

Prüfen Sie, ob der AWS Load Balancer Controller läuft:
```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

Ingress-Ereignisse prüfen:
```bash
kubectl describe ingress -n $NAMESPACE
```

---

## Anhang: Konfigurationsvorlage für Kunden

Die vollständige Vorlage (`template.yaml`) erhalten Sie über das
DefectDojo-Support-Portal oder per Anfrage an support@defectdojo.com. Kopieren Sie
sie, ersetzen Sie die `REPLACE_*`-Platzhalter und entfernen Sie Abschnitte, die
für Ihre Plattform nicht zutreffen. Die Vorlage enthält kommentierte Beispiele für:

- Plattformkennung (`cloudProvider`)
- Konfiguration des Image-Pull-Secrets
- Ingress- und Route-Konfiguration (Ingress für EKS/GKE/OpenShift, Route für OpenShift)
- Speicheroptionen für EFS und NFS
- Zertifikats- und TLS-Konfiguration
- Security-Contexts (uwsgi, nginx, OpenShift-fsGroup)
- Network Policies
- Optionen zur Lizenzübergabe (Datei, Secret, inline)

---

## Änderungshistorie

| Datum      | Version | Änderungen                                                           |
|------------|---------|----------------------------------------------------------------------|
| 2026-07-09 | 3.1.0   | Optionale PSIRT Advisory Engine ergänzt (`psirt.enabled`): bereitgestellt unter `/psirt/` über den nginx-Sidecar, eigene Datenbank über `psirt.databaseUrl`, Hinweise zum Festlegen der Secrets, Network-Policy-Regeln, BYO-Hooks |
| 2026-04-17 | 2.57.1  | `ddorch` + `ddorch-workers` dokumentiert (neues Orchestrator-Paar, das kairos/rulesengine/hatchet-integrators ersetzt); `--set-file`-Flags `ddorch.tls.rootCa/cert/key` in den Pre-flight- und Deploy-Befehlen ergänzt; neuer Abschnitt zu ddorch-mTLS-Zertifikaten mit SAN-Anforderungen; mcp-server in den erwarteten Pods aufgeführt; PDBs für ddorch (Singleton) und ddorch-workers ergänzt; Hinweis zu den ArgoCD-Voraussetzungen bezüglich der Übergabe der ddorch-Zertifikate; Hatchet-Warnung an die Worker-Konsolidierung angepasst |
| 2026-03-25 | 2.55.4  | Dokumentation zu EFS-Access-Points und Vorlagenfeld ergänzt; Wiederherstellung nach Initializer-Absturz dokumentiert (BUG-18); Connectors-Crashloop während der Initialisierung als erwartet dokumentiert; klargestellt, dass die Hatchet-Token-Warnung harmlos ist; veralteten Anker bei den bekannten Problemen korrigiert; versionierter Entpackungspfad für das Chart; Hinweise zum Betrieb ohne HTTPS zusammengeführt; PV-Aufräumen beim Deinstallieren; Hinweis zur Konsistenz des Namespace; Kasten zur Preset-Versionierung bei ArgoCD vs. CLI |
| 2026-03-11 | 2.53.0  | Pfade in den helm-Befehlen korrigiert; Chart-Entpacken, EKS-Voraussetzungen, Pre-flight-DB-Prüfung, HTTPS-Hinweis, TLS-Rotation und Abschnitt zu bekannten Problemen ergänzt |
