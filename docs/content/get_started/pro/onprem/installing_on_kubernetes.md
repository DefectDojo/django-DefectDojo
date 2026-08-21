---
title: "DefectDojo Pro Installation Guide"
description: "Install DefectDojo Pro on Kubernetes using the Helm chart, covering infrastructure, secrets, and the install itself"
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
Covers deployment on AWS EKS and OpenShift (ROSA). The workflow is the same
for both: set up infrastructure, create secrets, install the chart.

---

## Pre-Install Checklist

Gather the following information before starting. Having these ready avoids
delays during the install process.

### Infrastructure Details

| Item | Example | Where to find it |
|------|---------|-------------------|
| **PostgreSQL host** | `mydb.abc123.us-east-1.rds.amazonaws.com` | AWS RDS console or `aws rds describe-db-instances` |
| **PostgreSQL port** | `5432` | Usually 5432 unless customized |
| **PostgreSQL database name** | `dojodb` | Your DBA or Terraform/CloudFormation outputs — must be created before install (see note below) |
| **Orchestrator database** | `dojodb-ddorch` | Either grant the app role `CREATEDB` or pre-create `<dbname>-ddorch` — see [Pre-flight: Orchestrator (ddorch) Database](#pre-flight-orchestrator-ddorch-database) |
| **PostgreSQL username** | `defectdojo` | `aws rds describe-db-instances --query 'DBInstances[].MasterUsername'` |
| **PostgreSQL password** | — | AWS Secrets Manager, Terraform state, or your DBA |
| **Redis/ElastiCache endpoint** | `my-redis.abc123.use1.cache.amazonaws.com` | `aws elasticache describe-cache-clusters --show-cache-node-info` |
| **Redis password** | — | Omit if auth is disabled (VPC-only). Check: `aws elasticache describe-replication-groups --query 'ReplicationGroups[].AuthTokenEnabled'` |
| **EFS filesystem ID** | `fs-0abc123def456` | `aws efs describe-file-systems --region <region>` |
| **EFS access point ID** (if applicable) | `fsap-0abc123def456` | `aws efs describe-access-points --file-system-id <fs-id>` |
| **EFS access point UID/GID** | UID `1001`, GID `1337` | Must match the container security context (see note below) |
| **Domain name (FQDN)** | `dojo.example.com` | Your DNS administrator (see platform-specific notes below) |
| **ACM certificate ARN** (EKS with HTTPS) | `arn:aws:acm:...` | `aws acm list-certificates --region <region>` |
| **OpenShift apps domain** (ROSA only) | `apps.abc123.p1.openshiftapps.com` | `oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'` |
| **OpenShift namespace fsGroup** (ROSA only) | `1001070000` | `oc get namespace <ns> -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'` — use the start value |
| **License file** | `onprem-dojopro.lic` | Provided by DefectDojo support |

> **Create the databases before installing.** The chart does not create
> databases on an external PostgreSQL server. Create both of the following on
> your database server, owned by the application user, before running
> `helm install`:
>
> - `dojodb` — the main DefectDojo database
> - `dojodb-ddorch` — the orchestrator (ddorch) database, always named after
>   the main database with a `-ddorch` suffix. Alternatively, grant the
>   application role `CREATEDB` and ddorch creates this one itself on first
>   start.
>
> See [Pre-flight: Verify Database Connectivity](#pre-flight-verify-database-connectivity)
> and [Pre-flight: Orchestrator (ddorch) Database](#pre-flight-orchestrator-ddorch-database)
> for ready-to-run `CREATE DATABASE` commands.

> **EFS access point UID/GID:** If your EFS filesystem uses an access point,
> its POSIX user configuration **must** use UID `1001` and GID `1337` to match
> the DefectDojo container security context. A mismatch causes `Permission
> denied` errors during initialization when the containers attempt to create
> media subdirectories. Verify with:
>
> ```bash
> aws efs describe-access-points --file-system-id <fs-id> --region <region> \
>   --query 'AccessPoints[].{Id:AccessPointId,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
>   --output table
> ```

> **OpenShift/ROSA FQDN:** On ROSA, Routes auto-generate hostnames using the
> pattern `<release-name>-<namespace>.apps.<cluster-domain>`. For example, if
> your release is `dojopro` in namespace `dojopro`, the Route hostname will be
> `dojopro-dojopro.apps.abc123.p1.openshiftapps.com`. Determine your cluster's
> apps domain with:
>
> ```bash
> oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
> ```
>
> Use the resulting FQDN for `dojo.fqdn`, `dojo.url`, and `dojo.hosts.main`.

> **OpenShift/ROSA fsGroup:** You will need your namespace's supplemental-groups
> start value for `securityContext.openshift.fsGroup`. Look this up now to avoid
> having to edit your values file later:
>
> ```bash
> oc get namespace <your-namespace> \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Output example: 1001070000/10000 — use 1001070000 as fsGroup
> ```

### Secrets to Generate

The following secrets must be generated fresh for your deployment. Use the
commands shown to create cryptographically random values:

| Secret | Key in K8s Secret | Generate with |
|--------|-------------------|---------------|
| Django secret key | `DD_SECRET_KEY` | `openssl rand -hex 25` |
| AES-256 encryption key | `DD_CREDENTIAL_AES_256_KEY` | `openssl rand -hex 16` |
| Cloud portal secret | `CLOUD_PORTAL_SECRET_KEY` | `openssl rand -hex 25` |
| Connectors shared secret | `DD_CONNECTORS_SHARED_SECRET` | Use same value as `CLOUD_PORTAL_SECRET_KEY` |
| Admin password | `DD_ADMIN_PASSWORD` | `openssl rand -base64 16` |
| Metrics password | `METRICS_HTTP_AUTH_PASSWORD` | `openssl rand -hex 16` |

### Secrets from Your Infrastructure

These come from your existing infrastructure — do not generate them:

| Secret | Key in K8s Secret | Source |
|--------|-------------------|--------|
| Database password | `DD_DATABASE_PASSWORD` | Your PostgreSQL password |
| Database connection URL | `DD_DATABASE_URL` | `postgresql://<user>:<password>@<host>:<port>/<dbname>` |
| Redis password | `redis-password` (in separate `dojopro-redis` secret) | Your Redis password, or skip if no auth |
| Email service URL | `DD_EMAIL_URL` | `consolemail://` for testing, or your SMTP URL |

### Optional (leave empty to disable)

| Secret | Key in K8s Secret | Purpose |
|--------|-------------------|---------|
| EPSS bucket key | `DD_PRO_ENHANCEMENTS_EPSS_BUCKET_KEY` | EPSS score enrichment |

> **Tip:** Copy `secrets-template.yaml` and fill in the values above. See
> [Generate Secrets](#generate-secrets) for detailed instructions on creating
> the Kubernetes Secret.

---

## Prerequisites

```bash
# Required tools
brew install awscli helm kubectl jq openssl eksctl

# Verify AWS access
aws sts get-caller-identity
```

For OpenShift/ROSA, also install:
```bash
brew install rosa openshift-cli
```

### Outbound Connectivity Requirements

In restricted network environments, the following outbound connections must be
permitted before installation. Firewall rules may require advance change
requests — verify these are in place before proceeding.

**Container Registry (Required)**

All cluster nodes must reach the DefectDojo container registry on port 443:

```
host us-south1-docker.pkg.dev
# us-south1-docker.pkg.dev is an alias for googlecode.l.googleusercontent.com
```

> For air-gapped environments, see
> [Private Registry / Air-Gapped Environments](#private-registry-air-gapped-environments).

**Database (Required)**

Cluster nodes to your PostgreSQL instance, typically port 5432.

- RDS in the same VPC: ensure the EKS node security group is allowed inbound
  on port 5432
- RDS in a different VPC or account: VPC peering or Transit Gateway required
- External/on-premises: VPN or Direct Connect path must permit port 5432

**EPSS Updates (Recommended)**

```
host api.first.org
# api.first.org has address 151.101.1.91
# api.first.org has address 151.101.193.91
# api.first.org has address 151.101.129.91
# api.first.org has address 151.101.65.91
# Port 443
```

**KEV Feed (Recommended)**

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

host www.cisa.gov
# www.cisa.gov is an alias for www.cisa.gov.edgekey.net (Akamai CDN — IPs vary)
# Port 443
```

**AWS Services (EKS only, Required)**

The EBS CSI driver and ALB Controller require access to AWS API endpoints on
port 443:

- `sts.amazonaws.com`
- `ec2.amazonaws.com`
- `elasticloadbalancing.amazonaws.com`
- `elasticfilesystem.amazonaws.com` (if using EFS)

### AWS EKS Prerequisites

The following components must be installed in your EKS cluster before deploying
DefectDojo Pro. The deployment will fail without them.

**EBS CSI Driver** (only required when using the minimal profile with embedded
PostgreSQL and Redis — not needed if you are using external RDS and ElastiCache):

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

**EFS CSI Driver** (required when using EFS storage — the recommended storage
backend for multi-replica EKS deployments):

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

**AWS Load Balancer Controller** (required for ALB ingress):

Installation instructions vary by EKS version. Follow the
[official AWS Load Balancer Controller installation guide](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/deploy/installation/).

---

## Extract the Chart Package

The chart ships as a zip containing a `.tgz` Helm package. Extract both before
proceeding. Use a versioned extraction path to avoid silently overwriting
presets when you extract a newer chart version later:

```bash
unzip helm-chart-<version>.zip -d /tmp/dojopro-extract
cd /tmp/dojopro-extract
mkdir -p dojopro-<version>
tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
```

Set a `CHART` variable pointing to the extracted chart directory. All
subsequent `helm` commands in this guide use `$CHART`:

```bash
CHART="dojopro-<version>/dojopro"
# e.g. CHART="dojopro-2.55.4/dojopro"
```

> **Why extraction is required for CLI users:** The preset files
> (`presets/platforms/*.yaml`, `presets/profiles/*.yaml`) are bundled inside the
> `.tgz` package. `helm install -f` requires files on the local filesystem — it
> cannot read files from inside a packaged `.tgz`. You must extract the chart
> to access the presets.
>
> **ArgoCD users do not need to extract.** ArgoCD reads `valueFiles` directly
> from inside the chart package. See [Deploy with ArgoCD](#deploy-with-argocd).

---

## Prepare Your Values File

The customer configuration template (`template.yaml`) and secrets template
(`secrets-template.yaml`) are available separately from the DefectDojo support
portal, or from support@defectdojo.com. They are not included in the chart
`.tgz`. Once you have the template, copy it and fill in your details:

```bash
cp template.yaml my-company.yaml
```

At minimum, set:

| Setting | Description |
|---------|-------------|
| `dojo.fqdn` | Your domain name (ROSA: see [FQDN note](#infrastructure-details) above) |
| `dojo.url` | Full URL including protocol (e.g., `https://dojo.example.com`) |
| `dojo.hosts.main` | Must match your FQDN |
| `dojo.secureCookies` | Set `false` on **OpenShift/ROSA** (see warning below) |
| `dojo.admin.*` | `user`, `email`, `firstName`, `lastName` — admin account |
| `database.host`, `.port`, `.name`, `.user` | PostgreSQL connection details (password goes in secrets) |
| `celery.broker.host` | Your Redis/ElastiCache endpoint |
| `redis.enabled` | **Must be `false`** when using external Redis (see warning below) |
| `storage.type` | Storage backend — see platform-specific notes |
| `certificates.*` | TLS certificate configuration |
| `django.ingress.*` or `django.route.*` | Ingress (EKS) or Route (OpenShift) — preset sets defaults |
| `securityContext.openshift.fsGroup` | **ROSA only** — namespace supplemental-groups start value |

> **WARNING — `redis.enabled` must be explicitly set to `false` when using
> external Redis/ElastiCache.** The `standard` and `performance` profile presets
> set `redis.enabled: true` by default. If your values file does not override
> this, the chart will deploy an in-cluster Redis **alongside** your external
> broker, resulting in a broken configuration. Add this to your values file:
>
> ```yaml
> redis:
>   enabled: false
> ```

> **WARNING — `dojo.secureCookies` must be `false` on OpenShift/ROSA.** When
> using OpenShift Routes with edge TLS termination, `secureCookies: true`
> (the default in `template.yaml`) causes redirect loops and broken login.
> This is not optional — edge-terminated Routes require:
>
> ```yaml
> dojo:
>   secureCookies: false
> ```

**Storage notes:**
- **EKS:** Use EFS — not EBS. EBS volumes cannot be shared across nodes, causing
  `Multi-Attach` errors. See [Known Issues](#known-issues-chart-version-2.57.1).
  If your EFS uses an access point, also set `storage.efs.accessPointId` —
  see [EFS Access Points](#efs-access-points).
- **OpenShift/ROSA:** The platform preset defaults to `storage.type: "pvc"` with
  `createNew: true`, which uses the cluster's default StorageClass. For
  multi-node deployments, use NFS via EFS (`storage.type: "nfs"`).

Optionally, set log verbosity:
- `config.logLevel` — Django application log level (default: `"INFO"`)
- `celery.logLevel` — Celery worker/beat log level (default: `"INFO"`)

Set either to `"DEBUG"` for troubleshooting. See [Log Verbosity](#log-verbosity)
for how to toggle this at runtime without editing your values file.

Don't put secrets or license content in this file. Those are handled in the
next two sections.

See `template.yaml` for the full list of options.

### Pre-flight: Verify Database Connectivity

Confirm your database is reachable before proceeding — it will save significant
troubleshooting time later. Spin up a temporary pod with `psql`:

```bash
kubectl run psql-test --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -d dojodb -U defectdojo \
     -c "SELECT version();"
```

A successful connection looks like:

```
                                                version
--------------------------------------------------------------------------------------------------------
 PostgreSQL 16.x on x86_64-pc-linux-gnu, compiled by gcc ...
(1 row)

pod "psql-test" deleted
```

If this fails with `database "dojodb" does not exist`, your RDS instance is
reachable but the database has not been created yet. Create it:

```bash
kubectl run psql-create-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c "CREATE DATABASE dojodb OWNER <your-db-user>;"
```

Then re-run the connectivity check above to confirm.

If it fails for other reasons, check:
- **Security group / firewall rules** — port 5432 must be open from the cluster
  to the database host
- **Database user privileges** — the user must have CREATE, ALTER, and SELECT
  permissions on the target database, plus either `CREATEDB` or a pre-created
  orchestrator database (see the next section)

> The chart also includes built-in checks: an init container that waits for TCP
> connectivity to the database, and `helm test` that validates a full PostgreSQL
> connection after deployment. This pre-flight step catches problems before you
> invest time creating secrets and running `helm install`.

### Pre-flight: Orchestrator (ddorch) Database

The orchestrator (`ddorch`, enabled by default) stores its workflow state in a
**second database** alongside the main DefectDojo database. At startup it takes
the database name from `DD_DATABASE_URL`, appends `-ddorch`, and creates that
database if it does not exist — main database `dojodb` means the
orchestrator uses `dojodb-ddorch`.

If the application role is not allowed to create databases, the ddorch pod
fails at startup with:

```
ERROR: permission denied to create database (SQLSTATE 42501)
```

Satisfy **one** of the following before installing:

**Option A — grant `CREATEDB` to the application role** and let ddorch create
its database on first start:

```sql
ALTER ROLE defectdojo CREATEDB;
```

**Option B — pre-create the orchestrator database**, named after your main
database with a `-ddorch` suffix and owned by the same application user. The
hyphen in the name requires double quotes in SQL:

```sql
CREATE DATABASE "dojodb-ddorch" OWNER defectdojo;
```

Using the same temporary-pod approach as the connectivity check above:

```bash
kubectl run psql-create-ddorch-db --rm -i --restart=Never \
  --image=postgres:16 \
  -n $NAMESPACE \
  --env="PGPASSWORD=<your-db-password>" \
  -- psql -h <your-db-host> -p 5432 -U <your-db-user> -d postgres \
     -c 'CREATE DATABASE "dojodb-ddorch" OWNER <your-db-user>;'
```

---

## Generate Secrets

Two options here.

### Option A: External Secret (recommended for GitOps)

Create a Kubernetes Secret with the 12 required keys before installing the chart.
Use the `secrets-template.yaml` provided by DefectDojo support as a starting
point (see [Prepare Your Values File](#prepare-your-values-file) for how to
obtain it):

```bash
cp secrets-template.yaml /tmp/dojopro-secrets.yaml
```

Edit the file, replace all placeholder values, then apply:
```bash
kubectl apply -f /tmp/dojopro-secrets.yaml -n <your-namespace>
```

The secret can also be managed by External Secrets Operator, Sealed Secrets, or
any other tool that creates Kubernetes Secrets. The chart doesn't care how the
secret got there — just set `dojo.existingSecret` to its name.

At install time:
```bash
--set dojo.existingSecret=dojopro-secrets
```

The chart automatically skips rendering its built-in Secret when
`dojo.existingSecret` is set — no additional flags needed.

If your external Redis requires authentication, the `secrets-template.yaml` also
includes a separate `dojopro-redis` Secret. The chart reads Redis credentials from
`redis.auth.existingSecret` (default: `dojopro-redis`). If your Redis has no
password (e.g., VPC-only ElastiCache), you can skip it.

### Option B: Inline Secrets (simpler, not GitOps-friendly)

Pass secret values directly in a values file:

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

Save this as `my-secrets.yaml` and pass it with `-f` at install time.

> Do not commit secrets files to version control.

---

## Create Internal TLS Certificates

The chart needs internal TLS certs for service-to-service communication.

Create two Kubernetes TLS secrets in your namespace before installing:

1. `dojopro-internal-tls` — a TLS secret with `tls.crt` and `tls.key` for
   service-to-service encryption (nginx ↔ connectors, etc.)
2. `dojopro-internal-ca` — a secret containing the CA certificate under the
   key `ca.crt`, used by connectors to validate the internal TLS cert

You can generate a self-signed CA and server certificate with `openssl`, or
use your organization's internal CA. The server cert's CN/SAN **must** cover
the internal nginx service name used by the Helm release. By default, this is
`<release-name>-nginx` (e.g., `dojopro-nginx` if your release is named
`dojopro`).

Example generating a self-signed CA and server certificate:
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

> **Common mistake:** Using `nginx-internal` as the CN/SAN instead of
> `<release-name>-nginx`. The connectors pod validates the TLS certificate
> against the actual service name (`<release-name>-nginx.<namespace>.svc.cluster.local`),
> and will fail with an `x509: certificate is valid for ... not ...` error if
> the SAN does not match.

Then set in your values file:
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

### ddorch mTLS Certificates

In addition to the internal TLS secrets above, the `ddorch` orchestrator
requires a separate mTLS cert trio consumed by the ddorch server and every
worker that talks to it (`ddorch-workers`, `integrators`). These are
delivered to the chart at install time via `--set-file` (they are **not**
read from a pre-existing Kubernetes secret):

- `orch_tls_root.ca` — CA certificate
- `orch_tls.crt` — server certificate
- `orch_tls.key` — server private key

Without these three files, `helm install` fails with
`ddorch.tls.rootCa is required`.

The server certificate's SAN **must** include all hostnames the workers use
to reach ddorch:

- `ddorch` — in-cluster service short name
- `<release-name>-ddorch` — fully-qualified service name (e.g. `dojopro-ddorch`)
- `<release-name>-ddorch.<namespace>.svc.cluster.local` — cluster FQDN
- `nginx` — the default `SERVER_TLS_SERVER_NAME` used by hatchet-style workers
- `localhost`, `127.0.0.1` — same-pod workers reaching ddorch over the hostAlias loopback

Example generating the trio:

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

Pass them to `helm install` / `helm template`:

```bash
--set-file ddorch.tls.rootCa=orch_ca.crt \
--set-file ddorch.tls.cert=orch_server.crt \
--set-file ddorch.tls.key=orch_server.key
```

> The `scripts/bootstrap-aws-eks.sh` helper generates and reuses these
> automatically via the `dojopro-orch-certs-configmap` — if you are using
> that script you do not need to create them manually.

---

## License

The chart needs a DefectDojo Pro license.

### Inspecting Your License

Before deploying, verify your license is valid and has not expired:

```bash
sed -n '/^[[:space:]]*ey/,/-----END/p' license.lic \
  | sed '$d' | tr -d ' ' | base64 -d | jq .
```

This displays the license metadata including:
- `not_after` — license expiry date
- `license_package` — confirms your tier

> **Image pull secrets:** When `images.pullSecrets.extractFromLicense: true`
> is set (the default in platform presets), the chart automatically extracts
> the embedded GCP service account from your license file and creates the image
> pull secret needed to pull DefectDojo images from the container registry. No
> manual extraction or decoding is required. If you are using a private registry
> instead, set `extractFromLicense: false` and provide your own pull secret —
> see [Private Registry / Air-Gapped Environments](#private-registry-air-gapped-environments).

### Option 1: --set-file (standard Helm install)

Pass the license file at install time:
```bash
--set-file license.contents=/path/to/license.lic
```

### Option 2: Existing Secret (GitOps / ArgoCD)

Create a Kubernetes Secret containing the license, then tell the chart to use it.
This avoids needing `--set-file` or storing the license in git.

```bash
kubectl create secret generic dojopro-license \
  --namespace $NAMESPACE \
  --from-file=dojopro.lic=/path/to/license.lic
```

Then in your values file or helm flags:
```yaml
license:
  existingSecret: "dojopro-license"
```

The secret can be managed by External Secrets Operator, Sealed Secrets, or plain kubectl.

> **Important:** `license.existingSecret` is **not compatible** with the
> default `images.pullSecrets.extractFromLicense: true` setting. The chart
> needs the license content available at render time to extract the embedded
> container registry credentials. If you use `license.existingSecret`, you
> must also disable automatic pull secret extraction and provide your own:
>
> ```yaml
> images:
>   pullSecrets:
>     extractFromLicense: false
>     existingSecrets:
>       - "my-registry-pull-secret"
> ```
>
> If you want the chart to auto-extract pull secrets from the license (the
> default), use **Option 1** (`--set-file license.contents=`) instead.


---

## FIPS 140-3 Mode (optional)

For environments subject to FedRAMP **SC-13** or similar, the chart can deploy
the `-fips` image variants, whose cryptography is performed by the **OpenSSL
FIPS Provider 3.1.2** (NIST CMVP certificate **#4985**) and, for the Go
services, the **Go Cryptographic Module v1.0.0** (CMVP **#5247**).

Enforcement happens inside the container, so no FIPS-enabled host kernel is
required — which is what makes this workable on managed runtimes where the
host OS is not under your control.

Disabled by default; the rendered output is unchanged when it is off.

```yaml
fips:
  enabled: true
  validate: true    # refuse to render a partly-FIPS deployment (see below)
```

`-fips` tagged images must be available in your registry. Contact
hello@defectdojo.com for access.

### Components without a FIPS variant

Sensei and the **embedded** PostgreSQL/Redis have no FIPS build — the bundled
valkey image is Alpine-based, which has no FIPS-validated OpenSSL. A FIPS
install must therefore use external datastores and leave Sensei disabled:

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

With `fips.validate: true` (the default) the chart **fails to render** if you
enable FIPS alongside any of them, naming the offenders:

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei, redis (embedded). Disable them, or set fips.validate=false to accept
that they run non-validated cryptography.
```

That is deliberate. A deployment where most services use validated
cryptography and one or two quietly do not is worse than an obvious failure:
it looks compliant and only surfaces during an assessment. Set
`fips.validate: false` only if you have accepted that risk explicitly.

### Verifying after deploy

Every pod runs a fail-closed startup check — if the validated provider is not
active, the container exits rather than serving. The evidence it prints is
usually what an assessor wants:

```bash
kubectl -n $NAMESPACE logs deploy/dojopro-django | grep FIPS
kubectl -n $NAMESPACE exec deploy/dojopro-django -- openssl list -providers
kubectl -n $NAMESPACE exec deploy/dojopro-django -- python3 /verify_fips.py
```

Behaviour changes to plan for (password hashing moves to PBKDF2, ChaCha20 is
dropped from the TLS cipher list) are covered in the FIPS 140-3 Mode page of
the Asset documentation.

---

## Pre-flight: Validate Templates

Before installing, run `helm template` to render and validate all manifests
without touching the cluster. This catches values errors, missing required
fields, and YAML issues before you commit to `helm install`:

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

Use the same flags you plan to pass to `helm install`. If this exits cleanly,
your values are valid. If it fails, the error message will identify the missing
or invalid field — fix your values file and re-run until it passes.

---

## Deploy

Combine your platform overlay, resource profile, customer values, and the
secrets + license choices you made above.

### AWS EKS

> **HTTPS is strongly recommended for browser access on EKS.**
> When ingress TLS is active, the chart automatically enables
> `SECURE_SSL_REDIRECT` and sets CSRF/session cookies to `Secure`, which means
> browser login will fail without an HTTPS listener on the ALB. Configure an
> ACM certificate before deploying for the best experience.
>
> If you need to run without HTTPS, see
> [Deploying Without HTTPS (Not Recommended)](#deploying-without-https-not-recommended)
> below.

```bash
NAMESPACE="dojopro"
kubectl create namespace $NAMESPACE
```

> **Namespace consistency:** The namespace value must match across all
> resources: your secrets YAML (`metadata.namespace`), `kubectl create namespace`,
> and `helm install -n`. If you use a custom namespace instead of `dojopro`,
> replace it consistently in all commands and secret manifests.

**External secrets + license secret (GitOps):**

Apply your secrets if you haven't already (see [Generate Secrets](#generate-secrets)),
then install:

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

**Inline secrets + license file (simpler):**
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

#### Deploying Without HTTPS (Not Recommended)

> **Warning:** Running without HTTPS means session cookies are sent in
> cleartext and CSRF protection via secure cookies is disabled. Do not use
> this configuration in production.

If you need to deploy without HTTPS temporarily (e.g., initial testing without
an ACM certificate), apply **all** of the following changes in your values file:

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

All four changes are required. Missing any one will result in redirect loops
or broken login. When you are ready to enable HTTPS, revert these changes and
configure an ACM certificate.

### OpenShift / ROSA

```bash
NAMESPACE="dojopro"
oc new-project $NAMESPACE
# Or, if the namespace already exists:
# oc project $NAMESPACE
```

> **Reminder:** You should already have your namespace's `fsGroup` value from the
> [Pre-Install Checklist](#infrastructure-details). If not, look it up now:
>
> ```bash
> oc get namespace $NAMESPACE \
>   -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
> # Use the start value (e.g., 1001070000) as securityContext.openshift.fsGroup
> ```

**External secrets + license secret (GitOps):**

Apply your secrets if you haven't already (see [Generate Secrets](#generate-secrets)),
then install:

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

**Inline secrets + license file (simpler):**
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

## Deploy with ArgoCD

DefectDojo Pro is fully compatible with ArgoCD. The chart includes platform
and profile presets that ArgoCD can reference directly as `valueFiles`.

### Prerequisites

Before creating the ArgoCD Application, the following Kubernetes resources
must exist in the target namespace:

- The application secrets (see [Generate Secrets](#generate-secrets))
- The license secret (see [License](#license))
- Internal TLS secrets, if not using auto-generation (see [Create Internal TLS Certificates](#create-internal-tls-certificates))
- ddorch mTLS material (see [ddorch mTLS Certificates](#ddorch-mtls-certificates)). ArgoCD has no `--set-file` equivalent, so pass the three PEM contents via Application parameters (`ddorch.tls.rootCa` / `ddorch.tls.cert` / `ddorch.tls.key`). Use an ArgoCD secret-management plugin (Sealed Secrets, External Secrets, or a ConfigMap plugin) rather than committing the key in plain text.

### How It Works

ArgoCD references preset files relative to the chart root. Your Application
spec needs three things:

1. Platform and profile presets as `valueFiles`
2. Your environment-specific configuration (via `valueFiles`, inline `values`, or both)
3. Secret and license references as `parameters`

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

### Supplying Your Configuration

There are several ways to provide your environment-specific values to ArgoCD:

- Inline `values` in the Application spec — simplest approach, no extra files
  or repos needed. Works well when your configuration is straightforward.
- A values file in a separate git repo — use ArgoCD's multi-source feature
  (v2.6+) with a `$ref` variable to pull your values file alongside the chart.
  Recommended when using an OCI-published chart.
- A values file in the same git repo as the chart — reference it in
  `valueFiles` with a path relative to the chart directory
  (e.g., `../../overrides/customers/my-company.yaml`).

All three approaches follow the same layering: platform preset → profile
preset → your configuration. Later values override earlier ones.

### Upgrading

When the chart is published to an OCI registry, upgrading is a single change
to `targetRevision` in your Application spec. The platform and profile presets
are versioned with the chart, so they update automatically.

For full details on ArgoCD's Helm support, see the
[ArgoCD Helm documentation](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/).

---

## Verify

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

### Built-in Helm Tests

The chart ships with four tests that run as Kubernetes pods when you execute
`helm test`. They validate the critical integration points between DefectDojo
and its backing services:

| Test | What it checks |
|------|----------------|
| `test-database` | Connects to PostgreSQL using the configured credentials, runs `SELECT version()`, and confirms the database is accepting queries. Retries for up to 60 seconds. |
| `test-redis-broker` | Connects to the Redis/Valkey broker, sends a `PING`, then performs a set/get/delete cycle to verify read-write access. |
| `test-django-health` | Hits the `/api/v2/health_check/light/` endpoint on the internal nginx service and confirms an HTTP 2xx/3xx response. Runs after database and broker tests (hook-weight 10). |
| `test-storage` | Mounts the media volume and performs a write/read/delete cycle to confirm the storage backend is accessible and writable by the application. Runs last (hook-weight 15). |

Tests run in order by hook-weight — infrastructure tests (database, broker)
first, then application-level tests (health, storage). If an earlier test
fails, later tests may still run but are likely to fail as well.

To re-run tests after a failed deployment or configuration change:
```bash
helm test dojopro -n $NAMESPACE --logs --timeout 5m
```

Test pods are automatically cleaned up before each run
(`before-hook-creation` delete policy). To inspect a failed test pod's logs
manually:
```bash
kubectl logs -n $NAMESPACE dojopro-test-database
kubectl logs -n $NAMESPACE dojopro-test-redis-broker
kubectl logs -n $NAMESPACE dojopro-test-django-health
kubectl logs -n $NAMESPACE dojopro-test-storage
```

### Retrieve the Admin Password

The initial admin password is stored in the application secret. Retrieve it
with:

```bash
kubectl get secret dojopro-secrets -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

If you used inline secrets instead of an external secret, the password is in
the chart-managed secret:

```bash
kubectl get secret dojopro-defectdojo -n $NAMESPACE \
  -o jsonpath='{.data.DD_ADMIN_PASSWORD}' | base64 -d && echo
```

Log in at your configured URL with the admin username (default: `admin`) and
this password. Change the password after first login.

---

## Operations

### Log Verbosity

The chart exposes two log level settings, both defaulting to `INFO`:

| Setting | Controls | Env var |
|---------|----------|---------|
| `config.logLevel` | Django application logging | `DD_LOG_LEVEL` |
| `celery.logLevel` | Celery worker and beat logging | `DD_CELERY_LOG_LEVEL` |

To increase verbosity for troubleshooting, set either or both to `DEBUG` in
your values file and run `helm upgrade`:

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

The `--set` flags override values file settings, so you can toggle debug
logging without editing files. Once the issue is resolved, run `helm upgrade`
again without the `--set` flags to return to your configured defaults.

The Django deployment also supports `django.uwsgi.enableDebug: true`, which
sets `DD_DEBUG=True` for lower-level framework debugging. This produces
significantly more output and should only be used for short investigations.

### Scan Import Isolation

Scan imports (`/api/v2/import-scan/` and `/api/v2/reimport-scan/`) are parsed
synchronously and can consume large amounts of worker memory. By default the
chart runs a dedicated `django-import` deployment (uwsgi on port 3032 behind
its own Service) and the Django pod's nginx routes the import endpoints to it.
A heavy import cannot exhaust (or OOM) the interactive web workers, and the
importer pool (writers) scales independently of the web pods (readers).

Tunables under `django.uwsgiImport`:

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

Operational notes:

- The importer pods mount the shared media volume, so they need
  ReadWriteMany-capable storage to schedule freely across nodes. The chart's
  storage backends (`efs`, `filestore`, `gcsfuse`, `nfs`, and the default RWX
  media PVC) all qualify; a ReadWriteOnce PVC does not.
- Importer autoscaling is off by default because a scale-down evicts whatever
  import that pod is running once `terminationGracePeriodSeconds` expires.
  If you enable it, raise the grace period so in-flight imports can finish.
- A PodDisruptionBudget (`podDisruptionBudget.djangoImport`) protects the
  importer pool during voluntary disruptions whenever more than one importer
  runs.

The `minimal` profile disables the importer deployment to keep the footprint
small; imports then share the single uwsgi pool as before.

### PSIRT Advisory Engine (optional)

The chart can deploy the PSIRT Advisory Engine, a service for authoring and
publishing security advisories from DefectDojo findings. It is off by default.
When enabled it appears under `/psirt/` on your main DefectDojo host — the
nginx sidecar proxies it, so no extra ingress or DNS entry is needed.

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

`psirtSharedSecret` is a plain value you choose — no DefectDojo user or minted
token is involved. Set a high-entropy string (e.g.
`python -c "import secrets; print(secrets.token_urlsafe(48))"`). The chart wires
it into both the psirt engine Secret and the DefectDojo pods, so a single value
enables hands-off publishing on a fresh install with no post-boot step. Rotation:
change it and `helm upgrade`.

Database setup: point `databaseUrl` at the same PostgreSQL host DefectDojo
uses (or any other reachable host) with a database name of your choosing. The
pod creates the database on first start if it doesn't exist, which requires a
one-time grant as the postgres superuser:

```sql
ALTER ROLE pae CREATEDB;
```

Operational notes:

- Keep `psirt.replicas` at 1. The service runs its own internal job scheduler,
  and a second replica would run every scheduled job twice.
- The pod mounts the shared media volume (advisory attachments live under
  `<media>/pae/uploads`), so the same ReadWriteMany storage guidance as the
  importer pool applies.
- Outbound HTTPS is required for advisory feeds and NVD lookups. With
  `networkPolicy.profile=aggressive`, the allowed CIDR list
  (`networkPolicy.externalAPIs.allowedCidrs`) must cover those endpoints.
- An optional `psirt.nvdApiKey` raises the NVD rate limit from 5 to 50
  requests per 30 seconds.

### Sensei scan/fix engine (optional)

The chart can deploy the Sensei engine, the service behind server-side
scanning and auto-remediation (fix) jobs. It is off by default and needs no
extra configuration to boot:

```yaml
sensei:
  enabled: true
```

The engine holds no long-lived secrets. Scan/fix credentials and endpoint
URLs ride on each job, dispatched from DefectDojo's encrypted worker config.
django and celery reach the engine in-cluster (`SENSEI_ENGINE_URL` is wired
into the shared configmap automatically), so no ingress or DNS entry is
needed.

Operational notes:

- The engine calls DefectDojo back at your public site URL (`dojo.url`) by
  default. Set `sensei.ddCallbackUrl` to override — for purely in-cluster
  traffic point it at the internal nginx listener, but the engine must then
  trust DefectDojo's internal CA.
- LLM credentials for fix jobs are normally set in-app (AI Model Settings)
  and carried per job. Only set `sensei.llm.*` when the engine must read the
  key from its own environment; prefer `sensei.llm.existingSecret` over the
  plaintext `sensei.llm.apiKey`.
- To run the engine against Google Vertex AI instead of a provider API key,
  set `sensei.llm.provider: vertex` and `sensei.llm.vertexProject` to the GCP
  project hosting Vertex (`sensei.llm.vertexRegion` is usually `global`). The
  pod authenticates with Application Default Credentials, so give it a GCP
  service account through `sensei.serviceAccountName` + Workload Identity, or
  mount a key file with `sensei.extraVolumesRaw` and
  `sensei.extraVolumeMounts`, then point `GOOGLE_APPLICATION_CREDENTIALS` at
  it via `sensei.extraEnv`.
- `sensei.llm.fallbackChain` takes a comma-separated list of `provider` or
  `provider:model` entries the engine falls back to when the
  primary provider returns a retryable failure. Ending the chain on a
  different vendor (for example `vertex-gemini:gemini-2.5-pro`) keeps fix jobs
  running through a primary-provider outage.
- The scanner image is heavy. `sensei.maxConcurrentJobs` (default 3) caps
  parallel jobs per pod, and the default resources
  (1Gi request / 4Gi limit) are sized for that cap — raise both together.
- A CPU-based HPA (1 to 4 replicas) is on by default. Set
  `sensei.hpa.maxReplicas` equal to `sensei.hpa.minReplicas` to pin the
  count to `sensei.replicas` instead.
- Outbound HTTPS is required for repository clones, git-hosting APIs, and
  LLM provider APIs. With `networkPolicy.profile=aggressive`, the allowed
  CIDR list (`networkPolicy.externalAPIs.allowedCidrs`) must cover those
  endpoints.

### Rotating TLS Certificates

The chart uses two categories of TLS certificates, each with a different
rotation procedure.

#### Internal TLS (service-to-service)

These are the `dojopro-internal-tls` and `dojopro-internal-ca` secrets used
for communication between nginx, connectors, and other internal services.

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

#### Ingress TLS (external/browser-facing)

Rotation depends on how you configured TLS:

- **ACM-managed (EKS):** Renewal is automatic — no action needed.
- **cert-manager:** Renewal is automatic based on the `duration` and
  `renewBefore` settings (defaults: 2160h / 720h).
- **GKE managed certificates:** Renewal is automatic — no action needed.
- **Manual cert via Kubernetes secret:** Update the secret the ingress
  references using the same `kubectl create secret tls ... --dry-run=client`
  pattern shown above.
- **Auto-generated internal certs:** The chart can regenerate these with
  `helm upgrade` if `certificates.generation.enabled: true`.

> In Kubernetes the source of truth is the Secret object — updating the secret
> and rolling the deployment is how certificate rotation works.

> If you use External Secrets Operator or Sealed Secrets to manage TLS secrets,
> rotation is handled at that layer and the Kubernetes secrets update
> automatically — no manual `kubectl` steps needed.

---

## Values File Layering

The chart stacks values files. Later files win:

```
presets/platforms/<platform>.yaml       # Platform defaults (aws-eks or openshift)
presets/profiles/<size>.yaml            # Resource profiles (minimal, standard, performance)
overrides/customers/<company>.yaml      # Your config (domain, DB, storage, certs)
```

Platform presets and profile presets ship inside the chart (`dojopro/presets/`).
They're included in the packaged `.tgz` and versioned with the chart. Customers
don't need to modify them.

When using `helm install` from the extracted chart, reference them using the
`$CHART` variable set during [extraction](#extract-the-chart-package):
```
-f $CHART/presets/platforms/aws-eks.yaml
```

When using ArgoCD, reference them relative to the chart root:
```
valueFiles:
  - presets/platforms/aws-eks.yaml
```

Don't put resource limits in customer files or platform config in profile files.
Keep each layer focused on one thing.

> **Preset versioning — ArgoCD vs CLI:** ArgoCD references presets from inside
> the chart package, so they update automatically when you change
> `targetRevision`. CLI users must re-extract presets when upgrading to a new
> chart version to pick up any changes to platform or profile defaults. Use a
> versioned extraction path (e.g., `dojopro-2.55.4/`) to avoid confusion
> between chart versions — see [Extract the Chart Package](#extract-the-chart-package).

---

## Customization & Extensibility

Beyond platform/profile/customer values files, the chart provides first-class
extension points for wiring in your own infrastructure — sidecars, init
containers, env vars, volumes, service accounts, scheduling constraints, and
arbitrary extra manifests — without forking the chart:

- **Per-component hooks** — `extraEnv`, `extraEnvFrom`, `extraVolumesRaw`,
  `extraVolumeMounts`, `extraInitContainers`, `extraContainers`, `hostAliases`,
  `priorityClassName`, `topologySpreadConstraints`, `dnsConfig`, and
  `serviceAccountName` on every workload (django, celery worker/beat,
  connectors, ddorch, ddorch-workers, integrators, mcp-server, psirt).
- **Top-level `extraManifests`** — render arbitrary user-supplied YAML
  (ConfigMaps, Secrets, NetworkPolicies, etc.) alongside the chart, passed
  through Helm `tpl` with the chart's root context.
- **Umbrella-chart consumption** — `dojopro` can be embedded as a subchart
  via `file://` or OCI dependency, useful for shipping customer bundles that
  layer additional resources around the chart.
- **Schema-aware validation** — `values.schema.json` covers every hook, so
  editors get autocomplete and `helm lint`/`helm install` validate your
  overrides.

See the BYO Extensibility guide — bundled as
**Appendix: Bring Your Own Infrastructure (BYO)** in the PDF edition — for
patterns, examples, and upgrade-stability guarantees.

---

## Network Policies

The chart ships NetworkPolicies for every component, enabled by default
(`networkPolicy.enabled: true`). A default-deny baseline is scoped to this
release's pods (by `app.kubernetes.io/name` + `app.kubernetes.io/instance`
labels), so it never affects other workloads sharing the namespace.

How strict the rules are is controlled by **`networkPolicy.profile`**:

| Profile | Egress | Pod-to-pod ingress | External ingress |
|---------|--------|--------------------|------------------|
| `standard` (default) | All egress allowed (`0.0.0.0/0`) | All traffic between this release's own pods allowed | Restricted to the ingress controller / load balancer |
| `aggressive` | Granular per-component allowlist (DNS, database/broker, specific in-cluster services, explicitly-allowed external APIs only) | Granular per-component allowlist | Restricted to the ingress controller / load balancer |

- **`standard`** is recommended for most clusters. It avoids breakage from
  cluster-specific egress dependencies (the GKE metadata server, NodeLocal
  DNSCache, cloud storage/API endpoints) and from intra-app service calls,
  while still keeping external ingress locked to the ingress path: the release
  trusts its own pods, but the outside still comes through the front door.
- **`aggressive`** enforces a tight allowlist in both directions. If you use it,
  you may need to tune the carve-outs under `networkPolicy` for your cluster:
  - `nodeLocalDns` — allow the NodeLocal DNSCache resolver (link-local
    `169.254.20.10` by default, on port 53). Required on clusters running
    NodeLocal DNSCache (e.g. the GKE addon), otherwise DNS resolution fails.
  - `dnsSelectors` — override the DNS egress target for a custom DNS setup.
  - `allowExternalAPIs` / `externalAPIs` — control egress to external HTTPS
    APIs and which CIDRs are blocked (e.g. cloud metadata).

Set the profile in any values file, e.g.:

```yaml
networkPolicy:
  profile: aggressive
```

> **GKE health checks** are handled in both profiles — the GCE load balancer's
> probe ranges (`130.211.0.0/22`, `35.191.0.0/16`) are always allowed to reach
> the django backend on GKE. See [GCP GKE](#gcp-gke).

### Ingress controller access (502 Bad Gateway)

On non-GKE/non-OpenShift clusters, the django NetworkPolicy allows the ingress
controller in by selecting its namespace on the `kubernetes.io/metadata.name`
label that Kubernetes applies to every namespace automatically. By default this
expects the controller in a namespace named **`ingress-nginx`**, with controller
pods carrying `app.kubernetes.io/name: ingress-nginx` (the ingress-nginx chart
default).

If your ingress controller lives in a differently-named namespace, uses
different pod labels, or is a different controller entirely (Traefik, an ALB,
etc.), the policy will silently drop its traffic and requests return **502 Bad
Gateway** (`connect() failed (110: Operation timed out)` in the controller
logs). Point the policy at your real ingress source with `networkPolicy.ingressSource`:

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

Or adjust `networkPolicy.ingressNamespace` / `networkPolicy.ingressControllerLabel`
if only the names differ. See the comments under `networkPolicy` in
`values.yaml` for more `ingressSource` examples (Traefik, OpenShift router, AWS
ALB).

---

## Upgrading

The recommended upgrade path pulls the chart directly from the DefectDojo
OCI registry — no zip extraction required:

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

A typical OCI upgrade looks like this (same values files and `--set` flags
as the original install):

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

The packaged-zip workflow used at install time also works for upgrades —
substitute `helm upgrade` for `helm install` against the extracted `$CHART`
path.

See the [Upgrade Guide](/get_started/pro/onprem/upgrading_on_kubernetes/) — bundled as **Appendix: Upgrading
DefectDojo Pro** in the PDF edition — for authentication, ArgoCD upgrades,
verification, rollback, and troubleshooting.

---

## Uninstalling

```bash
helm uninstall dojopro -n $NAMESPACE
kubectl delete namespace $NAMESPACE
```

> PVCs, external databases, and external secrets are not deleted.
> Clean those up separately.

### Cleaning Up PersistentVolumes

PersistentVolumes with a `Retain` reclaim policy are **cluster-scoped** — they
are not removed by `helm uninstall` or namespace deletion. If you reinstall
DefectDojo to a different namespace, the orphaned PV's ownership metadata will
conflict with the new installation and block `helm install`.

Check for orphaned PVs after uninstalling:

```bash
kubectl get pv | grep dojopro
```

If any remain, delete them:

```bash
kubectl delete pv dojopro-media-pv
```

> **Note:** Deleting the PV removes the Kubernetes volume reference, but the
> underlying data persists on the storage backend (e.g., EFS filesystem). This
> is safe if you intend to reinstall, but should be done intentionally.

---

## Local Testing with Embedded PostgreSQL and Redis

> **This configuration is for local testing and evaluation only. Do not use
> embedded PostgreSQL or Redis in production.** Production deployments should
> use managed services (e.g., RDS, ElastiCache) for reliability, backups, and
> scaling. DefectDojo support does not cover issues with embedded databases in
> production environments.

The chart can deploy its own PostgreSQL and Redis for quick local testing using
the `minimal` profile. This avoids the need for external database and broker
infrastructure.

Add the following to your values file:

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

> **Important: `postgresql.database.password` is required** when
> `postgresql.enabled` is true and `database.existingSecret` is not set. The
> chart will fail to render without it. This password must match the
> `DD_DATABASE_PASSWORD` value in your application secrets.

> **Embedded PostgreSQL default credentials:** The chart defaults for the
> embedded PostgreSQL are username `dojodbusr` and database name `dojodb`
> (defined in the chart's `values.yaml`). Your `DD_DATABASE_URL` in the
> application secrets must use these values, not the external database
> placeholders in `secrets-template.yaml`. For example:
>
> ```
> DD_DATABASE_URL: "postgresql://dojodbusr:<password>@<release>-postgresql:5432/dojodb"
> ```

The `minimal` profile (`dojopro/presets/profiles/minimal.yaml`) sets reduced
resource requests appropriate for a single-node test cluster, but does not
toggle these database/broker flags — you must set them yourself.

> **Note on container privileges:** The embedded PostgreSQL and Redis containers
> do **not** run as root — PostgreSQL runs as UID 999 and Redis as UID 1001.
> The one exception is the PostgreSQL **init container** (`init-chmod-data`),
> which runs as root (UID 0) to set directory ownership on the data volume
> before the main process starts. This is a common pattern for StatefulSets
> with persistent storage. If your cluster enforces a `restricted` Pod Security
> Standard or OpenShift SCC that forbids root init containers, disable it with
> `postgresql.initContainer.enabled: false` (see [Known Issues](#known-issues-chart-version-2.57.1)).

When using embedded PostgreSQL on EKS, you will also need the EBS CSI driver
(see [AWS EKS Prerequisites](#aws-eks-prerequisites)) and may need to adjust
storage defaults (see [Known Issues](#known-issues-chart-version-2.57.1)).

Validate your values before installing — the minimal path requires more
overrides and is more likely to hit rendering errors:

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

If this exits cleanly, proceed with `helm install` using the same flags.

> **Use `--timeout 30m` for minimal/fresh-database installs.** The embedded
> PostgreSQL has reduced resources, and the initializer must run all database
> migrations from scratch on a new database. In testing this took ~23 minutes,
> which exceeds the `--timeout 15m` used in the standard install examples.
> A timeout causes `helm install` to report `INSTALLATION FAILED` even though
> the deployment completes successfully in the background. Using `--timeout 30m`
> avoids the false failure and the `failed` release status that results from it.

---

## Private Registry / Air-Gapped Environments

If your cluster can't pull from the default DefectDojo registry, mirror the
images to your own registry and configure the chart to use it.

### Option 1: Global registry override

Set `global.imageRegistry` to redirect all image pulls. The chart strips the
original registry from `images.prefix` and prepends yours:

```yaml
global:
  imageRegistry: "my-registry.example.com"
```

This affects all images (django, nginx, celery, connectors, redis, etc.).

### Option 2: Per-image overrides

For finer control, set `images.registry` (affects main app images) and
override individual images:

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

### Image pull secrets for private registries

If your registry requires authentication, create a pull secret and reference it:

```yaml
images:
  pullSecrets:
    existingSecrets:
      - "my-registry-pull-secret"
```

Or let the chart create one from explicit credentials:

```yaml
images:
  pullSecrets:
    create: true
    registry: "my-registry.example.com"
    # Provide credentials via a Kubernetes docker-registry secret
```

The default behavior (`extractFromLicense: true`) extracts GCP service account
credentials from the license file to pull from DefectDojo's registry. Disable
this when using your own registry:

```yaml
images:
  pullSecrets:
    create: true
    extractFromLicense: false
    existingSecrets:
      - "my-registry-pull-secret"
```

---

## Overriding Platform Annotations

The chart auto-injects platform-specific annotations on the Ingress and Service
based on `cloudProvider` (e.g., ALB annotations for EKS, GCE annotations for
GKE). If you need full control over annotations — for example, using an nginx
ingress controller on EKS instead of ALB — set `platformAnnotations.enabled: false`
and provide your own:

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

When `platformAnnotations.enabled` is `true` (the default), the chart merges
platform annotations with your custom annotations. Your annotations take
precedence on key conflicts, but you can't remove a platform annotation
without this toggle.

### Ingress upload size limit

By default the chart sets `nginx.ingress.kubernetes.io/proxy-body-size: "2400m"`
on the Ingress so large scan-result uploads and PDF reports pass through
nginx-ingress without a `413 Request Entity Too Large`. Override via:

```yaml
django:
  ingress:
    maxBodySize: "100m"     # set "" to omit the annotation entirely
```

This applies whenever nginx-ingress is the controller — including nginx-ingress
running on top of EKS, GKE, or AKS. Non-nginx controllers ignore the
annotation and must be tuned via their own mechanisms (AWS WAF body inspection
limits, AppGW request-body-limit, OpenShift Route HAProxy `tuningOptions`).

---

## Platform-Specific Notes

### AWS EKS

- Needs the AWS Load Balancer Controller for ALB ingress
- Needs the EFS CSI driver if using EFS storage
- TLS terminates at the ALB via ACM certificates
- Set `certificates.ingress.source: "acm"` and provide `acmCertArn`
- `dojo.secureCookies: true` works fine since ALB handles HTTPS

#### EFS Access Points

If your EFS filesystem is configured with an **access point** (recommended for
enforcing UID/GID ownership on the mount), you **must** set
`storage.efs.accessPointId` in your values file. Without it, the PV mounts the
EFS root as root-owned, and the DefectDojo containers (running as UID 1001)
cannot create media subdirectories — causing the initializer to fail with
`Permission denied` errors.

Check your EFS access points:

```bash
aws efs describe-access-points --file-system-id <your-fs-id> --region <region> \
  --query 'AccessPoints[].{Id:AccessPointId,Path:RootDirectory.Path,Uid:PosixUser.Uid,Gid:PosixUser.Gid}' \
  --output table
```

If an access point exists, add it to your values file:

```yaml
storage:
  type: "efs"
  efs:
    enabled: true
    fileSystemId: "fs-REPLACE_EFS_ID"
    accessPointId: "fsap-REPLACE_EFS_ACCESS_POINT_ID"
    region: "REPLACE_AWS_REGION"
```

> **Important:** The `volumeHandle` field on the PersistentVolume is
> **immutable** after creation. If you initially install without an access
> point and later need to add one, you must delete the existing PV and PVC
> before running `helm upgrade`:
>
> ```bash
> kubectl delete pvc defectdojo-media -n $NAMESPACE
> kubectl delete pv dojopro-media-pv
> helm upgrade dojopro $CHART ... (same flags as install)
> ```
>
> This is safe — deleting the PV removes only the Kubernetes reference; data
> on the EFS filesystem is not affected.

#### Storage Classes on hardened / GitOps-governed clusters

Two storage-class assumptions trip up clusters with custom StorageClass naming
or where cluster-scoped resources are managed outside the application chart.

**Dynamically-provisioned PVCs default to `gp3` on EKS.** Any PVC the chart
provisions dynamically — the embedded Redis volume (`redis.enabled: true`) and
the `storage.type: "pvc"` media volume — resolves its StorageClass to the
platform default, which is `gp3` on EKS. If your cluster has no StorageClass
named `gp3` (common on hardened clusters with custom naming), the PVC stays
`Pending` with a `storageclass.storage.k8s.io "gp3" not found` event and the
pods never start.

Override it one of two ways:

- **Globally (recommended)** — one lever for every chart-provisioned PVC:

  ```yaml
  storage:
    defaultStorageClass: "your-ebs-storageclass"   # or "" for the cluster default
  ```

- **Per component**, if you need different classes:

  ```yaml
  redis:
    redisVolume:
      pvc:
        storageClassName: "your-ebs-storageclass"
  storage:
    pvc:
      storageClassName: "your-ebs-storageclass"    # only for storage.type: "pvc"
  ```

  Resolution order is: per-component value → `storage.defaultStorageClass` →
  platform default (`gp3`). Set a value to `""` to fall back to the cluster's
  default StorageClass. This does **not** apply to the default EFS media path
  (see below), which uses no StorageClass.

**The default EFS media volume needs no StorageClass.** When
`storage.type: "efs"`, the chart binds the media PV statically via the EFS
filesystem's `volumeHandle` and a `claimRef` — both the PV and PVC use an empty
`storageClassName`. The `efs-sc` StorageClass does **not** need to exist for the
media PVC to bind.

The chart only creates a cluster-scoped `efs-sc` StorageClass if you explicitly
opt into **dynamic** EFS provisioning with `storageClasses.efs.enabled: true`
(default: `false`). On clusters where cluster-scoped resources are governed
outside the application chart (GitOps), leave it at the default `false` — the
static EFS path above requires no StorageClass and no cluster-scoped objects
from this chart. If you do want dynamic EFS provisioning under GitOps, create
the StorageClass out of band and keep `storageClasses.efs.enabled: false`.

### GCP GKE

- Uses the GCE ingress controller (`className: "gce"`) with TLS terminating at
  the Google Cloud load balancer
- The `gcp-gke.yaml` preset attaches a `FrontendConfig` (HTTP→HTTPS redirect +
  SSL policy) and a `BackendConfig` to the ingress automatically
- The GCE load balancer health-checks the django backend directly from Google's
  ranges (`130.211.0.0/22`, `35.191.0.0/16`). The chart's NetworkPolicies allow
  these automatically on GKE under both `networkPolicy.profile` values, so the
  `/nginx_health` probe succeeds and the backend reports healthy — see
  [Network Policies](#network-policies)

#### Google-managed vs BYO TLS

The `gcp-gke.yaml` preset defaults to **Google-managed certificates**. Choose
one of the two approaches:

- **Google-managed (default):** GCP provisions and renews the certificate. Just
  list your domains — no Kubernetes TLS secret is needed:

  ```yaml
  certificates:
    ingress:
      source: "google-managed"
      googleManaged:
        domains:
          - defectdojo.example.com
  ```

- **Bring your own (BYO):** Supply an existing Kubernetes TLS secret in the
  release namespace and point the ingress at it:

  ```yaml
  certificates:
    ingress:
      source: "secret"
      secretName: wildcard-example-com   # kubectl create secret tls ...
  ```

  This renders `spec.tls[].secretName` on the ingress and omits the
  `networking.gke.io/managed-certificates` annotation.

> **Bootstrap script support:** `scripts/bootstrap/bootstrap-gcp-gke.sh` only
> covers the GCP-native cert flows (`google-managed` and `pre-shared`). For the
> BYO `secret` path, install with `helm` directly (create the TLS secret first,
> then pass `certificates.ingress.source=secret` and
> `certificates.ingress.secretName=<your-secret>`).

> Renewal for Google-managed certificates is automatic — see
> [Rotating TLS Certificates](#rotating-tls-certificates).

### OpenShift / ROSA

- Uses Routes by default (`django.route.enabled: true`), but Ingress is also supported
- To use Ingress instead: set `django.ingress.enabled: true` and `django.route.enabled: false`
- Only one can be enabled at a time (the chart validates mutual exclusivity)
- **`dojo.secureCookies` must be `false`** when using edge-terminated Routes (the default).
  This is required — not optional. See the [warning in Prepare Your Values File](#prepare-your-values-file).
- `securityContext.openshift.fsGroup` must match your namespace's supplemental-groups range
  (see the [Pre-Install Checklist](#infrastructure-details) for how to look this up)
- NFS via EFS works well — use `storage.type: "nfs"` with the EFS DNS name as server

#### Using Ingress instead of Routes on OpenShift

OpenShift ships a default HAProxy-based ingress controller. If you prefer
Ingress over Routes (e.g., for consistency with other clusters or to use a
custom ingress controller), configure your values like this:

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

The chart's platform helpers will still handle security contexts, DNS resolver,
and storage defaults correctly for OpenShift regardless of which exposure
method you choose.

---

## Known Issues (Chart Version 2.57.1)

These are confirmed bugs in the current chart. Workarounds are documented
here until a patched version is released.

### Minimal install with local PostgreSQL or Redis only

The following issues only apply if you are using the chart's built-in
PostgreSQL or Redis (`postgresql.enabled: true` or `broker.external: false`).
They do not affect production deployments using external databases and brokers.

**Do not use EBS for the media volume (BUG-14, BUG-15)**

EBS volumes only support `ReadWriteOnce` — they can only attach to a single
node at a time. DefectDojo requires the media volume to be shared across
multiple pods (django, celery-worker, initializer, connectors), which may be
scheduled on different nodes. When this happens, pods will be stuck in
`ContainerCreating` with a `Multi-Attach error` because EBS cannot mount the
volume on more than one node simultaneously. This also affects `helm test`,
where the test-storage pod may be scheduled on a different node than the
application pods.

**Use EFS (or another `ReadWriteMany`-capable storage backend) instead of EBS
for the media volume.** EFS supports concurrent access from all nodes in the
cluster and is the recommended storage backend for EKS deployments.

If you must use EBS for testing on a single-node cluster, override the
defaults:

```yaml
storage:
  pvc:
    accessMode: "ReadWriteOnce"
    selector: null
    storageClassName: "gp3"
```

Be aware that even with this override, EBS will break as soon as pods are
scheduled across multiple nodes (e.g., during scaling, node replacement, or
`helm test`). EFS avoids this entirely.

**PostgreSQL init container conflicts with non-root security context (BUG-16)**

Disable it if you hit `CreateContainerConfigError`:

```yaml
postgresql:
  initContainer:
    enabled: false
```

### All deployments

**Connectors pod crashloops while initializer is running (Expected Behavior)**

During the first install, the connectors pod will enter `CrashLoopBackOff`
while the initializer job is running database migrations. This is expected —
the connectors pod attempts to call the Django API (`/api/connectors/v1/config/`),
which returns a 500 because the database schema is not yet fully migrated.
Once the initializer job completes successfully (shows `1/1 COMPLETIONS` in
`kubectl get jobs`), the connectors pod will recover on its next restart cycle.
No manual intervention is required.

**Initializer crash after migrations leaves unrecoverable database state (BUG-18)**

If the initializer job crashes **after** running database migrations but
**before** seeding initial data (e.g., due to storage permission errors or
resource limits), the database is left in a partially initialized state — tables
exist but the `dojo_system_settings` table is empty. On subsequent restarts,
the initializer fails immediately with:

```
CommandError: Failed to read system settings from database: 'NoneType' object is not iterable
```

This creates a crash loop with no automatic recovery. **Workaround:** Reset the
database schema and re-run the initializer:

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

> **Prevention:** Ensure storage permissions (especially EFS access points —
> see [EFS Access Points](#efs-access-points)) and resource limits are correctly
> configured **before** the first install. Run `helm template` to validate your
> values, and verify EFS mount permissions with a test pod if possible.

**Hatchet token warning in logs (Informational)**

When `hatchet.enabled: false` (the default), pods will log the following
warning on startup:

```
Could not create Hatchet handle; all future Hatchet invocations will fail.
Error: ... Token must be set
```

This is **expected and harmless**. As of chart 2.57, background workflow
execution has been consolidated into `ddorch` + `ddorch-workers`, which
replace the legacy Hatchet-backed workers (`kairos`, `rulesengine`,
`hatchet-integrators`). The Hatchet client code is still initialized on
startup, so the warning still appears when Hatchet is disabled, but nothing
depends on it. The warning can be safely ignored.

### HTTPS not configured

**ALB ssl-redirect annotation requires an HTTPS listener (BUG-17)**

The EKS preset includes an `ssl-redirect` annotation that assumes an HTTPS
listener exists on the ALB. If you have not configured an ACM certificate and
HTTPS listener, this annotation causes a redirect loop. Either configure HTTPS
(recommended) or see
[Deploying Without HTTPS (Not Recommended)](#deploying-without-https-not-recommended)
for the full set of required changes.

---

## Troubleshooting

### Pods stuck in CrashLoopBackOff

Check logs:
```bash
kubectl logs -n $NAMESPACE <pod-name> --previous
```

Usually one of: missing or wrong secrets (check all 12 keys), database unreachable
(check `database.host` and security groups), or internal TLS cert missing
(check `dojopro-internal-tls` secret exists).

### Mixing external and inline secrets

```
dojo.existingSecret is set to 'X', but the following inline secret values are also provided: [...]
```

Pick one approach. If you're using `dojo.existingSecret`, strip out all inline
secret values (`dojo.secretKey`, `dojo.admin.password`, `monitoring.password`, etc.)
from your values files.

### Schema says admin.password is required

Set `dojo.existingSecret` — the schema drops the password requirement when
an external secret is configured.

### OpenShift fsGroup permission errors

If pods fail with permission errors on NFS volumes, check that
`securityContext.openshift.fsGroup` falls within your namespace's
supplemental-groups range. See the fsGroup lookup in
[Deploy → OpenShift / ROSA](#openshift-rosa).

### ALB not showing up (EKS)

Verify the AWS Load Balancer Controller is running:
```bash
kubectl get pods -n kube-system -l app.kubernetes.io/name=aws-load-balancer-controller
```

Check ingress events:
```bash
kubectl describe ingress -n $NAMESPACE
```

---

## Appendix: Customer Configuration Template

The full template (`template.yaml`) is available from the DefectDojo support
portal or from support@defectdojo.com. Copy it, replace the `REPLACE_*`
placeholders, and remove sections that don't apply to your platform. The
template includes commented examples for:

- Platform identification (`cloudProvider`)
- Image pull secret configuration
- Ingress and Route configuration (Ingress for EKS/GKE/OpenShift, Route for OpenShift)
- EFS and NFS storage options
- Certificate and TLS configuration
- Security contexts (uwsgi, nginx, OpenShift fsGroup)
- Network policies
- License delivery options (file, secret, inline)

---

## Revision History

| Date       | Version | Changes                                                              |
|------------|---------|----------------------------------------------------------------------|
| 2026-07-09 | 3.1.0   | Add optional PSIRT Advisory Engine (`psirt.enabled`): served under `/psirt/` via the nginx sidecar, dedicated database via `psirt.databaseUrl`, secret pinning guidance, network policy rules, BYO hooks |
| 2026-04-17 | 2.57.1  | Document `ddorch` + `ddorch-workers` (new orchestrator pair that replaces kairos/rulesengine/hatchet-integrators); add `ddorch.tls.rootCa/cert/key` `--set-file` flags to pre-flight and deploy commands; new ddorch mTLS certificates section with SAN requirements; mcp-server listed in expected pods; PDBs added for ddorch (singleton) and ddorch-workers; ArgoCD prerequisites note about ddorch cert delivery; update Hatchet warning to reflect worker consolidation |
| 2026-03-25 | 2.55.4  | Add EFS access point documentation and template field; document initializer crash recovery (BUG-18); document connectors crashloop during init as expected; clarify Hatchet token warning is harmless; fix stale known-issues anchor; versioned chart extraction path; consolidate no-HTTPS guidance; PV cleanup in uninstall; namespace consistency note; ArgoCD vs CLI preset versioning callout |
| 2026-03-11 | 2.53.0  | Fix helm command paths; add chart extraction, EKS prerequisites, pre-flight DB check, HTTPS notice, TLS rotation, known issues section |
