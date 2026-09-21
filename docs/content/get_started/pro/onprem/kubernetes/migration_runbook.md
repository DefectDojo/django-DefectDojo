---
title: "Kubernetes Migration Runbook & Troubleshooting"
description: "Step-by-step OSS to Pro migration on Kubernetes, a troubleshooting index keyed on the exact error text, and a post-migration verification checklist"
draft: false
weight: 4
audience: pro
---

This is the detailed runbook for migrating an open source DefectDojo to self-hosted Pro **on Kubernetes**: the dry run and the cutover, a troubleshooting index keyed on the exact error text (search this page for the message you see), and a post-migration verification checklist. It is a companion to the general [Migrating from Open Source to Self-Hosted DefectDojo Pro](/get_started/pro/onprem/migrating_from_open_source/) overview, which covers the data-movement concepts that apply to either deployment method.

The sequence and the troubleshooting entries were validated by reproducing a `2.58.3` → `3.2.400` migration end to end. Read it alongside:

- [Migrating from Open Source to Self-Hosted DefectDojo Pro](/get_started/pro/onprem/migrating_from_open_source/) — the canonical procedure.
- [DefectDojo Pro Installation Guide](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/) (Kubernetes).
- [DefectDojo Pro Upgrade Guide](/get_started/pro/onprem/kubernetes/upgrading_on_kubernetes/) (Kubernetes).
- [Backing Up a Self-Hosted Deployment](/get_started/pro/onprem/backing_up/).
- [Hardware Sizing for Self-Hosted DefectDojo Pro](/get_started/pro/onprem/hardware_sizing/).

## Part 1 — The migration sequence

Restore into a **new, separate database** for Pro. Do not migrate your live OSS database in place. Your OSS instance and its database then stay untouched as an instant fallback: if you ever need to abort, you keep running OSS with zero data loss. See [Backing Up a Self-Hosted Deployment](/get_started/pro/onprem/backing_up/) for the dump/restore basics this builds on.

Run this once as a dry run against a copy of your data, then again for the real cutover against a fresh dump.

### 1. Provision the Pro database

PostgreSQL, major version **at least your source's**. The OSS Helm chart's bundled PostgreSQL is v17, so if that is what you run, the Pro database must be **v17 or newer**. A lower major rejects the dump (see [PG-1](#pg-1)). Use a separate database from your OSS one.

Create the app role and database first:

```sql
CREATE ROLE defectdojo WITH LOGIN PASSWORD '<app_db_password>';
CREATE DATABASE defectdojo OWNER defectdojo;
```

### 2. Dump the OSS database

Custom format (`-Fc`). For the dry run, dump a copy or snapshot, not the live DB.

```bash
pg_dump -Fc -U <db_user> <db_name> > defectdojo-backup.dump
```

On the OSS Helm chart the database runs in a pod, so exec into it and copy the file out:

```bash
kubectl exec -n <oss-ns> <postgres-pod> -- \
  sh -c "PGPASSWORD='<pw>' pg_dump -U <db_user> -Fc <db_name> -f /tmp/dd.dump"
kubectl cp <oss-ns>/<postgres-pod>:/tmp/dd.dump ./defectdojo-backup.dump
```

### 3. Restore into the Pro database, as the application role

Restore while connected **as the application role Pro will use**, so that role owns the restored objects. This is the single most common restore mistake (see [OWN-1](#own-1)).

```bash
pg_restore -v --no-owner --no-privileges \
  -h <pro-db-host> -U defectdojo -d defectdojo -j 2 \
  defectdojo-backup.dump
```

If your process forces you to restore as a master/superuser instead, transfer ownership to the app role afterward (see [OWN-1](#own-1) for why `REASSIGN OWNED` does not work from a system role).

### 4. Move media

Copy your OSS media (`/app/media`) to the Pro media volume, or reuse the same RWX PVC. For how the Pro media volume is provisioned, see the [Installation Guide](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/).

```bash
# from OSS:
kubectl exec -n <oss-ns> <oss-django-pod> -c uwsgi -- \
  sh -c 'cd /app/media && tar czf /tmp/media.tar.gz .'
kubectl cp <oss-ns>/<oss-django-pod>:/tmp/media.tar.gz ./media.tar.gz -c uwsgi

# into Pro (after it is up):
kubectl cp ./media.tar.gz <pro-ns>/<pro-django-pod>:/tmp/media.tar.gz -c uwsgi
kubectl exec -n <pro-ns> <pro-django-pod> -c uwsgi -- \
  sh -c 'cd /app/media && tar xzf /tmp/media.tar.gz \
         --no-same-permissions --no-overwrite-dir ./uploaded_files'
```

The `--no-same-permissions --no-overwrite-dir` flags matter (see [MEDIA-1](#media-1)).

### 5. Carry over the two keys

Read `DD_SECRET_KEY` and `DD_CREDENTIAL_AES_256_KEY` out of the OSS chart's Kubernetes Secret. The secret is named after your Helm release: `<release>-defectdojo` (see [KEY-1](#key-1) to confirm the name).

```bash
kubectl -n <oss-ns> get secret <release>-defectdojo \
  -o jsonpath='{.data.DD_SECRET_KEY}' | base64 -d; echo
kubectl -n <oss-ns> get secret <release>-defectdojo \
  -o jsonpath='{.data.DD_CREDENTIAL_AES_256_KEY}' | base64 -d; echo
```

Set those exact values into the Pro secret. They map to `dojo.secretKey` and `dojo.credentialAES256Key` (note the casing). **Never regenerate either key during a migration**; the AES key decrypts every stored credential, and the upgrade re-encrypts them with it on first boot (see [KEY-2](#key-2)).

### Before install — verify the signed release bundle

The Pro release ships as a signed bundle (`dojo-pro-helm-bundled-<version>.zip`), which contains the Helm values template, the secrets template, and the chart (`dojopro-<version>.tgz`). Verify its signature before you install, using the signing key and cosign public key provided with the release:

```bash
# GPG detached-signature check
gpg --import dojo-pro-release-signing.asc
gpg --verify dojo-pro-helm-bundled-<version>.zip.asc dojo-pro-helm-bundled-<version>.zip

# cosign check (SBOM/attestations are signed with the release cosign key)
cosign verify-blob \
  --key dojo-pro-cosign.pub \
  --signature dojo-pro-helm-bundled-<version>.zip.sig \
  dojo-pro-helm-bundled-<version>.zip
```

You also need your existing `dojopro.lic` license file, which is not part of the bundle.

### 6. Install the Pro chart against the restored DB

The Pro chart is layered: a platform preset, a profile preset, your override file, and the license. Follow the [Kubernetes Installation Guide](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/); this section only adds the migration-specific overrides. Point it at the restored DB, supply the two keys, supply the orchestration mTLS trio, and attach the license.

Minimum override for an external DB (see [VAL-1](#val-1), [VAL-2](#val-2), [DDORCH-1](#ddorch-1), [DDORCH-2](#ddorch-2), [RES-1](#res-1)):

```yaml
# your-override.yaml
postgresql: { enabled: false }
database:
  external: true
  host: "<pro-db-host>"
  port: "5432"
  name: "defectdojo"
  user: "defectdojo"
  password: "<app_db_password>"
redis: { enabled: true }
celery: { broker: { external: false } }
dojo:
  hosts: { main: "<your-host>", alternative: ["*"] }
  url: "https://<your-host>"
  fqdn: "<your-host>"
  emailUrl: "smtp://<mailhost>:25"   # required even if unused
  # secretKey / credentialAES256Key come from your secrets template (step 5)
monitoring:
  enabled: false
  password: "<any-nonempty>"          # required even when monitoring is off
```

Install with `helm install` (use a real resource profile, not `minimal` — see [RES-1](#res-1)):

```bash
helm install <release> <chart> -n <pro-ns> \
  -f presets/platforms/generic.yaml \
  -f presets/profiles/standard.yaml \
  -f your-override.yaml \
  --set-file dojo.secretKey=./secretkey \
  --set-file dojo.credentialAES256Key=./aeskey \
  --set-file ddorch.tls.rootCa=./orch-ca.crt \
  --set-file ddorch.tls.cert=./orch-server.crt \
  --set-file ddorch.tls.key=./orch-server.key \
  --set-file license.contents=./dojopro.lic
```

The initializer job runs `manage.py migrate` on first boot. It applies the Pro migrations first, then the full OSS + Pro chain. Watch it:

```bash
kubectl logs -n <pro-ns> job/<release>-initializer-<version> -f
```

### 7. Post-migration steps as needed

Endpoints → Locations and similar data moves run on demand (superuser, idempotent, safe to re-run), under Settings > Feature Flags or as commands:

```bash
python manage.py migrate_endpoints_to_locations
python manage.py migrate_components_to_dependencies
python manage.py migrate_findings_to_code_locations
```

Reconfigure SSO and any provider-level settings in the Pro UI.

### 8. Validate

Run [Part 3](#part-3--post-migration-verification-checklist) below.

## Part 2 — Troubleshooting index

Each entry gives the symptom (with the exact message to search for), the cause, and the fix. IDs are stable so you can reference them.

### PG-1

**`pg_restore` rejects the dump: "unsupported version"**

```
pg_restore: error: unsupported version (1.16) in file header
```

**Cause.** The target PostgreSQL major is older than the one that produced the dump. `pg_dump` writes an archive-format version tied to its server; a newer source (e.g. PG17) cannot be restored into an older target (e.g. PG16). The OSS Helm chart bundles PostgreSQL v17, which is easy to miss.

**Fix.** Provision the Pro database at a major version **at least** the source's, v17 or newer if you run the chart's bundled Postgres. Recreate the target and restore again.

### OWN-1

**After restore, the app can't read its tables: "permission denied"**

```
ERROR:  permission denied for table dojo_finding
```

**Cause.** `pg_restore --no-owner --no-privileges` leaves every restored object owned by whoever ran the restore. If that was a superuser/master account rather than the app role, the app role Pro connects as has no rights on the tables.

**Fix (preferred).** Restore while **connected as the application role** (`pg_restore -U defectdojo …`) so it owns the objects. There are no extensions in the dump, so a non-superuser restore succeeds.

**Fix (if you must restore as master).** Transfer ownership to the app role afterward (e.g. `ALTER TABLE … OWNER TO defectdojo` across the schema, or the equivalent your managed database provides). Note: `REASSIGN OWNED BY postgres TO defectdojo` is refused with `cannot reassign ownership of objects owned by role postgres because they are required by the database system`, so you cannot reassign from the built-in superuser; either restore as the app role or grant/alter ownership object by object.

### VAL-1

**Helm render fails: required value**

```
Error: execution error at (…defectdojo-secret.yaml): dojo.emailUrl is required.
Error: execution error at (…defectdojo-secret.yaml): monitoring.password is required.
```

**Cause.** The chart requires these values even when the feature is off.

**Fix.** Set `dojo.emailUrl` (any valid SMTP URL) and `monitoring.password` (any non-empty value) in your override.

### VAL-2

**Chart points at the built-in Postgres instead of your restored DB**

**Cause.** The profile presets (for example `minimal`) ship with the built-in Postgres on (`postgresql.enabled: true`, `database.external: false`). Layering your override on top does not automatically turn it off.

**Fix.** In your override set `postgresql.enabled: false` and `database.external: true` with the `database.host/port/name/user/password` block (see step 6). The chart enforces "exactly one of" for the DB and for the broker, so also keep exactly one of `redis.enabled: true` / `celery.broker.external: true`.

### DDORCH-1

**Helm render fails: orchestration TLS required**

```
… ddorch.tls.rootCa is required …
```

**Cause.** The orchestration service (ddorch) renders by default and requires an mTLS certificate trio at install time.

**Fix.** Supply `ddorch.tls.rootCa`, `ddorch.tls.cert`, `ddorch.tls.key` via `--set-file`. The server certificate's SAN must include `nginx`. Use the platform bootstrap script, [cert-manager](https://cert-manager.io/), or generate a self-signed set with OpenSSL:

```bash
openssl req -x509 -newkey rsa:2048 -nodes -keyout orch-ca.key -out orch-ca.crt \
  -days 3650 -subj "/CN=dojo-orch-ca"
openssl req -newkey rsa:2048 -nodes -keyout orch-server.key -out orch-server.csr \
  -subj "/CN=nginx"
printf 'subjectAltName=DNS:nginx\nextendedKeyUsage=serverAuth,clientAuth\n' > ext.cnf
openssl x509 -req -in orch-server.csr -CA orch-ca.crt -CAkey orch-ca.key \
  -CAcreateserial -out orch-server.crt -days 3650 -extfile ext.cnf
```

### DDORCH-2

**Orchestration pod crash-loops: can't create its database**

```
failed to create server: create workflow store: ensure database exists:
create database: ERROR: permission denied to create database (SQLSTATE 42501)
```

**Cause.** ddorch keeps its workflow state in a separate companion database named `<your-db>-ddorch` and creates it on startup. With an external database, the app role usually lacks the CREATEDB privilege.

**Fix.** Grant it (or pre-create the companion DB) with `ALTER ROLE`:

```sql
ALTER ROLE defectdojo CREATEDB;
```

Then restart the ddorch pod. The core application runs without ddorch (Django falls back gracefully), but you want it healthy for scheduled rules.

### RES-1

**Django or Celery pods restart with OOMKilled**

```
State: Terminated  Reason: OOMKilled  Exit Code: 137
```

**Cause.** The `minimal` profile caps the uwsgi/celery containers at memory levels below what Pro 3.2.x needs under real load.

**Fix.** Use the `standard` or `performance` profile and size `django.uwsgi` memory to your import volume; see [Hardware Sizing](/get_started/pro/onprem/hardware_sizing/) and the tailored sizing document your DefectDojo contact provided. As a quick unblock you can raise the limit in place:

```bash
kubectl set resources -n <pro-ns> deployment/<release>-django \
  -c uwsgi --limits=memory=3Gi --requests=memory=1Gi
```

### KEY-1

**The secret isn't named `defectdojo`**

**Symptom.** `kubectl get secret defectdojo` returns `NotFound`.

**Cause.** The OSS chart names the secret after the Helm release: `<release>-defectdojo`. It is the bare `defectdojo` only if the release itself is named `defectdojo`. (The chart's install notes can print a slightly different name than the one actually created.)

**Fix.** Find it, then read from that name:

```bash
kubectl -n <oss-ns> get secret | grep defectdojo
```

### KEY-2

**Stored credentials unreadable after migration**

**Cause.** `DD_CREDENTIAL_AES_256_KEY` was not carried over exactly, or was regenerated. Every stored tool/integration credential is encrypted with it, and the upgrade re-encrypts them with it on first boot. A changed key makes them permanently unreadable.

**Fix / prevention.** Carry both keys over verbatim (step 5) and never regenerate them. You can confirm the key round-trips before cutover: a value encrypted on OSS decrypts on Pro to the same plaintext. If it does not, the key did not carry over correctly; stop and fix it before proceeding.

### MEDIA-1

**Extracting media into the volume fails on permissions**

```
tar: .: Cannot utime: Operation not permitted
tar: .: Cannot change mode to rwxr-xr-x: Operation not permitted
tar: Exiting with failure status due to previous errors
```

**Cause.** `tar` tries to set mode/mtime on the media mount root (`.`), which the pod user does not own. The files themselves still extract, but `tar` exits non-zero.

**Fix.** Extract with flags that skip directory metadata and name the subtree:

```bash
tar xzf /tmp/media.tar.gz --no-same-permissions --no-overwrite-dir ./uploaded_files
```

### AUTH-1

**API/UI returns 301 redirects behind a port-forward**

**Symptom.** Every request to a port-forwarded Pro endpoint returns HTTP 301.

**Cause.** Pro forces HTTPS (`SECURE_SSL_REDIRECT`). A plain-HTTP port-forward that bypasses the ingress gets redirected, and there may be no pod-level TLS listener because TLS terminates at the ingress.

**Fix.** Reach Pro through its ingress over HTTPS as normal. If you are testing directly against a port-forward, send `X-Forwarded-Proto: https` on the request so Django treats it as already-secure. This is a test-harness detail, not a migration problem.

### ADMIN-1

**The admin password isn't what I set in the Pro values**

**Cause.** `dojo.admin.password` is only used to create the admin on a fresh database. On a migrated database the admin already exists, so the chart leaves that account and its password exactly as they were in OSS. The initializer logs `Admin user already exists; skipping first-boot setup`.

**Fix.** Log in with your existing OSS admin credentials. This is expected behavior, not an error.

### PGTRIGGER-1

**Initializer fails enabling audit-history triggers on a fresh install**

```
trigger "…" for table "…" does not exist
```

**Cause.** On some fresh-install paths the initializer can fail while enabling the pghistory audit triggers. This did not occur on the OSS → Pro upgrade path in the dry run (the initializer logged `Successfully enabled pghistory triggers`), but it is a known possibility.

**Fix.** Run the pgtrigger install step and re-run the initializer. If you hit it, let support know so we can capture your exact case.

## Part 3 — Post-migration verification checklist

Run these against the Pro deployment once the initializer job has completed.

1. **All migrations applied.** Uses `showmigrations` and `migrate --check`:

```bash
kubectl exec -n <pro-ns> <pro-django-pod> -c uwsgi -- python manage.py showmigrations \
  | grep -c '\[ \]'    # expect 0 unapplied
kubectl exec -n <pro-ns> <pro-django-pod> -c uwsgi -- python manage.py migrate --check
  # exit code 0 = nothing left to apply
```

Both the `dojo` and `pro` app sections should be fully applied.

2. **Record counts match OSS.** Compare against the numbers you recorded before the dump (via the API v2 `count` field or the ORM):

```bash
kubectl exec -n <pro-ns> <pro-django-pod> -c uwsgi -- python manage.py shell -c "
from dojo.models import Product,Product_Type,Engagement,Test,Finding
from django.contrib.auth import get_user_model
print('product_types',Product_Type.objects.count())
print('products',Product.objects.count())
print('engagements',Engagement.objects.count())
print('tests',Test.objects.count())
print('findings',Finding.objects.count())
print('users',get_user_model().objects.count())"
```

3. **Login and API token.** Log in with your OSS admin credentials (see [ADMIN-1](#admin-1)). An existing API token continues to work because `DD_SECRET_KEY` carried over.

4. **Media downloads.** Open a finding that had an attachment and download the file; confirm the bytes match (compare a checksum against the OSS copy).

5. **Credentials readable.** Open a tool/integration configuration that had stored credentials and confirm they still work. (See [KEY-2](#key-2) for the pre-cutover key round-trip check.)

6. **Locations (optional).** If you ran the Endpoints → Locations commands, confirm your endpoint history appears under Locations.

## Part 4 — Environment and scope notes

- **Restore into a separate database.** The whole rollback story depends on it. Your OSS instance stays a clean, instant fallback until you sign off on Pro. See [Backing Up a Self-Hosted Deployment](/get_started/pro/onprem/backing_up/).
- **Migration duration scales with database size**, and with the 3.0 major crossing the first boot does real work. Measure it on your own hardware during the dry run rather than planning to a fixed number. Budget a maintenance window of a few hours for the real cutover; the dry-run figure is usually well under that.
- **Sizing.** Size your deployment from the tailored sizing guidance your DefectDojo contact provided for your environment, which is usage-matched from performance testing. The public [Hardware Sizing](/get_started/pro/onprem/hardware_sizing/) guide is a deliberately conservative starting point and runs high, so prefer the tailored document where you have it. Sizing guidance is revised as performance improvements land, so treat any figure as current-as-of its revision date rather than a fixed SLA; ask your contact for the latest revision before a production cutover.
- **The `/api/v2/` API is the programmatic interface.** See the [API v2 documentation](/automation/api/api-v2-docs/). A few endpoints were removed at 3.0 if your automation used them: `/api/v2/credentials/`, `/api/v2/credential_mappings/`, `/api/v2/stub_findings/`, and the questionnaire API endpoints. Scan your integration scripts.
- **The "Product → Asset / Product Type → Organization" relabel** is a UI label only. Database names and API endpoints are unchanged and old URLs redirect. It can be turned off.
