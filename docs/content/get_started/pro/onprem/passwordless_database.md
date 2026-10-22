---
title: "Passwordless Database Authentication"
description: "Run self-hosted DefectDojo Pro against a managed PostgreSQL server that refuses passwords, using Microsoft Entra ID, Amazon RDS IAM or Cloud SQL IAM authentication"
draft: false
weight: 13
audience: pro
---

DefectDojo Pro can sign in to a managed PostgreSQL server with a short-lived token issued to its cloud identity instead of a password. Use it when your database refuses password sign-in, or when you would rather not keep a database password in a Secret at all.

Every DefectDojo process that connects to the database does this: the web application, Celery workers, the Go API service, the orchestrator (ddorch) and its workers, the webhook gateway, and the initializer. Each one asks its cloud for a token, caches it, and sends a current one as the password whenever it opens a new connection. The server checks the token only when a connection opens, so an established connection is not affected when its token later expires.

| Cloud | Database | Setting |
| --- | --- | --- |
| Azure | Azure Database for PostgreSQL flexible server, with Microsoft Entra authentication | `azure` |
| AWS | Amazon RDS or Aurora PostgreSQL, with IAM database authentication | `aws` |
| Google Cloud | Cloud SQL for PostgreSQL, with IAM database authentication | `gcp` |

Not supported together with passwordless authentication: the [sandbox](/get_started/pro/onprem/sandbox_mode/), the embedded PostgreSQL container, and the optional database connection pool.

## Kubernetes (Helm)

Set `database.auth.mode` and leave every password setting empty:

```yaml
database:
  external: true
  host: <server endpoint>
  port: 5432
  name: dojodb
  user: <the application identity's database role>
  password: ""
  auth:
    mode: azure            # azure, aws or gcp
  sslMode: require
serviceAccount:
  annotations: {}          # binds the application pods to their cloud identity (see below)
webhookGateway:
  serviceAccount:
    annotations: {}        # the webhook gateway runs on a cloud identity of its own
  database:
    role: <the gateway identity's database role>
```

The chart renders no database password, and refuses to render when `database.password`, `database.existingSecret`, `postgresql.enabled`, `sandbox.enabled` or `database.pool.enabled` is also set.

On AWS, `database.host` must be the instance's own endpoint, not a DNS alias: the token is signed for the exact host name the application connects to.

Use `sslMode: verify-full` in production. The token is the password, and `require` encrypts the connection without checking the server's identity, so anything that can intercept the traffic can present its own certificate and collect a token that stays valid until it expires. `verify-full` needs the certificate authority that signed the server certificate in `sslRootCert`; the cloud sections below say where to find it.

## Docker Compose and other deployments

The same settings are environment variables. Leave `DD_DATABASE_PASSWORD` unset and put no password in `DD_DATABASE_URL`.

| Variable | Value |
| --- | --- |
| `DD_DATABASE_AUTH_MODE` | `password` (the default), `azure`, `aws` or `gcp` |
| `DD_DATABASE_AUTH_AZURE_CLIENT_ID` | Azure, optional: the client ID of a user-assigned managed identity |
| `DD_DATABASE_AUTH_AWS_REGION` | AWS, optional: the region the token is signed for; defaults to `AWS_REGION` |
| `DD_DATABASE_SSLMODE` | `require` by default in a passwordless mode; `verify-full` with a CA bundle |
| `DD_DATABASE_SSLROOTCERT` | Path of the CA bundle that verifies the server, for `verify-full` |

Each process gets its token through its cloud SDK's default credential chain, which on a virtual machine includes the machine's own identity: a managed identity on Azure, an instance profile on EC2, or the attached service account on Compute Engine.

## Prepare the database

Do this once, as a database administrator, before the first install.

1. Create a database role for the application identity and one for the webhook gateway's identity. How depends on the cloud; see the sections below.
2. Create both databases, owned by the application role. The orchestrator uses a second database named after the first with a `-ddorch` suffix, and an IAM role cannot create it on its own:

   ```sql
   GRANT "<app role>" TO CURRENT_USER;
   GRANT "<gateway role>" TO CURRENT_USER;
   CREATE DATABASE dojodb OWNER "<app role>";
   CREATE DATABASE "dojodb-ddorch" OWNER "<app role>";
   ```

3. Connected to `dojodb`, create the extension the application needs (the application role is not an administrator) and the webhook gateway's schema:

   ```sql
   CREATE EXTENSION IF NOT EXISTS pg_trgm;
   GRANT CONNECT ON DATABASE dojodb TO "<gateway role>";
   CREATE SCHEMA IF NOT EXISTS whook AUTHORIZATION "<gateway role>";
   ```

4. Remove the temporary memberships from step 2:

   ```sql
   REVOKE "<app role>" FROM CURRENT_USER;
   REVOKE "<gateway role>" FROM CURRENT_USER;
   ```

### Azure

- **Cluster:** create AKS with `--enable-oidc-issuer --enable-workload-identity`. Create two user-assigned managed identities, one for the application and one for the webhook gateway. Give each a federated credential for its ServiceAccount: `system:serviceaccount:<namespace>:<release service account>` for the application and `system:serviceaccount:<namespace>:<release>-webhook-gateway` for the gateway, audience `api://AzureADTokenExchange`.
- **Annotations:** annotate each ServiceAccount with `azure.workload.identity/client-id: <the identity's client ID>`. DefectDojo adds the `azure.workload.identity/use` label to its pods itself.
- **Roles:** as the server's Microsoft Entra administrator, create each identity's role:

  ```sql
  SELECT * FROM pgaadauth_create_principal_with_oid('<identity name>', '<principal ID>', 'service', false, false);
  ```

  The role is named after the identity. That name is `database.user` for the application and `webhookGateway.database.role` for the gateway.
- **Extension:** allow-list it first by setting the server parameter `azure.extensions` to `PG_TRGM`.
- **Schema:** in a new database on Azure, the `public` schema belongs to `azure_pg_admin`. Give it to the application role in both databases:

  ```sql
  ALTER SCHEMA public OWNER TO "<app role>";
  ```

- **TLS:** the server certificate chains to a public root, so `sslMode: verify-full` with `sslRootCert: /etc/ssl/certs/ca-certificates.crt` works.

### AWS

- **Roles:** enable IAM database authentication on the instance, then create each role as a plain user: `CREATE USER <name>;`. Run the steps under [Prepare the database](#prepare-the-database), and only then give each role IAM sign-in:

  ```sql
  GRANT rds_iam TO <name>;
  ```

  A role that holds `rds_iam`, directly or through membership, can only sign in with IAM. If the master user is still a member of one of these roles when `rds_iam` is granted, its password stops working. In that case, an IAM principal allowed `rds-db:connect` for the master user can sign in with a token from `aws rds generate-db-auth-token --username <master user>` and revoke the membership.
- **IAM roles:** give each identity an IAM role allowed `rds-db:connect` on `arn:aws:rds-db:<region>:<account>:dbuser:<DbiResourceId>/<role name>`. Bind it to its ServiceAccount through the cluster's OIDC provider (IRSA: annotate the ServiceAccount with `eks.amazonaws.com/role-arn`) or with EKS Pod Identity.
- **TLS:** RDS certificates chain to the Amazon RDS certificate authority, which is not in public trust stores. Use `sslMode: require`, or mount the RDS CA bundle and use `verify-full`.
- **Token lifetime:** RDS tokens last 15 minutes. DefectDojo refreshes them before they expire.

### Google Cloud

- **Instance:** set the flag `cloudsql.iam_authentication=on`.
- **Service accounts:** create one Google service account per identity with `roles/cloudsql.instanceUser` and `roles/cloudsql.client`. Bind each to its Kubernetes ServiceAccount with `roles/iam.workloadIdentityUser`, and annotate the ServiceAccount with `iam.gke.io/gcp-service-account: <service account email>`.
- **Database users:** create each one without the `.gserviceaccount.com` suffix:

  ```bash
  gcloud sql users create <sa>@<project>.iam --instance <instance> --type cloud_iam_service_account
  ```

  `<sa>@<project>.iam` is the role name for `database.user` and `webhookGateway.database.role`.
- **TLS:** Cloud SQL server certificates come from a per-instance certificate authority. Use `sslMode: require`, or mount the instance's server CA and use `verify-full`.

## Switching an existing install

1. Upgrade the install on password authentication first, so every migration is applied.
2. Prepare the identities and roles as above.
3. As an administrator, move ownership in each database:

   ```sql
   REASSIGN OWNED BY <old password user> TO "<app role>";
   ```

4. Switch `database.auth.mode` and remove the password settings.

## Troubleshooting

| Error | Cause |
| --- | --- |
| `Password returned by client is empty` | The process did not get the passwordless setting. Check the pod's `DD_DATABASE_AUTH_MODE`. |
| `The access token has invalid format` (Azure), `PAM authentication failed` (AWS), `Cloud SQL IAM service account authentication failed` (Google Cloud) | The server expected a token and got something else, or the identity has no matching database role. |
| `pg_hba.conf rejects connection ... no encryption` | TLS is off. Set `sslMode` to `require` or stricter. |
| `permission denied to create database` from ddorch | Create the `-ddorch` database in advance, owned by the application role. |
