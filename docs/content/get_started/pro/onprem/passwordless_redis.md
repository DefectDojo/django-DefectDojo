---
title: "Passwordless Redis Authentication"
description: "Run self-hosted DefectDojo Pro against a managed Redis that refuses access keys, using Microsoft Entra ID, Amazon ElastiCache IAM or Memorystore IAM authentication"
draft: false
weight: 14
audience: pro
---

DefectDojo Pro can sign in to a managed Redis with a short-lived token issued to its cloud identity instead of an access key or password. Use it when your Redis has access keys disabled, or when you would rather not keep a Redis password in a Secret at all. It pairs with [Passwordless Database Authentication](/get_started/pro/onprem/passwordless_database/) for an install with no stored credentials.

Every DefectDojo process that talks to Redis does this: the web application (its cache), the Celery workers and beat (the task broker and, if you use one, a Redis result backend), the orchestrator's workers, the Go API service and its job worker, and the initializer.

Unlike a database, Redis checks a token again after the connection is open: Azure closes a connection whose token has expired unless the client sent a new one first, and ElastiCache closes an IAM connection 12 hours after its last sign-in. So each process also renews its sign-in before that happens. The Python processes send a fresh `AUTH` on the open connection, so a Celery worker keeps its connection to the broker. That includes a worker's subscription to the broker's broadcast channels, which renews alongside its periodic health check; it needs the RESP3 protocol, which Azure Managed Redis, ElastiCache for Valkey and Redis OSS 7 and later, and Memorystore all support. The Go services retire each connection after ten minutes and open the next one with a token that outlives it by at least five minutes.

| Cloud | Redis | Setting |
| --- | --- | --- |
| Azure | Azure Managed Redis or Azure Cache for Redis, with Microsoft Entra authentication | `azure` |
| AWS | Amazon ElastiCache for Valkey 7.2 or later or Redis OSS 7.0 or later, with IAM authentication | `aws` |
| Google Cloud | Memorystore for Valkey or Memorystore for Redis Cluster, with IAM authentication | `gcp` |

The Celery broker needs a single Redis endpoint that does not require the cluster protocol: on Azure Managed Redis, the **Enterprise** clustering policy; on ElastiCache and Memorystore for Valkey, cluster mode disabled.

The token is a bearer credential, so it only travels over TLS with the server's certificate checked: the broker and cache URLs must be `rediss://`, and DefectDojo refuses `ssl_cert_reqs=none` and `ssl_check_hostname=false` in a passwordless mode. Trust the server's certificate authority instead. Not supported together with passwordless Redis authentication: the Redis container the Helm chart can deploy, and any Redis password.

## Kubernetes (Helm)

Point the broker at your managed Redis over TLS, set `redis.auth.mode`, and leave every Redis password setting empty:

```yaml
redis:
  enabled: false
  auth:
    mode: azure              # azure, aws or gcp
    username: ""             # see the cloud's section below
    password: ""
    injectUrls: false
  master:
    service:
      ports:
        redis: 10000         # Azure Managed Redis: 10000; Azure Cache for Redis: 6380; ElastiCache and Memorystore: 6379
celery:
  broker:
    external: true
    scheme: rediss
    host: <Redis endpoint>
serviceAccount:
  annotations: {}            # binds the application pods to their cloud identity (see below)
```

The chart renders no Redis password in this mode, and refuses to render when `redis.enabled`, `redis.auth.password`, `redis.auth.injectUrls`, or `DD_CELERY_BROKER_PASSWORD` in `config.extra` or `secrets.extra` is also set, or when the broker scheme is not `rediss`.

## Docker Compose and other deployments

The same settings are environment variables. Put no password in `DD_CELERY_BROKER_URL` or `DD_CACHE_URL`, and use `rediss://` for both.

| Variable | Value |
| --- | --- |
| `DD_REDIS_AUTH_MODE` | `password` (the default), `azure`, `aws` or `gcp` |
| `DD_REDIS_AUTH_USERNAME` | Azure, optional: the identity's object (principal) ID; unset, it is read from the token. AWS: the ElastiCache user ID. Google Cloud: leave unset (a user name is refused) |
| `DD_REDIS_AUTH_AZURE_CLIENT_ID` | Azure, optional: the client ID of a user-assigned managed identity |
| `DD_REDIS_AUTH_AZURE_SCOPE` | Azure, optional: the token scope; only sovereign clouds need anything but `https://redis.azure.com/.default` |
| `DD_REDIS_AUTH_AWS_REGION` | AWS: the region the token is signed for; defaults to `AWS_REGION` or the SDK's configured region, and startup is refused when there is none |
| `DD_REDIS_AUTH_AWS_CACHE_NAME` | AWS: the replication group ID, or the serverless cache name |
| `DD_REDIS_AUTH_AWS_SERVERLESS` | AWS: `true` for an ElastiCache Serverless cache |

Each process gets its token through its cloud SDK's default credential chain, which on a virtual machine includes the machine's own identity: a managed identity on Azure, an instance profile on EC2, or the attached service account on Compute Engine.

## Prepare Redis

### Azure

1. On AKS, enable the OIDC issuer and workload identity, create a user-assigned managed identity for DefectDojo, and give it a federated credential for the release's ServiceAccount (`system:serviceaccount:<namespace>:<release ServiceAccount>`, audience `api://AzureADTokenExchange`). If you already use passwordless database authentication, the same identity works for both.
2. Annotate the ServiceAccount with `azure.workload.identity/client-id: <client ID>`. The chart adds the `azure.workload.identity/use` pod label in this mode.
3. On the cache, enable Microsoft Entra authentication and assign the managed identity a data access policy that can read and write data (on Azure Managed Redis, the database's `default` access policy; on Azure Cache for Redis, **Data Contributor** or **Data Owner**). The portal does this under the cache's **Authentication** settings; the assignment names the identity by its object (principal) ID.
4. Once DefectDojo runs on the token, disable access key authentication on the cache.

Redis takes the identity's object (principal) ID as the user name. DefectDojo reads it from the token, so `redis.auth.username` can stay empty; set it to the principal ID only if your tokens do not carry an `oid` claim.

### AWS

1. Create the replication group (or serverless cache) with encryption in transit, on Valkey 7.2 or later or Redis OSS 7.0 or later.
2. Create an ElastiCache user for DefectDojo with IAM authentication. Its user ID and user name must be the same:
   ```bash
   aws elasticache create-user --user-id dojo-app --user-name dojo-app \
     --engine valkey --authentication-mode Type=iam --access-string "on ~* &* +@all"
   ```
   Add it to a user group attached to the cache.
3. Give the pods' IAM role `elasticache:Connect` on both the cache and the user:
   `arn:aws:elasticache:<region>:<account>:replicationgroup:<id>` (or `serverlesscache:<name>`) and `arn:aws:elasticache:<region>:<account>:user:dojo-app`. Bind the role to the ServiceAccount with IRSA (`eks.amazonaws.com/role-arn`) or EKS Pod Identity.
4. Set `redis.auth.username: dojo-app`, `redis.auth.awsCacheName` to the replication group ID or serverless cache name, and `redis.auth.awsServerless: true` for a serverless cache.

### Google Cloud

1. Create the instance with IAM authentication and in-transit encryption enabled.
2. Grant the application's Google service account `roles/memorystore.dbConnectionUser` (Memorystore for Valkey) or `roles/redis.dbConnectionUser` (Memorystore for Redis Cluster), bind it to the release's ServiceAccount with `roles/iam.workloadIdentityUser`, and annotate the ServiceAccount with `iam.gke.io/gcp-service-account`.
3. Leave `redis.auth.username` empty: Memorystore signs in the token as its `default` user, and DefectDojo refuses a user name in this mode.

Memorystore signs its server certificates with the instance's own certificate authority. Download it from the instance and add it to the pods' trusted certificate authorities, so the connection to Redis is verified.

## Switching an existing install

Give the identity its access on the Redis side first, while access keys still work. Then upgrade with `redis.auth.mode` set and the password settings removed. Disable access keys only after every pod has restarted on the token.

## Troubleshooting

- **The pods do not start, and the log says `DD_REDIS_AUTH_MODE=... needs TLS`**: change the broker and cache URLs (or `celery.broker.scheme`) to `rediss://`.
- **`Could not get a Redis token`**: the pod has no cloud identity. Check the ServiceAccount annotation, the federated credential or role binding, and on Azure the `azure.workload.identity/use` pod label.
- **`WRONGPASS` or `invalid username-password pair`**: the identity has no access policy (Azure), no IAM user or `elasticache:Connect` permission (AWS), or no connection role (Google Cloud), or the change has not propagated yet. On Azure, check that the user name is the identity's principal ID, not its client ID.
