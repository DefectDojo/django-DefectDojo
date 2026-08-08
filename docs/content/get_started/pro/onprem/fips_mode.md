---
title: "FIPS 140-3 Mode"
date: 2026-07-27T00:00:00+00:00
weight: 6
audience: pro
---

DefectDojo Pro can be deployed with FIPS 140-3 validated cryptography, for environments subject to FedRAMP control **SC-13** or similar requirements.

FIPS mode ships as a **separate set of container images**, identified by a `-fips` tag suffix. The standard images are unchanged: enabling FIPS is an explicit choice, never a silent default.

For access to FIPS images, contact us at [hello@defectdojo.com](mailto:hello@defectdojo.com).

## What the FIPS images provide

All cryptographic operations are performed by the **OpenSSL FIPS Provider 3.1.2**, which holds NIST CMVP certificate **[#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985)** under FIPS 140-3. Go services use the **Go Cryptographic Module v1.0.0**, CMVP certificate **[#5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247)**.

Because enforcement happens **inside the container**, FIPS mode does not require the host to run a FIPS-enabled kernel. That is what makes it workable on managed container runtimes such as **Amazon ECS with the Fargate launch type**, where the host operating system is not under your control.

> **FIPS 140-3, not 140-2.** FIPS 140-3 supersedes 140-2 and satisfies a requirement written against it. All FIPS 140-2 certificates move to the CMVP Historical List on **21 September 2026** and stop supporting new deployments after that date, so new systems should be validated against a 140-3 module.

### Coverage

| Component | Covered | Module |
|---|:---:|---|
| Django application (`dojo`) | yes | OpenSSL FIPS Provider 3.1.2 |
| Async import (`dojo-import-scan`) | yes | OpenSSL FIPS Provider 3.1.2 |
| Celery worker and beat | yes | OpenSSL FIPS Provider 3.1.2 |
| Initializer (`init`) | yes | OpenSSL FIPS Provider 3.1.2 |
| Orchestration workers (`ddorch-workers`) | yes | OpenSSL FIPS Provider 3.1.2 |
| nginx | yes | OpenSSL FIPS Provider 3.1.2 |
| PSIRT advisory engine | yes | OpenSSL FIPS Provider 3.1.2 |
| Connectors, Integrators, ddorch, MCP server | yes | Go Cryptographic Module v1.0.0 |
| **Sensei** | **partial** | service binaries: Go Cryptographic Module v1.0.0. Bundled scanner toolchain: **not covered** |
| **PostgreSQL / Redis (embedded)** | **no** | use external FIPS-compliant services |

**Sensei is a partial case worth understanding.** Its own binaries are built against the validated Go module, so the job API's TLS and tokens are covered. The image also bundles a polyglot third-party scanner toolchain — Node (which ships its own OpenSSL), Rust (rustls), Python, Ruby, and third-party Go binaries we do not compile — and several of those fetch advisory databases over TLS using their own cryptography. That toolchain cannot be brought under a single validated module, so it is not covered and should not be represented as such to an assessor.

The embedded PostgreSQL/Redis have no FIPS variant at all. In Kubernetes the chart refuses to render if you enable FIPS alongside Sensei or the embedded datastores, so the trade-off is an explicit decision rather than an assumption (see [Guard rails](#guard-rails)).

## Enabling FIPS mode — Docker Compose

Two changes: use the `-fips` images, and set `DD_FIPS_MODE`.

**1. Point the image tags at the FIPS variants.** In your `.env` or compose override:

```bash
DD_IMAGE_TAG=<version>-fips
```

**2. Set `DD_FIPS_MODE` in the shared environment anchors.** The compose file defines shared blocks that every relevant service merges, so this is three edits rather than one per service:

```yaml
x-dojo-vars: &dojoenv
  DD_FIPS_MODE: "1"        # dojo, dojo-import-scan, celerybeat, celeryworker, init, ddorch-workers
  # ... existing settings

x-nginx-vars: &nginxenv
  DD_FIPS_MODE: "1"        # nginx
  # ... existing settings

x-psirt-vars: &psirtenv
  DD_FIPS_MODE: "1"        # psirt
  # ... existing settings
```

Then recreate the stack:

```bash
docker compose up -d --force-recreate
```

## Enabling FIPS mode — Kubernetes (Helm)

Set one value. The chart selects the `-fips` image variants and sets `DD_FIPS_MODE` for every pod:

```yaml
fips:
  enabled: true
```

```bash
helm upgrade --install dojopro charts/dojopro \
  -f your-values.yaml \
  --set fips.enabled=true
```

Because the embedded datastores have no FIPS variant and Sensei is only partially covered, a FIPS install should use external PostgreSQL and Redis, and leave Sensei disabled unless you accept the caveat above:

```yaml
fips:
  enabled: true
sensei:
  enabled: false          # partial coverage — see the table above
postgresql:
  enabled: false          # use an external FIPS-compliant database
redis:
  enabled: false          # use an external FIPS-compliant cache
```

If you need Sensei in a FIPS environment, enable it deliberately with
`fips.validate: false` and document the bundled scanner toolchain as
non-validated in your system security plan.

### Guard rails

If `fips.enabled` is true while a component without a FIPS variant is also enabled, **the chart refuses to render** and names the offenders:

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei (service crypto validated; bundled scanner toolchain is not),
redis (embedded). Disable them, or set fips.validate=false to accept that they
run non-validated cryptography.
```

This is deliberate. A deployment where most services use validated cryptography and one or two quietly do not is worse than an obvious failure: it looks compliant, survives a casual inspection, and only surfaces during an assessment. If you have accepted that risk in writing, override it with `fips.validate: false`.

## Enabling FIPS mode — Amazon ECS / Fargate

Fargate is a launch type for ECS, not a separate service: you register ECS task
definitions with `requiresCompatibilities: ["FARGATE"]` and `networkMode: awsvpc`.

If you already run DefectDojo Pro on ECS, only two things change:

**1. Image tags** gain the `-fips` suffix:

```
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips
<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips
```

**2. `DD_FIPS_MODE=1`** in the `environment` block of every container running
application code — uwsgi, celery worker, celery beat, the initializer, the
orchestration workers, nginx and psirt.

The rest of this section is a complete FIPS-enabled ECS deployment for readers
starting from nothing.

### What to provision first

| Resource | Notes |
|---|---|
| VPC with two subnets | Private subnets plus a NAT gateway, or public subnets with `assignPublicIp: ENABLED` |
| RDS for PostgreSQL | Use a FIPS-capable endpoint and document it as an inherited component |
| ElastiCache for Redis | Two logical databases are used: `/0` for the Celery broker, `/1` for the cache |
| EFS file system | Two directories: one for `/app/media`, one holding the nginx TLS certificates |
| Secrets Manager entries | Database URL, `DD_SECRET_KEY`, `DD_CREDENTIAL_AES_256_KEY`, and your Pro licence |
| Application Load Balancer | HTTPS listener, forwarding to an **HTTPS** target group on port **8443** |
| ECR repositories | Holding the two `-fips` images |
| IAM roles | An execution role that can pull from ECR, write logs and read those secrets, plus a task role |
| CloudWatch log group | Referenced by every container's `awslogs` configuration |

Put the TLS certificate and key on EFS as `dojo.crt` / `dojo.key`, plus
`nginx_int.crt` / `nginx_int.key`. Both pairs must exist — see
[Three things ECS needs](#three-things-ecs-needs-that-compose-provides-for-free)
below for why.

### 1. The initializer task (run once per upgrade)

Applies migrations and seeds first-boot data, then exits. It is a task, not a
service.

```json
{
  "family": "defectdojo-pro-init",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "containerDefinitions": [
    {
      "name": "init",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-initializer.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_INITIALIZE", "value": "true" },
        { "name": "DD_ALLOWED_HOSTS", "value": "<YOUR_HOSTNAME>" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" },
        { "name": "DD_ADMIN_USER", "value": "admin" },
        { "name": "DD_ADMIN_MAIL", "value": "admin@example.com" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_ADMIN_PASSWORD", "valueFrom": "<SECRET_ARN_ADMIN_PASSWORD>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "init"
        }
      }
    }
  ]
}
```

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-init.json
aws ecs run-task --cluster <CLUSTER> --launch-type FARGATE \
  --task-definition defectdojo-pro-init \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}"
```

Wait for it to reach `STOPPED` with exit code 0 before starting the services.

### 2. The web service (nginx + uwsgi)

Both containers live in one task so nginx reaches uwsgi on `127.0.0.1`.

```json
{
  "family": "defectdojo-pro-web",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "volumes": [
    {
      "name": "media",
      "efsVolumeConfiguration": {
        "fileSystemId": "<EFS_FILESYSTEM_ID>",
        "transitEncryption": "ENABLED",
        "rootDirectory": "/media"
      }
    },
    {
      "name": "certs",
      "efsVolumeConfiguration": {
        "fileSystemId": "<EFS_FILESYSTEM_ID>",
        "transitEncryption": "ENABLED",
        "rootDirectory": "/nginx-certs"
      }
    }
  ],
  "containerDefinitions": [
    {
      "name": "uwsgi",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_UWSGI_ENDPOINT", "value": "0.0.0.0:3031" },
        { "name": "DD_ALLOWED_HOSTS", "value": "<YOUR_HOSTNAME>" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "mountPoints": [{ "sourceVolume": "media", "containerPath": "/app/media" }],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "uwsgi"
        }
      }
    },
    {
      "name": "nginx",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-nginx:<VERSION>-fips",
      "essential": true,
      "dependsOn": [{ "containerName": "uwsgi", "condition": "START" }],
      "portMappings": [{ "containerPort": 8443, "protocol": "tcp" }],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "USE_TLS", "value": "false" },
        { "name": "GENERATE_TLS_CERTIFICATE", "value": "false" },
        { "name": "DD_UWSGI_HOST", "value": "127.0.0.1" },
        { "name": "DD_UWSGI_PORT", "value": "3031" },
        { "name": "DD_UWSGI_IMPORT_HOST", "value": "127.0.0.1" },
        { "name": "DD_UWSGI_IMPORT_PORT", "value": "3031" },
        { "name": "DD_SITE_URL", "value": "https://<YOUR_HOSTNAME>" },
        { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
        { "name": "DD_MCP_PORT", "value": "9142" },
        { "name": "PSIRT_ENABLED", "value": "false" },
        { "name": "NGINX_METRICS_ENABLED", "value": "false" }
      ],
      "mountPoints": [
        { "sourceVolume": "certs", "containerPath": "/etc/nginx/certs", "readOnly": true }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "nginx"
        }
      }
    }
  ]
}
```

`USE_TLS=false` selects the on-prem configuration, which terminates TLS itself on
8443 using the mounted certificates. Register it and create a service attached to
the load balancer:

```bash
aws ecs register-task-definition --cli-input-json file://taskdef-web.json
aws ecs create-service --cluster <CLUSTER> --service-name defectdojo-pro-web \
  --task-definition defectdojo-pro-web --launch-type FARGATE --desired-count 2 \
  --network-configuration "awsvpcConfiguration={subnets=[<SUBNET_A>,<SUBNET_B>],securityGroups=[<SG>]}" \
  --load-balancers "targetGroupArn=<TARGET_GROUP_ARN>,containerName=nginx,containerPort=8443"
```

### 3. The worker service (Celery worker and beat)

Same image and same secrets as uwsgi; the entry point selects the process. Run
exactly **one** beat replica.

```json
{
  "family": "defectdojo-pro-worker",
  "requiresCompatibilities": ["FARGATE"],
  "networkMode": "awsvpc",
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "<EXECUTION_ROLE_ARN>",
  "taskRoleArn": "<TASK_ROLE_ARN>",
  "runtimePlatform": { "cpuArchitecture": "X86_64", "operatingSystemFamily": "LINUX" },
  "containerDefinitions": [
    {
      "name": "celeryworker",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-celery-worker.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "celeryworker"
        }
      }
    },
    {
      "name": "celerybeat",
      "image": "<ACCOUNT>.dkr.ecr.<REGION>.amazonaws.com/defectdojo-pro-django:<VERSION>-fips",
      "essential": true,
      "entryPoint": ["/entrypoint-celery-beat.sh"],
      "environment": [
        { "name": "DD_FIPS_MODE", "value": "1" },
        { "name": "DD_CELERY_BROKER_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/0" },
        { "name": "DD_CACHE_URL", "value": "redis://<ELASTICACHE_ENDPOINT>:6379/1" }
      ],
      "secrets": [
        { "name": "DD_DATABASE_URL", "valueFrom": "<SECRET_ARN_DATABASE_URL>" },
        { "name": "DD_SECRET_KEY", "valueFrom": "<SECRET_ARN_SECRET_KEY>" },
        { "name": "DD_CREDENTIAL_AES_256_KEY", "valueFrom": "<SECRET_ARN_AES_KEY>" },
        { "name": "DD_LICENSE", "valueFrom": "<SECRET_ARN_LICENSE>" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "<LOG_GROUP>",
          "awslogs-region": "<REGION>",
          "awslogs-stream-prefix": "celerybeat"
        }
      }
    }
  ]
}
```

### 4. Confirm the deployment is running validated cryptography

```bash
aws logs tail <LOG_GROUP> --filter-pattern FIPS
```

Every container should report the module before it serves anything:

```
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
```

If a container is missing from that output it never started, because the check
fails closed — look at its log stream for the reason.

### Three things ECS needs that Compose provides for free

Docker Compose gives you a host filesystem to bind-mount from and DNS for
container names. Fargate provides neither, and each gap prevents nginx from
starting rather than degrading quietly.

**1. TLS certificates must exist before nginx starts.** nginx validates every
`ssl_certificate` at config load, and the on-prem configuration has no
certificate-free path: port 8080 only issues a `301` to HTTPS, so the 8443 TLS
listener is the functional one. Mount an **EFS** volume at `/etc/nginx/certs`
containing `dojo.crt` / `dojo.key` and `nginx_int.crt` / `nginx_int.key`. Both
pairs must be present even if you only use one listener.

Alternatively set `USE_TLS=true`, which serves the upstream `nginx_TLS.conf` and
lets `GENERATE_TLS_CERTIFICATE=true` have the entrypoint generate its own
certificate. That configuration proxies every path to Django and does not serve
the Vue UI from `/ui`, so it suits an API-only or strictly behind-ALB deployment.

**2. `DD_MCP_HOST` must resolve.** nginx resolves `proxy_pass` hostnames at
config load. The default `mcp-server` resolves under Compose (container name) and
Helm (Service name), but `awsvpc` gives containers no DNS names of their own and
rejects both `extraHosts` and `dnsSearchDomains`:

```json
{
  "environment": [
    { "name": "DD_MCP_HOST", "value": "127.0.0.1" },
    { "name": "DD_MCP_PORT", "value": "9142" }
  ]
}
```

Pointing it at loopback when the MCP server is not deployed makes `/mcp` answer
`502` rather than preventing the whole web tier from starting.

**3. The nginx configuration files come from the image.** The `-fips` nginx image
bakes the on-prem configuration set in, so no mounts are needed. Compose overlays
its own bind mounts, so Compose behaviour is unchanged.

### Other Fargate specifics

- **Persistent storage must be EFS.** Fargate cannot attach EBS, so the media
  directory (`/app/media`) needs an EFS volume if you retain uploaded scan files.
- **No privileged containers or host networking are required.** The images run
  as a non-root user, and `awsvpc` gives each task its own network interface.
- **nginx → uwsgi.** Containers in the *same* task share a network namespace, so
  co-locating nginx with uwsgi lets nginx reach it on `127.0.0.1` — the simplest
  correct option. If you split them into separate ECS services, point
  `DD_UWSGI_HOST` at a Cloud Map service-discovery name and open the security
  group on the uwsgi port.
- **Do not override the uwsgi entrypoint.** Set
  `DD_UWSGI_ENDPOINT=0.0.0.0:3031` and leave the image ENTRYPOINT in place;
  uwsgi speaks the uwsgi protocol, which is what nginx expects. Replacing the
  entrypoint with `uwsgi --http` skips the FIPS startup check along with it.
- **The initializer is a one-shot task**, not a service. Run it with
  `aws ecs run-task` (or as a pre-deploy step) and let it exit; do not give it a
  desired count.
- **`healthCheck.retries` cannot exceed 10.** Higher values are rejected when
  the task definition is registered.
- **Point the load balancer at 8443** with an HTTPS target group. The on-prem
  configuration's 8080 listener only redirects to HTTPS, so targeting 8080 loops.
  A self-signed certificate on the target is acceptable to an ALB.
- **TLS termination.** If the ALB terminates TLS for clients, document the load
  balancer's own FIPS posture separately in your SSP.
- **Secrets** belong in Secrets Manager or SSM Parameter Store through the
  `secrets` block, never in `environment`. That includes `DD_LICENSE`.

### Retrieving evidence on ECS

The startup evidence block lands in the log group named by the container's
`awslogs` configuration:

```bash
aws logs tail /ecs/<YOUR_LOG_GROUP> --filter-pattern FIPS
```

On demand inside a running task (requires `enableExecuteCommand` on the service):

```bash
aws ecs execute-command --cluster <CLUSTER> --task <TASK_ID> \
  --container uwsgi --interactive --command "python3 /verify_fips.py"
```

## Fail-closed startup

With `DD_FIPS_MODE` set, every container verifies at startup that the validated provider is loaded and that non-approved algorithms are genuinely refused. **If that check fails, the container exits instead of starting.**

Same reasoning as the chart guard: a container that quietly fell back to non-validated cryptography would keep serving traffic while breaking your compliance posture, and you would not find out until an assessment.

## Verifying FIPS mode

Each container prints an evidence block at startup, which is usually the most convenient form for an assessor. On managed runtimes it lands in your log aggregator:

```
================================================================
[FIPS] DefectDojo Pro FIPS mode verification
Providers:
  fips
    name: OpenSSL FIPS Provider
    version: 3.1.2
    status: active
[FIPS] MODE: ACTIVE
[FIPS] Module: OpenSSL FIPS Provider 3.1.2 (CMVP #4985, FIPS 140-3)
[FIPS] Non-approved algorithms (MD5-as-security, ChaCha20): blocked
================================================================
```

Retrieve it with:

```bash
# Docker Compose
docker compose logs dojo | grep FIPS

# Kubernetes
kubectl logs deploy/dojopro-django | grep FIPS
```

You can also verify on demand inside a running container:

```bash
# Docker Compose
docker compose exec dojo openssl list -providers     # fips provider, 3.1.2, active
docker compose exec dojo openssl md5 /dev/null       # expected to FAIL
docker compose exec dojo python3 /verify_fips.py     # full check

# Kubernetes
kubectl exec deploy/dojopro-django -- openssl list -providers
kubectl exec deploy/dojopro-django -- python3 /verify_fips.py
```

For Go services, FIPS mode is compiled in and reported by the Go runtime:

```bash
kubectl exec deploy/dojopro-connectors -- printenv GODEBUG   # fips140=on
```

## Behaviour differences in FIPS mode

Some non-approved algorithms are unavailable, so a few behaviours change. These are the ones worth planning for.

### Password hashing

FIPS builds use **PBKDF2-SHA256** as the default password hasher. Argon2, bcrypt and scrypt are not FIPS-approved key-derivation functions and are disabled.

Existing users are not locked out. Django re-hashes each password to PBKDF2 on the user's next successful login, and PBKDF2-SHA1 hashes remain verifiable during the transition. If you prefer a hard cutover, force a password reset rather than relying on gradual migration.

### TLS cipher suites

ChaCha20-Poly1305 is not FIPS-approved and is removed from every nginx configuration that terminates TLS, and TLS 1.3 is pinned to `TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256`. TLS 1.2 and TLS 1.3 remain available using AES-GCM suites. Clients that support only ChaCha20 will not be able to connect.

The validated module would refuse ChaCha20 in any case; removing it from the configuration means the server never advertises a suite it cannot complete, which keeps the deployed configuration self-documenting for an assessor.

### Metrics basic authentication

When nginx metrics authentication is enabled, the password hash uses SHA-256 crypt rather than Apache's MD5 (`apr1`) format, which the validated module refuses. This is transparent unless you generate `.htpasswd` entries yourself, in which case use `openssl passwd -5`.

### Scan parsers

Some parsers use MD5 to build deduplication keys. That is a non-security use and is explicitly annotated as such, so those parsers continue to work normally under FIPS. No parser functionality is lost.

## Deployment notes

- **TLS termination.** If TLS terminates at a load balancer in front of DefectDojo, that device is responsible for its own FIPS posture and should be documented separately in your system security plan. The `-fips` nginx image covers TLS terminated by DefectDojo itself.
- **Database and cache.** PostgreSQL and Redis are separate products. In a FIPS environment, use FIPS-compliant instances — for example a managed database offering a FIPS endpoint — and document them as inherited components.
- **Compliance scope.** DefectDojo is not itself a cryptographic module and holds no certificate of its own. What these images provide is validated cryptography performed by modules that do, running in FIPS-approved mode. Your assessor will want the module names and certificate numbers, which appear in the evidence output above.
