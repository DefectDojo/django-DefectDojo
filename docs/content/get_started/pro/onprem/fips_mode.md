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

Because enforcement happens **inside the container**, FIPS mode does not require the host to run a FIPS-enabled kernel. That matters on managed container runtimes — AWS ECS/Fargate, for example — where the host operating system is not under your control.

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
| **Sensei** | **no** | no FIPS variant available |
| **PostgreSQL / Redis (embedded)** | **no** | use external FIPS-compliant services |

Sensei and the embedded datastores have no FIPS variant. In Kubernetes the chart refuses to render if you enable FIPS alongside them, rather than producing a deployment that is only partly validated (see [Guard rails](#guard-rails)).

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

Because Sensei and the embedded datastores have no FIPS variant, a FIPS install must also use external PostgreSQL and Redis, and leave Sensei disabled:

```yaml
fips:
  enabled: true
sensei:
  enabled: false
postgresql:
  enabled: false          # use an external FIPS-compliant database
redis:
  enabled: false          # use an external FIPS-compliant cache
```

### Guard rails

If `fips.enabled` is true while a component without a FIPS variant is also enabled, **the chart refuses to render** and names the offenders:

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei, redis (embedded). Disable them, or set fips.validate=false to accept
that they run non-validated cryptography.
```

This is deliberate. A deployment where most services use validated cryptography and one or two quietly do not is worse than an obvious failure: it looks compliant, survives a casual inspection, and only surfaces during an assessment. If you have accepted that risk in writing, override it with `fips.validate: false`.

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

ChaCha20-Poly1305 is not FIPS-approved and is removed from the nginx cipher list. TLS 1.2 and TLS 1.3 remain available using AES-GCM suites. Clients that support only ChaCha20 will not be able to connect.

### Metrics basic authentication

When nginx metrics authentication is enabled, the password hash uses SHA-256 crypt rather than Apache's MD5 (`apr1`) format, which the validated module refuses. This is transparent unless you generate `.htpasswd` entries yourself, in which case use `openssl passwd -5`.

### Scan parsers

Some parsers use MD5 to build deduplication keys. That is a non-security use and is explicitly annotated as such, so those parsers continue to work normally under FIPS. No parser functionality is lost.

## Deployment notes

- **TLS termination.** If TLS terminates at a load balancer in front of DefectDojo, that device is responsible for its own FIPS posture and should be documented separately in your system security plan. The `-fips` nginx image covers TLS terminated by DefectDojo itself.
- **Database and cache.** PostgreSQL and Redis are separate products. In a FIPS environment, use FIPS-compliant instances — for example a managed database offering a FIPS endpoint — and document them as inherited components.
- **Compliance scope.** DefectDojo is not itself a cryptographic module and holds no certificate of its own. What these images provide is validated cryptography performed by modules that do, running in FIPS-approved mode. Your assessor will want the module names and certificate numbers, which appear in the evidence output above.
