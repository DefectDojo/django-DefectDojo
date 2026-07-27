---
title: "FIPS 140-3 Mode"
date: 2026-07-27T00:00:00+00:00
weight: 6
audience: pro
---

DefectDojo Pro can be deployed with FIPS 140-3 validated cryptography, for environments subject to FedRAMP control **SC-13** or similar requirements.

FIPS mode is delivered as a **separate set of container images**, identified by a `-fips` tag suffix. The standard images are unchanged: enabling FIPS is an explicit choice, not a silent default.

For access to FIPS images, contact us at [hello@defectdojo.com](mailto:hello@defectdojo.com).

## What the FIPS images provide

All cryptographic operations are performed by the **OpenSSL FIPS Provider 3.1.2**, which holds **NIST CMVP certificate [#4985](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4985)** under FIPS 140-3. The provider is embedded in the image and enforced in-process.

Because enforcement happens **inside the container**, FIPS mode does not require the host to be running a FIPS-enabled kernel. This matters on managed container runtimes — AWS ECS/Fargate, for example — where the host operating system is not under your control.

Coverage:

| Component | Cryptography |
|---|---|
| Django application (uWSGI) | Python `ssl`/`hashlib`, `cryptography`, `pyOpenSSL`, PyJWT, database and cache client TLS |
| nginx | TLS termination, restricted to FIPS-approved cipher suites |
| Celery / orchestration workers | Credential decryption, token handling, outbound TLS |

> **FIPS 140-3, not 140-2.** FIPS 140-3 supersedes 140-2 and satisfies a requirement written against it. All FIPS 140-2 certificates move to the CMVP Historical List on **21 September 2026** and stop supporting new deployments after that date, so new systems should be validated against a 140-3 module.

## Enabling FIPS mode

Deploy the `-fips` image variants and set `DD_FIPS_MODE=1` on the application, worker, and nginx services.

```yaml
services:
  uwsgi:
    image: defectdojo-pro-django:<version>-fips
    environment:
      DD_FIPS_MODE: "1"
  celeryworker:
    image: defectdojo-pro-django:<version>-fips
    environment:
      DD_FIPS_MODE: "1"
  nginx:
    image: defectdojo-pro-nginx:<version>-fips
    environment:
      DD_FIPS_MODE: "1"
```

### Fail-closed startup

With `DD_FIPS_MODE` set, every container verifies at startup that the validated provider is loaded and that non-approved algorithms are genuinely refused. **If that check fails, the container exits rather than starting.**

This is deliberate. A container that quietly fell back to non-validated cryptography would keep serving traffic while breaking your compliance posture, and the failure would not be visible until an assessment. Failing to start is the safer outcome.

## Verifying FIPS mode

Each container prints an evidence block at startup. On managed runtimes this lands in your log aggregator (CloudWatch, for example), which is usually the most convenient form for an assessor:

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

You can also verify on demand inside a running container:

```bash
# The validated provider must be listed as active
openssl list -providers

# A non-approved algorithm must be unavailable
openssl md5 /dev/null        # expected to fail

# Application-level check (Django containers)
python3 /verify_fips.py
```

## Behaviour differences in FIPS mode

Some non-approved algorithms are unavailable, so a few behaviours change. These are the ones worth planning for.

### Password hashing

FIPS builds use **PBKDF2-SHA256** as the default password hasher. Argon2, bcrypt and scrypt are not FIPS-approved key-derivation functions and are disabled.

Existing users are not locked out. Django re-hashes each password to PBKDF2 on the user's next successful login, and PBKDF2-SHA1 hashes remain verifiable during the transition. If you prefer a hard cutover, force a password reset instead of relying on gradual migration.

### TLS cipher suites

ChaCha20-Poly1305 is not FIPS-approved and is removed from the nginx cipher list. TLS 1.2 and TLS 1.3 remain available using AES-GCM suites. Clients that only support ChaCha20 will not be able to connect.

### Metrics basic authentication

When nginx metrics authentication is enabled, the password hash uses SHA-256 crypt rather than Apache's MD5 (`apr1`) format, which the validated module refuses. This is transparent unless you generate `.htpasswd` entries yourself, in which case generate them with `openssl passwd -5`.

### Scan parsers

Some parsers use MD5 to build deduplication keys. This is a non-security use and is explicitly annotated as such, so those parsers continue to work normally under FIPS. No parser functionality is lost.

## Deployment notes

- **TLS termination.** If TLS terminates at a load balancer in front of DefectDojo, that device is responsible for its own FIPS posture and should be documented separately in your system security plan. The `-fips` nginx image covers TLS terminated by DefectDojo itself.
- **Database and cache.** PostgreSQL and Redis/Valkey are deployed alongside DefectDojo but are separate products. In a FIPS environment, use FIPS-compliant instances of these services — for example a managed database offering a FIPS endpoint — and document them as inherited components.
- **Compliance scope.** DefectDojo is not itself a cryptographic module and holds no certificate of its own. What these images provide is validated cryptography performed by a module that does, running in FIPS-approved mode. Your assessor will want the module and certificate number, which are stated in the evidence output above.
