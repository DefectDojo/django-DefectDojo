---
title: "FIPS 140-3 Mode"
description: "Deploy DefectDojo Pro with FIPS 140-3 validated cryptography using the -fips container images, for FedRAMP SC-13 and similar requirements"
draft: false
date: 2026-07-27T00:00:00+00:00
weight: 8
audience: pro
---

DefectDojo Pro can be deployed with FIPS 140-3 validated cryptography, for environments subject to FedRAMP control **SC-13** or similar requirements.

FIPS mode ships as a **separate set of container images**, identified by a `-fips` tag suffix. The standard images are unchanged: enabling FIPS is an explicit choice, never a silent default.

FIPS images are published for every release from **3.3.200**. They come from the same registry as the standard images, and the registry credentials in your license already pull them, so there is nothing to request or enable. See [Getting the FIPS images](#getting-the-fips-images).

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
| Connectors, Integrators, ddorch, MCP server | yes | Go Cryptographic Module v1.0.0 |
| **Sensei** | **partial** | service binaries: Go Cryptographic Module v1.0.0. Bundled scanner toolchain: **not covered** |
| **PostgreSQL / Redis (embedded)** | **no** | use external FIPS-compliant services |
| **OSCAL validator** | **no** | no FIPS variant; leave it disabled |

**Sensei is a partial case worth understanding.** Its own binaries are built against the validated Go module, so the job API's TLS and tokens are covered. The image also bundles a polyglot third-party scanner toolchain — Node (which ships its own OpenSSL), Rust (rustls), Python, Ruby, and third-party Go binaries we do not compile — and several of those fetch advisory databases over TLS using their own cryptography. That toolchain cannot be brought under a single validated module, so it is not covered and should not be represented as such to an assessor.

The embedded PostgreSQL/Redis have no FIPS variant at all. In Kubernetes the chart refuses to render if you enable FIPS alongside Sensei, the embedded datastores, or the OSCAL validator, so the trade-off is an explicit decision rather than an assumption; see the Kubernetes tab under [Enabling FIPS mode](#enabling-fips-mode).

## Getting the FIPS images

Each image with a FIPS variant is published next to its standard image, in the same repository, tagged `<version>-fips`:

```
us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro/django:<version>-fips
us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro/nginx:<version>-fips
us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-connectors/connectors:<version>-fips
us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-integrators/integrators:<version>-fips
us-south1-docker.pkg.dev/defectdojo-container-registry/ddorch/ddorch:<version>-fips
us-south1-docker.pkg.dev/defectdojo-container-registry/go-dd-pro-mcp/mcp-server:<version>-fips
```

The registry credentials that come with your license cover these repositories, the same as the standard images. Nothing needs to be requested or enabled on your account.

On Kubernetes and Docker Compose you do not write these tags yourself: `fips.enabled` and `DD_FIPS_MODE` select them, as described under [Enabling FIPS mode](#enabling-fips-mode). You need them directly when you write your own deployment, such as an [Amazon ECS task definition](/get_started/pro/onprem/fips_on_ecs_fargate/), or when you mirror images into a private registry.

**linux/amd64 only.** The OpenSSL FIPS Provider's certificate lists x86_64 operating environments, so the FIPS images are published for amd64 and not for arm64. A FIPS deployment needs amd64 nodes.

**Signed.** Like the standard release images, each FIPS image is signed and carries SPDX and CycloneDX SBOM attestations.

## Enabling FIPS mode

{{< tabs "fips-enable" >}}
{{< tab "Kubernetes" >}}
Requires DefectDojo Pro 3.3.200 or later. Set one value. The chart selects the `-fips` image variants and sets `DD_FIPS_MODE` for every pod:

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
  enabled: false          # partial coverage, see the coverage table above
postgresql:
  enabled: false          # use an external FIPS-compliant database
redis:
  enabled: false          # use an external FIPS-compliant cache
```

If you need Sensei in a FIPS environment, enable it deliberately with `fips.validate: false` and document the bundled scanner toolchain as non-validated in your system security plan.

**Guard rails.** If `fips.enabled` is true while a component without a FIPS variant is also enabled, the chart refuses to render and names the offenders:

```
Error: fips.enabled is true but these services have no FIPS image variant:
sensei (service crypto validated; bundled scanner toolchain is not),
redis (embedded). Disable them, or set fips.validate=false to accept that they
run non-validated cryptography.
```

This is deliberate. A deployment where most services use validated cryptography and one or two quietly do not is worse than an obvious failure: it looks compliant, survives a casual inspection, and only surfaces during an assessment. If you have accepted that risk in writing, override it with `fips.validate: false`.
{{< /tab >}}
{{< tab "Compose" >}}
From version 3.3.300, one variable does both halves. `DD_FIPS_MODE` selects the `-fips` image of every service that has one, and turns on enforcement in the containers that check it, so the images and the setting cannot drift apart. Set it with the CLI, which keeps it in its own configuration, so it survives upgrades:

```bash
dojo-compose-cli environment add -k DD_FIPS_MODE -v 1
dojo-compose-cli app pull-images
dojo-compose-cli app restart
```

To turn FIPS mode off, remove the variable with `dojo-compose-cli environment remove -k DD_FIPS_MODE` and restart. Do not set it to `0`: any value selects the FIPS images.

The embedded Valkey cache and Sensei keep their standard images, since neither has a FIPS variant. For production, point DefectDojo at an external FIPS-compliant cache (see [Deployment notes](#deployment-notes)). Sensei runs only when your license includes it, and is partially covered, as described under [Coverage](#coverage).

**On version 3.3.200.** The 3.3.200 deployment files predate `DD_FIPS_MODE`, so upgrade to 3.3.300 or later to use it. If you need FIPS on 3.3.200, edit `docker-compose.yml` in your install directory instead: add `-fips` after `${version}` on the `x-nginx-image`, `x-django-image`, `x-connectors-image`, `x-integrators-image`, `x-ddorch-image` and `x-mcp-server-image` lines, add `DD_FIPS_MODE: "1"` to the `x-dojo-vars` and `x-nginx-vars` blocks, then run `dojo-compose-cli app restart`. An upgrade replaces `docker-compose.yml`, so these edits do not carry forward.
{{< /tab >}}
{{< /tabs >}}

## Running on Amazon ECS / Fargate

FIPS on Amazon ECS with the Fargate launch type is covered on its own page: see [FIPS 140-3 Mode on Amazon ECS / Fargate](/get_started/pro/onprem/fips_on_ecs_fargate/).

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

{{< tabs "fips-verify-logs" >}}
{{< tab "Kubernetes" >}}
```bash
kubectl logs deploy/dojopro-django | grep FIPS
```
{{< /tab >}}
{{< tab "Compose" >}}
```bash
docker compose logs dojo | grep FIPS
```
{{< /tab >}}
{{< /tabs >}}

You can also verify on demand inside a running container:

{{< tabs "fips-verify-exec" >}}
{{< tab "Kubernetes" >}}
```bash
kubectl exec deploy/dojopro-django -- openssl list -providers
kubectl exec deploy/dojopro-django -- python3 /verify_fips.py
```
{{< /tab >}}
{{< tab "Compose" >}}
```bash
docker compose exec dojo openssl list -providers     # fips provider, 3.1.2, active
docker compose exec dojo openssl md5 /dev/null       # expected to FAIL
docker compose exec dojo python3 /verify_fips.py     # full check
```
{{< /tab >}}
{{< /tabs >}}

For Go services (connectors, integrators, ddorch, MCP server), FIPS mode is compiled in and reported by the Go runtime as `GODEBUG=fips140=on`. Check it on a running service with `kubectl exec` on Kubernetes or `docker compose exec` on Docker Compose, for example `printenv GODEBUG`.

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
- **Database and cache.** PostgreSQL and Redis are separate Assets. In a FIPS environment, use FIPS-compliant instances — for example a managed database offering a FIPS endpoint — and document them as inherited components.
- **Compliance scope.** DefectDojo is not itself a cryptographic module and holds no certificate of its own. What these images provide is validated cryptography performed by modules that do, running in FIPS-approved mode. Your assessor will want the module names and certificate numbers, which appear in the evidence output above.
