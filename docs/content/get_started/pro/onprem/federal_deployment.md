---
title: "Deploying in Federal Environments"
description: "What a FedRAMP, DoD or other federal assessor asks about self-hosted DefectDojo Pro images: FIPS 140-3 cryptography, non-root containers, cosign signatures and SBOM attestations, and how to collect the evidence"
draft: false
weight: 7
audience: pro
---

This page is for teams deploying self-hosted DefectDojo Pro inside a federal boundary (FedRAMP, DoD RMF, CMMC or a similar program) and for the assessor who reviews that deployment. It covers what the container images guarantee and how to collect the evidence for each claim yourself, without asking DefectDojo for anything beyond the license materials you already have.

The deployment decisions themselves (which release, mirroring, managed PostgreSQL and Redis, SSO) are in [Planning a Private Deployment](/get_started/pro/onprem/private_deployment/). Read that page first if you are still choosing a platform.

## What the images provide

| Requirement | What DefectDojo Pro provides | Details |
|---|---|---|
| Validated cryptography (FedRAMP SC-13) | `-fips` images using the OpenSSL FIPS Provider 3.1.2 (CMVP #4985) and the Go Cryptographic Module v1.0.0 (CMVP #5247), enforced inside the container | [FIPS 140-3 Mode](/get_started/pro/onprem/fips_mode/) |
| Non-root containers | Every DefectDojo Pro application image runs as an unprivileged numeric user, with no setuid or setgid files in the web and worker images | [Containers run as non-root users](#containers-run-as-non-root-users) below |
| Image integrity and provenance | Every release image is signed with cosign | [Verifying Images and SBOMs](/get_started/pro/onprem/image_provenance/) |
| Software inventory | Each image carries signed SPDX and CycloneDX SBOM attestations, and the Helm chart's offline bundle carries the same SBOMs as signed files | [Verifying Images and SBOMs](/get_started/pro/onprem/image_provenance/) |
| Disconnected operation | The instance can run with no route off its network | [Running an Airgapped Instance](/get_started/pro/onprem/airgapped/) |

## Containers run as non-root users

Each DefectDojo Pro application image sets a numeric, unprivileged `USER`, so a container started from it runs without root even when the platform does not override the user:

| Image | Runs as |
|---|---|
| `dojo-pro/django` and `dojo-pro/django:<version>-fips` (web, Celery worker and beat, initializer) | uid 1001 |
| `dojo-pro/nginx` and `dojo-pro/nginx:<version>-fips` | uid 1001 (the Docker Compose bundles run it as 1002) |
| `dojo-pro/webhook-gateway` | uid 10001 |
| `dojo-connectors/connectors`, `ddorch/ddorch`, `go-dd-pro-mcp/mcp-server` | uid 1001 |

The `django` and `nginx` images, standard and `-fips`, are checked in DefectDojo's CI on every change: the configured user must be a numeric uid of 1000 or more that a container really runs as, the image must hold no setuid or setgid file, and no entrypoint may switch user at run time. The `-fips` images remove the setuid and setgid bits their base image ships, as the last step that runs as root.

How the user is applied depends on the platform:

- **Kubernetes.** The Helm chart sets `runAsNonRoot: true`, `runAsUser: 1001` and a `RuntimeDefault` seccomp profile on every DefectDojo Pro pod, and its containers run unprivileged, with privilege escalation disabled and all capabilities dropped.
- **OpenShift.** The chart runs under the default `restricted-v2` security context constraint and leaves the uid for OpenShift to assign. No `anyuid` or `privileged` grant is needed. See [Deploying on OpenShift](/get_started/pro/onprem/kubernetes/openshift_deployment/).
- **Docker Compose and Amazon ECS.** The containers run as the image's own user. In the Compose bundles these services still run as root: the Sensei engine (`sensei-engine`); `shogun-sensor-packages`, a one-shot container that copies signed packages into a volume with no network access and then exits; ClickHouse (`clickhouse`), whose official image starts as root and drops to its own user; and, in the containerized-database bundle only, PostgreSQL (`postgres`), which does the same. Use the separate-database bundle with a managed PostgreSQL in a boundary that requires non-root, and leave Sensei disabled as the [FIPS coverage table](/get_started/pro/onprem/fips_mode/#coverage) already recommends.

Check the user of an image you have pulled or mirrored:

```bash
docker image inspect --format '{{.Config.User}}' \
  registry.internal.example.com/defectdojo/dojo-pro/django:<version>-fips

docker run --rm --network none --entrypoint id \
  registry.internal.example.com/defectdojo/dojo-pro/django:<version>-fips
```

The first command prints `1001`, and the second prints `uid=1001` followed by the groups. On Kubernetes, `kubectl exec <pod> -c <container> -- id` shows the same for a running pod.

## Iron Bank

DefectDojo Pro images are not currently published in the DoD Iron Bank registry. The images already run as non-root numeric users, are signed, and carry SBOM attestations, which covers several Iron Bank requirements; rebuilding them on Iron Bank base images in the Iron Bank hardening pipeline is separate work. If your program requires images from Iron Bank, tell your DefectDojo account team, so the request is on record.

## Evidence for an assessor

Everything below can be collected from inside your boundary, including after you have mirrored the images into your own registry.

| Evidence | How to collect it |
|---|---|
| The image is the one DefectDojo released | `cosign verify --key dojo-pro-cosign.pub --offline <image>@<digest>`, as described in [Verifying the signature](/get_started/pro/onprem/image_provenance/#verifying-the-signature) |
| What software the image contains | `cosign verify-attestation --type cyclonedx` (or `--type spdx`) on the same digest, or the signed SBOM files in the offline bundle's `image-sboms/` directory. See [Downloading the SBOMs](/get_started/pro/onprem/image_provenance/#downloading-the-sboms) |
| The cryptographic module in use | `docker run --rm --entrypoint openssl <django-fips-image> list -providers` lists the FIPS provider as active. See [Verifying FIPS mode](/get_started/pro/onprem/fips_mode/#verifying-fips-mode) |
| The application refuses to run without FIPS enforcement | The fail-closed startup check in [FIPS 140-3 Mode](/get_started/pro/onprem/fips_mode/#fail-closed-startup) |
| The containers run without root | The `docker image inspect` and `id` commands above, or the pod's `securityContext` from `kubectl get pod <pod> -o yaml` |
| Which release is deployed and how long it is supported | [Releases and Support Lifecycle](/get_started/pro/onprem/support_lifecycle/) |

Pin the image digests you verified in your deployment, so the evidence you collected and the images you run stay the same.

**DefectDojo does not publish VEX documents for its images.** If a scanner in your boundary reports vulnerabilities in a DefectDojo Pro image, send the report to [support@defectdojo.com](mailto:support@defectdojo.com), as described in [Releases and Support Lifecycle](/get_started/pro/onprem/support_lifecycle/).
