---
title: "Planning a Private Deployment"
description: "Questions to settle before deploying self-hosted DefectDojo Pro on a private network, such as Amazon EKS in AWS GovCloud with FIPS images, mirrored images, managed PostgreSQL and Redis, and SSO"
draft: false
weight: 2
audience: pro
---

This page collects the decisions to make before a self-hosted deployment on a private network: a Kubernetes cluster with no internet egress, images mirrored into your own registry, managed data services, and often FIPS 140-3 cryptography. The examples use Amazon EKS (including AWS GovCloud), RDS and ElastiCache, but the same answers apply on other platforms. Each section links to the page with the full procedure.

## Which release to deploy

Deploy the most recent release in the [DefectDojo Pro Changelog](/releases/pro/changelog/). DefectDojo releases at least weekly and fixes forward, so the newest release is the one that carries every fix; see [Releases and Support Lifecycle](/get_started/pro/onprem/support_lifecycle/).

The chart, the images and the settings files of a release move together, so pick one version and use it for all of them ([Upgrade everything as one unit](/get_started/pro/onprem/upgrading/#upgrade-everything-as-one-unit)).

## FIPS images

Every release from 3.3.200 has `-fips` images, tagged `<version>-fips` next to the standard images, for example:

```
us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro/django:<version>-fips
```

The registry credentials in your license already pull them. They are built for **linux/amd64 only**, so a FIPS deployment needs amd64 nodes. On the Helm chart, `fips.enabled: true` selects them for you, and the chart refuses to render if a component without a FIPS variant (the embedded PostgreSQL and Redis, Sensei, the OSCAL validator) is also enabled. See [FIPS 140-3 Mode](/get_started/pro/onprem/fips_mode/) for the image list, the coverage of each component and how to prove the mode to an assessor.

## Mirroring images and checking provenance

Without egress, copy the images into a registry the cluster can reach and point the chart at it ([Private Registry / Air-Gapped Environments](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#private-registry--air-gapped-environments)). Copy them with `cosign copy` rather than `docker pull` and `docker push`, so each image's signature and SBOM attestations come along.

Every release image is signed and carries SPDX and CycloneDX SBOM attestations, which you can check inside the private network with `cosign verify --offline` and extract with `cosign download attestation <image>@<digest>`. DefectDojo does not publish VEX documents. See [Verifying Images and SBOMs](/get_started/pro/onprem/image_provenance/).

Also set [Airgapped mode](/get_started/pro/onprem/airgapped/), which stops the calls DefectDojo makes on its own (version checks, feeds, diagnostics) so they do not fail and log errors.

## PostgreSQL

- **Version:** PostgreSQL 16 or newer. Amazon RDS for PostgreSQL works; nothing checks the version before the migrations run, so confirm it with the [pre-flight check](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#pre-flight-verify-database-connectivity).
- **Two databases:** the main database (for example `dojodb`) and the orchestrator's, always named after it with `-ddorch` appended (`dojodb-ddorch`). Create both, owned by the application role, or grant that role `CREATEDB` and the orchestrator creates its own. See [Pre-flight: Orchestrator (ddorch) Database](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#pre-flight-orchestrator-ddorch-database).
- **Privileges:** the application role should own both databases; it does not need to be a superuser. The migrations create the `pg_trgm` extension, which PostgreSQL marks as trusted, so the database owner can create it without superuser rights.
- **Without a password:** on RDS, the application can sign in with IAM database authentication instead of a stored password; see [Passwordless Database Authentication](/get_started/pro/onprem/passwordless_database/).
- **FIPS:** the database is a separate product, so use a FIPS-compliant endpoint and document it as an inherited component ([Deployment notes](/get_started/pro/onprem/fips_mode/#deployment-notes)).

## Redis or Valkey

- **Version:** the Helm chart's embedded cache is Valkey 7.2 (`7.2.11-alpine`) and the Docker Compose deployment's is Valkey 9, so an ElastiCache Valkey 7.2 or newer cluster matches what DefectDojo itself ships.
- **External cache:** set `celery.broker.external: true`, `celery.broker.host`, and `redis.enabled: false`. The chart points both Celery (database 0) and Django's cache (database 1) at it. The initializer flushes database 1 on every install and upgrade, so do not share that database with anything else.
- **TLS:** for ElastiCache with in-transit encryption, set `celery.broker.scheme: "rediss"`. The cache then connects over TLS too and verifies the server certificate against public root CAs. For a certificate from a private CA, set `DD_CACHE_URL` yourself with `ssl_ca_certs`, as shown in the [installation guide's external Redis notes](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#prepare-your-values-file).
- **Password:** if the cache requires an auth token, put it in the `dojopro-redis` Secret ([Secrets from Your Infrastructure](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#secrets-from-your-infrastructure)).

## Storage for uploaded files

The Django and Celery pods all read and write the same media volume, and they can run on different nodes, so it needs `ReadWriteMany` storage. On EKS:

- **Amazon EFS** (`storage.type: "efs"`) is the recommended backend. If you use an EFS access point, its POSIX user must be UID `1001` and GID `1337`, and you set `storage.efs.accessPointId`; see [EFS Access Points](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#efs-access-points).
- **Amazon S3** through the Mountpoint for Amazon S3 CSI driver (`storage.type: "s3"`) is the alternative. The bucket is mounted as a filesystem, and the chart's default mount options already set UID `1001` and GID `1337`. The setup is in the "S3 Media Storage (Mountpoint)" section of the installation guide PDF that ships in the chart's bundled zip.
- **EBS** is `ReadWriteOnce` and is not supported for the media volume: pods scheduled on a second node fail with `Multi-Attach` errors ([Known Issues](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#known-issues)).

Switching `storage.type` after install means deleting and recreating the media volume, so choose before the first `helm install`. The storage drivers call AWS APIs (`elasticfilesystem` for EFS, `s3` for S3), alongside the endpoints listed under [Outbound Connectivity Requirements](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#outbound-connectivity-requirements), so on a network without egress, reach them through VPC endpoints.

## Upgrading later, including from an old release

You can upgrade straight from an old release to the current one without installing the releases in between. Back up both databases first, rehearse the upgrade on a restored copy to measure the maintenance window, and remember that migrations do not roll back: the way back is the backup. See [Upgrading across several releases](/get_started/pro/onprem/upgrading/#upgrading-across-several-releases), and [Reading the initializer's result](/get_started/pro/onprem/upgrading/#reading-the-initializers-result) for what each exit code means.

## Single sign-on and provisioning

- **SAML**, including AWS IAM Identity Center as the IdP: an instance without egress cannot fetch the IdP's metadata URL, so upload the IdP's metadata XML file instead. See [SAML Configuration](/admin/sso/pro__saml/), which has an [IAM Identity Center](/admin/sso/pro__saml/#aws-iam-identity-center) section, and [SAML Group Mapping](/admin/sso/pro__saml/#saml-group-mapping) for turning IdP groups into DefectDojo groups.
- **SCIM:** DefectDojo implements standard SCIM 2.0, so provisioning tools other than Okta and Entra ID, such as SailPoint, can connect within the documented limits. See [Other SCIM 2.0 providers](/admin/sso/pro__scim/#other-scim-20-providers).
- Neither depends on a license tier.

## Before you start

Gather the values in the installation guide's [Pre-Install Checklist](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#pre-install-checklist), and size the cluster with [Hardware Sizing](/get_started/pro/onprem/hardware_sizing/). For anything this page does not answer, contact [support@defectdojo.com](mailto:support@defectdojo.com).
