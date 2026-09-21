---
title: "Container Image Locations"
description: "Container Image locations model the image a finding was found in, identified by registry, repository and digest, and the assets that run it"
weight: 8
audience: pro
---

**Container Image Locations** extend the Locations model to container scanning: alongside URLs (DAST), Dependencies (SCA), Source Code (SAST) and Cloud Resources (posture), an **Image** location describes the container image a finding was found in, identified by its **registry, repository and digest**.

> Container Image Locations require the Locations feature and are enabled separately as the **Container Image Locations** flag (beta) on the [Feature Flags page](/admin/feature_flags/pro__feature_flags/). Images reported while the flag is off are still stored; they appear as soon as the flag is turned on.

## What They Model

A container scanner reports which package is vulnerable, but the finding is only actionable once you know which image it was in, where that image runs, and which repository built it. An Image location records the first two; the third is the image's `org.opencontainers.image.source` label, kept on the location for the image-to-repository link.

Each image carries:

- **Registry**: the host, normalised. Docker Hub short names become `index.docker.io`, and hosts are lower-cased with no scheme.
- **Repository**: the path within the registry, such as `library/nginx` or `acme/payments-api`. Docker Hub official images get the `library/` prefix, so `nginx:1.25` and `docker.io/library/nginx:1.25` are one image.
- **Digest**: the manifest digest (`sha256:` plus 64 hex characters) when the scanner knows it.
- **Tag**: the tag as reported.
- **Source and revision**: the `org.opencontainers.image.source` and `.revision` labels when the reporting tool exposes image labels.

### Identity: digests first, tags when that is all there is

The location's canonical value is `registry/repository@sha256:<digest>` when the digest is known, and `registry/repository:tag` when it is not. A tag-only image and a digest image for the same repository are **different locations on purpose**: tags move and digests do not, so collapsing them would make a finding on last week's `:latest` read as a finding on this week's. Every reference to an image records whether its digest is known (`digest_known`), and the lists mark tag-only images as **digest unknown**.

Image locations are **scan-managed**: they are created by imports and connectors, not by hand. There is no "New Image" action; the scanner or registry is the source of truth.

## Where to Find Them

- **All Images** in the sidebar (under Locations, or under Attack Surface in the reorganized menu) lists every image on the instance, with filters for registry, repository, tag and whether the digest is known.
- **View Images** in an Asset's Locations menu scopes the list to one asset.
- The asset **location map** draws a Container Images region, grouping images by registry and then repository. A repository with one image collapses to that image.
- A finding's page has a **Runs in** tile listing the images the finding was found in, each with its registry, repository, tag and short digest, and the assets that run it.

## Built From: the Image to Repository Link

An image's `org.opencontainers.image.source` label names the repository that built it. When the label is present, DefectDojo matches it against, in order, Sensei repository configurations, the **Repo** field of engagements, and repositories mapped through the SCM asset connectors (GitHub, GitLab, Azure DevOps, Bitbucket), and records the matching asset as the image's **Built from** owner together with the `.revision` label.

- One match is linked automatically and shown on the image page and in the finding's **Runs in** tile as "Built from *asset* at *revision*".
- More than one match is recorded as **candidates** rather than guessed at. The image page lists them, and a person can link one, or any other asset, with **Link repository**.
- A link made by hand outranks everything the scanners say and is never overwritten; **Unlink** hands the decision back to the resolver.
- Images built from one asset and seen running in another feed the [suggested edges](/asset_modelling/pro_hierarchy/asset_hierarchy/#suggested-edges-from-container-evidence) on the hierarchy page. No edge is ever drawn without a person accepting it.

Images are resolved when they arrive and again whenever a Sensei repository, an engagement's Repo field or an SCM connector mapping changes.

## API

Images are available read-only at `/api/v2/container_image/`, with the same filters as the list, and through the general locations resource at `/api/v3/locations?type=image`. Each row also exposes a `pkg:oci` Package URL for exports; the stored value stays the plain image reference.

## Relationship to Other Location Types

An Image location sits beside a finding's other locations rather than replacing them: a Trivy image scan still produces Dependency locations for the vulnerable packages, and a cluster connector can attach a Cloud Resource location for the workload the image runs as. Together they answer "which package, in which image, running where".
