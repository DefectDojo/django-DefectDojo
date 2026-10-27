---
title: "Verifying Images and SBOMs"
description: "Check the signature on a DefectDojo Pro container image and pull its SPDX and CycloneDX SBOMs, including from a mirrored registry with no internet access"
draft: false
weight: 10
audience: pro
---

DefectDojo Pro release images are signed with cosign, and each one carries two SBOMs as signed attestations: one in SPDX format and one in CycloneDX. The signatures and attestations are stored in the registry next to the image, so you can check where an image came from and what it contains before you deploy it, including after you have copied it into a registry of your own.

This applies to the standard images and to the [`-fips` images](/get_started/pro/onprem/fips_mode/#getting-the-fips-images): `dojo-pro/django`, `dojo-pro/nginx`, `dojo-pro/webhook-gateway`, `dojo-connectors/connectors`, `dojo-integrators/integrators`, `ddorch/ddorch` and `go-dd-pro-mcp/mcp-server`, all under `us-south1-docker.pkg.dev/defectdojo-container-registry/`.

**DefectDojo does not publish VEX documents for its images.** The attestations are the SPDX and CycloneDX SBOMs and nothing else. If a scanner reports vulnerabilities in a DefectDojo image, send the report to [support@defectdojo.com](mailto:support@defectdojo.com); see [Releases and Support Lifecycle](/get_started/pro/onprem/support_lifecycle/).

## What you need

- [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 2.0 or newer.
- The DefectDojo public key, `dojo-pro-cosign.pub`. It ships inside the Helm chart's bundled offline zip, next to the chart, and DefectDojo support can send it to you. The same key signs the chart package, as described under [Verify the Bundle Signature](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#verify-the-bundle-signature).
- Pull access to the image: the registry credentials in your license for DefectDojo's registry, or your own credentials for a mirror.

## Signatures and SBOMs belong to a digest

A signature or attestation is attached to an image **digest**, not to a tag. Look up the digest a tag points to with any registry client, for example:

```bash
docker buildx imagetools inspect \
  us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro/django:<version>-fips
```

The `Digest:` line is the value you need. A `-fips` tag is a single linux/amd64 image, so it has one digest. A standard tag is a multi-platform index: its output also lists one digest per platform under `Manifests:`. The SBOMs describe a platform's image, so use the digest of the platform you run, usually `linux/amd64`.

Working with digests also protects you from a tag being moved after you checked it. Pin the same digests in your deployment if your policy requires it.

## Mirroring with signatures and SBOMs

Signatures and attestations are stored in the registry as separate artifacts, under tags derived from the image digest. A plain `docker pull` and `docker push` copies the image without them. `cosign copy` copies the image together with its signatures and attestations:

```bash
cosign copy \
  us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro/django:<version>-fips \
  registry.internal.example.com/defectdojo/dojo-pro/django:<version>-fips
```

Run it from a host that can reach both registries. Copying keeps the digest, so a signature checked before the copy and one checked after it refer to the same image. To list what is attached to an image in either registry, run `cosign tree <image>@<digest>`.

How the chart then pulls from your mirror is covered under [Private Registry / Air-Gapped Environments](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#private-registry--air-gapped-environments).

## Verifying the signature

```bash
cosign verify --key dojo-pro-cosign.pub --offline \
  registry.internal.example.com/defectdojo/dojo-pro/django@sha256:<digest>
```

A good result lists the checks it performed, ending with `The signatures were verified against the specified public key`, then prints the signed payload as JSON.

`--offline` makes cosign use the transparency-log proof stored with the signature instead of contacting the public log, so the check works with no internet access. Leave it off if the host can reach the internet.

## Downloading the SBOMs

`cosign download attestation` prints every attestation on an image, one JSON envelope per line. This writes each SBOM to its own file:

```bash
IMAGE=registry.internal.example.com/defectdojo/dojo-pro/django@sha256:<digest>

cosign download attestation "$IMAGE" > attestations.jsonl

jq -r 'select((.payload | @base64d | fromjson | .predicateType) == "https://spdx.dev/Document")
       | .payload | @base64d | fromjson | .predicate' attestations.jsonl > django.spdx.json
jq -r 'select((.payload | @base64d | fromjson | .predicateType) == "https://cyclonedx.org/bom")
       | .payload | @base64d | fromjson | .predicate' attestations.jsonl > django.cdx.json
```

`download` does not check the signature on the attestations. To check it and extract the SBOM in one step, use `verify-attestation`, with `--type spdx` or `--type cyclonedx`:

```bash
cosign verify-attestation --key dojo-pro-cosign.pub --offline --type cyclonedx "$IMAGE" \
  | jq -r '.payload | @base64d | fromjson | .predicate' > django.cdx.json
```

Expect large files: the Django image's SBOMs run to several megabytes each.

## SBOMs in the offline bundle

You can also get every image's SBOMs without any registry access. The Helm chart's bundled offline zip has an `image-sboms/` directory holding the SPDX and CycloneDX SBOM of each Pro container image in the release, one pair per platform (`django-<version>-linux-amd64.spdx.json`) and per `-fips` variant (`django-<version>-fips.spdx.json`). `image-sboms/IMAGES.txt` maps each file to the image tag and digest it describes. Each SBOM file has a cosign signature bundle beside it:

```bash
cosign verify-blob --key dojo-pro-cosign.pub --offline \
  --bundle image-sboms/django-<version>-fips.cdx.json.bundle \
  image-sboms/django-<version>-fips.cdx.json
```

A good result prints `Verified OK`.
