---
title: "Upload Size Limits for Large Scan Files"
description: "Why a large scan file fails to upload on Docker Compose, and which limit to raise"
draft: false
weight: 5
audience: pro
---

A large scan file can be rejected at two points on a Docker Compose deployment: the application's own limit, and the nginx that ships in front of it. The error you get tells you which one you hit. Running Kubernetes? See [Upload Size Limits for Large Scan Files](/get_started/pro/onprem/kubernetes/upload_size_limits/) for the Helm chart, which adds ingress and import-route limits that do not apply here.

## Which limit am I hitting

| What you see | Where it came from |
| --- | --- |
| `Report file is too large. Maximum supported size is N MB` | The application limit, reported by DefectDojo itself |
| A plain `413 Request Entity Too Large`, unstyled, with no DefectDojo page around it | The nginx that ships with the deployment rejected the request before it reached the application |

## The application limit

DefectDojo enforces a maximum scan file size of its own, and rejects anything larger with a message naming the current limit. It defaults to 100 MB. On Docker Compose, set the `DD_SCAN_FILE_MAX_SIZE` environment variable, in megabytes, through the CLI, then restart:

```bash
sudo -E dojo-compose-cli environment add --key DD_SCAN_FILE_MAX_SIZE --value 200
sudo -E dojo-compose-cli app restart
```

Run `dojo-compose-cli environment add --help` for the exact syntax your CLI version expects.

## The connector chunk limit

Connectors send findings to DefectDojo in chunks of about 5,000 findings, and each chunk has its own size limit, separate from the scan file limit. A chunk over it fails the sync with `Chunk is too large. Maximum supported size is N MB`, or `decompressed chunk exceeds N MB` for a compressed chunk.

The limit defaults to the larger of `DD_SCAN_FILE_MAX_SIZE` and 100 MB, so lowering the scan file limit never shrinks it below 100 MB. Change it only if a connector sync fails with one of those messages: set `DD_CONNECTORS_CHUNK_MAX_MB`, in megabytes, then restart:

```bash
sudo -E dojo-compose-cli environment add --key DD_CONNECTORS_CHUNK_MAX_MB --value 200
sudo -E dojo-compose-cli app restart
```

DefectDojo holds each chunk in memory while it checks it, so raise the limit in steps rather than removing it. The nginx ceiling below still applies.

## The nginx ceiling

Compose deployments have no ingress controller, so the ingress limit that Kubernetes deployments raise does not apply. Instead, the nginx that ships in the deployment caps request bodies at 800 MB, which is the practical ceiling, and the application limit above applies on top of that.

Raising the nginx cap means changing a file that ships with the deployment, and those files are replaced when you upgrade rather than preserved like your `customizations` directory. Contact support before changing it, so the change does not disappear at the next upgrade.

## Questions or support

If uploads still fail after raising the limit that matches your symptom, collect the response your client received and the nginx logs covering the attempt, then contact [support@defectdojo.com](mailto:support@defectdojo.com).
