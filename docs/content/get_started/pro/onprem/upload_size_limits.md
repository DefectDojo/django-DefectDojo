---
title: "Upload Size Limits for Large Scan Files"
description: "Why a large scan file fails to upload, and which limit to raise in Kubernetes and Docker Compose deployments"
draft: false
weight: 9
audience: pro
---

A large scan file can be rejected by more than one limit, at different points in the request path, and the error you get tells you which one you hit. This page covers where those limits are and how to raise them in a self-hosted deployment.

## Which limit am I hitting

| What you see | Where it came from |
| --- | --- |
| A plain `413 Request Entity Too Large`, unstyled, no DefectDojo page around it | The ingress controller rejected the request before it reached the application |
| `Report file is too large. Maximum supported size is N MB` | The application limit, reported by DefectDojo itself |
| The upload runs for a while and then fails, rather than being refused immediately | A timeout rather than a size limit |

Work from the outside in. There is no point raising the application limit if the ingress controller is refusing the request first.

## The application limit

DefectDojo enforces a maximum scan file size of its own, and rejects anything larger with a message naming the current limit. It defaults to 100 MB.

In the Helm chart, set it in your values:

```yaml
dojo:
  scanMaxFileSize: 100
```

For Docker Compose deployments, set `DD_SCAN_FILE_MAX_SIZE` instead, in megabytes.

## The ingress limit

This is the one that produces a bare `413` with no DefectDojo styling, because the request never reaches the application.

The chart sets a request body cap on the ingress, defaulting to 2400 MB:

```yaml
django:
  ingress:
    maxBodySize: "2400m"
```

That value is emitted as the `nginx.ingress.kubernetes.io/proxy-body-size` annotation. It is emitted on every platform rather than only on generic Kubernetes, because the nginx ingress controller is often used in front of a managed platform. Setting it to an empty string omits the annotation, and it requires `django.ingress.platformAnnotations.enabled`, which is on by default.

Controllers other than nginx ignore that annotation, so on those you raise the limit through the controller's own mechanism instead:

| Platform default controller | Where the limit lives |
| --- | --- |
| EKS with the AWS Load Balancer Controller | ALB configuration |
| GKE with the GCE ingress controller | Load balancer configuration |
| AKS with Application Gateway | The Application Gateway request body limit |
| OpenShift Route | HAProxy `tuningOptions` on the router |

### Timeouts when nginx fronts a managed platform

The chart emits generous nginx proxy timeouts, 1800 seconds for read, send, and connect, along with disabled proxy buffering. Those annotations are only emitted when the platform is generic Kubernetes. On EKS, GKE, AKS, and OpenShift the chart emits that platform's own annotations instead, because that is what its default controller reads.

This matters if you run the nginx ingress controller on one of those platforms. You get the body size annotation, since that one is emitted everywhere, but not the timeouts. A large upload can then pass the size check and still be cut off partway through by the controller's default timeout, which is where the third row of the table above comes from. Supply the timeouts yourself:

```yaml
django:
  ingress:
    annotations:
      nginx.ingress.kubernetes.io/proxy-read-timeout: "1800"
      nginx.ingress.kubernetes.io/proxy-send-timeout: "1800"
```

## The import route limit

Kubernetes deployments run scan imports through dedicated pods, and the nginx in front of the import routes has its own body size cap. It is derived rather than fixed:

```yaml
django:
  uwsgiImport:
    maxBodySizeMb: null
```

Left at `null`, it is calculated as `dojo.scanMaxFileSize` plus 5 MB, the margin covering multipart encoding overhead. Raising the application limit therefore raises this one with it, and most deployments never need to set it. Set an integer only if you want to override the derived value.

## Docker Compose deployments

Compose deployments have no ingress controller, so the ingress limit does not apply. The nginx that ships in the deployment caps request bodies at 800 MB, which is the practical ceiling, and the application limit applies on top of that as it does everywhere.

Raising the nginx cap means changing a file that ships with the deployment, and those files are replaced when you upgrade rather than preserved like your customizations directory. Contact support before changing it, so the change does not disappear at the next upgrade.

## Questions or support

If uploads still fail after raising the limit that matches your symptom, collect the response your client received and the nginx or controller logs covering the attempt, then contact [support@defectdojo.com](mailto:support@defectdojo.com).
