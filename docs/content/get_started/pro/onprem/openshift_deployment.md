---
title: "Deploying DefectDojo Pro on OpenShift"
description: "What is specific to OpenShift when deploying self-hosted DefectDojo Pro: security context constraints, Routes, and ReadWriteMany storage"
draft: false
weight: 8
audience: pro
---

DefectDojo Pro runs on OpenShift 4.x, including OpenShift Container Platform, ROSA, and OKD.

This page is a supplement to the installation guide supplied with your DefectDojo Pro license. That guide has the full procedure, including a dedicated OpenShift section. This page covers what is different about OpenShift, so you know what to have ready before you start and what to expect from the platform-specific settings.

An OpenShift bootstrap script is provided with your license materials. It installs onto an existing cluster and handles most of what this page describes, including storage, the `fsGroup` value, the Route, and the install itself. It is idempotent, so re-running it reuses what it already created, and it supports a dry run that prints what it would do without changing anything. The rest of this page applies whether you use that script or run the install yourself.

## Security context constraints

DefectDojo Pro runs under the default `restricted-v2` SCC. You do not need to grant `anyuid`, `privileged`, or any other elevated SCC to the service account.

When configured for OpenShift, DefectDojo Pro runs with non-privileged security contexts throughout. Containers run without privilege, cannot escalate privileges, and drop all capabilities. The user ID is left for OpenShift to assign from the range allocated to your namespace, rather than pinned to a fixed UID that the SCC would reject.

If pods are rejected for failing SCC validation, the usual cause is that the deployment was not configured for OpenShift, not that a constraint needs granting.

## Storage has to be ReadWriteMany

The Django and Celery worker pods read and write the same media files, which are the uploaded scans, screenshots, and generated reports. They need a shared volume, so ReadWriteOnce storage is not sufficient for a multi-node deployment.

On OpenShift the default is a PersistentVolumeClaim against the cluster's default StorageClass. That works when the default class provisions ReadWriteMany, which is typical on clusters backed by OpenShift Data Foundation or NFS. For multi-node deployments where the default class is ReadWriteOnce, configure NFS-backed storage instead.

### fsGroup on NFS-backed storage

OpenShift restricts `fsGroup` to the range allocated to the namespace. When you use NFS or EFS storage, you have to supply a value from that range or the volume mount fails with a permissions error.

Read the start of the range from the namespace annotation and use it as your `fsGroup`:

```bash
oc get namespace <namespace> \
  -o jsonpath='{.metadata.annotations.openshift\.io/sa\.scc\.supplemental-groups}'
```

The annotation holds a range written as a start value and a length. Use the start value. This is only needed for NFS and EFS storage, not for the default PersistentVolumeClaim path.

## Routes, TLS, and cookies

On OpenShift, DefectDojo Pro is exposed through a Route rather than an Ingress, with edge TLS termination and a redirect from HTTP.

On ROSA, Route hostnames are generated as `<release-name>-<namespace>.apps.<cluster-domain>`, so a `dojopro` release in the `dojopro` namespace gets `dojopro-dojopro.apps.<cluster-domain>`. Get the cluster's apps domain with:

```bash
oc get ingresses.config.openshift.io cluster -o jsonpath='{.spec.domain}'
```

A hostname under the cluster's apps domain is covered by the default wildcard certificate and needs no certificate configuration. For any other hostname, supply your own certificate and add a CNAME to the Route hostname.

Set `dojo.secureCookies` to `false` on OpenShift. With an edge-terminated Route, TLS ends at the router and the connection from the router to the pod is plain HTTP, so cookies marked secure are never sent back and login fails. This is required rather than optional whenever the Route terminates TLS at the edge.

## Resource profiles

Three resource profiles are available and you select one at install time. `minimal` is for development, CI, and testing. `standard` is for production under moderate load. `performance` is for high-load production and enables autoscaling.

Set your sizing through the profile rather than by overriding individual values, so that your own configuration file does not conflict with it.

## Before you start

An OpenShift 4.x cluster you are logged in to, with `oc`, `helm`, `openssl`, and `jq` available locally.

A namespace, and its supplemental-groups annotation value if you are using NFS or EFS storage.

A default StorageClass that provisions ReadWriteMany, or the details of an NFS server.

PostgreSQL 16 for anything beyond evaluation. An embedded PostgreSQL is available for development, but move to an external managed database before running in production.

Your DefectDojo Pro license file.

Your intended Route hostname.

## Outbound network access

In a cluster with egress restrictions, allow outbound HTTPS on port 443 to the container registry that hosts the DefectDojo Pro images. The registry hostname is in the installation guide supplied with your license. Registry endpoints sit behind load balancers and their addresses change, so allow the hostname rather than a fixed address.

The cluster also needs to reach your database on the PostgreSQL port.

Exploitability enrichment is optional and needs two more destinations over HTTPS on port 443. EPSS scores come from `api.first.org`, and CISA KEV data comes from `www.cisa.gov`. Both are served from content delivery networks whose addresses change, so allow the hostnames. Without them DefectDojo runs normally and findings are not enriched with EPSS or KEV data.

Where outbound traffic goes through a proxy rather than direct, see [Running DefectDojo Behind a Forward HTTPS Proxy](/onprem_deployment/forward_proxy/).

## The initializer job has to finish first

Installation runs a Kubernetes job that applies migrations, creates the admin user, and loads initial data. It takes around fifteen minutes. Until it completes, the admin user does not exist and you cannot log in, even though the Route already answers.

Watch it:

```bash
oc get job -n <namespace>
oc logs -f -n <namespace> -l app.kubernetes.io/component=initializer
```

The job is done when `oc get job` reports `1/1` completions.

The other pods wait on the initializer through an init container. Once the database has been initialized, you can set `dojo.skipInitContainer` to `true` to skip that wait on subsequent upgrades.

## Verifying

```bash
oc get pods -n <namespace>
oc get route -n <namespace>
oc describe route -n <namespace>
```

Then open the Route hostname and sign in.

## Troubleshooting

### Pods rejected by security context constraints

The deployment was most likely not configured for OpenShift, so it fell back to defaults that pin a user ID the SCC will not allow. Granting `anyuid` or `privileged` is not the fix and is not required.

### Login redirects back to the login page

`dojo.secureCookies` is `true` behind an edge-terminated Route. Set it to `false` and upgrade.

### Volume mount permission errors on NFS

The `fsGroup` is outside the namespace's allowed range. Read the supplemental-groups annotation and use the start of the range.

### Multi-Attach errors, or pods stuck in ContainerCreating

The volume is ReadWriteOnce and more than one pod is trying to mount it. Check the claim and the class behind it:

```bash
oc get pvc -n <namespace>
oc describe pod <pod-name> -n <namespace> | tail -30
```

Move to a ReadWriteMany class, or to NFS-backed storage.

### Certificate warnings in the browser

The default Route TLS uses the cluster's wildcard certificate, which only covers names under the cluster's apps domain. For any other hostname, supply your own certificate.

### Reading logs

```bash
oc logs -n <namespace> -l app.kubernetes.io/component=django -c uwsgi --tail=50
oc logs -n <namespace> -l app.kubernetes.io/component=celery-worker --tail=50
```

For deeper output, `config.logLevel` and `celery.logLevel` both accept `DEBUG`.

## Upgrading

Upgrades follow the standard procedure. See [Upgrading DefectDojo Pro (On-Premise)](/get_started/pro/onprem/upgrading/).

## Questions or support

For help with an OpenShift deployment, contact your account representative or [support@defectdojo.com](mailto:support@defectdojo.com).
