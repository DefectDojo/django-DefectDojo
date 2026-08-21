---
title: "DefectDojo Pro Upgrade Guide"
description: "Upgrade an existing DefectDojo Pro Helm release, including pulling the chart, running the upgrade, and rolling back"
draft: false
weight: 14
audience: pro
aliases:
  - "/get_started/pro/onprem/upgrading/"
---

<!--
  Generated from the DefectDojo Pro Helm chart repository.
  Source: docs/UPGRADE_GUIDE.md at chart version 3.1.304.
  Edit the source guide, not this file. Local edits are overwritten
  the next time the chart is released.
-->
Covers upgrading an existing DefectDojo Pro release to a newer chart version.
The recommended path is to pull the chart directly from the DefectDojo OCI
registry — no zip extraction required. The packaged-zip workflow used at
install time also works for upgrades and is documented below.

This guide covers:

- [Before You Upgrade](#before-you-upgrade)
- [Chart Source: OCI Registry](#chart-source-oci-registry)
- [Authenticate to the Registry](#authenticate-to-the-registry)
- [Upgrade via OCI Registry (recommended)](#upgrade-via-oci-registry-recommended)
- [Upgrade via Extracted Zip](#upgrade-via-extracted-zip)
- [Upgrade with ArgoCD](#upgrade-with-argocd)
- [Verify the Upgrade](#verify-the-upgrade)
- [Rollback](#rollback)
- [Troubleshooting](#troubleshooting)

---

## What an Upgrade Covers

A DefectDojo Pro release is a chart version, a set of container image
versions, and the Pro settings files. Those are built and tested together and
have to move together. Upgrading the image tags on their own is not supported
and will break the deployment.

The same applies to settings. A new `pro_settings.py` ships with nearly every
release. Never carry a copy forward across an upgrade, and never hand-patch an
older one: the application has to run the `pro_settings.py` that matches its
version. Your own customizations belong in `local_settings.py`, which is
preserved across upgrades and is the only one of the two you should edit.

Using the chart handles this for you. It ships and mounts the matching
`pro_settings.py` alongside your `local_settings.py`, so there is nothing to
copy or migrate by hand.

## Before You Upgrade

Every upgrade should start the same way. Skipping these steps is the most
common cause of failed upgrades.

1. **Read the release notes** for every version between your current release
   and the target. Breaking changes, new required fields, and migration
   prerequisites are called out there. The GitHub release page for each tag
   links to the change log.
2. **Check your current chart version.** This is the floor for the upgrade:

   ```bash
   helm list -n $NAMESPACE
   helm get metadata dojopro -n $NAMESPACE
   ```
3. **Back up your database.** Chart upgrades can include Django migrations
   that alter schema. Take a logical dump (or a storage-level snapshot) of
   the PostgreSQL instance before proceeding.
4. **Have your values files available.** The upgrade command must pass the
   same platform preset, profile preset, and customer values file used at
   install. Missing or drifted values files cause surprising diffs.
5. **Confirm secret references still exist.** If you installed with
   `--set dojo.existingSecret=...` or `--set license.existingSecret=...`,
   verify those Kubernetes secrets are still present in the namespace.
6. **Render the upgrade locally first** to catch missing fields, invalid
   values, or template errors before touching the cluster:

   ```bash
   helm template dojopro $CHART_REF \
     -n $NAMESPACE \
     -f $CHART/presets/platforms/<platform>.yaml \
     -f $CHART/presets/profiles/<size>.yaml \
     -f my-company.yaml \
     --set dojo.existingSecret=dojopro-secrets \
     --set license.existingSecret=dojopro-license \
     > /tmp/dojopro-upgrade-render.yaml
   ```

   `$CHART_REF` is the OCI reference (see below) or the extracted chart path.

> Set `NAMESPACE` once — every command in this guide uses `$NAMESPACE`:
>
> ```bash
> NAMESPACE="dojopro"
> ```

> **Network policy default changed.** NetworkPolicies are now governed by
> `networkPolicy.profile`, which defaults to `standard`: all egress plus
> ingress between this release's own pods is allowed (external ingress is still
> restricted to the ingress path). This is more permissive than the previous
> always-granular egress allowlist. To keep the locked-down behavior, set
> `networkPolicy.profile: aggressive` and review the carve-outs
> (`nodeLocalDns`, `dnsSelectors`, `externalAPIs`) — see
> [Network Policies](/get_started/pro/onprem/installing_on_kubernetes/#network-policies).

> **Orchestrator database requirement.** The orchestrator (`ddorch`) uses a
> second database named `<main-db-name>-ddorch` and creates it at startup if
> it does not exist. If your application role lacks `CREATEDB`, pre-create it
> (`CREATE DATABASE "defectdojo-ddorch" OWNER defectdojo;`) before upgrading
> to a chart version that enables ddorch — otherwise the ddorch pod fails with
> `permission denied to create database (SQLSTATE 42501)`. See
> [Pre-flight: Orchestrator (ddorch) Database](/get_started/pro/onprem/installing_on_kubernetes/#pre-flight-orchestrator-ddorch-database).

> **Organization/Asset relabel default.** `dojo.V3EnableOrganizationAssetRelabel`
> now defaults to `null` (auto): it is **enabled for new installs** and **left
> off on upgrades**, so the UI relabel (Organization/Asset replacing
> ProductType/Asset) never flips on unexpectedly for an existing release. To
> opt an upgraded release in, set `dojo.V3EnableOrganizationAssetRelabel: true`
> explicitly; an explicit `true`/`false` always wins over the auto default.

---

## Chart Source: OCI Registry

The chart is published to the DefectDojo GCP Artifact Registry as an OCI
artifact:

```
oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro
```

Each release is tagged with the chart version (for example `2.57.2`). The
chart version matches the app version in `Chart.yaml`, so the tag you pass
to `helm upgrade --version` is the same version number shown on the GitHub
release.

List available chart versions:

```bash
helm show chart \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version <chart-version>
```

> **Why OCI for upgrades?** The presets (`presets/platforms/*.yaml`,
> `presets/profiles/*.yaml`) are packaged inside the chart. Referencing the
> chart by its OCI URL pulls the correct preset versions for the target
> chart automatically — no re-extraction step, no stale presets.

---

## Authenticate to the Registry

The registry is private. Helm must be logged in before it can pull the
chart. Use a GCP service-account key or short-lived access token provided
by DefectDojo support.

**Option A — service-account JSON key:**

```bash
gcloud auth activate-service-account --key-file=/path/to/key.json
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

**Option B — interactive gcloud login (for humans with registry access):**

```bash
gcloud auth login
gcloud auth configure-docker us-south1-docker.pkg.dev --quiet
gcloud auth print-access-token \
  | helm registry login -u oauth2accesstoken \
      --password-stdin us-south1-docker.pkg.dev
```

Access tokens from `gcloud auth print-access-token` expire after one hour.
Re-run `helm registry login` if you see a `401 Unauthorized` during the
upgrade.

> **Air-gapped / firewalled environments:** if your cluster nodes can reach
> `us-south1-docker.pkg.dev` but your workstation cannot, use the
> extracted-zip workflow below. The OCI workflow only works when the host
> running `helm upgrade` can reach the registry.

---

## Upgrade via OCI Registry (recommended)

Point `helm upgrade` directly at the OCI URL and pin the chart version with
`--version`. All values files, `--set` flags, and `--set-file` flags are the
same as the original install.

```bash
VERSION="<chart-version>"   # e.g. 2.57.2

helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  --set dojo.existingSecret=dojopro-secrets \
  --set license.existingSecret=dojopro-license \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

> The platform and profile preset paths above are `presets/platforms/...`
> (no `$CHART/` prefix). When Helm pulls a chart from OCI, the presets live
> inside the pulled chart, but `-f` here points at **local copies** of those
> files. If you do not keep local copies of the presets, extract the chart
> first with `helm pull oci://... --version $VERSION --untar` and reference
> them from the extracted directory — or use the extracted-zip workflow.

**Inline secrets + license file variant:**

```bash
helm upgrade dojopro \
  oci://us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2/dojopro \
  --version $VERSION \
  -n $NAMESPACE \
  -f presets/platforms/<platform>.yaml \
  -f presets/profiles/standard.yaml \
  -f my-company.yaml \
  -f my-secrets.yaml \
  --set-file license.contents=/path/to/license.lic \
  --set-file ddorch.tls.rootCa=orch_ca.crt \
  --set-file ddorch.tls.cert=orch_server.crt \
  --set-file ddorch.tls.key=orch_server.key \
  --wait --timeout 15m
```

> Always pin `--version`. Omitting it pulls whatever tag the registry
> resolves to at the moment of the command — not repeatable, not
> auditable. Pin the version so reruns, rollbacks, and incident response
> all reference the same artifact.

---

## Upgrade via Extracted Zip

For workstations that cannot reach the OCI registry, or for customers who
prefer to stage the chart as a local file, the packaged zip from the GitHub
release works the same way at upgrade time as it does at install time. The
only difference from install is the command verb (`helm upgrade` instead of
`helm install`).

1. Download `dojo-pro-helm-bundled-<version>.zip` (and the detached
   signature `.asc`) from the GitHub release.
2. Verify the signature using the public key
   (`dojo-pro-release-signing.asc`) as documented in the install guide.
3. Extract the chart to a **versioned path** so presets do not collide with
   older extractions:

   ```bash
   unzip dojo-pro-helm-bundled-<version>.zip -d /tmp/dojopro-<version>
   cd /tmp/dojopro-<version>
   mkdir -p dojopro-<version>
   tar -xzf dojopro-<version>.tgz -C dojopro-<version>/
   CHART="/tmp/dojopro-<version>/dojopro-<version>/dojopro"
   ```
4. Run the upgrade using the extracted chart path — same values files and
   flags as your original install:

   ```bash
   helm upgrade dojopro $CHART \
     -n $NAMESPACE \
     -f $CHART/presets/platforms/<platform>.yaml \
     -f $CHART/presets/profiles/standard.yaml \
     -f my-company.yaml \
     --set dojo.existingSecret=dojopro-secrets \
     --set license.existingSecret=dojopro-license \
     --set-file ddorch.tls.rootCa=orch_ca.crt \
     --set-file ddorch.tls.cert=orch_server.crt \
     --set-file ddorch.tls.key=orch_server.key \
     --wait --timeout 15m
   ```

> **Re-extract on every upgrade.** Preset files evolve between chart
> versions. Reusing an old extraction silently pins your upgrade to the old
> preset defaults.

---

## Upgrade with ArgoCD

When DefectDojo Pro is managed by ArgoCD, upgrading is a single change to
`targetRevision` in the Application spec. The platform and profile presets
are versioned inside the chart, so they update in lockstep.

```yaml
spec:
  source:
    repoURL: us-south1-docker.pkg.dev/defectdojo-container-registry/dojo-pro-helm-v2
    chart: dojopro
    targetRevision: <chart-version>    # bump this
    helm:
      valueFiles:
        - presets/platforms/aws-eks.yaml
        - presets/profiles/standard.yaml
      values: |
        # your environment-specific values
      parameters:
        - name: dojo.existingSecret
          value: dojopro-secrets
        - name: license.existingSecret
          value: dojopro-license
```

Sync the Application after editing `targetRevision`. ArgoCD will pull the
new chart from the OCI registry and reconcile.

> ArgoCD needs its own credentials to the OCI registry. Configure the repo
> secret with `type: helm` and `enableOCI: "true"`. See the ArgoCD
> [Helm OCI docs](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/#helm-oci-support)
> for the exact Secret shape.

---

## Verify the Upgrade

After `helm upgrade` returns (or ArgoCD reports Synced / Healthy), confirm
the new revision is live:

```bash
# Chart revision bumped and status is deployed
helm list -n $NAMESPACE

# All pods Running and Ready — expect django, celery worker/beat,
# connectors, ddorch, ddorch-workers, and (if enabled) mcp-server
kubectl get pods -n $NAMESPACE

# Migrations succeeded — the initializer job should show Completed
kubectl get jobs -n $NAMESPACE

# App version matches the target
kubectl get deployment -n $NAMESPACE \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.template.spec.containers[*].image}{"\n"}{end}'
```

Hit the login page to confirm the UI comes up and the admin user can
authenticate. For programmatic checks, the `/login/` endpoint returns 200
when the app is healthy.

---

## Rollback

Helm keeps release history by revision. If the upgrade regresses behavior,
roll back to the previous revision:

```bash
# Inspect history
helm history dojopro -n $NAMESPACE

# Roll back to the previous revision
helm rollback dojopro <previous-revision> -n $NAMESPACE --wait --timeout 15m
```

> **Database migrations do not roll back.** Helm rollback restores the
> manifest state (images, configs, secrets) but does not run
> `migrate --revert`. If the upgrade applied a schema migration you need
> to reverse, restore from the backup taken in
> [Before You Upgrade](#before-you-upgrade) or coordinate a manual
> migration reversal with DefectDojo support before rolling back the
> Helm release.

ArgoCD users can roll back by reverting the `targetRevision` change in
git (or via `argocd app rollback`) and syncing.

---

## Troubleshooting

**`401 Unauthorized` pulling the chart.**
Access token has expired. Re-run `helm registry login` with a fresh
`gcloud auth print-access-token`.

**`Error: UPGRADE FAILED: cannot patch ... field is immutable`.**
A selector or other immutable field drifted. The chart pins stable
selector labels, so this usually means a prior in-place edit to a
Deployment. Capture the diff, delete the offending resource, and re-run
the upgrade so Helm recreates it.

**`Error: UPGRADE FAILED: conflict occurred while applying object ... conflict with "kubectl-edit" ... .spec.replicas`.**
Helm 4 uses server-side apply, which tracks field ownership. This error
means another manager — `kubectl edit`, `kubectl scale`, or the HPA
controller (`kube-controller-manager`) — changed a field Helm renders,
most commonly `.spec.replicas`. Take ownership back once:

```bash
helm upgrade ... --force-conflicts
```

Chart versions with this fix omit `replicas` from Deployments whose HPA
is enabled, so the HPA scaling no longer conflicts with upgrades. If you
manually scaled a Deployment with `kubectl`, prefer adjusting the
corresponding `replicas`/`horizontalpodautoscaler` value instead so the
chart stays the owner.

**`Error: UPGRADE FAILED: timed out waiting for the condition`.**
Pods did not reach Ready within the `--timeout` window. Inspect the
laggy workload:

```bash
kubectl describe pod -n $NAMESPACE <pod>
kubectl logs -n $NAMESPACE <pod> --all-containers --tail=200
```

Common causes: image pull failures (registry auth), schema migration
still running (bump `--timeout`), or readiness probes failing against a
mis-configured FQDN.

**Preset changed between versions and my values file now conflicts.**
Re-render with `helm template` (see [Before You Upgrade](#before-you-upgrade))
and reconcile your overrides against the new preset defaults before
running `helm upgrade`.

**`values don't meet the specifications of the schema ... got string, want boolean`.**
An on/off value in your override is quoted. Helm treats `"false"` as a
non-empty string, and a non-empty string is truthy, so the feature was
switching **on** when you meant to switch it off. The schema now rejects
the quoted form instead of letting it through. Drop the quotes:

```yaml
networkPolicy:
  enabled: "false"   # wrong: turns network policies ON
  enabled: false     # right
```

The error message names the offending path. Unquoted `false`, `no`, and
`off` all parse as a real boolean and are accepted.
