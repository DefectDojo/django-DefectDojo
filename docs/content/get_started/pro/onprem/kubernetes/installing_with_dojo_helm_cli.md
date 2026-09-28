---
title: "Installing on Kubernetes with dojo-helm-cli"
description: "Use dojo-helm-cli to pull the DefectDojo Pro Helm chart and images, validate a cluster, deploy, and collect diagnostics"
draft: false
weight: 1
audience: pro
---

`dojo-helm-cli` is the command line tool DefectDojo provides for Kubernetes deployments. It is the Helm counterpart to `dojo-compose-cli`. It logs `docker` and `helm` into the DefectDojo Pro registry with your license, pulls the chart and every image the chart can use, checks a cluster before you install, runs the install for your platform, and gathers a diagnostics bundle when something goes wrong.

It does not replace the Helm chart or its installation guide. The CLI's `deploy` command hands off to a bootstrap script that makes sensible choices for each platform. If you need control over every value, or you deploy through GitOps, follow the full [DefectDojo Pro Installation Guide](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/) and use the CLI for the parts around it: registry access, pulling artifacts, preflight checks and diagnostics.

## Before you start

You need a Kubernetes cluster and a workstation with access to it. Size the cluster first, using the [hardware sizing guidance](/get_started/pro/onprem/hardware_sizing/).

On the workstation you run the CLI from:

- `docker` and `helm` 3.x, both on `PATH`
- `kubectl`, with its current context pointed at the target cluster (`oc` works too, for OpenShift)
- `bash`, `openssl` and `jq`, which the bootstrap scripts use during `deploy`
- The cloud provider's CLI when deploying to AWS or GCP: the `aws` CLI for EKS and `gcloud` for GKE, each already authenticated

The CLI ships as binaries for Linux (amd64, arm64 and 386), macOS (amd64 and arm64) and Windows. On Windows, run `deploy` from WSL or Git Bash, since the bootstrap scripts need `bash`.

You also need two files from DefectDojo, which arrive with your subscription: the `dojo-helm-cli` archive for your platform and your license file, usually named `dojopro.lic`. Contact your account representative or [support@defectdojo.com](mailto:support@defectdojo.com) if you do not have them.

### Outbound connectivity

The workstation needs HTTPS access to `us-south1-docker.pkg.dev`, the DefectDojo Pro registry, for `register`, `download-artifacts`, `deploy` (when it pulls the chart) and `update-binary`. Allowlist it by hostname. It sits behind a content delivery network, so its addresses change.

The cluster itself needs the same registry access to pull images, unless you mirror them into a private registry first. That is covered under [Air-gapped and private registries](#air-gapped-and-private-registries).

## Install the CLI

Extract the archive and put the binary somewhere on your `PATH`:

```bash
tar -xzvf dojo-helm-cli_*.tar.gz
sudo mv dojo-helm-cli /usr/local/bin/
dojo-helm-cli --version
```

Keep your license file handy. Every command that needs it takes `--license-path`, and if you leave that off the CLI looks for `dojopro.lic` in the current directory. Running the CLI from the directory that holds your license saves a lot of typing.

## Authenticate to the registry

```bash
dojo-helm-cli register --license-path /path/to/dojopro.lic
```

This logs both `docker` and `helm` into `us-south1-docker.pkg.dev` using the credential in your license. After it, plain `helm pull` and `docker pull` against the DefectDojo Pro registry work in the same shell, which is what the [Helm upgrade guide](/get_started/pro/onprem/kubernetes/upgrading_on_kubernetes/) assumes.

`download-artifacts`, `deploy` and `update-binary` authenticate on their own, so you only strictly need `register` when you want to use `helm` or `docker` directly.

## Deploy

`deploy` does not run Helm itself. It picks the bootstrap script for your platform, passes it your flags and license, and hands over the terminal. The script generates the application secrets and internal TLS certificates, provisions media storage, and runs `helm upgrade --install`. It prompts for anything you did not supply and asks for confirmation before it changes the cluster.

The script installs into whatever cluster your current `kubectl` context points at. Check it before you start:

```bash
kubectl config current-context
```

### Choose a platform

```bash
dojo-helm-cli deploy --list-platforms
```

| Platform | Target | What it sets up | Required flags |
| --- | --- | --- | --- |
| `aws` | AWS EKS | ALB ingress with an ACM certificate, EFS media storage | `--fqdn`, `--acm-cert-arn` |
| `gcp` | GCP GKE | Google-managed or pre-shared certificate, GCS bucket media storage through Workload Identity | `--fqdn` |
| `openshift` | OpenShift (OCP, ROSA, OKD) | Route ingress, PVC or NFS media storage | `--fqdn` |
| `generic` | Any other cluster (on-premise, Rancher, k3s, kind) | ingress-nginx, PVC or NFS media storage | `--fqdn` |

`--fqdn` is the DNS name users will browse to, for example `defectdojo.internal.example.com`.

Each platform expects a few things to exist already:

- **aws**: the AWS Load Balancer Controller and the EFS CSI driver installed in the cluster, and an issued ACM certificate for your FQDN. The script creates an EFS filesystem if you do not name one.
- **gcp**: Workload Identity and the GCS FUSE CSI driver add-on enabled on the cluster. The script creates the media bucket if it does not exist.
- **openshift**: a default StorageClass that provisions ReadWriteMany volumes, or an NFS export. For a name under your cluster's apps domain, the Route picks up the default wildcard certificate. See [Deploying DefectDojo Pro on OpenShift](/get_started/pro/onprem/kubernetes/openshift_deployment/) for what differs on that platform.
- **generic**: an ingress controller (nginx by default) and a default StorageClass. The `standard` and `performance` profiles run more than one replica, so they need ReadWriteMany storage such as NFS or Longhorn.

### Run it

On EKS, for example:

```bash
dojo-helm-cli deploy --platform aws \
    --fqdn defectdojo.internal.example.com \
    --acm-cert-arn arn:aws:acm:us-east-1:123456789012:certificate/<id> \
    --license-path /path/to/dojopro.lic
```

On any other cluster:

```bash
dojo-helm-cli deploy --platform generic \
    --fqdn defectdojo.internal.example.com \
    --license-path /path/to/dojopro.lic
```

Add `--dry-run` first if you want to see the commands the script would run without it touching the cluster.

The flags `deploy` accepts:

| Flag | What it does | Default |
| --- | --- | --- |
| `--platform` | `aws`, `gcp`, `openshift` or `generic` | none |
| `--fqdn` | DNS name users browse to | none |
| `--license-path` | License file | `./dojopro.lic` |
| `--chart-package` | A packaged chart `.tgz` you already have. Leave it out to pull the chart from the registry. | pull from registry |
| `--version` | Chart version to pull when `--chart-package` is not given | newest published |
| `--namespace`, `-n` | Namespace to install into | `dojopro` |
| `--release` | Helm release name | `dojopro` |
| `--acm-cert-arn` | ACM certificate for the ALB HTTPS listener (`aws` only) | none |
| `--dry-run` | Print the commands instead of running them | off |

### Supplying everything else

Anything else the script needs is read from `DOJO_*` environment variables, and prompted for when they are not set. Export them before running `deploy` and the script will not ask. The ones you are most likely to set:

| Variable | What it is |
| --- | --- |
| `DOJO_PROFILE` | Resource profile: `minimal`, `standard` or `performance`. Defaults to `standard`. |
| `DOJO_DB_HOST`, `DOJO_DB_PORT`, `DOJO_DB_NAME`, `DOJO_DB_USER`, `DOJO_DB_PASSWORD` | Your external PostgreSQL. Note that the scripts default the database name and user to `defectdojo`. |
| `DOJO_REDIS_HOST`, `DOJO_REDIS_PASSWORD` | An external Redis or Valkey, such as ElastiCache or Memorystore |
| `DOJO_ADMIN_USER`, `DOJO_ADMIN_EMAIL`, `DOJO_ADMIN_PASSWORD` | The initial administrator. The password is generated if you leave it unset. |
| `DOJO_STORAGE_TYPE`, `DOJO_STORAGE_CLASS`, `DOJO_MEDIA_EXISTING_PVC`, `DOJO_NFS_SERVER`, `DOJO_NFS_PATH` | Media storage on `openshift` and `generic` |
| `DOJO_EFS_FS_ID`, `DOJO_AWS_REGION` | An existing EFS filesystem, and the region to create one in (`aws`) |
| `DOJO_GCS_BUCKET`, `DOJO_GCP_PROJECT`, `DOJO_GCP_REGION` | The media bucket (`gcp`) |
| `DOJO_TLS_SECRET`, `DOJO_TLS_CERT_FILE`, `DOJO_TLS_KEY_FILE` | Your own certificate for the ingress (`generic`) |

**If you leave the database variables unset, the script deploys an embedded PostgreSQL inside the cluster.** That is fine for evaluation and wrong for production data. For production, point it at a managed or externally run PostgreSQL 16 or newer, and create the orchestrator database alongside the main one as described in [Pre-flight: Orchestrator (ddorch) Database](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#pre-flight-orchestrator-ddorch-database).

Each script lists the full set of variables it reads in its header. The installation guide's [pre-install checklist](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#pre-install-checklist) is also a good way to gather the values before you begin.

### Check on the release

```bash
dojo-helm-cli deploy status
```

This is `helm status` for the release. The first install runs an initializer job that applies database migrations, and the application is not usable until that job has completed. The installation guide's [Verify](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#verify) section covers what a healthy deployment looks like.

If you did not set `DOJO_ADMIN_PASSWORD`, the script generates one and prints it. Save it.

### Uninstalling

```bash
dojo-helm-cli deploy uninstall
```

This is `helm uninstall` for the release. It does not remove cloud resources the script created, such as EFS filesystems, GCS buckets or DNS records, and PersistentVolumes can outlive the release too. The [Uninstalling](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#uninstalling) section of the installation guide covers cleaning those up if you are tearing the deployment down for good.

Both `status` and `uninstall` take `--namespace`, `--release`, `--kubeconfig` and `--context` if you used something other than the defaults.

## Validate before deploying

`preflight` checks a pulled chart and a target cluster before you install. It is most useful when you install the chart yourself with your own values, rather than through `deploy`.

It expects the chart directory that `download-artifacts` produces:

```bash
dojo-helm-cli preflight --chart-dir ./dojopro --values my-values.yaml
```

It runs four checks, and `--check` or `--skip` pick among them:

| Check | What it verifies |
| --- | --- |
| `integrity` | Nothing in the chart has been modified except `values.yaml`. Customizations belong in values files, not in edited templates. |
| `connectivity` | `kubectl` is present, the cluster API answers its health check, and there is a current context. |
| `tls` | A certificate and key are a valid, matching pair, and how long until the certificate expires. Supply `--tls-cert` and `--tls-key`, or `--tls-secret` to check a secret already in the cluster. Skipped when you give it neither. |
| `scale` | The cluster has Ready nodes and a StorageClass, and the resource requests the chart would render, with your values, fit on those nodes. |

It warns rather than fails when there is no default StorageClass, since that only matters if your values do not name one.

## Air-gapped and private registries

`download-artifacts` is meant for staging an install onto a network that cannot reach the DefectDojo Pro registry. Run it on a connected host:

```bash
dojo-helm-cli download-artifacts \
    --license-path /path/to/dojopro.lic \
    --output-dir ./artifacts
```

It pulls the chart and extracts it to `./artifacts/dojopro`, along with an integrity manifest that `preflight` uses later. It then pulls every image the chart lists into the local Docker image store. That list covers every image any configuration of the chart can render, including optional components and the `-fips` variants, so what you stage still works if you change your values later. Development images are skipped.

Without `--version` it asks the registry for the newest chart and prints the version it chose, so you always know what you pulled. Pass `--version` to pin one. Chart versions published before the chart carried its own image list cannot be downloaded by this CLI, and the command fails with an error saying so rather than guessing.

The images end up in the local Docker image store, not in files. From there, retag and push them into a registry your cluster can reach, or `docker save` them for transfer. Then point the chart at that registry, which [Private Registry / Air-Gapped Environments](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#private-registry--air-gapped-environments) in the installation guide covers.

## Collecting diagnostics

When a deployment is not behaving, `diag` gathers its state into one `.tar.gz` you can send to support. It runs locally and uploads nothing.

```bash
dojo-helm-cli diag --namespace dojopro
```

**Pass `--namespace`.** `diag` defaults to `defectdojo`, while `deploy` installs into `dojopro` by default. Without the flag on a `deploy`-based install it collects from the wrong namespace.

It runs four collectors, and if one fails, the failure is recorded in the bundle and the rest still run:

| Collector | What it gathers |
| --- | --- |
| `env` | CLI, `kubectl`, `helm` and `docker` versions, the current context, and the API server health check |
| `helm` | `helm status`, the release's values, and its rendered manifest |
| `resources` | Pods, deployments, statefulsets, services, PVCs, configmaps, secrets and events in the namespace |
| `logs` | Recent container logs for each pod |

Useful options:

| Option | What it does | Default |
| --- | --- | --- |
| `--output`, `-o` | Where to write the bundle | `dojo-diag-<namespace>-<timestamp>.tar.gz` |
| `--release` | Helm release name | `dojopro` |
| `--since` | Only include logs newer than this, for example `1h` | `24h` |
| `--tail` | Maximum log lines per pod | `2000` |
| `--collector`, `--skip` | Run only, or leave out, named collectors | all four |
| `--kubeconfig`, `--context` | Which cluster to collect from | current context |

By default the bundle is redacted. Secret values, sensitive values and environment keys such as passwords and API tokens, and token-shaped strings in logs are masked. `--no-redact` turns that off, and the resulting bundle contains plaintext secrets. Even with redaction on, look through a bundle before you share it outside your organization.

## Updating the CLI

```bash
dojo-helm-cli update-binary
```

This replaces the CLI with the newest release. Pass `--version` to install a specific release instead, which is also how you go back to an earlier one. The CLI tests the downloaded binary before swapping it in, so a corrupt download is discarded rather than installed. An update downloads about 48 MB.

On Windows the running binary cannot be overwritten, so the old one is moved aside to `dojo-helm-cli.exe.old`. That file is safe to delete.

When a newer release exists, the CLI prints a one-line notice before running your command. The notice never updates anything on its own and never makes a command fail. The answer is cached for a day. It only appears in an interactive terminal, so it stays out of CI logs. To turn it off where a terminal is present, set `DOJO_CLI_DISABLE_UPDATE_CHECK=true` or pass `--disable-update-check`.

On an air-gapped machine, update the CLI on a connected host and copy the binary across.

## Command reference

`dojo-helm-cli --help` lists everything, and every subcommand takes `--help` as well.

| Command | What it does |
| --- | --- |
| `register` | Log `docker` and `helm` into the DefectDojo Pro registry |
| `license print` | Show license details. Repeat `--filter` to limit the output to specific fields. |
| `download-artifacts` | Pull the chart and every image it references |
| `preflight` | Validate a pulled chart and the target cluster |
| `deploy` | Install through the bootstrap script for a platform |
| `deploy --list-platforms` | List platforms and what each requires |
| `deploy status` | Show the release status |
| `deploy uninstall` | Uninstall the release |
| `diag` | Collect a diagnostics bundle for support |
| `update-binary` | Update the CLI itself |

Global options: `--verbose` (`-V`) for more output, and `--disable-update-check`.

## Questions or support

If an install fails, run `dojo-helm-cli diag` against the namespace and send the bundle, along with the command you ran and its output, to [support@defectdojo.com](mailto:support@defectdojo.com).
