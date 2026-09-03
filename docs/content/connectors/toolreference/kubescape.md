---
title: "Kubescape"
description: "How to set up the Kubescape Upstream Connector for DefectDojo"
weight: 85
audience: pro
---
The Kubescape connector reads Kubernetes posture (misconfiguration) results produced by the [Kubescape operator](https://kubescape.io/docs/install-operator/) directly from the cluster's Kubernetes API — no ARMO SaaS account is required. It reads the `WorkloadConfigurationScan` objects served by the operator's in-cluster storage aggregated API (`spdx.softwarecomposition.kubescape.io/v1beta1`). Each Kubernetes **namespace** that has posture results is mapped to a Record (Asset); each failed control on a workload becomes a Finding.

#### Prerequisites

- The Kubescape operator must be installed in the target cluster with configuration scanning enabled (see [Installing in your cluster](https://kubescape.io/docs/install-operator/)). Confirm results exist with `kubectl get workloadconfigurationscans -A`.
- A **kubeconfig** granting read access to the `spdx.softwarecomposition.kubescape.io` API group (list/get on `workloadconfigurationscans`) for the target cluster.

#### Connector Mappings

1. Enter the cluster's API server URL (or a friendly cluster identifier) in the **Location** field.
2. Paste the **kubeconfig** for the target cluster in the `kubeconfig` field. Optionally set `kube_context` to select a context within it, and `cluster_name` to label the discovered Assets.
3. Each namespace with posture results is discovered as a Record; map the ones you want to import to DefectDojo Assets.

Findings are derived per failed control: the control name and workload identify the Finding, severity comes from the control's score factor, the control ID becomes the vulnerability ID, and each Finding links to its control reference at `https://hub.armosec.io/docs/`.
