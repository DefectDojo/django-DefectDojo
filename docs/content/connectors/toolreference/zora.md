---
title: "Zora"
description: "How to set up the Zora Upstream Connector for DefectDojo"
weight: 146
audience: pro
---
The Zora connector imports **Kubernetes cluster findings** from Zora. DefectDojo creates a Record for each **scanned cluster**.

Zora is a multi\-cluster manager, so DefectDojo reads the Zora resources in your **management cluster** and maps each cluster Zora scans to its own Record.

#### Prerequisites

A **kubeconfig** granting read access to the **management cluster** where the Zora Operator writes its results.

Unlike most connectors, this one does not use an API token — Zora exposes no REST API, and its results live only as Kubernetes resources, so DefectDojo reads them directly from the cluster.

#### Connector Mappings

1. Provide the kubeconfig for the management cluster.
2. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each scanned cluster becomes a Record, carrying the issues and vulnerability reports Zora recorded for it.
