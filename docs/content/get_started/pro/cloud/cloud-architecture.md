---
title: "Cloud Architecture"
description: "How DefectDojo Cloud is deployed and isolated on Google Kubernetes Engine."
weight: 4
audience: pro
---

DefectDojo Cloud is a multi-tenant SaaS platform running on **Google Kubernetes
Engine (GKE)** in Google Cloud. This page describes how the platform is
structured and how customer environments are kept separate.

![DefectDojo Cloud Kubernetes architecture: customer traffic enters through Google Cloud Load Balancing with Google-managed TLS into regional GKE clusters; each customer runs in its own Kubernetes namespace with a dedicated PostgreSQL database, Cloud Storage bucket, and Vertex AI project.](images/cloud_architecture_kubernetes.svg)

## How a request flows

1. Customer traffic (browser, API, or CI) arrives over **HTTPS** at **Google
   Cloud Load Balancing**, which terminates TLS using Google-managed
   certificates.
2. The load balancer routes the request into the customer's environment inside a
   **regional GKE cluster**, where the web/API tier (django, served by nginx and
   uWSGI) handles it.
3. The web tier reads and writes the customer's **dedicated PostgreSQL database**
   and **dedicated Cloud Storage bucket**, and uses an **in-namespace cache**
   (Redis/Valkey) for sessions and as the task broker.
4. Longer-running work, such as scan imports, deduplication, and notifications,
   is handed to **asynchronous workers** (Celery) so requests stay responsive.

## Tenant isolation

Every customer runs in its **own Kubernetes namespace**, and the data each
customer stores never shares a store with another customer:

- **Dedicated database**: a separate PostgreSQL database per customer (Cloud SQL).
- **Dedicated object storage**: a separate Cloud Storage bucket per customer for
  uploaded scans and media, mounted into the workloads via the GCS FUSE CSI driver.
- **Dedicated cache**: each namespace runs its own Redis/Valkey instance.
- **Per-customer credentials**: each environment has its own secrets and its own
  TLS certificate and hostname.

There is **no shared application data plane** between customers. Data is encrypted
in transit (TLS) and at rest (Google Cloud default encryption).

## Regions and data residency

The platform runs **regional GKE clusters across multiple geographies** (for
example North America, Europe, and Asia-Pacific). A customer environment, along
with its database and storage bucket, lives in the region selected for that
customer, which supports data-residency requirements.

## Workloads in a customer environment

Each namespace contains the components needed to run DefectDojo Pro end to end:

| Group | Purpose |
|---|---|
| **Web & API** | Serves the UI and REST API (django · nginx + uWSGI). |
| **Async processing** | Background jobs and scheduling (Celery workers + beat). |
| **Orchestration** | Coordinates multi-step workflows across the platform. |
| **Integrations** | Connectors and ticketing integrations. |
| **MCP server** | AI interface for connecting your own AI tooling. |
| **Sensei** | AI remediation through Google's Vertex Platform. |
| **In-namespace cache** | Redis/Valkey for sessions and task brokering. |

On each deploy, a short-lived **initializer job** runs database migrations before
the new version serves traffic.

## Sensei and AI isolation

Sensei, DefectDojo's AI remediation capability, runs through **Google's Vertex
Platform** with the same per-customer isolation as the rest of the data plane:

- Each customer's Sensei requests run in **that customer's dedicated GCP
  project**, authenticated with **per-customer credentials**.
- There is no shared AI tenancy: one customer's prompts, findings, and results
  never pass through another customer's environment.
- An **external AI provider is used only if the customer configures one** (for
  example through the MCP server or a customer-supplied AI integration).

## Platform services and operations

Shared, Google-managed services support every environment without carrying
customer data between tenants:

- **Artifact Registry**: signed container images.
- **Secret Manager**: secret and key material.
- **Cloud Monitoring & Logging**: metrics, logs, and alerting used by our
  on-call team. Node pools **autoscale** to absorb load.

The only cross-customer shared data is public vulnerability enrichment
(EPSS and KEV).

## Integrations are outbound-only

Connections to external systems, such as email (SMTP), ticketing (Jira,
ServiceNow, and others), security scanners, and error monitoring, are
**configured by the customer and initiated outbound** from the customer's
environment.

## Isolation by tier

DefectDojo Cloud is offered in tiers that differ in how much of the stack is
dedicated to a single customer:

![DefectDojo Cloud tenant isolation by tier: Standard and Pay-as-you-go tenants run in isolated namespaces on a shared GKE cluster and share a PostgreSQL instance with per-tenant logical databases; Premium tenants get a dedicated PostgreSQL database; the Dedicated tier runs in its own GKE cluster, VPC, and GCP project.](images/cloud_architecture_tiers.svg)

| Tier | Compute | Database | Network boundary | Sensei |
|---|---|---|---|---|
| **Standard** | Isolated namespace on a shared cluster | Own logical database and credentials on a shared PostgreSQL instance | Shared VPC, per-tenant hostname + TLS, optional IP allowlist | Included |
| **Pay-as-you-go** *(coming soon)* | Isolated namespace on a shared cluster | Own logical database and credentials on a shared PostgreSQL instance | Shared VPC, per-tenant hostname + TLS, optional IP allowlist | Included |
| **Premium** | Isolated namespace on a shared cluster | **Dedicated PostgreSQL database** per customer | Shared VPC, per-tenant hostname + TLS, optional IP allowlist | Included |
| **Dedicated** | **Own GKE cluster** | **Dedicated PostgreSQL database** in the customer's own VPC | **Own GCP project and VPC**, ingress restricted to the customer's IP range | Included |

Sensei is included in every tier, and in every tier it runs through Google's
Vertex Platform in the customer's own GCP project with per-customer credentials.

*Have a question this page doesn't answer? Contact your DefectDojo
representative.*
