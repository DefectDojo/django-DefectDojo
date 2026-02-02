---
title: "Glossary"
weight: 1
---

Below is a simple glossary to help understand DefectDojo's various capabilities, along with an indication of whether each defined feature is present/applicable in the Pro version of DefectDojo, the OS version, or both. 

## Product Hierarchy (Both) 
The structural model used to organize security data within DefectDojo, consisting of Organizations → Assets → Engagements → Tests → Findings.
## Organization (Both)
A top-level hierarchical object that serves as the parent object of Assets in DefectDojo Pro. It provides a shared context for governance, access control, and reporting across all child Assets.
## Asset (Both)
A first-class object representing a deployable or logical system entity (e.g., application, host, environment) within Organizations. Assets support parent-child relationships and richer business metadata in the Pro version, but do not support parent-child relationships in the OS version.
### Asset Hierarchy (Pro)
A parent-child relationship model between Assets that enables inheritance of context and aggregation of Findings.
## Engagement (Both)
A scoped security activity representing a testing window, pipeline, or assessment context.
## Test (Both) 
A single execution of a scanner or manual assessment within an Engagement. Tests store execution metadata and act as the ingestion point for Findings.
## Service (Both)
An optional sub-object used to attribute Findings to a specific component or interface within an Asset. Services are most useful in OS DefectDojo, as their functionality is replicated and enhanced by Asset Hierarchy in the Pro version.
## Finding (Both)
The most granular vulnerability object in DefectDojo's Product Hierarchy that represents a discrete security issue.
### Finding Status (Both)
The current lifecycle state of a Finding (e.g., Active, Verified, Inactive/Mitigated, Under Review, Risk Accepted, False Positive, Out Of Scope). Finding Status determines inclusion in metrics and dashboards.
### Finding Priority/Risk (Pro) 
A calculated or derived value that represents remediation urgency by combining severity with contextual factors such as asset criticality or exploitability. Priority is distinct from raw severity and is used for risk-based decision-making.
### Finding Groups (Both)
A mechanism for grouping related Findings across Organizations, Assets, or tools. Finding Groups enable consolidated analysis and higher-level reporting.
## Endpoint (Both)
A network-reachable location (URL, IP, port) associated with a Finding. Endpoints provide technical exploit context.
## Import (Both)
The process of ingesting scan results or manual findings into DefectDojo, typically by uploading a file or submitting data via the API. During import, DefectDojo parses, normalizes, deduplicates, and associates findings with the appropriate Asset, Engagement, Test, and related objects.
## Reimport (Both)
The action of ingesting new scan results into an existing Test. Reimporting updates Finding states based on presence or absence in new data.
## Deduplication (Both)
The process of correlating incoming Findings with existing ones using hashes and matching logic, enabling historical tracking across scan executions.
## False Positive (Both)
A Finding state indicating the issue is invalid or non-exploitable. False positives are retained for auditability but excluded from risk calculations.
## Risk Acceptance (Both)
A workflow state indicating an acknowledged but unresolved Finding. Accepted risks remain visible but are excluded from SLA enforcement.
## Metadata (Both)
Key data attached to Tests or Findings, such as branch name or build ID, commonly supplied via CI/CD pipelines.
## CI/CD Integration (Both)
Automated ingestion of scan results during build or deployment workflows. Integrations typically rely on the API and importer framework.
## API (Both)
A RESTful interface used to programmatically manage DefectDojo objects. The API is the primary mechanism for automation and pipeline integration.
## Webhook (Pro)
An outbound HTTP callback triggered by specific events (e.g., Finding creation). Webhooks enable real-time integration with external systems.
## SLA Configuration (Pro)
Policy definitions that assign remediation deadlines based on severity or risk attributes. SLAs enable enforcement and performance measurement.
## User Role (Both)
A permission set defining allowed actions within DefectDojo. Roles enforce access control across Assets and Engagements.
## Universal Importer (Pro)
A flexible ingestion mechanism that allows scan data to be imported without a tool-specific importer. It relies on normalized field mapping rather than predefined scanner schemas.
## DefectDojo-CLI (Pro)
A command-line interface used to interact with DefectDojo programmatically. The CLI is commonly used in CI/CD pipelines to automate scan uploads and object management.
## API Connectors (Pro)
Prebuilt, managed integrations that connect DefectDojo with external platforms (e.g., ticketing, messaging, or DevOps tools). API Connectors reduce the need for custom scripting.
## Universal Parser (Pro)
A generalized parsing engine used by the Universal Importer to interpret incoming scan data. It applies consistent normalization and deduplication logic across unsupported formats.
## Smart Upload (Pro)
An intelligent ingestion workflow that automatically determines how scan results should be mapped to Assets or Engagements, reducing manual configuration during import.
## Executive Insights (Pro)
High-level, business-oriented analytics designed for leadership audiences, focusing on trends, exposure, and program health rather than individual Findings.
## Priority Insights (Pro)
Analytical views that surface the most critical risks based on priority scoring rather than severity alone, supporting risk-based remediation planning.
## Program Insights (Pro)
Metrics and visualizations that evaluate the effectiveness and maturity of a security program over time. Program Insights emphasize trends, coverage, and operational performance.
## Tool Insights (Pro)
Analytics focused on scanner performance, coverage, and contribution to Findings, helping teams optimize tool usage and reduce noise.
## Rules Engine (Pro)
A policy-driven automation system that applies conditional logic to Findings during ingestion or lifecycle events, automating severity changes, assignments, or workflows.
## Integrations (Both)
Connections between DefectDojo and external tools or platforms for data ingestion, notification, or workflow automation. Pro includes deeper, managed integrations beyond basic importers and API usage.
