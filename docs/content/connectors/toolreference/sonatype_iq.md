---
title: "Sonatype IQ"
description: "How to set up the Sonatype IQ Upstream Connector for DefectDojo"
weight: 128
audience: pro
---
The Sonatype IQ connector uses the Sonatype IQ Server (Nexus Lifecycle) REST API to import open\-source component vulnerabilities. It enumerates every application in your IQ organization and, for each one, imports the component vulnerabilities from that application's latest report at the lifecycle stage you configure. DefectDojo creates a Record for each application automatically — there is no per\-application configuration.

#### Prerequisites

You will need a Sonatype IQ user account with the **View IQ Elements** permission on the applications you want to import. Sonatype recommends authenticating with a **user token** (generated under **My Profile > User Token** in IQ Server) rather than a password; the token's two parts map to the Username and User Token fields below. The connector works with both self\-hosted IQ Server and Sonatype\-hosted (SaaS) instances.

#### Connector Mappings

1. In the **Location** field, enter your IQ Server base URL — for a self\-hosted server, `https://iq.example.com`; for a Sonatype\-hosted instance, `https://<tenant>.sonatype.app/platform`.
2. Enter the IQ user (or the user\-code part of your user token) in the **Username** field.
3. Enter the IQ user token (or password) in the **User Token** field.
4. Optionally, set a **Stage** to choose which lifecycle stage's report is imported per application (`build`, `stage-release`, `release`, and so on). Leave it blank to use `build`.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each application becomes a Record, and each security issue in that application's latest report for the selected stage is imported as a finding. Severity is derived from the issue's numeric score, and CVE references, CWE, the CVSS vector, and the affected component's package URL (PURL) are included where available.
