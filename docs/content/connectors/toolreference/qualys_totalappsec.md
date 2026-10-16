---
title: "Qualys TotalAppSec"
description: "How to set up the Qualys TotalAppSec Upstream Connector for DefectDojo"
weight: 109
audience: pro
---
The Qualys TotalAppSec connector imports **web application (DAST) findings** from Qualys TotalAppSec, formerly Qualys Web Application Scanning (WAS). It is a separate connector from [Qualys](/connectors/toolreference/qualys/) (VMDR): the two cover different assets and are configured independently, so you can use either or both. Both use the same Qualys API URL and API user.

DefectDojo creates a Record for each TotalAppSec **web application** the API user can see, or only for the web applications carrying the tags you name in **Web Application Tags**.

#### Prerequisites

A Qualys API user with **TotalAppSec (WAS) API access** and permission to the web applications you want to import. KnowledgeBase access is optional: with it, findings also carry Qualys's description, impact and solution text; without it, they import without that text.

You will also need your subscription's **Qualys API URL**, which differs per subscription. Find it in the Qualys UI under **Help \> About**, or on the Qualys [Platform Identification](https://www.qualys.com/platform-identification/) page (for example `https://qualysapi.qg2.apps.qualys.com` for US Platform 2).

#### Connector Mappings

1. Enter your Qualys API URL in the **Location** field (for example `https://qualysapi.qg2.apps.qualys.com`).
2. Enter the Qualys API username in the **Username** field.
3. Enter the Qualys API password in the **Password** field.
4. Optionally, restrict discovery with **Web Application Tags** (see below).
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

**Web Application Tags** is a comma\-separated list of Qualys tag names, for example `dast-in-scope, Production`. A web application is discovered if it carries **any** of the listed tags. Tag names are matched exactly, with no wildcards. Leave the field blank to discover every web application the API user can see; on a large subscription we recommend setting it.

Each sync imports the web application's **open** findings: those Qualys reports as New, Active or Reopened, of type Vulnerability or Sensitive Content. Information Gathered items are scan metadata and are not imported. A finding Qualys marks Fixed drops out of the next sync and is closed in DefectDojo.

| DefectDojo | Qualys TotalAppSec |
|---|---|
| Unique ID From Tool | the finding's Qualys unique ID |
| Vulnerability ID From Tool | QID |
| Severity | the CVSS v3 base score (below 4.0 Low, 4.0–6.9 Medium, 7.0–8.9 High, 9.0 and up Critical); when a finding has no CVSS score, the Qualys severity (1–2 Low, 3 Medium, 4 High, 5 Critical) |
| CWE, CVSS v3 Score | CWE, CVSS v3 base score |
| Endpoint | the finding's URL |
| Parameter, Payload | the vulnerable parameter and the payload that triggered it |
| Steps to Reproduce | every request and payload Qualys recorded |
| Description | KnowledgeBase diagnosis, plus where and how the finding was detected |
| Impact, Mitigation | KnowledgeBase consequence and solution |
| Date | first detected date |
| Status | ignored in Qualys as False Positive, Risk Accepted or Not Applicable: imported as False Positive, Risk Accepted or Out of Scope, and inactive |

Findings are imported under the **Qualys WAS \- Connectors Import** test type and de\-duplicated on the Qualys unique ID.

#### Notes

* A Qualys ignore status is applied when a finding is first imported. After that, triage each finding in one place: a finding closed in DefectDojo but still open in Qualys is reopened on the next sync, and a finding ignored (or un\-ignored) in Qualys after its first sync keeps its DefectDojo status.
* Findings imported earlier from Qualys WAS XML reports with the **Qualys Webapp Scan** parser are a different test type, so they are not de\-duplicated against findings from this connector.
