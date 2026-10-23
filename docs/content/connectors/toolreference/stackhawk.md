---
title: "StackHawk"
description: "How to set up the StackHawk Upstream Connector for DefectDojo"
weight: 55
audience: pro
---
The StackHawk connector uses the [StackHawk API](https://apidocs.stackhawk.com/) to import HawkScan DAST findings. DefectDojo reads every organization the API key's user belongs to and every application in each, creates a Record for each application, and imports the results of that application's most recent completed scan in each of its environments. No per\-application configuration is needed.

#### Prerequisites

You will need a StackHawk API key, created in the StackHawk platform under **Settings → API Keys**. Your StackHawk plan must include API access. DefectDojo exchanges the key for a short\-lived access token at sync time and logs in again when that token expires. Neither the key nor the token is logged.

#### Connector Mappings

1. Keep the pre-filled **Location**, `https://api.stackhawk.com`.
2. Enter the StackHawk API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each StackHawk application to a Record and reads the newest completed scan of each of its environments; a newer scan that errored or is still running does not replace it. Each alert (one per HawkScan plugin) becomes one finding:

* the title, description, severity (High/Medium/Low), CWE and references come from the alert,
* every path the alert was found on becomes an endpoint and is listed under **Steps to Reproduce** with its HTTP method,
* the application is recorded as the component and service, and the environment as the component version,
* when every path is marked **False Positive** or **Risk Accepted** in StackHawk, the finding is imported with that status.

Findings are imported as dynamic findings under the **StackHawk HawkScan** test type, the same test type used when a StackHawk webhook report is imported. They are de\-duplicated on the plugin id, application and environment, so a finding synced by the connector matches the same finding from an imported webhook report.

See the [StackHawk API documentation](https://apidocs.stackhawk.com/) for more information.
