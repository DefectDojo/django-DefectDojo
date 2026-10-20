---
title: "Wiz"
description: "How to set up the Wiz Upstream Connector for DefectDojo"
weight: 142
audience: pro
---
The Wiz connector imports **Issues and vulnerability findings**. DefectDojo creates a Record for each **Wiz Project**, plus a tenant\-level Record named after the tenant itself, for example **Wiz Tenant abc12**, that covers the entire Wiz tenant.

**You do not need Wiz Projects to use this connector.** If your tenant has no Projects, map the that tenant\-level Record Record and DefectDojo imports every Issue and vulnerability finding your service account can see. That Record also picks up findings on resources that no Project covers, so map it alongside your Project Records if your Projects do not cover everything. Mapping both a Project Record and the that tenant\-level Record Record imports that Project's findings into two Assets, so only do that if you want both views.

Using the Wiz connector requires you to create a service account: see the [Wiz documentation](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) for more info.  You will need a Wiz account to access the documentation.

The service account must meet all of the following requirements. A service account that misses one of them can still authenticate successfully but will import nothing:

* **Type**: Custom Integration (GraphQL API).
* **API scopes**: at minimum `read:projects`, `read:issues`, and `read:vulnerabilities`. `read:projects` is required even on a tenant with no Projects, because Discover still asks Wiz for the Project list.
* **Project visibility**: the service account must be scoped to every Wiz Project you want imported (or to all Projects). An account that can read issues but has no Project visibility discovers no Project Records, and only the that tenant\-level Record Record is available.

#### **Connector Mappings**

1. Enter your Wiz Client ID in the Client ID field.
2. Enter the Wiz Client Secret in the Secret field.
3. Choose which data classes to import in **Import Finding Types**. Both are selected by default.

#### **Import Finding Types**

Wiz serves two different data classes, and the connector imports both by default:

* **Issues**: a Wiz Control fired on a resource. These are policy and posture violations. A typical tenant has hundreds or thousands. An Issue is tagged with each NIST 800-53, PCI DSS and CIS requirement its Control maps to, for example `nist_sp_800-53_revision_5:ac-6(3)`. DefectDojo Pro maps the NIST 800-53 and PCI DSS tags to controls (see [Control Coverage](/federal_compliance/control_coverage/)). CIS tags are kept on the finding but are not mapped to a catalog. Other frameworks stay in the description only.
* **Vulnerability Findings**: one CVE on one package on one asset. A tenant with a few thousand assets can hold millions. Each asset carries many packages, and each package can carry many CVEs.

If your DefectDojo finding count is far higher than your asset count, Vulnerability Findings are the reason. That is expected: a finding is one problem on one asset, not one asset.

Deselect **Vulnerability Findings** to import Issues only. The connector then skips the vulnerability query entirely, so nothing is fetched from Wiz rather than fetched and discarded.

Two things to know before you change this setting:

* **Changing it triggers one full resync.** The connector normally asks Wiz only for what changed since the last sync. That cursor is cleared when you change the selection, so the next sync re-reads everything. Without the reset, re-enabling a data class never backfills the rows it skipped while it was off.
* **Deselecting a data class closes its existing findings.** The next sync sends none of that class, and DefectDojo closes what it no longer receives. Suppose you turn off Vulnerability Findings on a connector that already imported a million of them. That sync closes all one million.

Minimum Severity is a separate control and cannot be changed after the connector is created.

#### **Asset Exposure**

With [Asset Exposure](/triage_findings/finding_scoring/asset_exposure/) enabled, each sync also reports how reachable each Wiz Project's asset is. The connector reads two things Wiz already knows and keeps the strongest result across the Project's resources:

* **Network exposure**: the network paths Wiz found to a resource. A path from any internet address records **Externally Exposed**; one from a narrower internet source range, or from a custom IP range holding a public address, records **Partially Exposed**; one from another cloud account, a VPN, or a custom range of private addresses records **Internally Reachable**. A path inside the resource's own cloud account records nothing. The panel's evidence names each exposed resource with its port range and protocol.
* **Vulnerable assets**: the internet and network exposure fields Wiz sets on each asset that carries a vulnerability. These are read only while **Vulnerability Findings** is selected.

Network exposure is read on every sync whatever **Import Finding Types** says, and it never becomes a finding: it describes the asset, not a problem on it. Wiz cannot say when a path closes, so a path it stops reporting ages out of the asset's exposure after 30 days. If the service account cannot read network exposure, the sync logs a warning and reports the vulnerable-asset fields alone.
