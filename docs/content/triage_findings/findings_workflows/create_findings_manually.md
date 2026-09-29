---
title: "Creating Findings Manually"
description: "Track vulnerability information without using a scan tool"
weight: 2
aliases:
  - /en/working_with_findings/findings_workflows/create_findings_manually
---
Normally, most of the Findings in your environment will be imported from other security tools. If you wish, you can add manual Finding entries as well, if you have vulnerabilities or work you wish to manage that was not created from a scan tool.

1. From the DefectDojo Sidebar, open the New Finding link by clicking **Manage \> Findings \> New Finding**.  
​
![image](images/Creating_Findings_Manually.png)
  
2. This opens the **New Finding** form, which you can fill out with any relevant information surrounding your Finding. You will need to assign this Finding to a previously created Test in DefectDojo.

![image](images/Creating_Findings_Manually_2.png)

Most of the form sits under the collapsible **Optional Fields** panel. That includes a **Threat Intelligence** panel for the EPSS and CISA KEV values, which are otherwise only filled in by the [EPSS / KEV sync](/triage_findings/finding_scoring/epss_kev/) for Findings that reference a CVE. Setting them here lets a manually created Finding without a CVE carry exploit evidence for prioritization; see [Editing Findings](/triage_findings/findings_workflows/editing_findings/#edit-finding-form-fields) for how the sync treats hand-entered values.
