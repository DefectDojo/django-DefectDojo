---
title: "Invicti"
toc_hide: true
---

Vulnerabilities List - JSON report

Invicti is a web application security scanner available as Invicti 
Enterprise (cloud-based) and Invicti Standard (on-premise). It identifies 
vulnerabilities through automated crawling and attack simulation, producing 
confirmed and unconfirmed findings with proof of exploit where available.

DefectDojo supports two methods of ingesting Invicti findings:

1. **File-based import** - Export a Vulnerabilities List in JSON format 
   from Invicti and upload it manually into DefectDojo
2. **Native integration** - Configure Invicti Enterprise to push findings 
   directly to DefectDojo automatically after each scan

---

## File-Based Import

### How to Export from Invicti Enterprise

1. Log in to Invicti Enterprise
2. Go to **Scans > Recent Scans** and select the relevant scan
3. Select **Report**
4. Under **Lists**, select **Vulnerabilities List**
5. From the **Format** drop-down, select **JSON**
6. Configure export options as needed:
   - **Exclude Addressed Issues** — excludes findings already actioned 
     in Invicti
   - **Export Confirmed** - includes only findings verified with proof 
     of exploit
   - **Export Unconfirmed** - includes findings detected but not 
     fully verified
7. Select **Export** and save the JSON file
8. Upload the file into DefectDojo under your chosen Engagement 
   using **Import Scan > Invicti Scan**

### Confirmed vs Unconfirmed Findings

Invicti classifies findings in two ways:

- **Confirmed** - Invicti verified the vulnerability with a proof of 
  exploit. These are high-confidence findings and should be prioritized.
- **Unconfirmed** - Invicti detected indicators of a vulnerability but 
  could not fully verify it. These require manual review before acting 
  on them.

It is recommended to export both confirmed and unconfirmed findings and 
use DefectDojo's **Active/Verified** flags to track review status rather 
than filtering at export time. This preserves full visibility and avoids 
losing findings from the vulnerability record.

---

## Native Integration (Invicti Enterprise)

Invicti Enterprise supports direct integration with DefectDojo, allowing 
findings to be pushed automatically after each scan without manual 
file export.

### Prerequisites
- A DefectDojo API key with appropriate permissions
- An existing Product and Engagement in DefectDojo to receive findings

### Setup Steps

1. Log in to Invicti Enterprise
2. Go to **Integrations > New Integration**
3. Under **Issue Tracking Systems**, select **DefectDojo**
4. Enter a name for the integration
5. Enter your DefectDojo URL, API key, Product ID, and Engagement ID
6. Optionally add tags to help filter imported findings in DefectDojo
7. Select **Save**
8. Use **Test Credentials** to confirm the connection is working

Once configured, Invicti Enterprise can be set to automatically push 
findings to DefectDojo after each completed scan. This is recommended 
for teams running regular or scheduled scans as it removes the manual 
export step and keeps DefectDojo up to date in near real time.

---

## Severity Mapping

| Invicti Severity | DefectDojo Severity |
|---|---|
| Critical | Critical |
| High | High |
| Medium | Medium |
| Low | Low |
| Best Practice / Information | Info |

Invicti also uses action-based priority labels in its reports such as 
"Fix Immediately" and "Fix Soon". These do not map directly into 
DefectDojo severity fields but can be used to inform triage decisions 
when reviewing imported findings.

---

## Recommended Workflow for Enterprise Use

For teams running Invicti Enterprise across multiple applications:

1. **Use the native integration** rather than manual file exports to 
   reduce operational overhead
2. **Use Reimport** (not Import) for recurring scans on the same target 
   to track finding status over time rather than creating duplicate records
3. **Export Confirmed and Unconfirmed separately** if your team has a 
   formal triage process — import confirmed findings as active and 
   unconfirmed findings as requiring review
4. **Set SLA thresholds** in DefectDojo aligned to Invicti severity 
   levels so that Critical and High findings trigger appropriate 
   remediation timelines automatically

---

### Sample Scan Data

Sample Invicti scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/invicti).

---

## Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate Findings using these 
[hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
- severity

### Note on Deduplication for Large Scans

Invicti can report the same vulnerability type across multiple URLs, 
which means importing large scans without reviewing deduplication 
settings can result in a high volume of findings that represent the 
same underlying vulnerability class. To manage this:

- Consider enabling **Apply Same Findings** in your Engagement settings 
  to group similar findings
- Use **Reimport** instead of Import for recurring scans to update 
  existing findings rather than creating new ones each time
