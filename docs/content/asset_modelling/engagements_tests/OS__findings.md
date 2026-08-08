---
title: "Findings"
description: "Understanding Findings in DefectDojo OS"
audience: opensource
weight: 5
---
Organizations	→ Assets → Engagements → Tests → **FINDINGS**

## Overview

**Findings** represent the lowest level of the Product Hierarchy where individual vulnerabilities are tracked and managed, and are the main way that DefectDojo standardizes and guides the reporting and remediation process of your security tools. Regardless of whether a vulnerability was reported in SonarQube, Acunetix, or your team’s custom tool, Findings give you the ability to manage each vulnerability in the same way.

Examples of Findings include: 
- Cookie Not Marked as HttpOnly
- Out-of-Date Version (PHP)
- Out-of-Band Code Evaluation (PHP)
- Out-of-Date Version (MySQL)
- Backup Source Code Detected
- Blind Cross-Site Scripting

In addition to storing the vulnerability data and providing a remediation framework, DefectDojo also enhances your Findings in the following ways:
- Automatically adding related EPSS scores to a Finding to describe exploitability
- Automatically translating a security tool’s severity metric into a Severity score for each Finding, which confers an SLA onto the Finding according to your Asset’s SLA configuration. For more information on SLA configuration, click [here](/asset_modelling/os_hierarchy/os__sla_configuration/#main-content).

Overall, Findings are designed to work with the Product Hierarchy to standardize your efforts, and apply a consistent method to each Asset.

## Accessing Findings

Findings are accessible via the sidebar. The submenu provides access to Open and Closed Findings, All Findings (regardless of Open or Closed status), [Risk Accepted Findings](/triage_findings/findings_workflows/os__risk_acceptance/), as well as Findings Templates. Individual Findings are also accessible from within the Test that contains them. 

![image](images/osfindings_ss1.png)

### Permissions

Every Finding belongs to a Test, allowing DefectDojo to preserve which scan or assessment originally identified the vulnerability.

As Findings belong to Tests, access to Findings is determined by a User’s access to the Asset that contains the Test. Tests do not have independent access control lists.

## Findings View
Finding views contain a variety of tables to help interpret a Finding’s status at a glance. This includes:
- **Overview**
    - **ID**: The unique ID number for that Finding. 
    - **Severity**: The severity rating of that Finding, which is applied automatically. 
        - As mentioned above, DefectDojo automatically translates a security tool’s severity metric into a Severity score for each Finding, which confers an SLA onto the Finding according to your Asset’s SLA configuration.
    - **SLA**: The intended due date by which the Finding is intended to be resolved. 
    - **Status**: The status of the Finding (e.g., Active, Verified, False Positive, Duplicate, Out of Scope, and Under Defect Review).
    - **Finding type**: Whether the Finding is Static (SAST) or Dynamic (DAST).
    - **Date discovered**: The date on which the Finding was discovered. 
    - **CWE**: The CWE classification of the Finding. 
    - **Vulnerability ID**: IDs of vulnerabilities in security advisories associated with the Finding (e.g., CVE or other sources).  
    - **Found by**: The tool that revealed the Finding. 
- **Similar Findings**: Other Findings within the same Asset that are not exact duplicates but have similar values for vulnerability ID, CWE, file_path, line number, etc.
- **Import history**: List of imports/reimports that created/closed/reactivated this Finding in any Test. 
- **Vulnerable endpoints/systems**: Endpoints/Systems that the Finding reveals are vulnerable. 
- **Description**: The description of the Finding (added automatically depending on the type of Finding, or created manually). 
- **Mitigation**: Suggested steps to mitigate.
- **Impact**: Potential impact of leaving the Finding unresolved. 
- **Steps to reproduce**: Steps for reproducing the Finding. 
- **Severity justification**: Written description of why a certain Severity rating was associated with the Finding. 
- **References**: URL to cross-reference the third-party scan tool’s specific description of the Finding. For example, References could be links to a relevant entry in a Finding catalog, or a single advisory URL. 
- **Notes**: Notes left by Users related to the Finding. Marking a note as Private will mean it will not be included in any generated reports that include the selected Finding. 

## Findings Data

Findings require the following metadata:
**Title**
**Date**
**Severity**
**Description**

In addition to metadata corresponding to the tables in a Finding’s view, optional metadata fields include: 
- **Group**: Finding Groups that include the selected Finding. 
- **CVSS3/CVSS4 vector and score**: The CVSS3 and CVSS4 vector and score of the selected Finding. 
- **Request and response pairs**: A copy of the message sent by the client and the server's reply to the request.
- **Endpoints to add**: Vulnerable endpoints that may be affected by the selected Finding that are not reflected in the preceding list of systems/endpoints. 
- **EPSS score and percentile**: ESS score and percentile for the CVE. 
- **KEV date added**: The date the Finding was added to the KEV catalog. 
- **Fix availability and version**: Defines if there is a fix available for the vulnerability, and the version of the affected component in which the fix was implemented. 
- **User who requested a defect review**: Records who requested a defect review for the flaw in question. 
- **Line number**: Source line number of the attack vector. 
- **File path**: Identified files that contain the flaw. 
- **Component name and version**: Name and version of the affected component. 
- **Unique ID from tool**: Vulnerability technical ID from the source tool. 
- **Vulnerability ID from tool**: Non-unique technical ID from the source tool. 
- **SAST source object, line number, and file path**: Source object, line number, and file path of the attack vector. 
- **SAST sink object**: Sink object of the attack vector. 
- **Number of occurrences**: Number of occurrences in the source tool when several vulnerabilities were found and aggregated by the scanner. 
- **Publish date**: Date on which the Finding was published. 
- **Service**: Connected Services (self-contained pieces of functionality within an Asset) that are affected by the selected Finding. When populated, this field is included in deduplication matching (i.e., Findings with identical Service fields will deduplicate). 
- **Planned remediation date and version**: The date on which the Finding is planned to be remediated, and the version of the affected component in which the fix will be implemented.
- **Effort for fixing**: The level of effort involved in fixing the Finding (e.g., Low, Medium, or High). 
- **Tags**: Any tags that have been added to the Finding. 

The exact metadata available will depend on the parser/scanner that revealed the Finding. Some provide only basic information such as title and severity, while others include CVSS vectors, vulnerable components, endpoints, request/response pairs, and other scanner-specific metadata.
 
This metadata improves filtering, reporting, and prioritization across your security program, enabling long-term tracking and trend analysis. Additional details and metadata descriptions can be found [here](/triage_findings/findings_workflows/intro_to_findings/#a-finding-page). 

### Deduplication

DefectDojo includes deduplication capabilities that help identify and manage Findings representing the same underlying vulnerability. As scan results are imported from one or more tools, DefectDojo uses configurable matching logic to identify Findings that represent the same vulnerability.

Deduplication prevents the same vulnerability from appearing multiple times when discovered repeatedly by the same or different scanners, allowing remediation history to remain attached to a single Finding.

More information about deduplication can be found [here](/triage_findings/finding_deduplication/about_deduplication/).

### Reimport

DefectDojo's Reimport function allows Findings to be updated as new scan results are imported. When a scan is reimported, DefectDojo compares the incoming results against existing Findings and updates matching records instead of creating entirely new ones. This preserves valuable context such as status changes, remediation history, comments, and ownership information, providing a continuous record of a Finding's lifecycle across multiple testing cycles.

More information about the Reimport function can be found [here](/import_data/import_intro/reimport/#main-content).

### Risk Acceptances 

Risk Acceptances are a special status that can be applied to Findings to formally document and operationalize the decision to acknowledge them without immediately remediating them. 

More information about Risk Acceptances can be found [here](/triage_findings/findings_workflows/os__risk_acceptance/).

### Statuses 

Each Finding created in DefectDojo has a Status that communicates relevant information and helps your team keep track of their progress in resolving issues.

More information about Statuses can be found [here](/triage_findings/findings_workflows/finding_status_definitions/).

## Working with Findings 

### Creating Findings 

While most Findings are generated automatically through scan imports and integrations, DefectDojo also supports the manual creation of Findings. Manual Findings are useful for tracking vulnerabilities and security concerns identified through penetration testing, architecture reviews, compliance assessments, bug bounty programs, consultant engagements, or other activities that do not produce scanner output. 

To create a Finding manually:
1. Navigate to the Test in which you wish to manually add the Finding, click the + Plus sign, and then click **New Finding**.

![image](images/osfindings_ss2.png)

2. This opens the New Finding form, which you can fill out with any relevant information about your Finding.

3. Select either **Add Another Finding** to manually add another Finding, or **Finished** to finish the manual Finding creation process.

The Finding will now appear within the list of Findings contained in the original Test. 

Importantly, manually adding a Finding from the top bar will automatically create an ad hoc Engagement and Test to contain the new Finding, rather than adding it to the Test that is currently being viewed (see image below). This is because the top bar pertains to the Asset as a whole. If you wish to manually add a Finding to a specific, pre-existing Test, it is best to do so from within the Test itself, as outlined in steps 1-3 above. 

![image](images/osfindings_ss3.png)

### Editing Findings

#### ⋮ Kebab Menu

The ⋮ kebab menu next to Findings contains the following functions: 
- **View**: Open and view the Finding. 
- **Edit**: Edit the Finding. 
- **Copy**: Create a copy of the Finding. The Copy can be saved to any of the Tests contained within the corresponding Engagement. 
- **Request Peer Review**: Initiates the Peer Review process and changes the Finding’s status to “Under Review.” More information about Peer Reviews can be found [here](/triage_findings/findings_workflows/finding_status_definitions/#under-review).
- **Touch Finding**: Will log interactivity with the Finding in the Finding’s history. 
- **Make Finding a Template**: Will automatically create a Finding Template based on the selected Finding. 
- **Apply Template to Finding**: Will allow a pre-existing Finding Template to be applied to a Finding. 
- **Close Finding**: Will initiate the process of closing the Finding. 
- **Add Risk Acceptance**: Will initiate the Risk Acceptance process. More information can be found [here](/triage_findings/findings_workflows/os__risk_acceptance/#main-content).
- **View History**: Reveals the history of the selected Finding. 
- **Delete**: Deletes the selected Finding. 

#### Attaching Files to Findings 
You can attach files to any Finding to provide visual context — for example, a screenshot of a vulnerability in action or a proof-of-concept image.

Supported file types include: 

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

To attach a file to a Finding:
1. Open the Finding you want to attach a file to.
2. Open the actions menu (the ☰ button in the top-right of the Finding) and click Manage Files.

![image](images/OS_manage_files_menu.png)

3. On the Add files page, enter a Title for the file and choose the file from your computer. You can add up to three files at a time; save and return to add more if needed.

![image](images/OS_manage_files_form.png)

4. Click **Save**.

The file is then listed in the **Files** panel of the Finding. Image files appear as thumbnails:

![image](images/OS_finding_files_panel.png)

#### Bulk Edit Findings 

Findings can be edited in bulk from a Finding List, such as the table of All Findings accessible from the sidebar, or from the table of Findings within a specific Test.

More information about how to bulk edit Findings can be found [here](/triage_findings/findings_workflows/editing_findings/#bulk-edit-findings). 

### Closing Findings 

Once the work on a Finding is complete, you can manually close it by clicking **Close Finding** within the Finding’s ⋮ kebab menu or ☰ action menu. Alternatively, if a scan is re-imported into DefectDojo which does not contain a previously-recorded Finding, the previously-recorded Finding will automatically close.

If you don’t want any Findings to be closed, you can disable this behavior on Reimport:

- Uncheck the Close Old Findings checkbox if using the UI
- Set close_old_findings to False if using the API ​

### Deleting Findings 

Deleting a Finding can be done from the Finding’s ⋮ kebab menu or ☰ action menu. This action can’t be undone. 

For auditing purposes, it is recommended to close any remediated Findings, rather than deleting them. 

## Finding Groups 

**Finding Groups** allow you to treat multiple related Findings as a single logical unit for triage, reporting, and remediation coordination.

For example, a scan might produce 10 SQL injection Findings across different endpoints. Instead of managing each one independently, you can group them into a single Finding Group representing the broader SQL injection issue.

A Finding Group does not replace the individual Findings. Each Finding still exists with its own severity, status, metadata, comments, and remediation history. A Finding Group simply provides an additional organizational layer above the Findings it contains.

### Accessing Finding Groups 

Finding Groups can be accessed via the sidebar. The submenu provides access to Open and Closed Finding Groups as well as All Finding Groups (regardless of Open status).

![image](images/osfindings_ss1.png)

### Creating Finding Groups 


Finding Groups can be created either manually or automatically. 

Notably, Finding Groups can only be created from the Findings contained within a single Test. Findings from different Tests, Engagements, or Products cannot be added to the same Finding Group.

#### Manual Finding Groups 

To manually perform Finding Group actions:
1. Navigate to a list of Findings within a Test. 
2. Select the Finding(s) you wish to add to a Finding Group by clicking the corresponding checkbox. 
3. Click the **Group** checkbox. 
4. Click the corresponding action you wish to complete.
    - **Create**: Creates a Finding Group that includes the selected Findings.
    - **Add to**: Adds the selected Findings to a pre-existing Finding Group.
    - **Remove from any group**: Removes the selected Findings from any Finding Groups they were previously a part of. 
    - **Group by**: Groups the selected Findings based on the chosen option (e.g., Component name, File path, Finding title, etc.) 
5. Click **Submit**.

![image](images/osfindings_ss4.png)

Note that the only possible action when selecting Findings from the All Findings list is to remove the selected Findings from any Finding Group. This is because, as mentioned, Finding Groups can only be created from the Findings contained within a single Test.

#### Automatic Finding Groups 

When importing a scan, the “Group By” feature can automatically create Finding Groups based on a chosen grouping method. This is useful when a scanner produces many related Findings that should be managed together.

The adjoining **Create Finding Groups for all Findings** checkbox performs two functions: 
- **Checked**: Creates a Finding Group for every imported Finding, even if that Finding is the only member of the group.
- **Unchecked**: Creates Finding Groups only when there are actually multiple Findings to group together.

![image](images/osfindings_ss5.png)

If an option is not selected from the Group By dropdown menu during import, no grouping will occur. 

If the grouping criteria (e.g., component name, vulnerability ID, etc.) isn’t populated in the Finding, it will not have a group created or be added to a pre-existing Finding Group. 

If a scan is imported that reveals 10 Findings that are not grouped, and the same scan is reimported and the Findings are grouped, the first 10 Findings will not be added to that Finding Group (i.e., the Finding Group will only include the 10 Findings from the reimport, not the 10 Findings from the initial and subsequent import). 

## Finding Templates 

**Findings Templates** allow Users to create reusable templates for commonly reported vulnerabilities and security issues. A template can include standardized information such as a title, description, impact, steps to reproduce, mitigation, references, and other Finding metadata.

Finding Templates are most useful in situations where Users need to create manual Findings repeatedly and want to avoid re-entering the same supporting information each time.

### Accessing Finding Templates 

Finding Templates are found within the Findings submenu in the sidebar. 

![image](images/osfindings_ss6.png) 

### Creating Finding Templates 

Finding Templates can be created by clicking the + Plus button at the top right of the Finding Templates view. 

The ensuing page provides an overview of the metadata that will be applied to a Finding when a Finding Template is used.

You can also use a pre-existing Finding as the basis for a new Finding Template by clicking **Make Finding a Template** within the Finding’s ⋮ kebab menu. 

### Applying Finding Templates 

Finding Templates can be applied to Findings by clicking the **Apply Template to Finding** button within the ⋮ kebab menu of the selected Finding.

![image](images/osfindings_ss7.png)

The ensuing page will allow you to select the template to be applied to the Finding in question, and then whether to keep, replace, or combine the metadata from the Finding with the template. 

### Reporting 

DefectDojo’s report builder lets you assemble a custom report from a set of content widgets, run it, and export the result (for example, by printing it to PDF). Custom reports can summarize the Findings or Endpoints you want to share with an external audience, and can include branding and boilerplate text.

More information about DefectDojo’s Report Builder can be found [here](/metrics_reports/reports/using-the-report-builder/).

#### Export Findings 

Pages that show a list of Findings or a list of Engagements have a CSV and Excel export option in the top-right dropdown menu.

From any Findings list page, open the dropdown menu in the top-right corner to export the visible Findings as a CSV or Excel file. The list of Engagements can also be exported as CSV or Excel using the same dropdown menu on the Engagements list page.