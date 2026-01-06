---
title: "SonarQube API Import"
toc_hide: true
---
All parsers that use API pull have common basic configuration steps, but with different values. Please, [read these steps](../) first.

## Tool Configuration

In `Tool Configuration`, select `Tool Type` "SonarQube" and `Authentication Type` "API Key".
The URL must be in the format of `https://<sonarqube_host>/api`
Paste your SonarQube API token in the "API Key" field.
By default, the tool will import vulnerability issues
and security hotspots only, but additional filters can be applied using the 
"Extras" field separated by commas (e.g. `BUG,VULNERABILITY,CODE_SMELL`). When using
SonarCloud, you must also specify the Organization ID in the "Extras" field (e.g. 
`OrgID=sonarcloud-organzation-ID`). When also specifying issue type filters, please 
separate the items in the "Extras" field by a vertical bar (e.g. 
`BUG,VULNERABILITY,CODE_SMELL|OrgID=sonarcloud-organzation-ID`)

## Product-Level Configuration

In `Add API Scan Configuration`
-   `Service key 1` must
    be the SonarQube project key, which can be found by navigating to a specific project and
    selecting the value from the url
    `https://<sonarqube_host>/dashboard?id=key`.
    When you do not provide a SonarQube project key, DefectDojo will
    use the name of the Product as the project key in SonarQube. If you would like to
    import findings from multiple projects, you can specify multiple keys as
    separated `API Scan Configuration` in the `Product` settings.
-   If using SonarCloud, the organization ID can be used from step 1, but it
    can be overridden by supplying a different organization ID in the `Service key 2` input field.

## Multiple SonarQube API Configurations

In the import or re-import dialog, you can select which `API Scan
Configuration` shall be used. If you do not choose
any, DefectDojo will use the `API Scan Configuration` of the Product if there is
only one defined or the SonarQube `Tool Configuration` if there is only one.

## Multi-Branch Scanning

If using a version of SonarQube with multi-branch scanning, the branch to be scanned can
be supplied in the `branch_tag` field at import/re-import time. If the branch does not exist,
a notification will be generated in the alerts table, indicating that branch to be imported
does not exist. If a branch name is not supplied during import/re-import, the default branch
of the SonarQube project will be used.