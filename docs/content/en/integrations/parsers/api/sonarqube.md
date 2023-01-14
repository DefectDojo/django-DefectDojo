---
title: "SonarQube API Import"
toc_hide: true
---
All parsers which using API have common basic configuration step but with different values. Please, [read these steps](../) at first.

In `Tool Configuration`, select `Tool Type` to "SonarQube API" and `Authentication Type` "API Key".
Note the url must be in the format of `https://<sonarqube_host>/api`
Paste your SonarQube API token in the "API Key" field.
By default the tool will import vulnerabilities issues
and security hotspots only, but additional filters can be setup using the 
Extras field separated by commas (e.g. `BUG,VULNERABILITY,CODE_SMELL`). When using
SonarCloud, you must also specify the Organization ID in the Extras field as follows
`OrgID=sonarcloud-organzation-ID`. If also specifying issue type filters, please 
seperate the items in the Extras field by a vertical bar as follows
`BUG,VULNERABILITY,CODE_SMEL|OrgID=sonarcloud-organzation-ID`

In "Add API Scan Configuration"
-   `Service key 1` must
    be the SonarQube project key, which can be found by navigating to a specific project and
    selecting the value from the url
    `https://<sonarqube_host>/dashboard?id=key`.
    When you do not provide a SonarQube project key, DefectDojo will
    use the name of the Product as the project key in SonarQube. If you would like to
    import findings from multiple projects, you can specify multiple keys as
    separated `API Scan Configuration` in the `Product` settings.
-   If using SonarCloud, the orginization ID can be used from step 1, but it
    can be overiden by supplying a different orginization ID in the `Service key 2` input field.

## Multiple SonarQube API Configurations

In the import or re-import dialog you can select which `API Scan
Configuration` shall be used. If you do not choose
any, DefectDojo will use the `API Scan Configuration` of the Product if there is
only one defined or the SonarQube `Tool Configuration` if there is only one.

## Multi Branch Scanning

If using a version of SonarQube with multi branch scanning, the branch tha be scanned can
be supplied in the `branch tag` fieild at import/re-import time. If the branch does not exist,
a notification will be generated in the alerts table indicating that branch to be imported
does not exist. If a branch name is not supplied during import/re-import, the default branch
of the SonarQube project will be used.

**Note:**: If `https` is used for the SonarQube, the certificate must be
trusted by the DefectDojo instance.
