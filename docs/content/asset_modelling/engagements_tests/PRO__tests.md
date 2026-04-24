---
title: "Tests"
description: "Understanding Tests in DefectDojo Pro"
audience: pro
weight: 2
---
Organizations → Assets → Engagements → **TESTS** → Findings

## Overview

A Test is a container for one or more scan executions, which are used to discover flaws in an Asset. Tests are the final, most granular component of DefectDojo’s object hierarchy, serving as the container for the Findings that result from an execution of a security tool or manual assessment while also adding the context in which any such Findings were found (i.e., which tool reported it, when that tool was last run, etc.).

Examples of Tests include: 
- Static Application Security Testing
- Dynamic Application Security Testing
- Software Composition Analysis
- Container Security Scans
- Infrastructure / Network Scans
- Manual Penetration Tests
- CI/CD Pipeline Scans

### Test Types 

There are several ways to create Tests in DefectDojo, including **vendor-specific parsers** (e.g., Burp, OWASP ZAP, Acunetix, Invicti), **Generic Findings Import**, **Universal Parser**, and **Connectors**.

These methods can create new Tests or reimport Findings into existing Tests depending on configuration and deduplication strategy.

While each method differs primarily in how scan data is parsed and ingested, they all ultimately result in Findings being associated with a Test.

#### Parsers 

**Parsers** are components that process specific scan output formats (e.g., XML, JSON, CSV) and map it into DefectDojo’s internal Finding model. When scan results are imported, DefectDojo uses the selected parser to extract Findings and attach them to a newly created or existing Test.

#### Generic Findings Import

When no native parser exists for a given tool, [**Generic Findings Import**](/supported_tools/parsers/generic_findings_import) allows you to import findings using a standardized JSON or CSV schema, regardless of the original source. 

DefectDojo parses the provided data, creates a new Test (or imports into an existing one), and attaches the Findings. A corresponding Test Type is also created in the format “`{Test Name}` (Generic Findings Import).”

#### Universal Parser 

[**Universal Parser**](/supported_tools/parsers/universal_parser) allows users to define how arbitrary input data maps into DefectDojo’s Finding model. After configuring the parser and uploading scan data, DefectDojo applies the mapping rules to extract Findings, creates a Test (or updates an existing one), and associates the Findings with that Test.

#### Connectors 

[**Connectors**](/import_data/pro/connectors/about_connectors) can be used to automatically ingest and organize vulnerability data from external tools via API calls. Once configured, a Connector fetches scan results, parses the data, and creates new Tests or updates existing Tests depending on its configuration. Findings are then attached to the corresponding Test.

#### Test Creation Mechanism Comparison 

| | **Native Parsers** | **Generic Findings Import** | **Universal Parser (Pro)** | **Connectors** |
|----------|---------------|------------------------|------------------------|------------|
| **Primary purpose** | Ingest supported tool outputs | Ingest unsupported/custom data via fixed schema | Ingest arbitrary formats via configurable mappings | Continuously sync external systems |
| **Input format** | Tool-specific (e.g., ZAP XML, SARIF) | Strict JSON/CSV schema | Arbitrary (JSON, XML, etc.) | External API responses |
| **Who handles normalization** | DefectDojo (built-in parser) | User (must conform to schema) | DefectDojo (via parser config) | External tool + DefectDojo |
| **Test creation trigger** | Manual upload or API import | Manual upload or API import | Manual upload or API import | Automated sync (scheduled or event-driven) |
| **Test Type** | Predefined (e.g., "ZAP Scan") | Auto-created "Generic" type | Derived from parser configuration | Depends on connector / underlying parser |
| **Setup effort** | Low | Moderate (data transformation required) | High (parser configuration) | Moderate–High (integration setup) |
| **Flexibility** | Low (only supported tools) | Medium | High | Medium–High |
| **Automation level** | Low–Moderate | Low–Moderate | Low–Moderate | High |
| **Typical use case** | Standard scanners (SAST, DAST, SCA) | Custom scripts, unsupported tools | Complex/custom formats at scale | CI/CD, SCM, or platform integrations |

Regardless of the ingestion method, all scan data in DefectDojo is ultimately represented as Findings attached to a Test, which serves as the unit of execution and lifecycle tracking.

### Test Data 

Tests store a variety of metadata that helps to document various components of each testing effort, such as: 
- Test title / name 
- Test type
- Test description / notes
- Start and end date 
- The Environment in which the Test was run (e.g., Development, Staging, Pre-Production, Production, etc.)
- Version / Branch / Build ID / Commit Hash
- API scan configuration 
- Personnel associated with the Test 
- Additional files that can be used for later audits or re-imports
- The parent Engagement, Asset, and Organization 
- Import and reimport history

Each Test maintains an import history, which records all scan imports and reimports associated with the Test. Each History item includes metadata such as scan date, version, branch, commit hash, and build ID.

This history provides traceability across multiple scan executions within the same Test.

### Permissions 

Multiple Tests can be stored within a single Engagement, and Engagements are stored within Assets. As such, access to an Asset automatically grants access to all Tests (and Engagements) within that Asset. Tests do not have independent access control lists.

## Accessing Tests 

Tests can be accessed from various sections of the DefectDojo UI. 

- The sidebar 

![image](images/tests_ss13.png)

- Within an Engagement 

![image](images/tests_ss14.png)

- The top bar of an Asset

![image](images/tests_ss15.png)

- The Metadata table within a Finding’s view

![image](images/tests_ss16.png)

## Test Lifecycle 

### Create Tests

Tests can be automatically created when scan data is imported directly into an Engagement, resulting in a new Test containing the scan data. Tests can also be created in anticipation of planning future Engagements, or for manually entered security findings requiring tracking and remediation.

#### Manual Workflows 

In order to make a Test, an Engagement must be made to contain it, as well as an Asset that will contain that Engagement. Afterwards, there are several ways to create a Test: 

- In the sidebar, under Tests within the **Manage** subsection
    - You will have to select the pre-existing Engagement to attribute the Test to when completing the New Test form. 

![image](images/Tests_ss1.png)

- The settings dropdown at the top right corner of an Asset view
    - **Import Scan** will automatically create a Test once a scan file has been added to the Import Scan form. You will have the opportunity to either attribute the Test to a pre-existing Engagement or create and name a new Engagement to contain the new Test. 
        - While completing the Import Scan form, you may add metadata such as the version, branch tag, commit hash, and build ID. This will be reflected in the Import History section of the Test View.

![image](images/Tests_ss2.png)

- The settings dropdown at the top right of an Engagement view
    - **Import Scan** will follow the same workflow as Assets, but will automatically place the Test object within the Engagement in which you clicked Import Scan. 
    - **Add Test** will create a Test object but does not require that a scan be uploaded to the Test itself, which is useful in anticipation of planning future Tests or for manually entered security findings requiring tracking and remediation.

![image](images/Tests_ss3.png)

If you select Add Test and later wish to manually import the results of a scan to a Test, you can do so by opening the Test and clicking the Reimport Findings button in the Test’s settings or the Reimport Scan button in the Findings table.

![image](images/tests_ss21.png)

#### Automated Workflows 

In automated workflows, Tests can be created programmatically as part of the scan import process, allowing pipelines to upload results without requiring a Test to be created manually in advance.

When using the API or CLI to import scan results, a new Test can be created automatically by providing an `engagement` instead of a `test`.

##### API 

curl -X POST `"https://<your-instance>/api/v2/import-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"engagement=45"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"`

Given the above, a new Test is created under the specified Engagement, and the scan results are attached to that Test.

If a `test` ID is provided instead, the scan results will be added to an existing Test, which is common in reimport workflows.  

##### CLI 

Using the DefectDojo CLI, this behavior is handled automatically based on the arguments provided.

defectdojo-cli import \
  --engagement-id 45 \
  --scan-type `"ZAP Scan"` \
GOog  --file report.xml

Given the above, providing an `engagement-id` creates a new Test, and providing a `test-id` reuses an existing Test and reimports scan results into that Test. 

See [DefectDojo-CLI](/import_data/pro/specialized_import/external_tools/#defectdojo-cli) for more details on required flags.

### Edit Tests

Tests can be edited by clicking **Edit Test** from within the gear menu. All ensuing fields that can be edited are also available when the Test is being created.

### Delete Tests 

Deleting a Test can be performed by selecting **Delete Test** from the Test’s settings. This action can’t be undone. 

Deleting a Test will also delete any Findings contained within that Test.

### Reimporting Scan Results (UI)

In order to add new data to an existing Test, open the Test you’re adding new data to and click the Reimport Findings button in the Test’s settings or the Reimport Scan button in the Findings table. 

![image](images/tests_ss21.png)

While completing the Reimport Scan form, you’ll have the option to update metadata for the scan being reimported, including the version, branch tag, commit hash, and build ID. These changes are reflected in the Import History section of the Test View, which will also include the same metadata from prior scan imports. 

For example, in the below screenshot, the branch tag, build ID, commit hash, and version were all manually updated between the initial import and the subsequent reimport. 

![image](images/tests_ss23.png)

To edit the metadata of the most recently reimported scan, click the gear icon located at the top right corner of an Engagement View and select “Edit Test.” Only the most recent import’s metadata can be edited.

### Reimporting Scan Results (API/CLI)

When Tests are created or updated through a CI/CD pipeline, you’re able to include metadata from the pipeline run so that Tests can be properly linked to the code they scanned. This allows you to:
- Associate scan results with a specific commit or branch.
- Track how Findings evolve across code changes.
- Improve Deduplication by understanding when two scans apply to the same or different versions of the code.
- Support auditability by showing exactly what code was scanned and when.

DefectDojo’s CLI and API accept these values during import or reimport so they can be stored as part of the scan import and reflected in the Test’s import history. This metadata can be used to identify commit hashes or anything associated with any relevant repository information associated with a CI/CD run.

#### Supported Metadata Fields 

The API and CLI support a defined set of metadata fields that can be included during reimport. These include:

- `tags`
- `version`
- `build_id`
- `branch_tag`
- `commit_hash`
- `scan_date`
- `minimum_severity`
- `active / verified` flags

These fields represent the primary mechanism for attaching contextual metadata during a reimport operation. 

In automated pipelines, the most commonly supplied metadata includes:
- `build_id` (CI job identifier)
- `commit_hash` (source control reference)
- `branch_tag` (branch or environment context)
- `tags` (e.g., `nightly`, `staging`, `production`)

These fields provide traceability across scans without requiring manual intervention.

Although metadata can be updated manually through the Reimport Scan form, most automated environments will handle this by calling the `/api/v2/reimport-scan/` endpoint directly or using the DefectDojo CLI (`defectdojo-cli reimport`) as part of the build process. This approach allows the pipeline to automatically attach metadata upon reimport.

##### API Reimport with Metadata

curl -X POST `"https://<your-instance>/api/v2/reimport-scan/"` \
  -H `"Authorization: Token <api_key>"` \
  -F `"test=123"` \
  -F `"scan_type=ZAP Scan"` \
  -F `"file=@report.xml"` \
  -F `"tags=nightly,api-scan"` \
  -F `"version=1.4.2"` \
  -F `"build_id=jenkins-842"` \
  -F `"branch_tag=main"` \
  -F `"commit_hash=a1b2c3d4"`

##### CLI Reimport with Metadata 

defectdojo-cli import \
  --test-id 123 \
  --scan-type "ZAP Scan" \
  --file report.xml \
  --tag nightly \
  --tag api \
  --build-id jenkins-842 \
  --branch main \
  --commit a1b2c3d4

The CLI maps directly to the same API endpoint and supports the same set of metadata fields.

There are some limitations to be aware of when working with metadata during reimport:
- The API/CLI only supports predefined parameters. Custom key-value metadata cannot be added during reimport
- Additional metadata may be extracted from the scan file itself, depending on the scan type and parser.
- Metadata provided during reimport does not behave as a direct update to the Test object in the same way as manual edits in the UI.

##### Metadata, Reimport, and Scheduled Scans 

Scans may also be scheduled to run at routine intervals, such as those triggered by cron jobs. Scheduled scans are not tied to repository activity, making metadata like commit hashes or branch names irrelevant unless explicitly injected by the script itself. Nevertheless, using reimport may still be useful if you prefer to keep a rolling record of your security posture within a single Test. 

## Reimport and Deduplication 

Reimporting scans within Tests is fundamental to effective deduplication. When scan results are reimported into the same Test:

- Existing Findings may be updated
- Duplicate Findings may be suppressed
- New Findings may be created if no match is found

This behavior depends on the configured deduplication rules and the scan type.

Creating a new Test instead of reimporting into an existing one may result in duplicate Findings being created rather than updated.

### Reimport vs. Import 

Reimport is typically used when:

- Running recurring scans against the same target
- Tracking how Findings evolve over time
- Maintaining a continuous view of application security posture

In contrast, importing (creating a new Test) is more appropriate for one-time or independent scan executions.