---
title: "Wiz Scanner Parser"
toc_hide: true
---

The [Wiz](https://www.wiz.io/) parser for DefectDojo supports imports from both Wiz Scanner Standard and SCA (Software Composition Analysis) .csv output from Wiz.io. This document details the parsing of both formats into DefectDojo field mappings, unmapped fields, and location of each field's parsing code for easier troubleshooting and analysis.

<span style="background-color:rgba(242, 86, 29, 0.3)">⚠️ **DefectDojo Pro**</span> Users can also automatically create Findings directly from Wiz using the Wiz Connector.  See our [Connectors documentation](/import_data/pro/connectors/about_connectors/) for more details.

## Link To Tool

- [Wiz.io](https://www.wiz.io/)
- [Wiz Documentation](https://docs.wiz.io/)

## Supported File Types

The Wiz parser accepts CSV file format. There are two primary formats supported:

1. **Standard Format** - Issues exports with "Title" field (processed by WizParserByTitle class)
2. **SCA Format** - Vulnerability exports with "Name" and "DetailedName" fields (processed by WizParserByDetailedName class)

To generate these files, export the findings from the Wiz platform by:

- Standard Format: Select "Export to CSV" option from the Issues view in the Wiz.io platform
- SCA Format: Select "Export to CSV" option from the Vulnerability view in the Wiz.io platform

### Sample Scan Data

Sample Wiz Scanner scans can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/wiz).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- description
- severity

## Mapped Fields Dictionary

### Standard Format CSV 

This format applies the `WizParserByTitle` parser class.

#### Total Fields in Standard Format CSV

- Total data fields: 32
- Total data fields parsed: 32
- Total data fields NOT parsed: 0

#### Standard Format Field Mapping Details

| CSV Field                    | Finding Field                   | Parser Line # | Notes                                                                                                    |
| ---------------------------- | ------------------------------- | ------------- | -------------------------------------------------------------------------------------------------------- |
| `Created At`                 | date                            | 68            | Parsed using the parse_wiz_datetime function to convert to datetime object                               |
| `Title`                      | title                           | 67            | Direct mapping to Finding title                                                                          |
| `Severity`                   | severity                        | 69            | Converted to lowercase then capitalized to match DefectDojo's severity format                            |
| `Status`                     | active, is_mitigated, mitigated | 65            | Converted through WizcliParsers.convert_status function to determine active status and mitigation status |
| `Description`                | description (partial)           | 79-81         | Added to description with "Description:" prefix                                                          |
| `Resource Type`              | description (partial)           | 79-81         | Added to description with "Resource Type:" prefix                                                        |
| `Resource external ID`       | description (partial)           | 79-81         | Added to description with "Resource external ID:" prefix                                                 |
| `Subscription ID`            | description (partial)           | 79-81         | Added to description with "Subscription ID:" prefix                                                      |
| `Project IDs`                | description (partial)           | 79-81         | Added to description with "Project IDs:" prefix                                                          |
| `Project Names`              | description (partial)           | 79-81         | Added to description with "Project Names:" prefix                                                        |
| `Resolved Time`              | mitigated                       | 71-74         | Used to set mitigated timestamp if finding is marked as mitigated                                        |
| `Resolution`                 | mitigation (partial)            | 62-63         | Added to mitigation text with "Resolution:" prefix                                                       |
| `Control ID`                 | description (partial)           | 79-81         | Added to description with "Control ID:" prefix                                                           |
| `Resource Name`              | description (partial)           | 79-81         | Added to description with "Resource Name:" prefix                                                        |
| `Resource Region`            | description (partial)           | 79-81         | Added to description with "Resource Region:" prefix                                                      |
| `Resource Status`            | description (partial)           | 79-81         | Added to description with "Resource Status:" prefix                                                      |
| `Resource Platform`          | description (partial)           | 79-81         | Added to description with "Resource Platform:" prefix                                                    |
| `Resource OS`                | description (partial)           | 79-81         | Added to description with "Resource OS:" prefix                                                          |
| `Resource original JSON`     | description (partial)           | 79-81         | Added to description with "Resource original JSON:" prefix                                               |
| `Issue ID`                   | unique_id_from_tool             | 85            | Used as unique identifier for the finding                                                                |
| `Resource vertex ID`         | description (partial)           | 79-81         | Added to description with "Resource vertex ID:" prefix                                                   |
| `Ticket URLs`                | description (partial)           | 79-81         | Added to description with "Ticket URLs:" prefix                                                          |
| `Note`                       | description (partial)           | 79-81         | Added to description with "Note:" prefix                                                                 |
| `Due At`                     | description (partial)           | 79-81         | Added to description with "Due At:" prefix                                                               |
| `Remediation Recommendation` | mitigation                      | 61            | Direct mapping to mitigation field                                                                       |
| `Subscription Name`          | description (partial)           | 79-81         | Added to description with "Subscription Name:" prefix                                                    |
| `Wiz URL`                    | description (partial)           | 79-81         | Added to description with "Wiz URL:" prefix                                                              |
| `Cloud Provider URL`         | description (partial)           | 79-81         | Added to description with "Cloud Provider URL:" prefix                                                   |
| `Resource Tags`              | description (partial)           | 79-81         | Added to description with "Resource Tags:" prefix                                                        |
| `Kubernetes Cluster`         | description (partial)           | 79-81         | Added to description with "Kubernetes Cluster:" prefix                                                   |
| `Kubernetes Namespace`       | description (partial)           | 79-81         | Added to description with "Kubernetes Namespace:" prefix                                                 |
| `Container Service`          | description (partial)           | 79-81         | Added to description with "Container Service:" prefix                                                    |

#### Additional Finding Field Settings (Standard Format)

| Finding Field   | Default Value | Parser Line # | Notes                         |
| --------------- | ------------- | ------------- | ----------------------------- |
| static_finding  | False         | 84            | Set to False for all findings |
| dynamic_finding | True          | 84            | Set to True for all findings  |

### SCA Format

This format applies the `WizParserByDetailedName` parser class.

### Total Fields in SCA CSV

- Total data fields: 41
- Total data fields parsed: 36
- Total data fields NOT parsed: 5

#### SCA Format Field Mapping Details

| CSV Field                                     | Finding Field                  | Parser Line # | Notes                                                                              |
| --------------------------------------------- | ------------------------------ | ------------- | ---------------------------------------------------------------------------------- |
| `ID`                                          | unique_id_from_tool            | 182           | Used as unique identifier for the finding                                          |
| `WizURL`                                      | description                    | 150-154       | Added to description with "Wiz URL" prefix                                         |
| `Name`                                        | title, vulnerability_ids       | 169, 182-184  | Used in title format as vulnerability ID and added to vulnerability_ids list       |
| `CVSSSeverity`                                | Not parsed                     | -             | Not used in mapping                                                                |
| `HasExploit`                                  | description                    | 150-154       | Added to description with "Has Exploit" prefix                                     |
| `HasCisaKevExploit`                           | description                    | 150-154       | Added to description with "Has Cisa Kev Exploit" prefix                            |
| `FindingStatus`                               | active, is_mitigated           | 180           | Mapped through convert_status function to determine active state                   |
| `VendorSeverity`                              | severity                       | 181           | Mapped through _validate_severities to convert to DefectDojo severity format       |
| `FirstDetected`                               | date                           | 185           | Parsed into date object using date_parser                                          |
| `LastDetected`                                | Not parsed                     | -             | Not used in mapping                                                                |
| `ResolvedAt`                                  | Not parsed                     | -             | Not used in mapping                                                                |
| `ResolutionReason`                            | Not parsed                     | -             | Not used in mapping                                                                |
| `Remediation`                                 | mitigation                     | 155-159       | Added to mitigation with "Remediation" prefix                                      |
| `LocationPath`                                | description, mitigation        | 150-159       | Added to both description and mitigation with "Location Path" prefix               |
| `DetailedName`                                | title, component_name          | 169, 183      | Used in title format and mapped to component_name                                  |
| `Version`                                     | description, component_version | 150-154, 184  | Added to description with "Version" prefix and mapped to component_version         |
| `FixedVersion`                                | mitigation                     | 155-159       | Added to mitigation with "Fixed Version" prefix                                    |
| `DetectionMethod`                             | description                    | 150-154       | Added to description with "Detection Method" prefix                                |
| `Link`                                        | description                    | 150-154       | Added to description with "Link" prefix                                            |
| `Projects`                                    | description                    | 150-154       | Added to description with "Projects" prefix                                        |
| `AssetID`                                     | description                    | 150-154       | Added to description with "Asset ID" prefix                                        |
| `AssetName`                                   | description                    | 150-154       | Added to description with "Asset Name" prefix                                      |
| `AssetRegion`                                 | description                    | 150-154       | Added to description with "Asset Region" prefix                                    |
| `ProviderUniqueId`                            | description                    | 150-154       | Added to description with "Provider Unique Id" prefix                              |
| `CloudProviderURL`                            | description                    | 150-154       | Added to description with "Cloud Provider URL" prefix                              |
| `CloudPlatform`                               | description                    | 150-154       | Added to description with "Cloud Platform" prefix                                  |
| `Status`                                      | Not parsed                     | -             | Not directly used (FindingStatus is used instead)                                  |
| `SubscriptionExternalId`                      | description                    | 150-154       | Added to description with "Subscription External Id" prefix                        |
| `SubscriptionId`                              | description                    | 150-154       | Added to description with "Subscription Id" prefix                                 |
| `SubscriptionName`                            | description                    | 150-154       | Added to description with "Subscription Name" prefix                               |
| `Tags`                                        | unsaved_tags                   | 186           | Parsed into tags list using _parse_tags function                                   |
| `ExecutionControllers`                        | description                    | 150-154       | Added to description with "Execution Controllers" prefix                           |
| `ExecutionControllersSubscriptionExternalIds` | description                    | 150-154       | Added to description with "Execution Controllers Subscription External Ids" prefix |
| `ExecutionControllersSubscriptionNames`       | description                    | 150-154       | Added to description with "Execution Controllers Subscription Names" prefix        |
| `CriticalRelatedIssuesCount`                  | Not parsed                     | -             | Not used in mapping                                                                |
| `HighRelatedIssuesCount`                      | Not parsed                     | -             | Not used in mapping                                                                |
| `MediumRelatedIssuesCount`                    | Not parsed                     | -             | Not used in mapping                                                                |
| `LowRelatedIssuesCount`                       | Not parsed                     | -             | Not used in mapping                                                                |
| `InfoRelatedIssuesCount`                      | Not parsed                     | -             | Not used in mapping                                                                |
| `OperatingSystem`                             | description                    | 150-154       | Added to description with "Operating System" prefix                                |
| `IpAddresses`                                 | description                    | 150-154       | Added to description with "Ip Addresses" prefix                                    |

#### Additional Finding Field Settings (SCA Format)

| Finding Field  | Default Value | Parser Line # | Notes                               |
| -------------- | ------------- | ------------- | ----------------------------------- |
| static_finding | True          | 182           | Set to True for SCA format findings |
| Severity       | "Info"        | 210           | Default if not a valid severity     |

## Special Processing Notes

#### Date Processing

- Parser uses function `parse_wiz_datetime()` (lines 207-246) to handle different date formats from Wiz
- Handles both ISO8601 and custom Wiz timestamp formats

#### Status Conversion

- Both parser formats use `WizcliParsers.convert_status()` function to determine finding status (active, mitigated, etc.)
- Standard format - if a finding is mitigated, the Resolved Time is used as the mitigated timestamp

#### Description Construction

- Most CSV fields maintain field name as a prefix when added to the Finding description
- Description generated by iterating through predefined list of fields and adding data if present

#### Title Format

- Standard format: Used directly from the "Title" field
- SCA format: Combines package name (DetailedName) and vulnerability ID (Name) in format "{package_name}: {vulnerability_id}"

#### Mitigation Construction

- Standard format: Primary source is "Remediation Recommendation" field with optional "Resolution" field
- SCA format: Combines "Remediation", "LocationPath", and "FixedVersion" fields

#### Deduplication

- Both formats use the respective ID field as the unique_id_from_tool for deduplication

#### Tags Handling (SCA Format)

- "Tags" field is parsed from a JSON string format into a list of tag strings in format "key: value" (lines 186, 193-201)

### Source Code
Source code for the Wiz parser can be found on [GitHub](https://github.com/DefectDojo/django-DefectDojo/tree/cba7d81c98e040dc0a16032e82fd92f786b1dbd9/dojo/tools/wiz).