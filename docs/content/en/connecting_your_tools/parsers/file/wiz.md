---
title: "Wiz Scanner Parser"
toc_hide: true
weight: 1
---

# Wiz Scanner Parser Documentation

## Overview
The [Wiz](https://www.wiz.io/) parser for DefectDojo supports imports from both Wiz Scanner Standard and SCA (Software Composition Analysis) .csv output from Wiz.io. This document details the parsing of both formats into DefectDojo field mappings, unmapped fields, and location of each field's parsing code for easier troubleshooting and analysis.

## Supported File Types
The Wiz parser accepts CSV file format. There are two primary formats supported:

1. **Standard Format** - Issues exports with "Title" field (processed by WizParserByTitle class)
2. **SCA Format** - Vulnerability exports with "Name" and "DetailedName" fields (processed by WizParserByDetailedName class)

To generate these files, export the findings from the Wiz platform by:
- Standard Format: Select "Export to CSV" option from the Issues view in the Wiz.io platform
- SCA Format: Select "Export to CSV" option from the Vulnerability view in the Wiz.io platform

## Standard Format CSV (WizParserByTitle)

### Total Fields in Standard Format CSV
- Total data fields: 32
- Total data fields parsed: 32
- Total data fields NOT parsed: 0

### Standard Format Field Mapping Details

| CSV Field # | CSV Field | Finding Field | Parser Line # | Notes |
|-------------|-----------|---------------|--------------|-------|
| 1 | Created At | date | 68 | Parsed using the parse_wiz_datetime function to convert to datetime object |
| 2 | Title | title | 67 | Direct mapping to Finding title |
| 3 | Severity | severity | 69 | Converted to lowercase then capitalized to match DefectDojo's severity format |
| 4 | Status | active, is_mitigated, mitigated | 65 | Converted through WizcliParsers.convert_status function to determine active status and mitigation status |
| 5 | Description | description (partial) | 79-81 | Added to description with "Description:" prefix |
| 6 | Resource Type | description (partial) | 79-81 | Added to description with "Resource Type:" prefix |
| 7 | Resource external ID | description (partial) | 79-81 | Added to description with "Resource external ID:" prefix |
| 8 | Subscription ID | description (partial) | 79-81 | Added to description with "Subscription ID:" prefix |
| 9 | Project IDs | description (partial) | 79-81 | Added to description with "Project IDs:" prefix |
| 10 | Project Names | description (partial) | 79-81 | Added to description with "Project Names:" prefix |
| 11 | Resolved Time | mitigated | 71-74 | Used to set mitigated timestamp if finding is marked as mitigated |
| 12 | Resolution | mitigation (partial) | 62-63 | Added to mitigation text with "Resolution:" prefix |
| 13 | Control ID | description (partial) | 79-81 | Added to description with "Control ID:" prefix |
| 14 | Resource Name | description (partial) | 79-81 | Added to description with "Resource Name:" prefix |
| 15 | Resource Region | description (partial) | 79-81 | Added to description with "Resource Region:" prefix |
| 16 | Resource Status | description (partial) | 79-81 | Added to description with "Resource Status:" prefix |
| 17 | Resource Platform | description (partial) | 79-81 | Added to description with "Resource Platform:" prefix |
| 18 | Resource OS | description (partial) | 79-81 | Added to description with "Resource OS:" prefix |
| 19 | Resource original JSON | description (partial) | 79-81 | Added to description with "Resource original JSON:" prefix |
| 20 | Issue ID | unique_id_from_tool | 85 | Used as unique identifier for the finding |
| 21 | Resource vertex ID | description (partial) | 79-81 | Added to description with "Resource vertex ID:" prefix |
| 22 | Ticket URLs | description (partial) | 79-81 | Added to description with "Ticket URLs:" prefix |
| 23 | Note | description (partial) | 79-81 | Added to description with "Note:" prefix |
| 24 | Due At | description (partial) | 79-81 | Added to description with "Due At:" prefix |
| 25 | Remediation Recommendation | mitigation | 61 | Direct mapping to mitigation field |
| 26 | Subscription Name | description (partial) | 79-81 | Added to description with "Subscription Name:" prefix |
| 27 | Wiz URL | description (partial) | 79-81 | Added to description with "Wiz URL:" prefix |
| 28 | Cloud Provider URL | description (partial) | 79-81 | Added to description with "Cloud Provider URL:" prefix |
| 29 | Resource Tags | description (partial) | 79-81 | Added to description with "Resource Tags:" prefix |
| 30 | Kubernetes Cluster | description (partial) | 79-81 | Added to description with "Kubernetes Cluster:" prefix |
| 31 | Kubernetes Namespace | description (partial) | 79-81 | Added to description with "Kubernetes Namespace:" prefix |
| 32 | Container Service | description (partial) | 79-81 | Added to description with "Container Service:" prefix |

### Additional Finding Field Settings (Standard Format)

| Finding Field | Default Value | Parser Line # | Notes |
|--------------|---------------|---------------|-------|
| static_finding | False | 84 | Set to False for all findings |
| dynamic_finding | True | 84 | Set to True for all findings |

## SCA Format (WizParserByDetailedName)

### Total Fields in SCA CSV
- Total data fields: 41
- Total data fields parsed: 36
- Total data fields NOT parsed: 5

### SCA Format Field Mapping Details 

| CSV Field # | CSV Field | Finding Field | Parser Line # | Notes |
|-------------|-----------|---------------|---------------|-------|
| 1 | ID | unique_id_from_tool | 182 | Used as unique identifier for the finding |
| 2 | WizURL | description | 150-154 | Added to description with "Wiz URL" prefix |
| 3 | Name | title, vulnerability_ids | 169, 182-184 | Used in title format as vulnerability ID and added to vulnerability_ids list |
| 4 | CVSSSeverity | Not parsed | - | Not used in mapping |
| 5 | HasExploit | description | 150-154 | Added to description with "Has Exploit" prefix |
| 6 | HasCisaKevExploit | description | 150-154 | Added to description with "Has Cisa Kev Exploit" prefix |
| 7 | FindingStatus | active, is_mitigated | 180 | Mapped through convert_status function to determine active state |
| 8 | VendorSeverity | severity | 181 | Mapped through _validate_severities to convert to DefectDojo severity format |
| 9 | FirstDetected | date | 185 | Parsed into date object using date_parser |
| 10 | LastDetected | Not parsed | - | Not used in mapping |
| 11 | ResolvedAt | Not parsed | - | Not used in mapping |
| 12 | ResolutionReason | Not parsed | - | Not used in mapping |
| 13 | Remediation | mitigation | 155-159 | Added to mitigation with "Remediation" prefix |
| 14 | LocationPath | description, mitigation | 150-159 | Added to both description and mitigation with "Location Path" prefix |
| 15 | DetailedName | title, component_name | 169, 183 | Used in title format and mapped to component_name |
| 16 | Version | description, component_version | 150-154, 184 | Added to description with "Version" prefix and mapped to component_version |
| 17 | FixedVersion | mitigation | 155-159 | Added to mitigation with "Fixed Version" prefix |
| 18 | DetectionMethod | description | 150-154 | Added to description with "Detection Method" prefix |
| 19 | Link | description | 150-154 | Added to description with "Link" prefix |
| 20 | Projects | description | 150-154 | Added to description with "Projects" prefix |
| 21 | AssetID | description | 150-154 | Added to description with "Asset ID" prefix |
| 22 | AssetName | description | 150-154 | Added to description with "Asset Name" prefix |
| 23 | AssetRegion | description | 150-154 | Added to description with "Asset Region" prefix |
| 24 | ProviderUniqueId | description | 150-154 | Added to description with "Provider Unique Id" prefix |
| 25 | CloudProviderURL | description | 150-154 | Added to description with "Cloud Provider URL" prefix |
| 26 | CloudPlatform | description | 150-154 | Added to description with "Cloud Platform" prefix |
| 27 | Status | Not parsed | - | Not directly used (FindingStatus is used instead) |
| 28 | SubscriptionExternalId | description | 150-154 | Added to description with "Subscription External Id" prefix |
| 29 | SubscriptionId | description | 150-154 | Added to description with "Subscription Id" prefix |
| 30 | SubscriptionName | description | 150-154 | Added to description with "Subscription Name" prefix |
| 31 | Tags | unsaved_tags | 186 | Parsed into tags list using _parse_tags function |
| 32 | ExecutionControllers | description | 150-154 | Added to description with "Execution Controllers" prefix |
| 33 | ExecutionControllersSubscriptionExternalIds | description | 150-154 | Added to description with "Execution Controllers Subscription External Ids" prefix |
| 34 | ExecutionControllersSubscriptionNames | description | 150-154 | Added to description with "Execution Controllers Subscription Names" prefix |
| 35 | CriticalRelatedIssuesCount | Not parsed | - | Not used in mapping |
| 36 | HighRelatedIssuesCount | Not parsed | - | Not used in mapping |
| 37 | MediumRelatedIssuesCount | Not parsed | - | Not used in mapping |
| 38 | LowRelatedIssuesCount | Not parsed | - | Not used in mapping |
| 39 | InfoRelatedIssuesCount | Not parsed | - | Not used in mapping |
| 40 | OperatingSystem | description | 150-154 | Added to description with "Operating System" prefix |
| 41 | IpAddresses | description | 150-154 | Added to description with "Ip Addresses" prefix |

### Additional Finding Field Settings (SCA Format)

| Finding Field | Default Value | Parser Line # | Notes |
|--------------|---------------|---------------|-------|
| static_finding | True | 182 | Set to True for SCA format findings |
| Severity | "Info" | 210 | Default if not a valid severity |

## Special Processing Notes

### Date Processing
- Parser uses function `parse_wiz_datetime()` (lines 207-246) to handle different date formats from Wiz
- Handles both ISO8601 and custom Wiz timestamp formats

### Status Conversion
- Both parser formats use `WizcliParsers.convert_status()` function to determine finding status (active, mitigated, etc.)
- Standard format -  if a finding is mitigated, the Resolved Time is used as the mitigated timestamp

### Description Construction
- Most CSV fields maintain field name as a prefix when added to the Finding description 
- Description generated by iterating through predefined list of fields and adding data if present

### Title Format
- Standard format: Used directly from the "Title" field
- SCA format: Combines package name (DetailedName) and vulnerability ID (Name) in format "{package_name}: {vulnerability_id}"

### Mitigation Construction
- Standard format: Primary source is "Remediation Recommendation" field with optional "Resolution" field
- SCA format: Combines "Remediation", "LocationPath", and "FixedVersion" fields

### Deduplication
- Both formats use the respective ID field as the unique_id_from_tool for deduplication

### Tags Handling (SCA Format)
- "Tags" field is parsed from a JSON string format into a list of tag strings in format "key: value" (lines 186, 193-201)

## Sample Scan Data or Unit Tests
- [Sample Scan Data Folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/wiz)

## Link To Tool
- [Wiz.io](https://www.wiz.io/)
- [Wiz Documentation](https://docs.wiz.io/)
