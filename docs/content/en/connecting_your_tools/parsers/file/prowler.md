---
title: "Prowler Scanner"
toc_hide: true
---

## Summary

Prowler is a command-line tool and open-source security tool to perform AWS, Azure, GCP, and Kubernetes security best practices assessments, audits, incident response, continuous monitoring, hardening, and forensics readiness.

## Usage

Prowler file can be imported in CSV or JSON format. The parser supports scans from all four cloud providers: AWS, Azure, GCP, and Kubernetes.

## Data Mapping

| Data From Prowler | Maps to Finding Field |
|-------------------|----------------------|
| CHECK_ID/check_id | vuln_id_from_tool |
| CHECK_TITLE/title | title (combined with CHECK_ID) |
| DESCRIPTION/risk_details | description |
| SEVERITY/severity | severity |
| PROVIDER/provider | tags |
| SERVICE_NAME/service | tags |
| STATUS/status_code | active (FAIL = True) |

## Severity Mapping

Prowler severity levels are mapped as follows:

* critical → Critical
* high → High
* medium → Medium
* low → Low
* informational/info → Info

### Sample Scan Data

Sample Prowler scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/prowler).

To use the Prowler scanner with DefectDojo, follow these steps:

1. Run a Prowler scan against your cloud environment (AWS, Azure, GCP, or Kubernetes)
2. Export the results in CSV or JSON format:

```bash
# For AWS, export as CSV
prowler aws --output csv

# For Azure, export as CSV  
prowler azure --output csv

# For GCP, export as CSV
prowler gcp --output csv

# For Kubernetes, export as CSV 
prowler kubernetes --output csv

# Alternatively, export as JSON for any platform
prowler aws --output json
```

3. In DefectDojo, select "Prowler Scan" as the scan type when uploading the results

## Data Mapping

The Prowler parser supports both CSV and JSON formats and automatically determines the format when processing a file. It extracts the following data:

| Prowler Field     | DefectDojo Field      |
|-------------------|------------------------|
| CHECK_ID          | vuln_id_from_tool     |
| CHECK_TITLE       | title (with CHECK_ID) |
| DESCRIPTION       | description           |
| SEVERITY          | severity              |
| STATUS            | active/inactive       |
| PROVIDER          | tags                  |
| SERVICE_NAME      | tags                  |
| RISK              | description (appended)|
| REMEDIATION_*     | mitigation            |

## Severity Mapping

Prowler severity levels are mapped to DefectDojo severity levels as follows:

| Prowler Severity  | DefectDojo Severity   |
|-------------------|------------------------|
| CRITICAL          | Critical               |
| HIGH              | High                   |
| MEDIUM            | Medium                 |
| LOW               | Low                    |
| INFORMATIONAL     | Info                   |

## Support

The parser supports:
- All major cloud platforms (AWS, Azure, GCP, and Kubernetes)
- CSV format (comma or semicolon delimiters)
- JSON format (OCSF format)
- Field extraction and validation
- Active/inactive status based on finding status code
