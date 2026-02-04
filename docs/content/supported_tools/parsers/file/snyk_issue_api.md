---
title: "Snyk Issue API"
toc_hide: true
---
The Snyk Issue API parser supports importing vulnerability data from the Snyk Issue API in JSON format.

Currently parsing issues of type `code` (SAST) and `package_vulnerability` (SCA) are supported.

Samples of ther issue types are welcome.

For more information about the Snyk Issue API, refer to the [official Snyk API documentation](https://docs.snyk.io/snyk-api/reference/issues#get-orgs-org_id-issues).

### API request
Example API request to get only code issues:
```
GET https://api.snyk.io/rest/orgs/{org_id}/issues?version=2025-08-02&type=code
```

For more details see: https://docs.snyk.io/snyk-api/reference/issues#get-orgs-org_id-issues

### Sample Scan Data
Sample Snyk Issue API scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/snyk_issue_api).

### Field Mapping
The parser maps fields from the Snyk Issue API response to DefectDojo's Finding model as follows:

| Finding Field | Snyk Issue API Field | Notes |
|--------------|---------------------|-------|
| title | attributes.title | |
| severity | attributes.effective_severity_level | Mapped to Critical/High/Medium/Low/Info |
| description | attributes.description | |
| unique_id_from_tool | id | Top-level issue ID |
| file_path | coordinates[].representations[].sourceLocation.file | First occurrence |
| line | coordinates[].representations[].sourceLocation.region.start.line | Line where the issue starts |
| date | attributes.created_at | ISO format date |
| cwe | classes[].id | First CWE class found |
| active | attributes.status == "open" AND NOT attributes.ignored | Inactive if ignored or not open |
| verified | true | Always set to true |
| static_finding | true | Always set to true |
| dynamic_finding | false | Always set to false |
| out_of_scope | attributes.ignored | Set to true if issue is ignored |
| fix_available* | coordinates[].is_fixable_* | True if any fixability flag is true.  |

#### Impact Field
The impact field combines multiple pieces of information:
1. Problem details:
   - Source (e.g., "SNYK")
   - Type (e.g., "vulnerability")
   - Last update timestamp
   - Severity level
2. All source locations, each containing:
   - File path
   - Commit ID
   - Line range (start-end)
   - Column range (start-end)

#### Additional Processing
- Multiple CWEs are handled by using the first one as the primary CWE and listing additional ones in the references field
- Risk scores are included in the severity_justification field when available
- Only issues with type="code" are processed
- Line numbers: Only the starting line is stored in the Finding model, but both start and end lines are included in the impact field for reference

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique id from tool
- file path