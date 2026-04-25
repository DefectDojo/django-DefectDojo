---
title: "Snyk"
toc_hide: true
---

Snyk output file can be imported in JSON format. Snyk is a developer-first 
security platform that identifies vulnerabilities in open source dependencies 
(SCA) and application code (SAST). DefectDojo currently supports the SCA 
report format via the Snyk parser. For SAST findings, use the 
[Snyk Code](snyk_code.md) parser instead.

### Sample Scan Data

Sample Snyk scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/snyk).

---

## Supported Report Types

| Report Type | Supported | Parser |
|---|---|---|
| Snyk SCA (Open Source) | ✅ Yes | Snyk |
| Snyk SAST (Code) | ✅ Yes | Snyk Code |
| Snyk Issue API | ✅ Yes | Snyk Issue API |

This page covers the **Snyk SCA (Open Source)** parser only.

---

## How to Export from Snyk

### Option 1 — Snyk Web UI (Recommended for Enterprise Use)

1. Log in to your Snyk account at **app.snyk.io**
2. Navigate to your **Organization** and select the **Project** you want 
   to export
3. Click on the project to open the vulnerability list
4. Click the **Export** button at the top right of the findings list
5. Select **JSON** as the export format
6. Save the exported file

### Option 2 — Snyk CLI

If you prefer to export via the command line:

```bash
snyk test --json > snyk.json
```

For monorepos or projects with multiple package managers, scan all 
projects at once:

```bash
snyk test --all-projects --json > snyk.json
```

For specific package managers:

```bash
# For npm projects
snyk test --json --file=package.json > snyk.json

# For Maven projects  
snyk test --json --file=pom.xml > snyk.json

# For Python projects
snyk test --json --file=requirements.txt > snyk.json
```

Once you have the JSON file, upload it into DefectDojo under your chosen 
Engagement using **Import Scan > Snyk Scan**.

---

## Severity Mapping

Snyk uses its own severity model which maps to DefectDojo as follows:

| Snyk Severity | DefectDojo Severity |
|---|---|
| Critical | Critical |
| High | High |
| Medium | Medium |
| Low | Low |

---

## Recommended Workflow for Enterprise Use

For teams running Snyk across multiple applications and repositories:

1. **Use Reimport** (not Import) for recurring scans on the same target 
   to track finding status over time rather than creating duplicate records
2. **Export at the project level** rather than the organization level 
   to maintain clean engagement boundaries in DefectDojo
3. **Set SLA thresholds** in DefectDojo aligned to Snyk severity levels 
   so that Critical and High findings trigger appropriate remediation 
   timelines automatically
4. **Use Snyk's CI/CD integration** to export JSON automatically as part 
   of your pipeline and feed results into DefectDojo via the API for 
   continuous vulnerability tracking

---

## Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate Findings using these 
[hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- vuln id from tool
- file path
- component name
- component version

### Note on Deduplication

Snyk can report the same vulnerability across multiple projects or 
package versions. When importing findings from multiple Snyk projects 
into the same DefectDojo product, review your deduplication settings 
to avoid over-counting the same underlying vulnerability.
