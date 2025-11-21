---
title: "OpenReports"
toc_hide: true
---

Import vulnerability scan reports formatted as [OpenReports](https://github.com/openreports/reports-api).

OpenReports is a Kubernetes-native reporting framework that aggregates vulnerability scan results and compliance checks from various security tools into a unified format. It provides a standardized API for collecting and reporting security findings across your Kubernetes infrastructure.

### File Types

DefectDojo parser accepts a .json file.

### Exporting Reports from Kubernetes

To export OpenReports from your Kubernetes cluster, use kubectl:

```bash
kubectl get reports -A -ojson > reports.json
```

This command retrieves all Report objects from all namespaces and saves them in JSON format. You can then import the `reports.json` file into DefectDojo.

To export reports from a specific namespace:

```bash
kubectl get reports -n <namespace> -ojson > reports.json
```

### Report Formats

The parser supports multiple input formats:

- Single Report object
- Array of Report objects
- Kubernetes List object containing Report items

### Sample Scan Data

Sample OpenReports scans can be found in the [unittests/scans/openreports directory](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/openreports).

### Supported Fields

The parser extracts the following information from OpenReports JSON:

- **Metadata**: Report name, namespace, UID for stable deduplication
- **Scope**: Kubernetes resource information (kind, name, namespace)
- **Results**: Individual security findings with:
  - Message and description
  - Policy ID (e.g., CVE identifiers)
  - Severity (critical, high, medium, low, info)
  - Category (e.g., "vulnerability scan", "compliance check")
  - Source scanner information
  - Package details (name, installed version, fixed version)
  - References and URLs

### Severity Mapping

OpenReports severity levels are mapped to DefectDojo as follows:

| OpenReports Severity | DefectDojo Severity |
|----------------------|---------------------|
| critical             | Critical            |
| high                 | High                |
| medium               | Medium              |
| low                  | Low                 |
| info                 | Info                |

### Result Status Mapping

The `result` field in OpenReports is mapped to DefectDojo finding status:

| OpenReports Result | Active | Verified | Description                                    |
|--------------------|--------|----------|------------------------------------------------|
| fail               | True   | True     | Finding requires attention                     |
| warn               | True   | True     | Warning-level finding                          |
| pass               | False  | False    | Check passed, no vulnerability found           |
| skip               | False  | False    | Check was skipped                              |

### Features

**CVE Tracking**: Findings with CVE policy IDs are automatically tagged with vulnerability identifiers.

**Fix Availability**: The parser automatically sets the `fix_available` flag when a fixed version is provided.

**Service Mapping**: Findings are mapped to services based on Kubernetes scope (namespace/kind/name).

**Stable Deduplication**: Uses report UID from metadata for consistent deduplication across reimports.

**Tagging**: Findings are automatically tagged with category, source scanner, and Kubernetes resource kind.

### Example JSON Format

```json
{
  "apiVersion": "openreports.io/v1alpha1",
  "kind": "Report",
  "metadata": {
    "name": "deployment-test-app-630fc",
    "namespace": "test",
    "uid": "b1fcca57-2efd-44d3-89e9-949e29b61936"
  },
  "scope": {
    "kind": "Deployment",
    "name": "test-app"
  },
  "results": [
    {
      "category": "vulnerability scan",
      "message": "openssl: Out-of-bounds read in HTTP client",
      "policy": "CVE-2025-9232",
      "properties": {
        "fixedVersion": "3.5.4-r0",
        "installedVersion": "3.5.2-r1",
        "pkgName": "libcrypto3",
        "primaryURL": "https://avd.aquasec.com/nvd/cve-2025-9232"
      },
      "result": "warn",
      "severity": "low",
      "source": "image-scanner"
    }
  ]
}
```

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool (format: `report_uid:policy:package_name`)
- title
- severity
- vulnerability ids (for CVE findings)
- description

The parser uses the report UID from metadata to create a stable `unique_id_from_tool` that persists across reimports.
