---
title: "Lacework API Import"
toc_hide: true
---
All parsers that use API pull have common basic configuration steps, but with different values. Please, [read these steps](../) first.

## Tool Configuration

In `Tool Configuration`, select `Tool Type` "Lacework" and `Authentication Type` "API Key".
The URL must be in the format of `https://<your_lacework_instance>.lacework.net`
Enter the key ID in the "Username" field and paste your Lacework API secret key in the "API Key" field.
By default, the tool will import both container and host vulnerabilities.

To restrict the import to only containers or only hosts, use the "Extras" field with the following options:

| Extras value | Effect |
|---|---|
| *(empty)* | Import both containers and hosts (default) |
| `include_hosts=false` | Import containers only |
| `include_containers=false` | Import hosts only |
| `include_containers=true,include_hosts=true` | Both (same as empty) |

## Product-Level Configuration

In `Add API Scan Configuration`
- `Service key 1` can optionally be set to filter container vulnerabilities by repository name pattern.
  When set, only container repositories matching the pattern (rlike) will be imported.
  Leave empty to import all container repositories.

## Import All Repositories (Management Command)

Instead of importing per-product through the UI, you can import all repositories at once and auto-create Products using the management command:

```bash
python manage.py lacework_import_all --tool-config <tool_config_id>
```

This command will:
1. Fetch all container vulnerabilities from Lacework
2. Automatically group them by repository
3. Create a Product for each unique repository (if it doesn't already exist)
4. Create an Engagement and Test for each product
5. Create Findings for each vulnerability

The configuration for `include_containers` and `include_hosts` is automatically read from the "Extras" field of the Tool Configuration.

## Sample Scan Data

Sample Lacework vulnerability data can be examined using the debug command:

```bash
python manage.py lacework_debug_vuln --tool-config <tool_config_id> --type containers
python manage.py lacework_debug_vuln --tool-config <tool_config_id> --type hosts
```

## Field Mapping

Lacework vulnerability fields are mapped to DefectDojo Finding fields as follows:

| Lacework Field | Finding Field | Example |
|---|---|---|
| `vulnId` | `vuln_id_from_tool` | CVE-2025-62727 |
| `severity` (or inferred from `riskScore`) | `severity` | Critical, High, Medium, Low, Info |
| `cveProps.description` + `featureProps.introduced_in` | `description` | Vulnerability description |
| `cveProps.link` + `cveProps.source` | `references` | CVE link and data source |
| `featureKey.name` | `component_name` | starlette, zlib, openssl |
| `featureKey.version` / `version_installed` | `component_version` | 0.47.3 |
| `featureProps.src` | `file_path` | Package path within image |
| `fixInfo.fix_available` | `fix_available` | 1 (true) if fix exists |
| `fixInfo.fixed_version` | `fix_version` | 0.49.1 |
| `cveRiskScore` / `riskScore` | `cvssv3_score` | 9.8 |
| `status` (VULNERABLE/GOOD) | `active` / `verified` | Active only if vulnerable |
| `packageStatus` | tags | pkg:NO_AGENT_AVAILABLE |
| `evalCtx.request_source` | tags | scanner:INLINE_SCANNER |
| `evalCtx.integration_props.NAME` | tags | integration:bitbucket-pipelines |
| `featureProps.feed` | tags | feed:rbs |

## Deduplication

The Lacework API Import uses `hash_code` algorithm for deduplication with the following fields:
- `vuln_id_from_tool` (CVE ID)
- `component_name` (package name)
- `file_path` (namespace/package path)

This means the same CVE found in the same package will be properly deduplicated.

## Multiple Lacework API Configurations

In the import or re-import dialog, you can select which `API Scan Configuration` shall be used. If you do not choose any, DefectDojo will use the `API Scan Configuration` of the Product if there is only one defined or the Lacework `Tool Configuration` if there is only one.