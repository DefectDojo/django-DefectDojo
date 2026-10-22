---
title: "Import from GitHub Actions"
description: "Import scan results from a GitHub Actions workflow with the official DefectDojo action"
weight: 3
---

The official [DefectDojo action](https://github.com/marketplace/actions/defectdojo) imports a scan report into DefectDojo from a GitHub Actions workflow. It works with DefectDojo Pro and the Open Source edition, and reads every report format DefectDojo supports, including SARIF.

Each run reimports into the same Test, so Findings the scanner no longer reports are closed and each Finding keeps its history. The action records the build, branch, commit and repository on the Test, and can fail the workflow step when Findings at a chosen severity remain active.

## Before you start

1. Create an API v2 key for a user that can import into the Asset (and create it, if you let the action create Assets). The key is under **API v2 Token** in the user menu.
2. In the GitHub repository, add the key as a secret named `DEFECTDOJO_API_TOKEN` under **Settings > Secrets and variables > Actions**.

## Add the action to a workflow

Run your scanner, then pass its report to the action:

```yaml
permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Scan
        uses: aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25 # v0.36.0
        with:
          scan-type: fs
          format: json
          output: trivy.json
      - name: Import into DefectDojo
        uses: DefectDojo/defectdojo-action@v1
        with:
          defectdojo-url: https://defectdojo.example.com
          api-token: ${{ secrets.DEFECTDOJO_API_TOKEN }}
          file: trivy.json
          scan-type: Trivy Scan
          fail-on: critical
```

`scan-type` is the name of the report format as DefectDojo lists it, for example `SARIF`, `Trivy Scan` or `Semgrep JSON Report`. See [Supported Tools](/supported_tools/) for every name.

## Where the Findings go

Unless you set them, the action uses names from the repository and creates any that don't exist yet:

| DefectDojo object | Default | Input |
| --- | --- | --- |
| Organization (Product Type) | Repository owner | `organization-name` or `product-type-name` |
| Asset (Product) | Repository name | `asset-name` or `product-name` |
| Engagement | Branch name | `engagement-name` |
| Test | Scan type | `test-title` |

When one Engagement gets several reports of the same scan type, give each its own `test-title` so each reimport finds its own Test.

### Branches, pull requests and tags

Each branch gets its own Engagement, so a pull request's scan never closes or reopens Findings on the default branch. Pull requests use their source branch, tags use the tag name, and the merge queue uses one Engagement per base branch.

Engagements the action creates for anything other than the default branch deduplicate only within themselves (**Deduplication within this engagement only**). Without that, a Finding first seen on a branch would mark the default branch's copy as a duplicate. Branch Engagements stay in DefectDojo after the branch is merged, so run the import only on the default branch if you want to keep them out of the Asset's counts.

## Fail the build

Set `fail-on` to `low`, `medium`, `high` or `critical` to fail the step when the Test has active Findings at that severity or above after the import. Duplicates don't count. The job summary shows the counts by severity and a link to the Test.

## Pro features

On DefectDojo Pro, the action can also:

- Push new Findings to the Connectors set up for the Asset (`push-to-connector: true`).
- Import large reports in the background (`background-import: true`). The action waits until the Test finishes processing before it reports counts or applies `fail-on`.
- Warn when an Asset was renamed or moved, so you can update the names in the workflow.

On the Open Source edition, these inputs are skipped with a warning, and the import still runs. Set `strict: true` to fail the step instead.

## Pull requests from forks

GitHub doesn't give secrets to workflows that run on pull requests from forks, so the action can't authenticate there. Run the import on `push`, or on pull requests from branches in the same repository. Don't use `pull_request_target` to get around this: it runs with your secrets while checking out code you don't control.

## All inputs and outputs

The [action's README](https://github.com/DefectDojo/defectdojo-action#inputs) lists every input and output. Most inputs match a field of the **/reimport** endpoint described in [Import from API](/import_data/import_scan_files/api_pipeline_modelling/).
