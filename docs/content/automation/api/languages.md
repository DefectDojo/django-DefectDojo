---
title: "Languages and Lines of Code"
description: "Import language composition data for an Asset using the cloc tool"
weight: 3
audience: opensource
aliases:
  - /en/open_source/languages
---

DefectDojo can display a breakdown of programming languages and lines of code for an Asset, populated by importing a report from the [cloc](https://github.com/AlDanial/cloc) (Count Lines of Code) tool via the API.

> **Naming:** The UI labels these objects **Assets** and **Organizations**. The API v2 wire surface keeps the original names — an Asset is `product` and an Organization is `product_type`. Endpoint paths, field names and event names are unchanged.

## Generating the cloc Report

Run `cloc` against your codebase using the `--json` flag to produce a JSON file in the correct format:

```bash
cloc --json /path/to/your/project > cloc-report.json
```

## Importing via the API

Upload the JSON report to DefectDojo via the API. When importing, all existing language data for the Asset is replaced with the contents of the new file.

The import endpoint is documented in the [DefectDojo API v2 docs](../api-v2-docs/).

## Viewing Results

After import, the language breakdown is displayed on the left side of the Asset details page, showing each language and its line count. Colors for each language are defined by entries in the `Language_Type` table, pre-populated with data from GitHub.

## Updating Language Colors

GitHub periodically updates language colors as new languages emerge. To pull the latest color data, run the following management command:

```bash
./manage.py import_github_languages
```

This reads from [ozh/github-colors](https://github.com/ozh/github-colors) and adds new languages or updates existing colors.
