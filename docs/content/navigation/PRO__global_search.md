---
title: "Global Search"
description: "Search across Findings, Assets, and related objects from the DefectDojo Pro topbar"
audience: pro
weight: 3
---

DefectDojo Pro includes a **global search** that looks across your Findings and related objects from a single box in the topbar. It is backed by native Postgres full-text search with fuzzy, typo-tolerant matching, so you can find an object without remembering its exact wording.

Global search finds your **data**: findings, assets, engagements, and the other records listed below. To find a **page** (a menu destination such as a settings screen or a list view), use the menu search instead: press **Cmd+K** or **Ctrl+K**, or the magnifying-glass control in the top-right corner of the sidebar. See [The Sidebar Menu](/navigation/pro__sidebar/).

## Running a search

- **Topbar search box** — click the **Search** box in the top navigation and start typing. As you type, a dropdown previews the top matches **grouped by object type**, with a count next to each type and a **See all *N* results** link at the bottom.
- **Full results page** — press **Enter**, or click **See all *N* results**, to open the full results page. This is a single, sortable, filterable table of every match across all object types.

Results are always **scoped to what you are authorized to view** — global search never surfaces objects you would not otherwise have access to. (Finding Templates are the one exception: like elsewhere in DefectDojo, they are visible to any signed-in user.)

## What you can search

Global search covers these object types:

| Object type | Notes |
| --- | --- |
| **Findings** | |
| **Assets** | (Assets) |
| **Organizations** | (Organizations) |
| **Engagements** | |
| **Tests** | |
| **Endpoints** *or* **Locations** | Whichever your instance uses — instances with [Locations](/asset_modelling/locations/pro__locations_overview/) enabled search Locations; others search Endpoints. |
| **Finding Templates** | |
| **Technologies** | |
| **Vulnerability IDs** | e.g. CVEs |

For most types, search matches against the object's **name/title and description**. For Findings, Assets, Engagements, and Tests, it also matches **tags** (by prefix). Vulnerability IDs match on the ID value itself.

## Query syntax

### Free text

Type any keywords to search everything at once. Matches are ranked by relevance, with title/name hits ranked above description hits. Fuzzy matching (see below) means close-but-not-exact terms still match.

### Quoted phrases

Wrap a phrase in double quotes to keep it together — `"space inside"` is treated as one term rather than two keywords.

### Operators

Prefix a term with an operator (`operator:value`) to narrow the search. Supported operators:

| Operator | What it does |
| --- | --- |
| `finding:` `product:` `engagement:` `test:` `template:` `technology:` | Scope the search to a single object type and search it for the value (e.g. `finding:sqli`). |
| `id:` | Look up a Finding by its numeric ID (e.g. `id:12345`). |
| `endpoint:` | Find Findings whose endpoint/location host contains the value. |
| `vulnerability_id:` | Exact match on a Vulnerability ID. Accepts a comma-separated list, and can be repeated (e.g. `vulnerability_id:CVE-2020-1234,CVE-2018-7489`). |
| `tag:` / `tags:` | Match objects by tag. `tag:` matches a single tag by substring; `tags:` matches any tag in a list. |
| `test-tag:` `engagement-tag:` `product-tag:` (and their `-tags` plurals) | Match by a tag on the related Test, Engagement, or Asset rather than on the object itself. |
| `not-tag:` `not-tags:` (and the `not-…-tag` relation variants) | Negate any of the tag operators above to **exclude** matches. |

You can combine operators with free-text keywords in the same query.

### Fuzzy matching

For queries of **three or more characters**, global search also does trigram (word-similarity) matching. This tolerates typos and finds terms **inside** longer dotted or hyphenated values — for example, `internal` matches `api.internal.example.com`.

## Filtering and sorting the results page

On the full results page, the columns can be filtered and sorted independently of the query text — filter by **object type**, **severity**, **title**, or **context**, and sort by any column. These are separate from the `operator:` syntax above and apply to the merged results table.

## Result limits

- The full results page is **paginated** (25 rows per page by default).
- Each object type contributes up to a **maximum number of matches** per search — **100** by default. When more matches exist than are shown, the results are flagged as truncated; narrow your query to see the most relevant hits.
- The topbar dropdown shows a smaller preview (the top few matches per type) with the total counts, so **See all *N* results** always reflects the true totals.
