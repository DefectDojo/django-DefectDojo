---
title: "Report Builder"
description: "Performance metrics and insights"
summary: ""
date: 2026-01-20T17:33:00+00:00
lastmod: 2026-01-20T17:33:00+00:00
draft: false
weight: 2
chapter: true
seo:
    title: ""
    description: ""
    canonical: ""
    robots: ""
exclude_search: true
---
The Report Builder lets you turn DefectDojo data into polished, shareable reports — executive summaries, compliance snapshots, POA&M packages, engineering detail, and more — for audiences inside and outside your security team.

## Open source vs. DefectDojo Pro

How you build reports depends on which edition you run:

| | Open Source | DefectDojo Pro |
|---|---|---|
| **Build a report** | Yes — assemble from widgets | Yes — compose from reusable Blocks |
| **Run and retrieve output** | Yes (HTML, print-to-PDF) | Yes (saved PDF or HTML) |
| **Save reusable Themes / Blocks / Templates** | No — rebuild each time | Yes |
| **Persisted history of generated reports** | No | Yes — list, download, re-run |
| **REST API + LLM automation** | — | Yes — full create → run → download |

In short: **open source** lets you build a report, run it, and export the result, but does not save templates or keep a report history. **DefectDojo Pro** turns reporting into reusable, brandable building blocks that you can drive from the UI, the REST API, or an LLM.

## Where to go next

**DefectDojo Pro**

- **[Report Builder](report-builder/)** — concepts (Themes, Blocks, Templates, Generated Reports) and a full UI walkthrough.
- **[Automating Reports with the API](report-builder-api/)** — create, run, poll, and download reports over the REST API, with a complete script.
- **[Building Reports with an LLM](report-builder-llm/)** — let an LLM design, create, run, and download reports for you.

**Open Source**

- **[Using the Report Builder](using-the-report-builder/)** — build, run, and export a report with the widget-based builder.