---
title: "Hardware Sizing for Self-Hosted DefectDojo Pro"
description: "General guidance for sizing compute, memory, and storage for a self-hosted DefectDojo Pro deployment"
draft: false
weight: 4
audience: pro
---

Sizing a DefectDojo deployment comes down to two questions. How much data are you holding, and how many people are working in it at once. This page gives starting points for both.

Treat what follows as general guidance rather than a specification. The figures lean deliberately conservative, and they assume a deployment doing everyday triage alongside regular scan imports. Your own numbers will move depending on how you use the product, so read the notes under the table before you provision anything.

Specs are given as generic vCPU and memory figures so they apply to any cloud provider or on-premise hardware. The application node guidance assumes Kubernetes. If you run Docker Compose on a single host, use the same totals.

## Sizing table

| Findings | Concurrent users | Database | Application nodes |
| --- | --- | --- | --- |
| Up to 100K | Up to ~25 | 2–4 vCPU / 16–32 GB | 2 × (2–4 vCPU / 8–16 GB) |
| 100K–500K | ~25–50 | 4–8 vCPU / 32–64 GB | 2–3 × (4 vCPU / 16 GB) |
| 500K–1M | ~50–100 | 8 vCPU / 64–96 GB | 2–3 × (8 vCPU / 32 GB) |
| 1M–5M | ~100–250 | 8–16 vCPU / 96–128 GB | 5–6 × (8 vCPU / 32 GB) |
| 5M–10M | ~250–500 | 16 vCPU / 128–192 GB | 9–10 × (8 vCPU / 32 GB) |

Where you land inside a range depends on your workload. Start at the upper end of a range if anything in [What pushes you up a tier](#what-pushes-you-up-a-tier) applies to you.

## How to read these numbers

### Database memory matters more than database CPU

DefectDojo runs aggregation-heavy queries across your findings. Those stay fast while the working set and its indexes are served from memory, and they degrade quickly once the database starts reaching for disk. When you have to choose, buy memory before you buy cores. The table reflects that. Memory roughly doubles from tier to tier while CPU counts move much more slowly.

### Application nodes track users, not findings

The concurrent user figures in the table assume smaller datasets belong to smaller teams. That assumption breaks often. If you hold 200K findings but have 100 people in the UI at once, size the application layer for the users and leave the database where your finding count puts it. The two scale independently.

### Node shape is flexible

Kubernetes will spread the load whether you give it a few large nodes or more small ones, so the node counts above are one workable arrangement rather than a requirement. Two things are worth holding to. Keep at least two nodes so losing one doesn't take the application down, and avoid nodes smaller than 2 vCPU / 8 GB so individual pods schedule comfortably.

## Storage

Plan on 20–30 GB of database storage per million findings. Where you fall in that spread depends on how much you hang off each finding. Long descriptions and large endpoint counts push you toward the top of it.

Even the largest deployment in the table fits inside a few hundred GB of general-purpose SSD. Storage is cheap next to the cost of running out, so provision for where you expect to be in a year rather than where you are now. If your provider offers storage autoscaling, turn it on.

Media storage is separate and usually much smaller. It holds uploaded artifacts such as screenshots and risk acceptance documents, so size it from your own upload habits.

## What pushes you up a tier

Finding count is the headline number, but several things will have you sizing up sooner than the count alone suggests.

- **Import volume and frequency.** Large scans arriving often, especially several at the same time, put sustained load on both the database and the async workers. CI pipelines that import on every build are the usual cause.
- **Deduplication.** Deduplication compares incoming findings against what you already hold. The more findings you have and the broader your deduplication configuration, the more work every import does.
- **Reporting and dashboards.** Metrics views and large report generation are read-heavy, and they hit the database harder than day-to-day triage does.
- **API traffic.** Integrations that poll or pull large result sets add concurrent load that never shows up in your interactive user count.
- **Retention.** Deployments that keep everything forever grow into the next tier on schedule. Archiving or deleting old data keeps you where you are for longer.

## When in doubt, round up

The figures here already lean conservative, and being one size too large costs far less than being one size too small. Database memory pressure in particular does not degrade gracefully. Performance holds up fine until it doesn't.

Adding application capacity later is straightforward, since you add nodes. Resizing a database typically means downtime, so that is the one worth getting right up front.

## Questions or support

These are starting points, not limits. If your deployment sits at the top of the table, or your workload doesn't resemble the assumptions here, talk to us before you provision. Contact your account representative or [support@defectdojo.com](mailto:support@defectdojo.com).
