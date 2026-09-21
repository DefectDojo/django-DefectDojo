---
title: "Hardware Sizing for Self-Hosted DefectDojo Pro"
description: "General guidance for sizing compute, memory, and storage for a self-hosted DefectDojo Pro deployment"
draft: false
weight: 2
audience: pro
---

Sizing a DefectDojo deployment comes down to two questions. How much data are you holding, and how many people are working in it at once. This page gives starting points for both.

Treat what follows as general guidance rather than a specification. The figures lean deliberately conservative, and they assume a deployment doing everyday triage alongside regular scan imports. Your own numbers will move depending on how you use the Asset, so read the notes under the table before you provision anything.

Specs are given as generic vCPU and memory figures so they apply to any cloud provider or on-premise hardware. The sizing table has a tab for each deployment method: Kubernetes runs the application tier as pods across nodes and scales out, while Docker Compose runs everything on one host and scales up. Whichever you choose, read [Sizing and tuning the application tier](#sizing-and-tuning-the-application-tier) too, where the two differ most.

## Sizing table

{{< tabs "sizing-table" >}}
{{< tab "Kubernetes" >}}
| Findings | Concurrent users | Database | Application nodes |
| --- | --- | --- | --- |
| Up to 100K | Up to ~25 | 2–4 vCPU / 16–32 GB | 2 × (2–4 vCPU / 8–16 GB) |
| 100K–500K | ~25–50 | 4–8 vCPU / 32–64 GB | 2–3 × (4 vCPU / 16 GB) |
| 500K–1M | ~50–100 | 8 vCPU / 64–96 GB | 2–3 × (8 vCPU / 32 GB) |
| 1M–5M | ~100–250 | 8–16 vCPU / 96–128 GB | 5–6 × (8 vCPU / 32 GB) |
| 5M–10M | ~250–500 | 16–32 vCPU / 128–192 GB | 9–10 × (8 vCPU / 32 GB) |
| 500M | 500+ | 192 vCPU / 768 GB+ | 50+ × (8 vCPU / 32 GB) |

Where you land inside a range depends on your workload. Start at the upper end of a range if anything in [What pushes you up a tier](#what-pushes-you-up-a-tier) applies to you.

The 500M row is a reference point at the far end rather than a continuation of the pattern above it, so do not interpolate between it and the 10M tier. A deployment sitting between those two needs to be sized individually. It also assumes work that hardware alone will not do for you, covered in [Very large deployments](#very-large-deployments).
{{< /tab >}}
{{< tab "Compose" >}}
Docker Compose runs everything on one host, so this is the Kubernetes guidance consolidated onto a single machine: the "Application host" figure is the Kubernetes application-tier total run as one instance instead of spread across pods, and the database column is unchanged. Provision the host to match your finding count, then tune the application to use it (see [Sizing and tuning the application tier](#sizing-and-tuning-the-application-tier)).

| Findings | Concurrent users | Application host (CPU / RAM) | Database (CPU / RAM) |
| --- | --- | --- | --- |
| Up to 100K | Up to ~25 | 4–8 vCPU / 16–32 GB | 2–4 vCPU / 16–32 GB |
| 100K–500K | ~25–50 | 8–12 vCPU / 32–48 GB | 4–8 vCPU / 32–64 GB |
| 500K–1M | ~50–100 | 16–24 vCPU / 64–96 GB | 8 vCPU / 64–96 GB |
| 1M–5M | ~100–250 | 40–48 vCPU / 160–192 GB | 8–16 vCPU / 96–128 GB |
| 5M–10M | ~250–500 | 72–80 vCPU / 288–320 GB | 16–32 vCPU / 128–192 GB |

A single host has no redundancy and scales only by getting bigger. The compute at the larger tiers gets impractical to put on one machine, so toward the top of this range Kubernetes is usually the better fit, both for horizontal scale and for surviving the loss of a node. The database figures assume a separate database host, which we recommend for production; if you run the database in a container on the same host (evaluation only, not production data), add its CPU and memory to the host's.
{{< /tab >}}
{{< /tabs >}}

## How to read these numbers

### Database memory matters more than database CPU

DefectDojo runs aggregation-heavy queries across your findings. Those stay fast while the working set and its indexes are served from memory, and they degrade quickly once the database starts reaching for disk. When you have to choose, buy memory before you buy cores. The table reflects that. Memory roughly doubles from tier to tier while CPU counts move much more slowly.

### The application tier tracks users, not findings

The concurrent user figures in the table assume smaller datasets belong to smaller teams. That assumption breaks often. If you hold 200K findings but have 100 people in the UI at once, size the application tier for the users and leave the database where your finding count puts it. The two scale independently.

There is one exception, at the far end of the table. Import and deduplication run on the application tier rather than in the database, so once a data set is large enough for that work to dominate, the application tier follows ingest volume instead of user count. That is why the 500M row sits well above what its user figure on its own would suggest.

### Sizing and tuning the application tier

The "Application nodes" column is the compute the application tier needs. How you provide it, and what you have to do to make the application actually use it, is where the two deployment methods differ.

{{< tabs "sizing-app-tier" >}}
{{< tab "Kubernetes" >}}
The Helm chart runs the application tier as pods and sets the uWSGI and Celery concurrency for you from your values, so on Kubernetes you provide the capacity and let the chart place pods on it. Kubernetes spreads the load whether you give it a few large nodes or more small ones, so the node counts in the table are one workable arrangement rather than a requirement. Two things are worth holding to: keep at least two nodes so losing one doesn't take the application down, and avoid nodes smaller than 2 vCPU / 8 GB so individual pods schedule comfortably.
{{< /tab >}}
{{< tab "Compose" >}}
On a single host there are no pods to schedule or nodes to spread across, so read the "Application nodes" column as one total: add the per-node figures together and provision that much CPU and memory on the one machine. Compute-optimized hardware for that host is worth choosing when your provider offers it. A single host has no redundancy, so treat losing it as downtime and keep a tested backup and a restore plan.

Sizing the host is only half of it. The application does not reach for extra cores on its own: the uWSGI web processes and the Celery workers run at fixed counts until you raise them. After you resize the host, tune these and restart.

Scale with **processes, not threads.** uWSGI threads do not run Python in parallel — the GIL lets only one thread per process execute at a time — so past a handful they mostly consume database connections and add context-switching overhead instead of throughput. Keep threads low and add processes as the lever:

```bash
dojo-compose-cli environment add --key "DD_UWSGI_NUM_OF_THREADS"        --value "4"
dojo-compose-cli environment add --key "DD_UWSGI_NUM_OF_PROCESSES"      --value "<1–1.5× the host's CPU count, then tune>"
dojo-compose-cli environment add --key "DD_CELERY_WORKER_CONCURRENCY"   --value "<app_cpus>"
dojo-compose-cli environment add --key "DD_CELERY_WORKER_AUTOSCALE_MAX" --value "<app_cpus>"

dojo-compose-cli environment print   # confirm the values
dojo-compose-cli app stop
dojo-compose-cli app start
```

What each knob does:

| Knob | Start at | What raising it does |
| --- | --- | --- |
| `DD_UWSGI_NUM_OF_PROCESSES` | 1–1.5× host vCPU | The main throughput lever. More web processes serve more requests at once, until they saturate CPU or outrun the database's connections. |
| `DD_UWSGI_NUM_OF_THREADS` | 4 | Little throughput to gain past a handful, since the GIL serializes them, and each thread still opens its own database connections. Leave it low. |
| `DD_CELERY_WORKER_CONCURRENCY` | host vCPU | Parallel async workers for imports, deduplication, and notifications. Raise it for import-heavy or CI-driven workloads; lower it if background work is starving the web processes of CPU. |
| `DD_CELERY_WORKER_AUTOSCALE_MAX` | host vCPU | The ceiling Celery scales up to under load. Keep it near the core count so bursts don't open more connections than the database can serve. |

These four decide how many database connections the application holds open, so tune them alongside the database's own limits (see [Tuning the database](#tuning-the-database)). The Helm chart derives the same settings from your values, so on Kubernetes you normally leave them to the chart.
{{< /tab >}}
{{< /tabs >}}

## Tuning the database

The database is where finding queries live or die, and PostgreSQL ships with defaults tuned for a small machine. On a dedicated database host you have to raise a handful of settings before it will use the memory you gave it. A 64 GB host left on stock `shared_buffers` performs like a small one. These are the settings that move the needle for DefectDojo's aggregation-heavy reads, in rough order of impact:

| Setting | Starting point | What it controls |
| --- | --- | --- |
| `shared_buffers` | ~25% of the host's RAM | PostgreSQL's own cache of table and index pages. This is the lever behind "buy memory before cores": while the working set and its indexes fit here, finding queries stay fast; once they don't, the database reaches for disk and latency climbs sharply. |
| `effective_cache_size` | ~50–75% of RAM | A planner hint, not an allocation. It tells the planner how much data is likely cached, which steers it toward index scans over full-table scans on your findings. Set too low, the planner picks slow plans on a host that had the memory all along. |
| `work_mem` | 32–128 MB | Memory for one sort or hash step, and DefectDojo sorts and groups findings constantly. It is allocated per operation per connection, so a large value multiplied by hundreds of connections is how you run the host out of memory. Raise it in small steps. |
| `maintenance_work_mem` | 512 MB–2 GB | Memory for index builds, `VACUUM`, and schema migrations. It doesn't affect steady-state queries, but it decides how long an upgrade's migrations and reindexes take. |
| `max_connections` | above the application's total | The ceiling on concurrent connections. It has to clear what the application holds open, with headroom. Too low and requests fail outright under load; far too high and every idle connection still costs memory. |

On a managed database (RDS, Cloud SQL, and the like) these are parameter-group settings rather than lines in `postgresql.conf`, but they are the same knobs. Whichever you run, raise them together with the memory you provision.

### Keep the connection budget balanced

The application tier and the database are tuned against one shared number: how many connections the application holds open. Every uWSGI process and every Celery worker keeps its own, so the total is roughly:

```
(uWSGI processes × uWSGI threads) + Celery worker concurrency
```

On a 12 vCPU host tuned as above that is `18 × 4 + 12 = 84`, and under load it settles near that. Keep the database's `max_connections` comfortably ahead of the number you land on. The failure mode is not the obvious one: too many processes and workers open more connections than the database can serve and end up hammering it, which surfaces as slow queries and 500s under load rather than as more throughput. Raise the application's process and worker counts gradually while watching the connection count and CPU headroom, rather than setting a large multiple of the core count up front.

## Storage

Plan on 20–30 GB of database storage per million findings. Where you fall in that spread depends on how much you hang off each finding. Long descriptions and large endpoint counts push you toward the top of it. The finding rows themselves are a small part of this. Most of the space goes to indexes and to the related tables that hang off each finding, so sizing from row data alone will leave you well short.

Every tier through 10M fits inside a few hundred GB of general-purpose SSD. Storage is cheap next to the cost of running out, so provision for where you expect to be in a year rather than where you are now. If your provider offers storage autoscaling, turn it on.

The 500M row is sized at 2.5 TB. That figure assumes the live data set is actively managed, with older findings archived out of the hot path rather than accumulating indefinitely. Applied naively, the per-million rate above would put an unmanaged 500M deployment several times higher. If you are heading toward this scale, treat the archiving strategy as part of the sizing exercise rather than something to sort out later.

Storage at this scale also needs attention to throughput, not only capacity. Once the working set stops fitting in memory, default baseline IOPS on general-purpose volumes becomes the limit well before capacity does.

Media storage is separate and usually much smaller. It holds uploaded artifacts such as screenshots and risk acceptance documents, so size it from your own upload habits.

## What pushes you up a tier

Finding count is the headline number, but several things will have you sizing up sooner than the count alone suggests.

- **Import volume and frequency.** Large scans arriving often, especially several at the same time, put sustained load on both the database and the async workers. CI pipelines that import on every build are the usual cause.
- **Deduplication.** Deduplication compares incoming findings against what you already hold. The more findings you have and the broader your deduplication configuration, the more work every import does.
- **Reporting and dashboards.** Metrics views and large report generation are read-heavy, and they hit the database harder than day-to-day triage does.
- **API traffic.** Integrations that poll or pull large result sets add concurrent load that never shows up in your interactive user count.
- **Retention.** Deployments that keep everything forever grow into the next tier on schedule. Archiving or deleting old data keeps you where you are for longer.

## Very large deployments

Past the 10M tier, hardware stops being the whole answer. Two things change.

The binding constraint moves from reading to writing. Deduplication compares each incoming finding against what you already hold, so the cost of an import grows with the size of the data set behind it. At the top of the table this is usually what you hit first, ahead of anything users notice in the UI. Whatever import volume built a data set that large is generally still running, so you pay that cost continuously rather than once.

The memory figures assume the hot set stays small. A deployment works recent findings and leaves older ones largely untouched, which is what lets a database hold far more data than it has memory and still perform well. If your access pattern is genuinely spread across the whole data set, you will need more memory than the table lists, and past a point no single instance will have enough.

Both of those point at the same work. Partitioning and archiving cold findings out of the live data set matter more at this scale than another increment of vCPU, and heavy reporting belongs on a read replica rather than on the primary. Plan for that alongside the hardware rather than after it, and talk to us before you provision.

## When in doubt, round up

The figures here already lean conservative, and being one size too large costs far less than being one size too small. Database memory pressure in particular does not degrade gracefully. Performance holds up fine until it doesn't.

Adding application capacity later is straightforward: on Kubernetes you add pods or nodes, and on Docker Compose you resize the host and raise the process and worker counts as above. Resizing a database typically means downtime, so that is the one worth getting right up front.

## Questions or support

These are starting points, not limits. If your deployment sits at the top of the table, or your workload doesn't resemble the assumptions here, talk to us before you provision. Contact your account representative or [support@defectdojo.com](mailto:support@defectdojo.com).
