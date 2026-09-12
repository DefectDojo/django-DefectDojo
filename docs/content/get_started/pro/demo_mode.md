---
title: "🧪 Demo Mode: sample data and the guided tour"
description: "How to load sample data and take the guided tour, and how to remove it again"
draft: "false"
weight: 5
chapter: true
exclude_search: false
audience: pro
---

A brand new DefectDojo instance does not show you very much: empty lists, empty
filters, and metrics pages with nothing to plot. Demo Mode fills it in. With
around 150 findings from a handful of scanners in place, the lists, the filters,
the deduplication and the metrics all behave the way they will once your own
scans are flowing, and a short guided tour walks you through the loop.

Nothing is loaded unless you ask for it. Your instance starts empty, sample data
appears only when an administrator loads it, and it is removable from inside the
product at any time. Removing it does not touch anything you created yourself.

## Loading the sample data

On an instance with nothing in it yet, the home page offers a **Getting Started**
card with two choices:

- **Import Your First Scan** takes you to the import page, which is what most
  people want.
- **Load Sample Data** fills the instance with the sample set described below.

Loading runs in the background and takes a moment, because the sample scans go
through the same importer your own scans do. When it finishes the page refreshes,
a bar appears at the top confirming that sample data is loaded, and you are
offered the tour.

The card only appears on an instance that has no applications and no findings in
it. Once you have data of your own, it goes away and stays away, so sample
findings can never turn up alongside real ones by accident.

{{% alert title="Only administrators can load it" color="info" %}}
Sample data is visible to everyone on the instance, so loading it is offered only
to superusers. The same rule applies to removing it.
{{% /alert %}}

## What gets loaded

The sample data is imported through the same importer your own scans go through,
so it behaves like real data rather than looking like it.

| What | How much |
|------|----------|
| Groups | 2 (Sample: Corporate Applications, Sample: Cloud Platform) |
| Applications | 4 (Storefront Web App, Payments API, Container Platform, Legacy Customer Portal) |
| Engagements | 5, including one interactive penetration test |
| Imports | 8 scan reports across static analysis, dependency scanning, container scanning, dynamic scanning and secret detection |
| Findings | ~150, spread across every severity |

A few of the imports are backdated by 30, 60 and 90 days. That is what gives the
metrics pages a real trend line on the first day, and what puts some findings past
their SLA so the overdue views have something in them.

Some findings are already triaged: a few verified, a few marked false positive, a
few mitigated, and two with a recorded risk acceptance. One scan is imported twice,
so you can see how DefectDojo recognizes a re-reported issue as a duplicate instead
of adding it to the queue a second time.

Everything created this way is tagged **`sample-data`**, so you can filter for it or
filter it out at any point.

## The guided tour

Once sample data is loaded you are offered a short tour, a few minutes, that walks
the loop: where findings come from, how they are triaged, how a risk acceptance is
recorded, and where progress is reported.

You can leave the tour at any point. The bar at the top of the page offers:

- **Resume Tour**, which picks up from where you stopped.
- **Restart Tour**, which starts again from the beginning.

If you have never taken it, that second button reads **Start Tour** instead.

The tour is available to every user on the instance, not just administrators, so it
works for a walkthrough with several people signed in.

## Removing the sample data

Two places offer this, and both do the same thing:

- The last step of the tour.
- **Remove Sample Data** in the bar at the top of the page.

You will be shown exactly what is about to be deleted before anything happens.
Removal runs in the background; the bar shows progress and disappears once the data
is gone.

Removing the sample data deletes the sample groups, applications, engagements, tests
and findings, along with the notes and risk acceptances created with them. It does
not touch anything you added, including anything you added underneath a sample
application. Objects are matched by an internal record of what the seeding created,
never by their name or their tag, so renaming or re-tagging a sample object does not
change what gets removed, and tagging one of your own objects `sample-data` does not
put it at risk.

Removal is permanent, and it also turns Demo Mode off: the bar and the tour go with
the data they were about. If your instance is still empty afterwards, the
**Getting Started** card comes back, so you can load the sample data again with one
click.

## From the command line

Everything above is also available to an administrator with shell access, which is
useful for scripting a demo environment:

```bash
manage.py seed_demo_data
manage.py purge_demo_data
```

These are the same operations the buttons run, including turning Demo Mode on and
off, so an instance seeded from the command line offers the tour exactly as one
seeded from the button does.

`seed_demo_data` will not run twice by accident: if sample data is already present
it reports that and exits without creating a second copy.

The `demo_mode` feature flag controls the tour, the welcome dialog and the bar. It
creates and deletes nothing on its own, so you can turn it off while keeping the
sample data if you would rather keep the data without the tour:

```bash
manage.py set_feature demo_mode False
```

## Notes

- **Deduplication.** The duplicate pair in the sample data is only flagged if
  deduplication is enabled on your instance. Seeding will not turn it on for you,
  because that would change how your own imports behave. If it is off, the tour
  simply skips that step.
- **Findings count.** The sample findings count toward your instance's licensed
  finding total while they are present, and removing them gives that headroom back.
- **Notifications.** Seeding does not send notifications, so loading the sample
  data will not fill your alerts or email anyone.
