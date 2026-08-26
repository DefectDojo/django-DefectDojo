---
title: "🧪 Demo Mode: sample data and the guided tour"
description: "How trial and demo instances come preloaded with sample data, and how to remove it"
draft: "false"
weight: 5
chapter: true
exclude_search: false
audience: pro
---

Trial instances of DefectDojo Pro start with sample data already loaded and a short
guided tour of the core workflow. The idea is simple: an empty instance does not
show you very much. With around 130 findings from a handful of scanners already in
place, the lists, the filters, the deduplication and the metrics all behave the way
they will once your own scans are flowing.

Everything the sample data creates is removable from inside the product, at any
time, and removing it does not touch anything you created yourself.

## What gets loaded

The sample data is imported through the same importer your own scans go through, so
it behaves like real data rather than looking like it.

| What | How much |
|------|----------|
| Groups | 2 (Sample: Corporate Applications, Sample: Cloud Platform) |
| Applications | 4 (Storefront Web App, Payments API, Container Platform, Legacy Customer Portal) |
| Engagements | 5, including one interactive penetration test |
| Imports | 8 scan reports across static analysis, dependency scanning, container scanning, dynamic scanning and secret detection |
| Findings | ~130, spread across every severity |

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

On first sign-in you are offered a short tour, about three minutes, that walks the
loop: where findings come from, how they are triaged, how a risk acceptance is
recorded, and where progress is reported.

You can leave the tour at any point. A bar at the top of the page shows that sample
data is loaded and offers **Resume tour**, which picks up from where you stopped.

The tour is available to every user on the instance, not just administrators, so it
works for a walkthrough with several people signed in.

## Removing the sample data

Two places offer this, and both do the same thing:

- The last step of the tour.
- **Remove sample data** in the bar at the top of the page.

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

Removal is permanent. If you want the sample data back afterwards, an administrator
can recreate it with the command below.

{{% alert title="Only administrators can remove it" color="info" %}}
Everyone sees the tour and the bar, but **Remove sample data** is only offered to
superusers.
{{% /alert %}}

## Self-hosted instances

Demo Mode is off by default on a fresh self-hosted install: a new instance boots
clean. To turn it on:

```bash
manage.py set_feature demo_mode True
manage.py seed_demo_data
```

And to remove it again:

```bash
manage.py purge_demo_data
manage.py set_feature demo_mode False
```

The two halves are deliberately independent. The feature flag controls the tour and
the bar and creates nothing; seeding creates data and changes no setting. That means
you can turn the tour off while keeping the sample data, or clear the sample data
while leaving the flag on, without one surprising the other.

`seed_demo_data` will not run twice by accident: if sample data is already present
it reports that and exits without creating a second copy.

## Notes

- **Deduplication.** The duplicate pair in the sample data is only flagged if
  deduplication is enabled on your instance. Seeding will not turn it on for you,
  because that would change how your own imports behave. If it is off, the tour
  simply skips that step.
- **Findings count.** The sample findings count toward your instance's licensed
  finding total while they are present, and removing them gives that headroom back.
- **Notifications.** Seeding does not send notifications, so importing the sample
  data will not fill your alerts or email anyone.
