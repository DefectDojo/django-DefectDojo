---
title: "Emerging Threats"
description: "See the new vulnerabilities DefectDojo is building Early Light detectors for, check your Findings against them, and request a detector"
weight: 1
audience: pro
---

A new vulnerability usually reaches advisory databases days after it is disclosed, so scanners that read those databases can't report it yet. DefectDojo builds an [Early Light](https://github.com/DefectDojo/earlylight) detector for the most urgent ones, often within a day of disclosure. **Emerging Threats** shows you that work: which threats DefectDojo is building detectors for, which detectors are ready, how to run them, and what they found in your instance.

## Enabling Emerging Threats

Emerging Threats is a **beta** feature behind the `emerging_threats` feature flag. A superuser can turn it on from **Settings > Feature Flags**. See [Feature Flags](/admin/feature_flags/pro__feature_flags/).

When the flag is on, an **Emerging Threats** entry (marked **NEW**) appears in the **ACT** section of the sidebar, below **Vulnerability Explorer**.

DefectDojo Pro reads the list of threats from a signed feed every 30 minutes. An air-gapped instance reads the same list from the nightly threat intelligence bundle.

## Threat states

Each threat has one state:

| State | Meaning |
| --- | --- |
| **Tracking** | DefectDojo is watching the threat. No detector is planned yet. Only teams that requested the threat see it. |
| **Building** | A detector is in progress. DefectDojo does not publish dates. |
| **Available** | An Early Light release includes the detector. The page shows the version and how to run it. |
| **Covered by Scanners** | Advisory databases already cover the threat, so scanners you already use report it. The reason is shown. |
| **Not Planned** | DefectDojo is not building a detector. The reason is shown. |
| **Received** | Your team's request has not been linked to a threat yet. Only your team sees it. |

## The list

The top of the page shows each **Available** threat and what your instance holds for it:

- **Open findings**: the number of open Findings that match the threat, and on how many Assets.
- **Not Checked**: no Finding has ever matched the threat. That can mean you are not affected, or that nothing here has scanned for it yet.
- **No open findings**: matching Findings existed and none is open now.

Below it, the list shows every threat you can see, with filters for **Building**, **Available**, **Tracking**, threats you follow, and your team's requests. **Teams Asking** appears when three or more teams have asked for a threat.

A Finding matches a threat when one of its vulnerability IDs is one of the threat's IDs (for example a CVE or GHSA ID), or when it came from the threat's Early Light detector. Counts only include Findings you have permission to see.

## A threat's page

Each threat's page shows:

- **What It Is**: a short description, the affected software, advisory links, and the Early Light detector with the first release that includes it.
- **Check Your Environment**: commands for the Early Light command line, its container image and its GitHub Action, scoped to this threat's detector and to the targets it supports (container images, filesystems, source repositories or TLS endpoints). Import the JSON report with the **Early Light Scan** scan type.
- **In This Instance**: open, mitigated and needs-review Findings for the threat, with links to Vulnerability Explorer and the Findings list.
- A timeline of the threat's states.

Early Light checks each binary it finds for evidence of the fix. It reports what it can prove, and marks the rest for review with a reason. It only sees the targets it is pointed at. Findings Early Light could not settle are tagged `needs-review`.

### Fixing with Sensei

When Sensei is licensed and some matching Findings can be fixed automatically, the page offers **Fix with Sensei**. DefectDojo first shows how many Findings it would fix, then opens one pull request per Finding after you confirm. See [Sensei](/sensei/).

## Following a threat

Select **Follow** to be notified when a threat changes state. On a threat that is **Tracking** or **Building**, select **We Need This Too** instead: it tells DefectDojo your team needs the detector and follows the threat.

Two notification events can be set in your notification settings:

- **Emerging threat update**: a threat you follow changes state, or your team's request is linked or closed. In-app and email by default.
- **Emerging threat available**: a new detector is available. Sent to global owners and maintainers, in-app by default, with the number of open Findings in your instance that match it.

## Requesting a detector

Select **Request a Detector** and answer three questions:

1. **What should Early Light detect?** Paste a CVE or GHSA ID or an advisory link, or describe the vulnerability. The form checks the list as you type and points you to the threat when it is already there.
2. **Where does it run for you?** Container images, servers and VMs, source repositories, TLS endpoints, or not sure.
3. **Why now?** Exploited in the wild, a customer or auditor asked, or a precaution.

Your request and your name go to DefectDojo. Only include vulnerabilities that are already public. To report a vulnerability in DefectDojo itself, use the [vulnerability disclosure program](https://hackerone.com/defectdojo/reports/new).

The request appears in your list as **Received** until DefectDojo links it to a threat. From then on it shows that threat's state, and you are notified as it changes.

An air-gapped instance cannot send requests. The form shows the request as text that can be copied into an email to DefectDojo support.

## What leaves your instance

- The list of threats is a public, signed file. Fetching it sends nothing about your instance.
- Matching Findings are counted inside your instance. Finding data never leaves it.
- A request or a **We Need This Too** vote sends the request text and the name and email of the person who sent it to DefectDojo, as a Support request does.
