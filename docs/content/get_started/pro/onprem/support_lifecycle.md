---
title: "Releases and Support Lifecycle"
description: "How often self-hosted DefectDojo Pro is released, which release is supported, and where to report scan results or a vulnerability in DefectDojo"
draft: false
weight: 14
audience: pro
---

## Release cadence

DefectDojo releases at least once a week: a minor release (`X.Y.0`) once a month, and a patch release (`X.Y.100`, `X.Y.200`, ...) in the other weeks. Every release carries whatever was finished since the last one, so any of them can include dependency and security updates, bug fixes and new features. When something cannot wait for the next scheduled release, DefectDojo publishes an extra one in between. Every release is listed in the [DefectDojo Pro Changelog](/releases/pro/changelog/).

## Which release is supported

DefectDojo fixes forward: a fix, including a security fix, ships in the next release rather than being backported to older ones. For that reason DefectDojo does not publish an end-of-life date per release. The supported posture is to run a current release and to keep upgrading on a regular schedule.

In practice:

- For a new deployment, install the most recent release in the changelog.
- To pick up a fix, upgrade to the release that contains it. You do not need to step through the releases in between; see [Upgrading across several releases](/get_started/pro/onprem/upgrading/#upgrading-across-several-releases).
- If you report a problem on an older release, expect the fix to be an upgrade, because that is where fixes land.

## Reporting scan results for DefectDojo images

If your own scanners report vulnerabilities in a DefectDojo container image, send the report to [support@defectdojo.com](mailto:support@defectdojo.com) with the image, its digest and the scanner output. Each image's SBOMs are available for your own analysis; see [Verifying Images and SBOMs](/get_started/pro/onprem/image_provenance/). DefectDojo does not publish VEX documents.

## Reporting a vulnerability in DefectDojo

To report a security vulnerability in DefectDojo itself, follow the disclosure process in DefectDojo's [security policy](https://github.com/DefectDojo/django-DefectDojo/security/policy): submit it through the [HackerOne disclosure program](https://hackerone.com/defectdojo/reports/new). Please do not open a public GitHub issue for it.

For anything else, see [Contact Support](/help/contact_support/).
