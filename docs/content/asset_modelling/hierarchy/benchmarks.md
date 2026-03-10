---
title: "OWASP ASVS Benchmarks"
description: "Benchmark a Product against the OWASP Application Security Verification Standard"
weight: 6
audience: opensource
---

DefectDojo supports benchmarking Products against the [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/), which provides a basis for testing web application technical security controls.

Benchmarks allow you to measure how well a Product meets your organization's defined security requirements, and to publish a score on the Product page for visibility.

## Accessing Benchmarks

Benchmarks are available from the **Product** page. To open the Benchmarks view, select the dropdown menu in the upper-right area of the Product page and choose **OWASP ASVS v.3.1** near the bottom of the menu.

## Benchmark Levels

OWASP ASVS defines three levels of verification coverage:

- **Level 1** – For all software. Covers the most critical security requirements with the lowest cost to verify. This is the default level in DefectDojo.
- **Level 2** – For applications that contain sensitive data. Appropriate for most applications.
- **Level 3** – For the most critical applications, such as those performing high-value transactions or storing sensitive medical, financial, or safety data.

You can switch between levels using the dropdown in the upper-right of the Benchmarks view.

## Benchmark Score

The left side of the Benchmarks view displays the current score for your Product at the selected ASVS level:

- The **desired score** your organization has set as a target
- The **percentage of benchmarks passed** toward achieving that score
- The **total number of enabled benchmarks** for the selected level

Enabling the **Publish** checkbox will display the ASVS score directly on the Product page.

## Managing Benchmark Entries

Individual benchmark entries can be marked as passed or failed as your team works through the ASVS controls. Additional benchmark entries, beyond the default ASVS set, can be added or updated through the **Django admin site**.
