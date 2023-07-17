---
title: "API Pull"
description: "Report pulled to DefectDojo via API exposed by scanning service"
weight: 2
chapter: true
---
All parsers which using API have common basic configuration step but with different values.

Follow these steps to setup API importing:

1.  Configure the API authentication details by navigating to
    `Configuration -> Tool Configuration -> Add Tool Configuration`. Enter a `Name`,
    selecting related `Tool Type` and `Authentication Type` "API Key". Paste your credentials to field
    and other fields based on definitions below.

2.  In the `Product` settings select `Add API Scan Configuration` and select the
    previously added `Tool Configuration`. Proved values based on definitions below

3.  After this is done, you can import the findings on the `Product` page through
    `Findings -> Import Scan Results`. As the `Scan type`, select the related type,
    the API scan configuration from the last step, and click `Import`.
