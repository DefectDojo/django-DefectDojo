---
title: "API Pull"
description: "Report pulled to DefectDojo via API exposed by scanning service"
weight: 4
chapter: true
sidebar:
  collapsed: true
exclude_search: true
---
All parsers that use API pull have common basic configuration steps, but with different values.

Follow these steps to set up API importing:

## Tool Configuration

1.  Configure the API authentication details by navigating to
    `Configuration -> Tool Configuration -> Add Tool Configuration`. Enter a `Name`,
    selecting the related `Tool Type` and `Authentication Type` "API Key". Paste your credentials
    into the proper fields based on the selected parser.

## Product-Level Configuration

1.  Navigate to `Products -> All Products` and select a product from the list.

2.  Click on `Settings` and select `Add API Scan Configuration`

3.  Select the previously added `Tool Configuration` and provide additional values based on the selected parser.

4.  After this is done, you can import the findings on the `Product` page through
    `Findings -> Import Scan Results`. As the `Scan type`, select the related type
    (the `API Scan Configuration` created above) and click `Import`.
