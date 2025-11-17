---
title: "Vulners"
toc_hide: true
---
All parsers which using API have common basic configuration step but with different values. Please, [read these steps](../) at first.

Import Vulners [Audit](https://vulners.com/docs/API_wrapper/linux_audit/#linux-audit) results, no file required.

In `Tool Configuration`, select `Tool Type` to "Vulners" and add the API Key

In the `Product` settings select `Add API Scan Configuration` and select the previously added Vulners `API Tool Configuration`.

After this is done, you can import the findings by selecting "Vulners" as the scan type.

Detailed installation steps can be found in [vulners documentation](https://vulners.com/docs/plugins/defectdojo/).

Use following [instructions](https://vulners.com/docs/apikey/) to generate Vulners API Key.

More details about DefectDojo-plugin integration can be found at [vulners integrations page](https://vulners.com/plugins).
