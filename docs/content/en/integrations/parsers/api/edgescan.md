---
title: "Edgescan"
toc_hide: true
---
Import Edgescan vulnerabilities by API or [JSON file](../../file/edgescan.md)

All parsers which using API have common basic configuration step but with different values. Please, [read these steps](../) at first.

In `Tool Configuration`, select `Tool Type` to "Edgescan" and `Authentication Type` "API Key".
Paste your Edgescan API key in the `API Key` field.

In `Add API Scan Configuration` and select the
previously added Edgescan `Tool Configuration`. Provide the edgescan asset ID(s)
that you wish to import the findings for in the field `Service key 1`. 
*Multiple asset IDs should be comma separated with no spacing.*

After this is done, you can import the findings by selecting
"Edgescan Scan" as the scan type. If you have more than one asset
configured, you must also select which Edgescan API Scan Configuration to
use.
