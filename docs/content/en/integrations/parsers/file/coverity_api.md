---
title: "Coverity API"
toc_hide: true
---
Export Coverity API view data in JSON format (`/api/viewContents/issues` endpoint).

Currently these columns are mandatory:
 * `displayType` (`Type` in the UI)
 * `displayImpact` (`Impact` in the UI)
 * `status` (`Status` in the UI)
 * `firstDetected` (`First Detected` in the UI)

Other supported attributes: `cwe`, `displayFile`, `occurrenceCount` and `firstDetected`
