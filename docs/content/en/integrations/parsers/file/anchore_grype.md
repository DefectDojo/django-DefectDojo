---
title: "Anchore Grype"
toc_hide: true
---
Anchore Grype JSON report format generated with `-o json` option.

{{< highlight bash >}}
grype defectdojo/defectdojo-django:1.13.1 -o json > many_vulns.json
{{< /highlight >}}