---
title: "Twistlock"
toc_hide: true
---
JSON output of the `twistcli` tool. Example:

{{< highlight bash >}}
./twistcli images scan <REGISTRY/REPO:TAG> --address https://<SECURE_URL_OF_TWISTLOCK_CONSOLE> --user <USER> --details --output-file=<PATH_TO_SAVE_JSON_FILE>
{{< /highlight >}}

The CSV output from the UI is now also accepted.

### Sample Scan Data
Sample Twistlock scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/twistlock).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component name
- component version
