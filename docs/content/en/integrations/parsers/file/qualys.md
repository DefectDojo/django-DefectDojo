---
title: "Qualys Scan"
toc_hide: true
---
Qualys output files can be imported in API XML format. Qualys output
files can be imported in WebGUI XML format.

A CSV formatted Qualys Scan Report can also be used. Ensure the following values are checked in the Scan Report Template config:

`CVSS Version = CVSSv3`

* Vulnerability Details
  * Threat
  * Impact
* Solution
  * Patches and Workarounds
  * Virtual Patches and Mitigating Controls
* Results

### Sample Scan Data
Sample Qualys Scan scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/qualys).