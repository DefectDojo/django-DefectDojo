---
title: "Xeol Parser"
toc_hide: true
---
Import JSON reports of Xeolscans.

### Parser
You can find the parser [here](https://github.com/xeol-io/xeol).

### Severity
The severity of a EOL detected findings is as follows:
- Critical: The component is already 8 weeks end of life
- High: The component is already 6 weeks end of life
- Medium: The component is already 4 weeks end of life
- Low: The component is already 2 weeks end of life
- Info: The component is not yet end of life, but was included in the Xeol report

### Sample Scan Data
Sample kube-bench Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/xeol).