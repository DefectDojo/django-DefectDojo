---
title: "Wiz-cli IaC Scanner"
toc_hide: true
---
This parser imports scan results from [wizcli](https://www.wiz.io/) IaC scan. You have to export scan results in JSON format so that it will be parsable within DefectDojo.
`wizcli iac scan --path ./ -o scan_iac.json,json`

### Sample Scan Data
Sample Wizcli Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/wizcli_iac).