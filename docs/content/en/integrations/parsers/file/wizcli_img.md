---
title: "Wiz-cli Img Scanner"
toc_hide: true
---
This parser imports scan results from [wizcli](https://www.wiz.io/) IaC scan. You have to export scan results in JSON format so that it will be parsable within DefectDojo.
`wizcli docker scan --image wizcli-imagescan -o scan_img.json,json`

### Sample Scan Data
Sample Wizcli Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/wizcli_img).