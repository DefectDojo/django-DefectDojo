---
title: "Aqua"
toc_hide: true
---

### File Types
DefectDojo parser accepts JSON report format.

See Aqua documention: https://docs.aquasec.com

### CI/CD Scans
Aqua scanning can be integrated with several types of third-party CI/CD systems. 

If there is no plugin available for a particular development tool, Aqua can be integrated with the CI/CD pipeline using Scanner CLI.

CI/CD scans produces JSON scan reports that are supported by the parser. With this kind of report, the parser is able to retrieve vulnerabilities as well as sensitive datas.

### REST API

You can also retrieve the JSON directly from Aqua if you use one of the following endpoint:

-	`/api/v1/scanner/registry/<registryName>/image/<imageName>/scan_result`

-	`/api/v2/risks/vulnerabilities`

Example
```
curl -X GET <aquaseceurl>/api/v1/scanner/registry/<registryName>/image/<imageName>/scan_result > report.json
```

```
curl -X GET <aquaseceurl>/api/v2/risks/vulnerabilities?show_negligible=true&image_name_exact_match=true&registry_name=<registryName>&image_name=<imageName> > report.json
```

Those JSON files will only list vulnerabilities. Thus, DefectDojo parser will not retrieve findings such as sensitive datas.

### Sample Scan Data
Sample Aqua scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/aqua).
