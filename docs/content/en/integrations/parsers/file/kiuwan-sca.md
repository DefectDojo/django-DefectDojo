---
title: "Kiuwan Scanner (SCA i.e. \"Insights\")"
toc_hide: true
---
Import Kiuwan Insights Scan in JSON format. Export via API endpoint as json and create a file for importing to DefectDojo.

Data will be feched from the [Kiuwan REST API](https://static.kiuwan.com/rest-api/kiuwan-rest-api.html) like this:

```
import requests, json
headers = {'Authorization': 'Basic $KIUWAN_TOKEN', 'Accept' : 'application/json'}

appName = "Test"
analysisCode = "A-111-1111111111"

URL = "https://api.kiuwan.com/insights/analysis/security?analysisCode=" + analysisCode + "&application=" + appName
r = requests.get(url = URL, headers = headers)
res = r.json()
data = res["data"] # save this data to a json file and upload to defect dojo
print(json.dumps(data, indent=2))
```

### Sample Scan Data
Sample Kiuwan Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kiuwan-sca).
