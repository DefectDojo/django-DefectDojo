---
title: Kiuwan Scanner (SCA i.e. "Insights")
toc_hide: true
---
Import Kiuwan Insights Scan in JSON format. Export via API endpoint `insights/analysis/security` as json and create a file for importing to DefectDojo.

### Example Code

Data can be fetched from the [Kiuwan REST API](https://static.kiuwan.com/rest-api/kiuwan-rest-api.html) like this:

```
import requests, json
headers = {'Authorization': 'Basic $KIUWAN_TOKEN', 'Accept' : 'application/json'}

appName = "Test"
analysisCode = "A-111-1111111111"

URL = "https://api.kiuwan.com/insights/analysis/security?analysisCode=" + analysisCode + "&application=" + appName
response = requests.get(url = URL, headers = headers)
jsonResponse = r.json()
data = jsonResponse["data"]
saveFile("result.json", json.dumps(data, indent=2))
```

### Sample Scan Data
Sample Kiuwan Scanner scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/kiuwan_sca).
