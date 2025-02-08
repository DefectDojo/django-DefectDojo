---
title: "Veracode"
toc_hide: true
---

Veracode reports can be ingested in either XML or JSON Format

- Detailed XML Report
- JSON REST Findings from `/appsec/v2/applications/{application_guid}/findings/`
  - Acceptable scan types include `STATIC`, `DYNAMIC`, and `SCA`
  - Findings with a status of `CLOSED` will not be imported into DefectDojo
  - Acceptable formats are as follows:
    - Findings list
      - Requires slight modification of the response returned from the API
      - Exmample of a request being: `url <endpoint> | jq "{findings}"`
      - Desired Format:
        ```json
        {
            "findings": [
                {
                    ...
                },
                ...
            ]
        }
        ```
    - Embedded 
      - This response can be saved directly to a file and uploaded
      - Not as ideal for crafting a refined report consisting of multiple requests
      - Desired Format:
        ```json
        {
            "_embedded": {
                "findings": [
                   {
                        ...
                    },
                    ... 
                ]
            },
            "_links": {
                ...
            },
            "page": {
               ...
            }
        }
        ```

### Sample Scan Data
Sample Veracode scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/veracode).