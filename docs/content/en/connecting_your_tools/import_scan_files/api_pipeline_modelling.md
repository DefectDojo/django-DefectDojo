---
title: "Create an automated import pipeline via API"
description: ""
---

DefectDojo’s API allows for robust pipeline solutions, which automatically ingest new scans to your instance. Automation like this can take a few different forms:

* A daily import which scans your environment on a daily basis, and then imports the results of the scan to DefectDojo (similar to our **Connectors** feature)
* A CI/CD pipeline which scans new code as it is deployed, and imports the results to DefectDojo as a triggered action

These pipelines can be created by directly calling our API **/reimport** endpoint with an attached scan file in a way that closely resembles our **Import Scan Form**. 

#### Universal Importer: out of the box automation

DefectDojo Inc. maintains a **Universal Importer** which can be set up with existing CI/CD pipelines, triggered via GitHub actions, or run in any other automated context.

This external tool is a useful way to build a pipeline directly from the command line: a much faster solution than writing your own code.

See our guide to [external tools](../../external_tools) to learn more.  External tools are available for **DefectDojo Pro** users only.

## DefectDojo’s API

DefectDojo’s API is documented in\-app using the OpenAPI framework. You can access this documentation from the User Menu in the top right\-hand corner, under **‘API v2 OpenAPI3’**.

\- The documentation can be used to test API calls with various parameters, and does so using your own user’s API Token.

If you need to access an API token for a script or another integration, you can find that information under the **API v2 Token** option from the same menu.

![image](images/api_pipeline_modelling.png)

### General API Considerations

* Although our OpenAPI documentation is detailed regarding the parameters that can be used with each endpoint, it assumes that the reader has a solid understanding of DefectDojo’s key concepts. (Product Hierarchy, Findings, Deduplication, etc).
* Users who want a working import integration but are less familiar with DefectDojo as a whole should consider our **Universal Importer**.
* DefectDojo’s API can sometimes create unintended data objects, particularly if ‘Auto\-Create Context’ is used on the **/import** or **/reimport** endpoint.
* Fortunately, it is very difficult to accidentally delete data using the API. Most objects can only be removed using a dedicated **DELETE** call to the relevant endpoint.

### Specific notes on /import and /reimport endpoints

The **/reimport** endpoint can be used for both an initial Import, or a “Reimport” which extends a Test with additional Findings. You do not need to first create a Test with **/import** before you can use the **/reimport** endpoint. As long as ‘Auto Create Context’ is enabled, the /reimport endpoint can create a new Test, Engagement, Product or Product Type. In almost all cases, you can use the **/reimport** endpoint exclusively when adding data via API.

However, the **/import** endpoint can instead be used for a pipeline where you always want to store each scan result in a discrete Test object, rather than using **/reimport** to handle the diff within a single Test object. Either option is acceptable, and the endpoint you choose depends on your reporting structure, or whether you need to inspect an isolated run of a Pipeline.

### Using the Scan Completion Date (API: `scan_date`) field

DefectDojo offers a plethora of supported scanner reports, but not reports them contain the information most important to a user. The `scan_date` field is a flexible smart feature that allows users to set the completion date of the a given scan report, and have it propagate down to all the findings imported.

This field is **not** mandatory, but the default value for this field is the date of import (whenever the request is processed and a successful response is returned).

Here are the following use cases for this field, and the results applied to the Test:

1. If the report **does not** set the date, and `scan_date` is **not** set at import
    - Finding date will be the default value of `scan_date`
2. If the report **sets** the date, and the `scan_date` is **not** set at import
    - Finding date will be whatever the report sets
3. If the report **does not** set the date, and the `scan_date` is **set** at import
    - Finding date will be whatever the user set for `scan_date`
4. If the report **sets** the date, and the `scan_date` is **set** at import
    - Finding date will be whatever the user set for `scan_date`
