---
title: "Creating an automated import pipeline via API"
description: ""
---

DefectDojo’s API allows for robust pipeline solutions, which automatically ingest new scans to your instance. Automation like this can take a few different forms:


* A daily import which scans your environment on a daily basis, and then imports the results of the scan to DefectDojo (similar to our **Connectors** feature)
* A CI/CD pipeline which scans new code as it is deployed, and imports the results to DefectDojo as a triggered action

These pipelines can be created by directly calling our API **/reimport** endpoint with an attached scan file in a way that closely resembles our **Import Scan Form**. 




# Universal Importer \- out of the box CI/CD tool


DefectDojo maintains a **Universal Importer** which can be set up with existing CI/CD pipelines, triggered via GitHub actions, or run in any other automated context. The **Universal Importer** runs in a separate container, and will call your DefectDojo instance’s API in the appropriate way.



The Universal Importer is a useful way to leverage the API without needing to create and maintain the necessary API calls in your own pipeline. This is generally a faster solution than writing your own code.



If you have an active DefectDojo subscription and want to request a copy of the Universal Importer, please contact us at **[support@defectdojo.com](mailto:support@defectdojo.com)** along with the operating system you want to use to run the tool.




# Working with DefectDojo’s API


DefectDojo’s API is documented in\-app using the OpenAPI framework. You can access this documentation from the User Menu in the top right\-hand corner, under **‘API v2 OpenAPI3’**.



\- The documentation can be used to test API calls with various parameters, and does so using your own user’s API Token.



If you need to access an API token for a script or another integration, you can find that information under the **API v2 Token** option from the same menu.




![](https://downloads.intercomcdn.com/i/o/1194909638/703454b50036cf2ca1a81f32/AD_4nXfIr4WW26929_IyD_QPSwgKNOuCOGjAmWDgSG8xspkV9wTnaSoAAZfDALaryqiB2oveX28Q6vjDKHvwmb0ifQeLHgBu0wiBj_3koRlREsgeVlqoaCXQsF0aKrEFRvW9nHbAcN7j3sZ5CYBf8PAlyIVdUUrv?expires=1729720800&signature=e40de8269826823a00522ded678a3c30dc87de5a6e19eeea8fc3af90cad39c9b&req=dSEuEsB%2BlIdcUfMW1HO4zeLU2UHEgkjAHhhk9dUYCHZLgsIxMijLHi39L0MB%0AIeeQ%0A)
## General API Considerations


* Although our OpenAPI documentation is detailed regarding the parameters that can be used with each endpoint, it assumes that the reader has a solid understanding of DefectDojo’s key concepts. (Product Hierarchy, Findings, Deduplication, etc).
* Users who want a working import integration but are less familiar with DefectDojo as a whole should consider our **Universal Importer**.
* DefectDojo’s API can sometimes create unintended data objects, particularly if ‘Auto\-Create Context’ is used on the **/import** or **/reimport** endpoint.
* Fortunately, it is very difficult to accidentally delete data using the API. Most objects can only be removed using a dedicated **DELETE** call to the relevant endpoint.


## Specific notes on /import and /reimport endpoints


The **/reimport** endpoint can be used for both an initial Import, or a “Reimport” which extends a Test with additional Findings. You do not need to first create a Test with **/import** before you can use the **/reimport** endpoint. As long as ‘Auto Create Context’ is enabled, the /reimport endpoint can create a new Test, Engagement, Product or Product Type. In almost all cases, you can use the **/reimport** endpoint exclusively when adding data via API.



However, the **/import** endpoint can instead be used for a pipeline where you always want to store each scan result in a discrete Test object, rather than using **/reimport** to handle the diff within a single Test object. Either option is acceptable, and the endpoint you choose depends on your reporting structure, or whether you need to inspect an isolated run of a Pipeline.

