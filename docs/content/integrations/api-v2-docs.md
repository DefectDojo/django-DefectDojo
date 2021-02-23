---
title: "DefectDojo API v2 Documentation"
date: 2021-02-02T20:46:28+01:00
draft: false
---


DefectDojo\'s API is created using [Django Rest
Framework](http://www.django-rest-framework.org/). The documentation of
each endpoint is available within each DefectDojo installation at
[/api/v2/doc/]{.title-ref} and can be accessed by choosing the API v2
Docs link on the user drop down menu in the header.

![image](../../images/api_v2_1.png)

The documentation is generated using [Django Rest Framework
Swagger](https://marcgibbons.com/django-rest-swagger/), and is
interactive.

To interact with the documentation, a valid Authorization header value
is needed. Visit the [/api/v2/key/]{.title-ref} view to generate your
API Key (Token \<api\_key\>) and copy the header value provided.

![image](../../images/api_v2_2.png)

Return to the [/api/v2/doc/]{.title-ref} and click on
[Authorize]{.title-ref} to open Authorization form. Paste your key in
the form field provided and clic on [Authorize]{.title-ref} button. Your
authorization header value will be captured and used for all requests.

Each section allows you to make calls to the API and view the Request
URL, Response Body, Response Code and Response Headers.

![image](../../images/api_v2_3.png)

Currently the following endpoints are available:

-   Engagements
-   Findings
-   Products
-   Scan Settings
-   Scans
-   Tests
-   Users

Authentication
--------------

The API uses header authentication with API key. The format of the
header should be: :

    Authorization: Token <api.key>

For example: :

    Authorization: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

Sample Code
-----------

Here are some simple python examples and their results produced against
the [/users]{.title-ref} endpoint: :

    import requests

    url = 'http://127.0.0.1:8000/api/v2/users'
    headers = {'content-type': 'application/json',
               'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
    r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

    for key, value in r.__dict__.iteritems():
      print key
      print value
      print '------------------'

This code will return the list of all the users defined in DefectDojo.
The json object result looks like : :

    [
        {
          "first_name": "Tyagi",
          "id": 22,
          "last_login": "2019-06-18T08:05:51.925743",
          "last_name": "Paz",
          "resource_uri": "/api/v1/users/22/",
          "username": "dev7958"
        },
        {
          "first_name": "saurabh",
          "id": 31,
          "last_login": "2019-06-06T11:44:32.533035",
          "last_name": "",
          "resource_uri": "/api/v1/users/31/",
          "username": "saurabh.paz"
        }
    ]

Here is another example against the [/users]{.title-ref} endpoint, this
time we will filter the results to include only the users whose user
name includes \`jay\`: :

    import requests

    url = 'http://127.0.0.1:8000/api/v2/users/?username__contains=jay'
    headers = {'content-type': 'application/json',
               'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
    r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

    for key, value in r.__dict__.iteritems():
      print key
      print value
      print '------------------'

The json object result is: :

    [
        {
          "first_name": "Jay",
          "id": 22,
          "last_login": "2015-10-28T08:05:51.925743",
          "last_name": "Paz",
          "resource_uri": "/api/v1/users/22/",
          "username": "jay7958"
        },
        {
          "first_name": "",
          "id": 31,
          "last_login": "2015-10-13T11:44:32.533035",
          "last_name": "",
          "resource_uri": "/api/v1/users/31/",
          "username": "jay.paz"
        }
    ]

See [Django Rest Framework\'s documentation on interacting with an
API](http://www.django-rest-framework.org/topics/api-clients/) for
additional examples and tips.

Manually calling the API
------------------------

Tools like Postman can be used for testing the API.

Example for importing a scan result:

-   Verb: POST
-   URI: <http://localhost:8080/api/v2/import-scan/>
-   

    Headers tab: add the authentication header

    :   -   Key: Authorization
        -   Value: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

-   

    Body tab

    :   -   select \"form-data\", click \"bulk edit\". Example for a ZAP
            scan:

<!-- -->

    engagement:3
    verified:true
    active:true
    lead:1
    tags:test
    scan_date:2019-04-30
    scan_type:ZAP Scan
    minimum_severity:Info
    skip_duplicates:true
    close_old_findings:false

-   

    Body tab

    :   -   Click \"Key-value\" edit
        -   Add a \"file\" parameter of type \"file\". This will trigger
            multi-part form data for sending the file content
        -   Browse for the file to upload

-   Click send
