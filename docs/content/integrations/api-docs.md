---
title: "DefectDojo API Documentation"
date: 2021-02-02T20:46:28+01:00
draft: false
---


::: {.warning}
::: {.admonition-title}
Warning
:::

API v1 is deprecated and will be no longer maintained after 12-31-2020.
API v1 will be removed on 06-30-2021. Please move to API v2 and raise
issues for any unsupported operations.
:::

DefectDojo\'s API is created using
[Tastypie](https://django-tastypie.readthedocs.org). The documentation
of each endpoint is available within each DefectDojo installation at
[/api/v1/doc/]{.title-ref} and can be accessed by choosing the API Docs
link on the user drop down menu in the header.

![image](../../images/api_1.png)

The documentation is generated using [Tastypie
Swagger](http://django-tastypie-swagger.readthedocs.org/), and is
interactive.

To interact with the documentation, a valid Authorization header value
is needed. Visit the [/api/key/]{.title-ref} view to generate your API
Key and copy the header value provided.

![image](../../images/api_3.png)

Return to the [/api/v1/doc/]{.title-ref} view to paste your key in the
form field and click [Explore]{.title-ref}. Your authorization header
value will be captured and used for all requests.

Each section allows you to make calls to the API and view the Request
URL, Response Body, Response Code and Response Headers.

![image](../../images/api_2.png)

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

    Authorization: ApiKey <username>:<api_key>

For example: :

    Authorization: ApiKey jay7958:c8572a5adf107a693aa6c72584da31f4d1f1dcff

Sample Code
-----------

Here are some simple python examples and their results produced against
the [/users]{.title-ref} endpoint: :

    import requests

    url = 'http://127.0.0.1:8000/api/v1/users'
    headers = {'content-type': 'application/json',
               'Authorization': 'ApiKey jay7958:c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
    r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

    for key, value in r.__dict__.iteritems():
      print key
      print value
      print '------------------'

This code will display the list of all the users defined in DefectDojo.
The json object result of the above code is: :

    {
      "meta": {
        "limit": 20,
        "next": null,
        "offset": 0,
        "previous": null,
        "total_count": 3
      },
      "objects": [
        {
          "first_name": "Greg",
          "id": 22,
          "last_login": "2018-10-28T08:05:51.925743",
          "last_name": "",
          "resource_uri": "/api/v1/users/22/",
          "username": "greg.dev"
        },

    {
          "first_name": "Andy",
          "id": 29,
          "last_login": "2019-05-28T08:05:51.925743",
          "last_name": "",
          "resource_uri": "/api/v1/users/29/",
          "username": "andy586432"
        },

        {
          "first_name": "Dev",
          "id": 31,
          "last_login": "2018-10-13T11:44:32.533035",
          "last_name": "",
          "resource_uri": "/api/v1/users/31/",
          "username": "dev.paz"
        }
      ]
    }

Here is another example against the [/users]{.title-ref} endpoint,we
apply the condition(username\_\_contains=jay) which will filter and
display the list of the users whose username includes \`jay\`: :

    import requests

    url = 'http://127.0.0.1:8000/api/v1/users/?username__contains=jay'
    headers = {'content-type': 'application/json',
               'Authorization': 'ApiKey jay7958:c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
    r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

    for key, value in r.__dict__.iteritems():
      print key
      print value
      print '------------------'

The json object result of the above code is: :

    {
      "meta": {
        "limit": 20,
        "next": null,
        "offset": 0,
        "previous": null,
        "total_count": 2
      },
      "objects": [
        {
          "first_name": "Jay",
          "id": 22,
          "last_login": "2019-04-22T08:05:51.925743",
          "last_name": "Paz",
          "resource_uri": "/api/v1/users/22/",
          "username": "jay7958"
        },
        {
          "first_name": "",
          "id": 31,
          "last_login": "2019-04-04T11:44:32.533035",
          "last_name": "",
          "resource_uri": "/api/v1/users/31/",
          "username": "jay.paz"
        }
      ]
    }

Here is a simple python POST example for creating a new product\_type: :

    import requests

      url = 'http://127.0.0.1:8000/api/v1/product_types/'
      data = {
          'name':'Spartans Dev Team',
          "critical_product": "true",
          "key_product": "true"
          }
      headers = {'content-type': 'application/json',
                'Authorization': 'ApiKey jay7958:c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
      r = requests.get(url, json = data, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

      print("The response status code :%s"%r.status_code)
      print("The response text is :%s"%r.text)

See [Tastypie\'s documentation on interacting with an
API](https://django-tastypie.readthedocs.org/en/latest/interacting.html)
for additional examples and tips.

See [defectdojo\_api
project](https://github.com/DefectDojo/defectdojo_api), a Python API
wrapper for DefectDojo (a utility to call the API using python)

Manually calling the API
------------------------

Tools like Postman can be used for testing the API.

Example for importing a scan result:

-   Verb: POST
-   URI: <http://localhost:8080/api/v1/importscan/>
-   

    Headers tab: add the authentication header

    :   -   Key: Authorization
        -   Value: ApiKey
            jay7958:c8572a5adf107a693aa6c72584da31f4d1f1dcff

-   

    Body tab

    :   -   select \"form-data\", click \"bulk edit\". Example for a ZAP
            scan:

<!-- -->

    verified:true
    active:true
    lead:/api/v1/users/1/
    tags:test
    scan_date:2019-04-30
    scan_type:ZAP Scan
    minimum_severity:Info
    engagement:/api/v1/engagements/1/

-   

    Body tab

    :   -   Click \"Key-value\" edit
        -   Add a \"file\" parameter of type \"file\". This will trigger
            multi-part form data for sending the file content
        -   Browse for the file to upload

-   Click send
