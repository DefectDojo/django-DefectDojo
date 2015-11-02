DefectDojo API Documentation
============================

DefectDojo's API is created using `Tastypie`_.  The documentation of each endpoint is available within each DefectDojo
installation at `/api/v1/doc/` and can be accessed by choosing the API Docs link on the user drop down menu in the
header.

.. image:: /_static/api_1.png

The documentation is generated using `Tastypie Swagger`_, and is interactive.

To interact with the documentation, a valid Authorization header value is needed.  Visit the `/api/key/` view to generate
your API Key and copy the header value provided.

.. image:: /_static/api_3.png

Return to the `/api/v1/doc/` view to paste your key in the form field and click `Explore`.  Your authorization header
value will be captured and used for all requests.

Each section allows you to make calls to the API and view the Request URL, Response Body, Response Code and Response
Headers.

.. image:: /_static/api_2.png

Currently the following endpoints are available:

* Engagements
* Findings
* Products
* Scan Settings
* Scans
* Tests
* Users

.. _Tastypie: https://django-tastypie.readthedocs.org
.. _Tastypie Swagger: http://django-tastypie-swagger.readthedocs.org/

Authentication
--------------

The API uses header authentication with API key.  The format of the header should be: ::

    Authorization: ApiKey <username>:<api_key>

For example: ::

    Authorization: ApiKey jay7958:c8572a5adf107a693aa6c72584da31f4d1f1dcff


Sample Code
-----------

Here is a simple python example against the `/users` endpoint: ::

    import requests

    url = 'http://127.0.0.1:8000/api/v1/users'
    headers = {'content-type': 'application/json',
               'Authorization': 'ApiKey jay7958:c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
    r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

    for key, value in r.__dict__.iteritems():
      print key
      print value
      print '------------------'

This code will return all users defined in DefectDojo.

Here is another example against the `/users` endpoint, this time we will filter the results to include only the users
whose user name includes `jay`: ::

    import requests

    url = 'http://127.0.0.1:8000/api/v1/users/?username__contains=jay'
    headers = {'content-type': 'application/json',
               'Authorization': 'ApiKey jay7958:c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
    r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

    for key, value in r.__dict__.iteritems():
      print key
      print value
      print '------------------'

The json object result is: ::

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
    }

See `Tastypie's documentation on interacting with an API`_ for additional examples and tips.

.. _Tastypie's documentation on interacting with an API: https://django-tastypie.readthedocs.org/en/latest/interacting.html
