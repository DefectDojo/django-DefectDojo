---
title: "Custom Trust"
toc_hide: true
weight: 2
---

In some cases, you may want to connect to a tool that uses a certificate from a certification authority (CA) that is not
in the default trust store (e.g. a company-internal CA), which requires that you add custom trust to an existing trust
store or replace the existing trust store with your own.

## Using a Custom-Built DefectDojo Image

When you are building your own container image for `django-DefectDojo`, you can simply add the certificates you would
like to include as custom trust to the `docker/certs` path (see
[Dockerfile.django](https://github.com/DefectDojo/django-DefectDojo/blob/861b617bfcb17cb5e858f46e31509134d0e98171/Dockerfile.django#L70))

## Using the Prebuilt DefectDojo Image

1. Create a new mounted volume where the new trust store will be added (ensures persistence).
2. Create a new trust store
    1. Prepare a new PEM-encoded trust store file (`custom-cacerts.pem`).
    2. Optional, if you want to keep existing trust: Add the custom trust to the existing trust store
        1. Find the location of the existing trust store by running `python -m certifi` in the container
        2. Append your custom trust to the existing trust store by running
           `cat cacert.pem custom-cacerts.pem > extended-cacerts.pem`.  
           ***Important: The consequence of copying the existing trust store is that you will not receive any updates
           (added or removed CA certificates).***
3. Copy the new trust store (`custom-cacerts.pem` or `extended-cacerts.pem`) to the mounted volume.
4. Point the environment variable `REQUESTS_CA_BUNDLE` to the new trust store file.

> `REQUESTS_CA_BUNDLE` is an environment variable from the Python `requests` package. By default, it uses the trust
> store provided by the `certifi` package. For more details, check the respective documentation
> ([requests](https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification) or
> [certifi](https://certifiio.readthedocs.io/en/latest/))