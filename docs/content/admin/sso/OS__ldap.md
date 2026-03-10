---
title: "LDAP Authentication"
description: "Authenticate users via LDAP by building custom Docker images"
weight: 20
audience: opensource
aliases:
  - /en/open_source/ldap-authentication
---

**This feature is experimental, and is not implemented in DefectDojo Pro**.

DefectDojo does not support LDAP authentication out of the box. However, since DefectDojo is built on Django, LDAP can be added by building your own Docker images and modifying a small number of configuration files.

## Files to Modify

- `Dockerfile.django-*`
- `Dockerfile.nginx-*`
- `requirements.txt`
- `local_settings.py`
- `docker-compose.yml` *(optional — for passing secrets via environment variables)*

## Dockerfile Modifications

In both `Dockerfile.django-alpine` and `Dockerfile.nginx-alpine`, add the following to the `apk add` layer:

```bash
openldap-dev \
cyrus-sasl-dev \
```

In `Dockerfile.django-debian`, add the following to the `apt-get install` layer:

```bash
libldap2-dev \
libsasl2-dev \
ldap-utils \
```

## requirements.txt

Check [pypi.org](https://pypi.org) for the latest versions at the time of implementation, then add:

```
python-ldap==3.4.5
django-auth-ldap==5.2.0
```

- [python-ldap](https://pypi.org/project/python-ldap/)
- [django-auth-ldap](https://pypi.org/project/django-auth-ldap/)

## local_settings.py

Find the settings file (see `/dojo/settings/settings.py` for instructions on using `local_settings.py`) and make the following additions.

At the top of the file:

```python
import ldap
from django_auth_ldap.config import LDAPSearch, GroupOfNamesType
import environ
```

Add LDAP variables to the `env` dict:

```python
# LDAP
env = environ.FileAwareEnv(
    DD_LDAP_SERVER_URI=(str, 'ldap://ldap.example.com'),
    DD_LDAP_BIND_DN=(str, ''),
    DD_LDAP_BIND_PASSWORD=(str, ''),
)
```

Then add the LDAP settings beneath the `env` dict:

```python
AUTH_LDAP_SERVER_URI = env('DD_LDAP_SERVER_URI')
AUTH_LDAP_BIND_DN = env('DD_LDAP_BIND_DN')
AUTH_LDAP_BIND_PASSWORD = env('DD_LDAP_BIND_PASSWORD')

AUTH_LDAP_USER_SEARCH = LDAPSearch(
    "ou=Groups,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=%(user)s)"
)

AUTH_LDAP_USER_ATTR_MAP = {
    "first_name": "givenName",
    "last_name": "sn",
    "email": "mail",
}
```

Customise all search variables to match your organisation's LDAP configuration.

### Optional: Group Controls

```python
AUTH_LDAP_GROUP_SEARCH = LDAPSearch(
    "dc=example,dc=com",
    ldap.SCOPE_SUBTREE,
    "(objectClass=groupOfNames)",
)
AUTH_LDAP_GROUP_TYPE = GroupOfNamesType(name_attr="cn")

AUTH_LDAP_REQUIRE_GROUP = "cn=DD_USER_ACTIVE,ou=Groups,dc=example,dc=com"

AUTH_LDAP_USER_FLAGS_BY_GROUP = {
    "is_active": "cn=DD_USER_ACTIVE,ou=Groups,dc=example,dc=com",
    "is_staff": "cn=DD_USER_STAFF,ou=Groups,dc=example,dc=com",
    "is_superuser": "cn=DD_USER_ADMIN,ou=Groups,dc=example,dc=com",
}
```

Finally, add `django_auth_ldap.backend.LDAPBackend` to `AUTHENTICATION_BACKENDS`:

```python
AUTHENTICATION_BACKENDS = (
    'django_auth_ldap.backend.LDAPBackend',
    'django.contrib.auth.backends.RemoteUserBackend',
    'django.contrib.auth.backends.ModelBackend',
)
```

Full documentation: [Django Authentication with LDAP](https://django-auth-ldap.readthedocs.io/en/latest/)

## docker-compose.yml

To pass LDAP credentials to the container via environment variables, add these to the `uwsgi` service environment section:

```yaml
DD_LDAP_SERVER_URI: "${DD_LDAP_SERVER_URI:-ldap://ldap.example.com}"
DD_LDAP_BIND_DN: "${DD_LDAP_BIND_DN:-}"
DD_LDAP_BIND_PASSWORD: "${DD_LDAP_BIND_PASSWORD:-}"
```

Alternatively, set these values directly in `local_settings.py`.
