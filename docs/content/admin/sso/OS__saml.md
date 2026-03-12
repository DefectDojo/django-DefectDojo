---
title: "SAML Configuration"
description: "Configure SAML in Open-Source DefectDojo"
weight: 2
audience: opensource
aliases:
  - /en/working_with_findings/sla_configuration
---

Open-Source DefectDojo supports SAML authentication via environment variables. DefectDojo Pro users should refer to the [Pro SAML guide](/admin/sso/pro__saml/).

## Setup

1. Navigate to your SAML Identity Provider and locate your metadata.

2. Set the following as environment variables, or without the `DD_` prefix in your `local_settings.py` file (see [Configuration](/get_started/open_source/configuration/)):

   {{< highlight python >}}
   DD_SAML2_ENABLED=(bool, True),
   # Login button text shown on the DefectDojo login page
   DD_SAML2_LOGIN_BUTTON_TEXT=(str, 'Login with SAML'),
   # If the metadata is accessible from a URL:
   DD_SAML2_METADATA_AUTO_CONF_URL=(str, 'https://your_IdP.com/metadata.xml'),
   # Otherwise, download the metadata as an XML file and set the path:
   DD_SAML2_METADATA_LOCAL_FILE_PATH=(str, '/path/to/your/metadata.xml'),
   # Map SAML assertion attributes to DefectDojo user fields:
   DD_SAML2_ATTRIBUTES_MAP=(dict, {
       # Format: 'SAML attribute': 'django_user_field'
       'Email': 'email',
       'UserName': 'username',
       'Firstname': 'first_name',
       'Lastname': 'last_name'
   }),
   {{< /highlight >}}

   **Note:** In Kubernetes, `DD_SAML2_ATTRIBUTES_MAP` can be set in `extraConfig` as:
   `DD_SAML2_ATTRIBUTES_MAP: 'Email'='email', 'Username'='username'...`

   **Note:** `DD_SITE_URL` may also need to be set depending on whether you use a metadata URL or a local file.

3. Review the SAML section in `dojo/settings/settings.dist.py` to verify the configuration matches your requirements. See the [djangosaml2 plugin documentation](https://djangosaml2.readthedocs.io/contents/setup.html#configuration) for further options.

4. Restart DefectDojo. A **Login with SAML** button will appear on the login page.

**Note:** If your IdP uses a self-signed certificate, set the `REQUESTS_CA_BUNDLE` environment variable to the path of your private CA certificate.

## Advanced Configuration

The [djangosaml2](https://github.com/IdentityPython/djangosaml2) plugin supports many additional options. All DefectDojo defaults can be overridden in `local_settings.py`. For example, to customize the organization name:

{{< highlight python >}}
if SAML2_ENABLED:
    SAML_CONFIG['contact_person'] = [{
        'given_name': 'Extra',
        'sur_name': 'Example',
        'company': 'DefectDojo',
        'email_address': 'dummy@defectdojo.com',
        'contact_type': 'technical'
    }]
    SAML_CONFIG['organization'] = {
        'name': [('DefectDojo', 'en')],
        'display_name': [('DefectDojo', 'en')],
    },
{{< /highlight >}}

## Troubleshooting

The SAML Tracer browser extension can help debug SAML issues: [Chrome](https://chromewebstore.google.com/detail/saml-tracer/mpdajninpobndbfcldcmbpnnbhibjmch?hl=en), [Firefox](https://addons.mozilla.org/en-US/firefox/addon/saml-tracer/).

## Migrating from django-saml2-auth

Prior to release 1.15.0, SAML was handled by [django-saml2-auth](https://github.com/fangli/django-saml2-auth). The following parameters changed with the switch to djangosaml2:

| Old parameter | Status |
|---|---|
| `DD_SAML2_ASSERTION_URL` | No longer needed — auto-generated |
| `DD_SAML2_DEFAULT_NEXT_URL` | No longer needed — default forwarding is used |
| `DD_SAML2_NEW_USER_PROFILE` | No longer supported — default profile is used |
| `DD_SAML2_ATTRIBUTES_MAP` | Syntax has changed |
| `DD_SAML2_CREATE_USER` | Default changed to `False` to prevent security issues |
