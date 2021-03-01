---
title: "Configuration"
date: 2021-02-02T20:46:28+01:00
draft: false
---


For more info on custom settings and use of custom settings during
development, please see: \[settings.py
documentation\](<https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.py>)
and \[extra
settings\](<https://github.com/DefectDojo/django-DefectDojo/blob/master/docker/extra_settings/README.md>)

{{% notice note %}}
To complete
{{% /notice %}}



-   `DD_AUTHORIZED_USERS_ALLOW_CHANGE`: Grants `Active` users (e.g
    regular users) the ability to perform changes for the `Products`
    they are authorized.
-   `DD_AUTHORIZED_USERS_ALLOW_DELETE`: Grants `Active` users (e.g
    regular users) delete powers for the `Products` they are authorized.
-   `DD_SITE_URL`:
-   `DD_DEBUG`:
-   `DD_DJANGO_METRICS_ENABLED`:
-   `DD_LOGIN_REDIRECT_URL`:
-   `DD_DJANGO_ADMIN_ENABLED`:
-   `DD_SESSION_COOKIE_HTTPONLY`:
-   `DD_CSRF_COOKIE_HTTPONLY`:
-   `DD_SECURE_SSL_REDIRECT`:
-   `DD_SECURE_HSTS_INCLUDE_SUBDOMAINS`:
-   `DD_SECURE_HSTS_SECONDS`:
-   `DD_SESSION_COOKIE_SECURE`:
-   `DD_CSRF_COOKIE_SECURE`:
-   `DD_SECURE_BROWSER_XSS_FILTER`:
-   `DD_SECURE_CONTENT_TYPE_NOSNIFF`:
-   `DD_TIME_ZONE`:
-   `DD_LANG`:
-   `DD_WKHTMLTOPDF`:
-   `DD_TEAM_NAME`:
-   `DD_ADMINS`:
-   `DD_PORT_SCAN_CONTACT_EMAIL`:
-   `DD_PORT_SCAN_RESULT_EMAIL_FROM`:
-   `DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST`:
-   `DD_PORT_SCAN_SOURCE_IP`:
-   `DD_WHITENOISE`:
-   `DD_TRACK_MIGRATIONS`:
-   `DD_SECURE_PROXY_SSL_HEADER`:
-   `DD_TEST_RUNNER`:
-   `DD_URL_PREFIX`:
-   `DD_ROOT`:
-   `DD_LANGUAGE_CODE`:
-   `DD_SITE_ID`:
-   `DD_USE_I18N`:
-   `DD_USE_L10N`:
-   `DD_USE_TZ`:
-   `DD_MEDIA_URL`:
-   `DD_MEDIA_ROOT`:
-   `DDimages_URL`:
-   `DDimages_ROOT`:
-   `DD_CELERY_BROKER_URL`:
-   `DD_CELERY_BROKER_SCHEME`:
-   `DD_CELERY_BROKER_USER`:
-   `DD_CELERY_BROKER_PASSWORD`:
-   `DD_CELERY_BROKER_HOST`:
-   `DD_CELERY_BROKER_PORT`:
-   `DD_CELERY_BROKER_PATH`:
-   `DD_CELERY_TASK_IGNORE_RESULT`:
-   `DD_CELERY_RESULT_BACKEND`:
-   `DD_CELERY_RESULT_EXPIRES`:
-   `DD_CELERY_BEAT_SCHEDULE_FILENAME`:
-   `DD_CELERY_TASK_SERIALIZER`:
-   `DD_FORCE_LOWERCASE_TAGS`:
-   `DD_FOOTER_VERSION`: Optionally pass a custom version string
    displayed in the footer of all pages (base.html template). Defaults
    to the version configured in
    [django-DefectDojo/setup.py](https://github.com/DefectDojo/django-DefectDojo/blob/6258a8b73ecbe4c45fdd9929d5165ebed11f9021/setup.py#L7)
-   `DD_MAX_TAG_LENGTH`:
-   `DD_DATABASE_ENGINE`:
-   `DD_DATABASE_HOST`:
-   `DD_DATABASE_NAME`:
-   `DD_TEST_DATABASE_NAME`:
-   `DD_DATABASE_PASSWORD`:
-   `DD_DATABASE_PORT`:
-   `DD_DATABASE_USER`:
-   `DD_SECRET_KEY`:
-   `DD_CREDENTIAL_AES_256_KEY`:
-   `DD_DATA_UPLOAD_MAX_MEMORY_SIZE`:
-   `DD_SOCIAL_AUTH_TRAILING_SLASH`:
-   `DD_SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED`:
-   `DD_SOCIAL_AUTH_AUTH0_KEY`:
-   `DD_SOCIAL_AUTH_AUTH0_SECRET`:
-   `DD_SOCIAL_AUTH_AUTH0_DOMAIN`:
-   `DD_SOCIAL_AUTH_AUTH0_SCOPE`:
-   `DD_SOCIAL_AUTH_GOOGLE_OAUTH2_ENABLED`:
-   `DD_SOCIAL_AUTH_GOOGLE_OAUTH2_KEY`:
-   `DD_SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET`:
-   `DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS`:
-   `DD_SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS`:
-   `DD_SOCIAL_AUTH_OKTA_OAUTH2_ENABLED`:
-   `DD_SOCIAL_AUTH_OKTA_OAUTH2_KEY`:
-   `DD_SOCIAL_AUTH_OKTA_OAUTH2_SECRET`:
-   `DD_SOCIAL_AUTH_OKTA_OAUTH2_API_URL`:
-   `DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_ENABLED`:
-   `DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY`:
-   `DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET`:
-   `DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID`:
-   `DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_RESOURCE`:
-   `DD_SOCIAL_AUTH_GITLAB_OAUTH2_ENABLED`:
-   `DD_SOCIAL_AUTH_GITLAB_KEY`:
-   `DD_SOCIAL_AUTH_GITLAB_SECRET`:
-   `DD_SOCIAL_AUTH_GITLAB_API_URL`:
-   `DD_SOCIAL_AUTH_GITLAB_SCOPE`:
-   `DD_SAML2_ENABLED`:
-   `DD_SAML2_METADATA_AUTO_CONF_URL`:
-   `DD_SAML2_METADATA_LOCAL_FILE_PATH`:
-   `DD_SAML2_ASSERTION_URL`:
-   `DD_SAML2_ENTITY_ID`:
-   `DD_SAML2_DEFAULT_NEXT_URL`:
-   `DD_SAML2_NEW_USER_PROFILE`:
-   `DD_SAML2_ATTRIBUTES_MAP`:
-   `DD_DISABLE_FINDING_MERGE`:
-   `DD_AUTHORIZED_USERS_ALLOW_CHANGE`:
-   `DD_AUTHORIZED_USERS_ALLOW_DELETE`:
-   `DD_AUTHORIZED_USERS_ALLOW_STAFF`:
-   `DD_SLA_NOTIFY_ACTIVE`: Consider \"Active\" findings for SLA
    notifications.
-   `DD_SLA_NOTIFY_ACTIVE_VERIFIED_ONLY`: Consider \"Active\" and
    \"Verified\" findings only for SLA notifications.
-   `DD_SLA_NOTIFY_WITH_JIRA_ONLY`: Considers findings that have a JIRA
    issue linked.
-   `DD_SLA_NOTIFY_PRE_BREACH`: Number of days to notify before
    breaching the SLA.
-   `DD_SLA_NOTIFY_POST_BREACH`: Number of days to keep notifying after
    the SLA has been breached.
-   `DD_EMAIL_URL, default`:
