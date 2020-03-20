# Django settings for DefectDojo
import os
from datetime import timedelta

import environ
root = environ.Path(__file__) - 3  # Three folders back

env = environ.Env(
    # Set casting and default values
    DD_DEBUG=(bool, False),
    DD_DJANGO_METRICS_ENABLED=(bool, False),
    DD_LOGIN_REDIRECT_URL=(str, '/'),
    DD_DJANGO_ADMIN_ENABLED=(bool, False),
    DD_SESSION_COOKIE_HTTPONLY=(bool, True),
    DD_CSRF_COOKIE_HTTPONLY=(bool, True),
    DD_SECURE_SSL_REDIRECT=(bool, False),
    DD_SECURE_HSTS_INCLUDE_SUBDOMAINS=(bool, False),
    DD_SECURE_HSTS_SECONDS=(int, 31536000),  # One year expiration
    DD_SESSION_COOKIE_SECURE=(bool, False),
    DD_CSRF_COOKIE_SECURE=(bool, False),
    DD_SECURE_BROWSER_XSS_FILTER=(bool, True),
    DD_SECURE_CONTENT_TYPE_NOSNIFF=(bool, True),
    DD_TIME_ZONE=(str, 'UTC'),
    DD_LANG=(str, 'en-us'),
    DD_WKHTMLTOPDF=(str, '/usr/local/bin/wkhtmltopdf'),
    DD_TEAM_NAME=(str, 'Security Team'),
    DD_ADMINS=(str, 'DefectDojo:dojo@localhost,Admin:admin@localhost'),
    DD_PORT_SCAN_CONTACT_EMAIL=(str, 'email@localhost'),
    DD_PORT_SCAN_RESULT_EMAIL_FROM=(str, 'email@localhost'),
    DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST=(str, ['email@localhost']),
    DD_PORT_SCAN_SOURCE_IP=(str, '127.0.0.1'),
    DD_WHITENOISE=(bool, False),
    DD_TRACK_MIGRATIONS=(bool, False),
    DD_SECURE_PROXY_SSL_HEADER=(bool, False),
    DD_TEST_RUNNER=(str, 'django.test.runner.DiscoverRunner'),
    DD_URL_PREFIX=(str, ''),
    DD_ROOT=(str, root('dojo')),
    DD_LANGUAGE_CODE=(str, 'en-us'),
    DD_SITE_ID=(int, 1),
    DD_USE_I18N=(bool, True),
    DD_USE_L10N=(bool, True),
    DD_USE_TZ=(bool, True),
    DD_MEDIA_URL=(str, '/media/'),
    DD_MEDIA_ROOT=(str, root('media')),
    DD_STATIC_URL=(str, '/static/'),
    DD_STATIC_ROOT=(str, root('static')),
    DD_CELERY_BROKER_URL=(str, ''),
    DD_CELERY_BROKER_SCHEME=(str, 'sqla+sqlite'),
    DD_CELERY_BROKER_USER=(str, ''),
    DD_CELERY_BROKER_PASSWORD=(str, ''),
    DD_CELERY_BROKER_HOST=(str, ''),
    DD_CELERY_BROKER_PORT=(int, -1),
    DD_CELERY_BROKER_PATH=(str, '/dojo.celerydb.sqlite'),
    DD_CELERY_TASK_IGNORE_RESULT=(bool, True),
    DD_CELERY_RESULT_BACKEND=(str, 'django-db'),
    DD_CELERY_RESULT_EXPIRES=(int, 86400),
    DD_CELERY_BEAT_SCHEDULE_FILENAME=(str, root('dojo.celery.beat.db')),
    DD_CELERY_TASK_SERIALIZER=(str, 'pickle'),
    DD_FORCE_LOWERCASE_TAGS=(bool, True),
    DD_MAX_TAG_LENGTH=(int, 25),
    DD_DATABASE_ENGINE=(str, 'django.db.backends.mysql'),
    DD_DATABASE_HOST=(str, 'mysql'),
    DD_DATABASE_NAME=(str, 'defectdojo'),
    # default django database name for testing is test_<dbname>
    DD_TEST_DATABASE_NAME=(str, 'test_defectdojo'),
    DD_DATABASE_PASSWORD=(str, 'defectdojo'),
    DD_DATABASE_PORT=(int, 3306),
    DD_DATABASE_USER=(str, 'defectdojo'),
    DD_SECRET_KEY=(str, '.'),
    DD_CREDENTIAL_AES_256_KEY=(str, '.'),
    DD_DATA_UPLOAD_MAX_MEMORY_SIZE=(int, 8388608),  # Max post size set to 8mb
    DD_SOCIAL_AUTH_TRAILING_SLASH=(bool, False),
    DD_SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED=(bool, False),
    DD_SOCIAL_AUTH_AUTH0_KEY=(str, ''),
    DD_SOCIAL_AUTH_AUTH0_SECRET=(str, ''),
    DD_SOCIAL_AUTH_AUTH0_DOMAIN=(str, ''),
    DD_SOCIAL_AUTH_AUTH0_SCOPE=(list, ['openid', 'profile', 'email']),
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_ENABLED=(bool, False),
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_KEY=(str, ''),
    DD_SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET=(str, ''),
    DD_SOCIAL_AUTH_OKTA_OAUTH2_ENABLED=(bool, False),
    DD_SOCIAL_AUTH_OKTA_OAUTH2_KEY=(str, ''),
    DD_SOCIAL_AUTH_OKTA_OAUTH2_SECRET=(str, ''),
    DD_SOCIAL_AUTH_OKTA_OAUTH2_API_URL=(str, 'https://{your-org-url}/oauth2/default'),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_ENABLED=(bool, False),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY=(str, ''),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET=(str, ''),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID=(str, ''),
    DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_RESOURCE=(str, 'https://graph.microsoft.com/'),
    DD_SOCIAL_AUTH_GITLAB_OAUTH2_ENABLED=(bool, False),
    DD_SOCIAL_AUTH_GITLAB_KEY=(str, ''),
    DD_SOCIAL_AUTH_GITLAB_SECRET=(str, ''),
    DD_SOCIAL_AUTH_GITLAB_API_URL=(str, 'https://gitlab.com'),
    DD_SOCIAL_AUTH_GITLAB_SCOPE=(list, ['api', 'read_user', 'openid', 'profile', 'email']),
)


def generate_url(scheme, double_slashes, user, password, host, port, path):
    result_list = []
    result_list.append(scheme)
    result_list.append(':')
    if double_slashes:
        result_list.append('//')
    result_list.append(user)
    if len(password) > 0:
        result_list.append(':')
        result_list.append(password)
    if len(user) > 0 or len(password) > 0:
        result_list.append('@')
    result_list.append(host)
    if port >= 0:
        result_list.append(':')
        result_list.append(str(port))
    if len(path) > 0 and path[0] != '/':
        result_list.append('/')
    result_list.append(path)
    return ''.join(result_list)


# Read .env file as default or from the command line, DD_ENV_PATH
if os.path.isfile(root('dojo/settings/.env.prod')) or 'DD_ENV_PATH' in os.environ:
    env.read_env(root('dojo/settings/' + env.str('DD_ENV_PATH', '.env.prod')))

# ------------------------------------------------------------------------------
# GENERAL
# ------------------------------------------------------------------------------

# False if not in os.environ
DEBUG = env('DD_DEBUG')

# Hosts/domain names that are valid for this site; required if DEBUG is False
# See https://docs.djangoproject.com/en/2.0/ref/settings/#allowed-hosts
ALLOWED_HOSTS = tuple(env.list('DD_ALLOWED_HOSTS', default=['localhost', '127.0.0.1']))

# Raises django's ImproperlyConfigured exception if SECRET_KEY not in os.environ
SECRET_KEY = env('DD_SECRET_KEY')

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = env('DD_TIME_ZONE')

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = env('DD_LANGUAGE_CODE')

SITE_ID = env('DD_SITE_ID')

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = env('DD_USE_I18N')

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = env('DD_USE_L10N')

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = env('DD_USE_TZ')

TEST_RUNNER = env('DD_TEST_RUNNER')

# ------------------------------------------------------------------------------
# DATABASE
# ------------------------------------------------------------------------------

# Parse database connection url strings like psql://user:pass@127.0.0.1:8458/db
if os.getenv('DD_DATABASE_URL') is not None:
    DATABASES = {
        'default': env.db('DD_DATABASE_URL')
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': env('DD_DATABASE_ENGINE'),
            'NAME': env('DD_DATABASE_NAME'),
            'TEST': {
                'NAME': env('DD_TEST_DATABASE_NAME'),
            },
            'USER': env('DD_DATABASE_USER'),
            'PASSWORD': env('DD_DATABASE_PASSWORD'),
            'HOST': env('DD_DATABASE_HOST'),
            'PORT': env('DD_DATABASE_PORT'),
        }
    }

# Track migrations through source control rather than making migrations locally
if env('DD_TRACK_MIGRATIONS'):
    MIGRATION_MODULES = {'dojo': 'dojo.db_migrations'}

# ------------------------------------------------------------------------------
# MEDIA
# ------------------------------------------------------------------------------

DOJO_ROOT = env('DD_ROOT')

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/var/www/example.com/media/"
MEDIA_ROOT = env('DD_MEDIA_ROOT')

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://example.com/media/", "http://media.example.com/"
MEDIA_URL = env('DD_MEDIA_URL')

# ------------------------------------------------------------------------------
# STATIC
# ------------------------------------------------------------------------------

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/var/www/example.com/static/"
STATIC_ROOT = env('DD_STATIC_ROOT')

# URL prefix for static files.
# Example: "http://example.com/static/", "http://static.example.com/"
STATIC_URL = env('DD_STATIC_URL')

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    os.path.join(os.path.dirname(DOJO_ROOT), 'components', 'node_modules'),
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
)

FILE_UPLOAD_HANDLERS = (
    "django.core.files.uploadhandler.TemporaryFileUploadHandler",
)

DATA_UPLOAD_MAX_MEMORY_SIZE = env('DD_DATA_UPLOAD_MAX_MEMORY_SIZE')

# ------------------------------------------------------------------------------
# URLS
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#root-urlconf

# AUTHENTICATION_BACKENDS = [
# 'axes.backends.AxesModelBackend',
# ]

ROOT_URLCONF = 'dojo.urls'

# Python dotted path to the WSGI application used by Django's runserver.
# https://docs.djangoproject.com/en/dev/ref/settings/#wsgi-application
WSGI_APPLICATION = 'dojo.wsgi.application'

URL_PREFIX = env('DD_URL_PREFIX')

# ------------------------------------------------------------------------------
# AUTHENTICATION
# ------------------------------------------------------------------------------

LOGIN_REDIRECT_URL = env('DD_LOGIN_REDIRECT_URL')
LOGIN_URL = '/login'

# These are the individidual modules supported by social-auth
AUTHENTICATION_BACKENDS = (
    'social_core.backends.auth0.Auth0OAuth2',
    'social_core.backends.google.GoogleOAuth2',
    'dojo.okta.OktaOAuth2',
    'social_core.backends.azuread_tenant.AzureADTenantOAuth2',
    'social_core.backends.gitlab.GitLabOAuth2',
    'django.contrib.auth.backends.RemoteUserBackend',
    'django.contrib.auth.backends.ModelBackend',
)

SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'dojo.pipeline.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'social_core.pipeline.social_auth.associate_by_email',
    'social_core.pipeline.user.create_user',
    'dojo.pipeline.modify_permissions',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
)

CLASSIC_AUTH_ENABLED = True

SOCIAL_AUTH_STRATEGY = 'social_django.strategy.DjangoStrategy'
SOCIAL_AUTH_STORAGE = 'social_django.models.DjangoStorage'
SOCIAL_AUTH_ADMIN_USER_SEARCH_FIELDS = ['username', 'first_name', 'last_name', 'email']
SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL = True

GOOGLE_OAUTH_ENABLED = env('DD_SOCIAL_AUTH_GOOGLE_OAUTH2_ENABLED')
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = env('DD_SOCIAL_AUTH_GOOGLE_OAUTH2_KEY')
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = env('DD_SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET')
SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_DOMAINS = ['']
SOCIAL_AUTH_GOOGLE_OAUTH2_WHITELISTED_EMAILS = ['']
SOCIAL_AUTH_LOGIN_ERROR_URL = '/login'
SOCIAL_AUTH_BACKEND_ERROR_URL = '/login'

OKTA_OAUTH_ENABLED = env('DD_SOCIAL_AUTH_OKTA_OAUTH2_ENABLED')
SOCIAL_AUTH_OKTA_OAUTH2_KEY = env('DD_SOCIAL_AUTH_OKTA_OAUTH2_KEY')
SOCIAL_AUTH_OKTA_OAUTH2_SECRET = env('DD_SOCIAL_AUTH_OKTA_OAUTH2_SECRET')
SOCIAL_AUTH_OKTA_OAUTH2_API_URL = env('DD_SOCIAL_AUTH_OKTA_OAUTH2_API_URL')

AZUREAD_TENANT_OAUTH2_ENABLED = env('DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_ENABLED')
SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY = env('DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_KEY')
SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET = env('DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_SECRET')
SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID = env('DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_TENANT_ID')
SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_RESOURCE = env('DD_SOCIAL_AUTH_AZUREAD_TENANT_OAUTH2_RESOURCE')

GITLAB_OAUTH2_ENABLED = env('DD_SOCIAL_AUTH_GITLAB_OAUTH2_ENABLED')
SOCIAL_AUTH_GITLAB_KEY = env('DD_SOCIAL_AUTH_GITLAB_KEY')
SOCIAL_AUTH_GITLAB_SECRET = env('DD_SOCIAL_AUTH_GITLAB_SECRET')
SOCIAL_AUTH_GITLAB_API_URL = env('DD_SOCIAL_AUTH_GITLAB_API_URL')
SOCIAL_AUTH_GITLAB_SCOPE = env('DD_SOCIAL_AUTH_GITLAB_SCOPE')

AUTH0_OAUTH2_ENABLED = env('DD_SOCIAL_AUTH_AUTH0_OAUTH2_ENABLED')
SOCIAL_AUTH_AUTH0_KEY = env('DD_SOCIAL_AUTH_AUTH0_KEY')
SOCIAL_AUTH_AUTH0_SECRET = env('DD_SOCIAL_AUTH_AUTH0_SECRET')
SOCIAL_AUTH_AUTH0_DOMAIN = env('DD_SOCIAL_AUTH_AUTH0_DOMAIN')
SOCIAL_AUTH_AUTH0_SCOPE = env('DD_SOCIAL_AUTH_AUTH0_SCOPE')
SOCIAL_AUTH_TRAILING_SLASH = env('DD_SOCIAL_AUTH_TRAILING_SLASH')

LOGIN_EXEMPT_URLS = (
    r'^%sstatic/' % URL_PREFIX,
    r'^%swebhook/' % URL_PREFIX,
    r'^%sapi/v1/' % URL_PREFIX,
    r'^%sreports/cover$' % URL_PREFIX,
    r'^%sfinding/image/(?P<token>[^/]+)$' % URL_PREFIX,
    r'^%sapi/v2/' % URL_PREFIX,
    r'complete/auth0-oauth2/',
    r'complete/google-oauth2/',
    r'complete/okta-oauth2/',
    r'complete/gitlab-oauth2/',
    r'empty_survey/([\d]+)/answer'
    r'complete/azuread-tenant-oauth2/',
)

# ------------------------------------------------------------------------------
# SECURITY DIRECTIVES
# ------------------------------------------------------------------------------

# If True, the SecurityMiddleware redirects all non-HTTPS requests to HTTPS
# (except for those URLs matching a regular expression listed in SECURE_REDIRECT_EXEMPT).
SECURE_SSL_REDIRECT = env('DD_SECURE_SSL_REDIRECT')

# If True, the SecurityMiddleware sets the X-XSS-Protection: 1;
# mode=block header on all responses that do not already have it.
SECURE_BROWSER_XSS_FILTER = env('DD_SECURE_BROWSER_XSS_FILTER')

# If True, the SecurityMiddleware sets the X-Content-Type-Options: nosniff;
SECURE_CONTENT_TYPE_NOSNIFF = env('DD_SECURE_CONTENT_TYPE_NOSNIFF')

# Whether to use HTTPOnly flag on the session cookie.
# If this is set to True, client-side JavaScript will not to be able to access the session cookie.
SESSION_COOKIE_HTTPONLY = env('DD_SESSION_COOKIE_HTTPONLY')

# Whether to use HttpOnly flag on the CSRF cookie. If this is set to True,
# client-side JavaScript will not to be able to access the CSRF cookie.
CSRF_COOKIE_HTTPONLY = env('DD_CSRF_COOKIE_HTTPONLY')

# Whether to use a secure cookie for the session cookie. If this is set to True,
# the cookie will be marked as secure, which means browsers may ensure that the
# cookie is only sent with an HTTPS connection.
SESSION_COOKIE_SECURE = env('DD_SESSION_COOKIE_SECURE')

# Whether to use a secure cookie for the CSRF cookie.
CSRF_COOKIE_SECURE = env('DD_CSRF_COOKIE_SECURE')

if env('DD_SECURE_PROXY_SSL_HEADER'):
    SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

if env('DD_SECURE_HSTS_INCLUDE_SUBDOMAINS'):
    SECURE_HSTS_SECONDS = env('DD_SECURE_HSTS_SECONDS')
    SECURE_HSTS_INCLUDE_SUBDOMAINS = env('DD_SECURE_HSTS_INCLUDE_SUBDOMAINS')

# ------------------------------------------------------------------------------
# DEFECTDOJO SPECIFIC
# ------------------------------------------------------------------------------

# Credential Key
CREDENTIAL_AES_256_KEY = env('DD_CREDENTIAL_AES_256_KEY')
DB_KEY = env('DD_CREDENTIAL_AES_256_KEY')

# wkhtmltopdf settings
WKHTMLTOPDF_PATH = env('DD_WKHTMLTOPDF')

PORT_SCAN_CONTACT_EMAIL = env('DD_PORT_SCAN_CONTACT_EMAIL')
PORT_SCAN_RESULT_EMAIL_FROM = env('DD_PORT_SCAN_RESULT_EMAIL_FROM')
PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST = env('DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST')
PORT_SCAN_SOURCE_IP = env('DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST')

# Used in a few places to prefix page headings and in email salutations
TEAM_NAME = env('DD_TEAM_NAME')

# Django-tagging settings
FORCE_LOWERCASE_TAGS = env('DD_FORCE_LOWERCASE_TAGS')
MAX_TAG_LENGTH = env('DD_MAX_TAG_LENGTH')


# ------------------------------------------------------------------------------
# ADMIN
# ------------------------------------------------------------------------------
from email.utils import getaddresses
ADMINS = getaddresses([env('DD_ADMINS')])

# https://docs.djangoproject.com/en/dev/ref/settings/#managers
MANAGERS = ADMINS

# Django admin enabled
DJANGO_ADMIN_ENABLED = env('DD_DJANGO_ADMIN_ENABLED')

# ------------------------------------------------------------------------------
# API V2
# ------------------------------------------------------------------------------

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.TokenAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.DjangoModelPermissions',
    ),
    'DEFAULT_RENDERER_CLASSES': (
        'rest_framework.renderers.JSONRenderer',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.LimitOffsetPagination',
    'PAGE_SIZE': 25
}

SWAGGER_SETTINGS = {
    'SECURITY_DEFINITIONS': {
        'api_key': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization'
        }
    },
}

# ------------------------------------------------------------------------------
# TEMPLATES
# ------------------------------------------------------------------------------

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'OPTIONS': {
            'debug': env('DD_DEBUG'),
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'social_django.context_processors.backends',
                'social_django.context_processors.login_redirect',
                'dojo.context_processors.globalize_oauth_vars',
                'dojo.context_processors.bind_system_settings',
                'dojo.context_processors.bind_alert_count',
            ],
        },
    },
]

# ------------------------------------------------------------------------------
# APPS
# ------------------------------------------------------------------------------

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'polymorphic',  # provides admin templates
    'overextends',
    'django.contrib.admin',
    'django.contrib.humanize',
    'gunicorn',
    'tastypie',
    'auditlog',
    'defectDojo_engagement_survey',
    'dojo',
    'tastypie_swagger',
    'watson',
    'tagging',
    'custom_field',
    'imagekit',
    'multiselectfield',
    'rest_framework',
    'rest_framework.authtoken',
    'rest_framework_swagger',
    'dbbackup',
    'taggit_serializer',
    # 'axes'
    'django_celery_results',
    'social_django',
    'drf_yasg',
)

# ------------------------------------------------------------------------------
# MIDDLEWARE
# ------------------------------------------------------------------------------
DJANGO_MIDDLEWARE_CLASSES = [
    # 'debug_toolbar.middleware.DebugToolbarMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'dojo.middleware.LoginRequiredMiddleware',
    'dojo.middleware.TimezoneMiddleware',
    'social_django.middleware.SocialAuthExceptionMiddleware',
    'watson.middleware.SearchContextMiddleware',
    'auditlog.middleware.AuditlogMiddleware',
]

MIDDLEWARE = DJANGO_MIDDLEWARE_CLASSES

# WhiteNoise allows your web app to serve its own static files,
# making it a self-contained unit that can be deployed anywhere without relying on nginx
if env('DD_WHITENOISE'):
    WHITE_NOISE = [
        # Simplified static file serving.
        # https://warehouse.python.org/project/whitenoise/
        'whitenoise.middleware.WhiteNoiseMiddleware',
    ]
    MIDDLEWARE = MIDDLEWARE + WHITE_NOISE

EMAIL_CONFIG = env.email_url(
    'DD_EMAIL_URL', default='smtp://user@:password@localhost:25')

vars().update(EMAIL_CONFIG)

# ------------------------------------------------------------------------------
# CELERY
# ------------------------------------------------------------------------------

# Celery settings
CELERY_BROKER_URL = env('DD_CELERY_BROKER_URL') \
    if len(env('DD_CELERY_BROKER_URL')) > 0 else generate_url(
    env('DD_CELERY_BROKER_SCHEME'),
    True,
    env('DD_CELERY_BROKER_USER'),
    env('DD_CELERY_BROKER_PASSWORD'),
    env('DD_CELERY_BROKER_HOST'),
    env('DD_CELERY_BROKER_PORT'),
    env('DD_CELERY_BROKER_PATH'),
)
CELERY_TASK_IGNORE_RESULT = env('DD_CELERY_TASK_IGNORE_RESULT')
CELERY_RESULT_BACKEND = env('DD_CELERY_RESULT_BACKEND')
CELERY_TIMEZONE = TIME_ZONE
CELERY_RESULT_EXPIRES = env('DD_CELERY_RESULT_EXPIRES')
CELERY_BEAT_SCHEDULE_FILENAME = env('DD_CELERY_BEAT_SCHEDULE_FILENAME')
CELERY_ACCEPT_CONTENT = ['pickle', 'json', 'msgpack', 'yaml']
CELERY_TASK_SERIALIZER = env('DD_CELERY_TASK_SERIALIZER')

# Celery beat scheduled tasks
CELERY_BEAT_SCHEDULE = {
    'add-alerts': {
        'task': 'dojo.tasks.add_alerts',
        'schedule': timedelta(hours=1),
        'args': [timedelta(hours=1)]
    },
    'dedupe-delete': {
        'task': 'dojo.tasks.async_dupe_delete',
        'schedule': timedelta(minutes=1),
        'args': [timedelta(minutes=1)]
    },
    'update-findings-from-source-issues': {
        'task': 'dojo.tasks.async_update_findings_from_source_issues',
        'schedule': timedelta(hours=3),
    }
}


# ------------------------------------
# Monitoring Metrics
# ------------------------------------
# address issue when running ./manage.py collectstatic
# reference: https://github.com/korfuri/django-prometheus/issues/34
PROMETHEUS_EXPORT_MIGRATIONS = False
# django metrics for monitoring
if env('DD_DJANGO_METRICS_ENABLED'):
    DJANGO_METRICS_ENABLED = env('DD_DJANGO_METRICS_ENABLED')
    INSTALLED_APPS = INSTALLED_APPS + ('django_prometheus',)
    MIDDLEWARE = ['django_prometheus.middleware.PrometheusBeforeMiddleware', ] + \
        MIDDLEWARE + \
        ['django_prometheus.middleware.PrometheusAfterMiddleware', ]
    database_engine = DATABASES.get('default').get('ENGINE')
    DATABASES['default']['ENGINE'] = database_engine.replace('django.', 'django_prometheus.', 1)
    # CELERY_RESULT_BACKEND.replace('django.core','django_prometheus.', 1)
    LOGIN_EXEMPT_URLS += (r'^%sdjango_metrics/' % URL_PREFIX,)


# ------------------------------------
# Hashcode configuration
# ------------------------------------
# List of fields used to compute the hash_code
# The fields must be one of HASHCODE_ALLOWED_FIELDS
# If not present, default is the legacy behavior: see models.py, compute_hash_code_legacy function
# legacy is:
#   static scanner:  ['title', 'cwe', 'line', 'file_path', 'description']
#   dynamic scanner: ['title', 'cwe', 'line', 'file_path', 'description', 'endpoints']
HASHCODE_FIELDS_PER_SCANNER = {
    # In checkmarx, same CWE may appear with different severities: example "sql injection" (high) and "blind sql injection" (low).
    # Including the severity in the hash_code keeps those findings not duplicate
    'Checkmarx Scan': ['cwe', 'severity', 'file_path'],
    'SonarQube Scan': ['cwe', 'severity', 'file_path'],
    'Dependency Check Scan': ['cve', 'file_path'],
    # possible improvment: in the scanner put the library name into file_path, then dedup on cwe + file_path + severity
    'NPM Audit Scan': ['title', 'severity', 'file_path', 'cve', 'cwe'],
    # possible improvment: in the scanner put the library name into file_path, then dedup on cve + file_path + severity
    'Whitesource Scan': ['title', 'severity', 'description'],
    'ZAP Scan': ['cwe', 'endpoints', 'severity'],
    'Qualys Scan': ['title', 'endpoints', 'severity'],
    'PHP Symfony Security Check': ['title', 'cve'],
    # for backwards compatibility because someone decided to rename this scanner:
    'Symfony Security Check': ['title', 'cve'],
    'DSOP Scan': ['cve'],
}

# This tells if we should accept cwe=0 when computing hash_code with a configurable list of fields from HASHCODE_FIELDS_PER_SCANNER (this setting doesn't apply to legacy algorithm)
# If False and cwe = 0, then the hash_code computation will fallback to legacy algorithm for the concerned finding
# Default is True (if scanner is not configured here but is configured in HASHCODE_FIELDS_PER_SCANNER, it allows null cwe)
HASHCODE_ALLOWS_NULL_CWE = {
    'Checkmarx Scan': False,
    'SonarQube Scan': False,
    'Dependency Check Scan': True,
    'NPM Audit Scan': True,
    'Whitesource Scan': True,
    'ZAP Scan': False,
    'Qualys Scan': True,
    'DSOP Scan': True,
}

# List of fields that are known to be usable in hash_code computation)
# 'endpoints' is a pseudo field that uses the endpoints (for dynamic scanners)
# 'unique_id_from_tool' is often not needed here as it can be used directly in the dedupe algorithm, but it's also possible to use it for hashing
HASHCODE_ALLOWED_FIELDS = ['title', 'cwe', 'cve', 'line', 'file_path', 'component_name', 'component_version', 'description', 'endpoints', 'unique_id_from_tool', 'severity']

# ------------------------------------
# Deduplication configuration
# ------------------------------------
# List of algorithms
# legacy one with multiple conditions (default mode)
DEDUPE_ALGO_LEGACY = 'legacy'
# based on dojo_finding.unique_id_from_tool only (for checkmarx detailed, or sonarQube detailed for example)
DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL = 'unique_id_from_tool'
# based on dojo_finding.hash_code only
DEDUPE_ALGO_HASH_CODE = 'hash_code'
# unique_id_from_tool or hash_code
# Makes it possible to deduplicate on a technical id (same parser) and also on some functional fields (cross-parsers deduplication)
DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE = 'unique_id_from_tool_or_hash_code'

# Choice of deduplication algorithm per parser
# Key = the scan_type from factory.py (= the test_type)
# Default is DEDUPE_ALGO_LEGACY
DEDUPLICATION_ALGORITHM_PER_PARSER = {
    'Checkmarx Scan detailed': DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    'Checkmarx Scan': DEDUPE_ALGO_HASH_CODE,
    'SonarQube Scan detailed': DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL,
    'SonarQube Scan': DEDUPE_ALGO_HASH_CODE,
    'Dependency Check Scan': DEDUPE_ALGO_HASH_CODE,
    'NPM Audit Scan': DEDUPE_ALGO_HASH_CODE,
    'Whitesource Scan': DEDUPE_ALGO_HASH_CODE,
    'ZAP Scan': DEDUPE_ALGO_HASH_CODE,
    'Qualys Scan': DEDUPE_ALGO_HASH_CODE,
    'PHP Symfony Security Check': DEDUPE_ALGO_HASH_CODE,
    # for backwards compatibility because someone decided to rename this scanner:
    'Symfony Security Check': DEDUPE_ALGO_HASH_CODE,
    'DSOP Scan': DEDUPE_ALGO_HASH_CODE,
}

# ------------------------------------------------------------------------------
# JIRA
# ------------------------------------------------------------------------------
# The 'Bug' issue type is mandatory, as it is used as the default choice.
JIRA_ISSUE_TYPE_CHOICES_CONFIG = (
    ('Task', 'Task'),
    ('Story', 'Story'),
    ('Epic', 'Epic'),
    ('Spike', 'Spike'),
    ('Bug', 'Bug'),
    ('Security', 'Security')
)


# ------------------------------------------------------------------------------
# LOGGING
# ------------------------------------------------------------------------------
# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[%(asctime)s] %(levelname)s '
                      '[%(name)s:%(lineno)d] %(message)s',
            'datefmt': '%d/%b/%Y %H:%M:%S',
        },
        'simple': {
            'format': '%(levelname)s %(funcName)s %(lineno)d %(message)s'
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        },
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue'
        },
    },
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler'
        },
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },
        'dojo': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
        'dojo.specific-loggers.deduplication': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        }
    }
}

# As we require `innodb_large_prefix = ON` for MySQL, we can silence the
# warning about large varchar with unique indices.
SILENCED_SYSTEM_CHECKS = ['mysql.E001']

# Issue on benchmark : "The number of GET/POST parameters exceeded settings.DATA_UPLOAD_MAX_NUMBER_FIELD S"
DATA_UPLOAD_MAX_NUMBER_FIELDS = 10240
