# Django settings for DefectDojo
import os
from datetime import timedelta

import environ
root = environ.Path(__file__) - 3  # Three folders back

env = environ.Env(
    # Set casting and default values
    DD_DEBUG=(bool, False),
    DD_DJANGO_ADMIN_ENABLED=(bool, False),
    DD_SESSION_COOKIE_HTTPONLY=(bool, True),
    DD_CSRF_COOKIE_HTTPONLY=(bool, True),
    DD_SECURE_SSL_REDIRECT=(bool, False),
    DD_CSRF_COOKIE_SECURE=(bool, False),
    DD_SECURE_BROWSER_XSS_FILTER=(bool, False),
    DD_TIME_ZONE=(str, 'UTC'),
    DD_LANG=(str, 'en-us'),
    DD_WKHTMLTOPDF=(str, '/usr/local/bin/wkhtmltopdf'),
    DD_TEAM_NAME=(str, 'Security'),
    DD_ADMINS=(str, 'Aaron:aaron@localhost,Greg:greg@localhost'),
    DD_PORT_SCAN_CONTACT_EMAIL=(str, 'email@localhost'),
    DD_PORT_SCAN_RESULT_EMAIL_FROM=(str, 'email@localhost'),
    DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST=(str, ['email@localhost']),
    DD_PORT_SCAN_SOURCE_IP=(str, '127.0.0.1'),
    DD_WHITENOISE=(bool, False),
    DD_TRACK_MIGRATIONS=(bool, False),
)

# Read .env file as default or from the command line, DD_ENV_PATH
env.read_env(root('dojo/settings/' + env.str('DD_ENV_PATH', '.env.prod')))

# ------------------------------------------------------------------------------
# GENERAL
# ------------------------------------------------------------------------------

# False if not in os.environ
DEBUG = env('DD_DEBUG')

# Hosts/domain names that are valid for this site; required if DEBUG is False
# See https://docs.djangoproject.com/en/1.5/ref/settings/#allowed-hosts
ALLOWED_HOSTS = tuple(env.list('DD_ALLOWED_HOSTS', default=[]))

# Raises django's ImproperlyConfigured exception if SECRET_KEY not in os.environ
SECRET_KEY = env('DD_SECRET_KEY')

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = env('DD_TIME_ZONE')

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
# LANGUAGE_CODE = env('DD_LANG')

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = True

TEST_RUNNER = 'django.test.runner.DiscoverRunner'

# ------------------------------------------------------------------------------
# DATABASE
# ------------------------------------------------------------------------------

# Parse database connection url strings like psql://user:pass@127.0.0.1:8458/db
DATABASES = {
    'default': env.db('DD_DATABASE_URL')
}

# Track migrations through source control rather than making migrations locally
if env('DD_TRACK_MIGRATIONS'):
    MIGRATION_MODULES = {'dojo': 'dojo.db_migrations'}

# ------------------------------------------------------------------------------
# MEDIA
# ------------------------------------------------------------------------------

DOJO_ROOT = root('dojo/')

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/var/www/example.com/media/"
MEDIA_ROOT = root('media')

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://example.com/media/", "http://media.example.com/"
MEDIA_URL = '/media/'

# ------------------------------------------------------------------------------
# STATIC
# ------------------------------------------------------------------------------

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/var/www/example.com/static/"
STATIC_ROOT = root('static')

# URL prefix for static files.
# Example: "http://example.com/static/", "http://static.example.com/"
STATIC_URL = '/static/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    os.path.join(os.path.dirname(DOJO_ROOT), 'components', 'node_modules',
                 '@yarn_components'),
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

# ------------------------------------------------------------------------------
# URLS
# ------------------------------------------------------------------------------

# AUTHENTICATION_BACKENDS = [
# 'axes.backends.AxesModelBackend',
# ]

ROOT_URLCONF = 'dojo.urls'

# Python dotted path to the WSGI application used by Django's runserver.
# https://docs.djangoproject.com/en/dev/ref/settings/#wsgi-application
WSGI_APPLICATION = 'dojo.wsgi.application'

URL_PREFIX = ''

# ------------------------------------------------------------------------------
# AUTHENTICATION
# ------------------------------------------------------------------------------

LOGIN_REDIRECT_URL = '/'

LOGIN_URL = '/login'
LOGIN_EXEMPT_URLS = (
    r'^%sstatic/' % URL_PREFIX,
    r'^%swebhook/' % URL_PREFIX,
    r'^%sapi/v1/' % URL_PREFIX,
    r'^%sajax/v1/' % URL_PREFIX,
    r'^%sreports/cover$' % URL_PREFIX,
    r'^%sfinding/image/(?P<token>[^/]+)$' % URL_PREFIX,
    r'^%sapi/v2/' % URL_PREFIX,
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

# Whether to use HTTPOnly flag on the session cookie.
# If this is set to True, client-side JavaScript will not to be able to access the session cookie.
SESSION_COOKIE_HTTPONLY = env('DD_SESSION_COOKIE_HTTPONLY')

# Whether to use HttpOnly flag on the CSRF cookie. If this is set to True,
# client-side JavaScript will not to be able to access the CSRF cookie.
CSRF_COOKIE_HTTPONLY = env('DD_CSRF_COOKIE_HTTPONLY')

# Whether to use a secure cookie for the CSRF cookie. If this is set to True,
# the cookie will be marked as secure, which means browsers may ensure that the
# cookie is only sent with an HTTPS connection.
CSRF_COOKIE_SECURE = env('DD_CSRF_COOKIE_SECURE')

# SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

# ------------------------------------------------------------------------------
# DEFECTDOJO SPECIFIC
# ------------------------------------------------------------------------------

# Credential Key
CREDENTIAL_AES_256_KEY = env('DD_CREDENTIAL_AES_256_KEY')

# wkhtmltopdf settings
WKHTMLTOPDF_PATH = env('DD_WKHTMLTOPDF')

PORT_SCAN_CONTACT_EMAIL = env('DD_PORT_SCAN_CONTACT_EMAIL')
PORT_SCAN_RESULT_EMAIL_FROM = env('DD_PORT_SCAN_RESULT_EMAIL_FROM')
PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST = env('DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST')
PORT_SCAN_SOURCE_IP = env('DD_PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST')

# Used in a few places to prefix page headings and in email salutations
TEAM_NAME = env('DD_TEAM_NAME')

# Django-tagging settings
FORCE_LOWERCASE_TAGS = True
MAX_TAG_LENGTH = 25


# ------------------------------------------------------------------------------
# ADMIN
# ------------------------------------------------------------------------------

ADMINS = [x.split(':') for x in env.list('DD_ADMINS')]

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
    'dojo.middleware.TimezoneMiddleware'
]

MIDDLEWARE_CLASSES = DJANGO_MIDDLEWARE_CLASSES

# WhiteNoise allows your web app to serve its own static files,
# making it a self-contained unit that can be deployed anywhere without relying on nginx
if env('DD_WHITENOISE'):
    WHITE_NOISE = [
        # Simplified static file serving.
        # https://warehouse.python.org/project/whitenoise/
        'whitenoise.middleware.WhiteNoiseMiddleware',
    ]
    MIDDLEWARE_CLASSES = MIDDLEWARE_CLASSES + WHITE_NOISE

EMAIL_CONFIG = env.email_url(
    'DD_EMAIL_URL', default='smtp://user@:password@localhost:25')

vars().update(EMAIL_CONFIG)

# ------------------------------------------------------------------------------
# CELERY
# ------------------------------------------------------------------------------

# Celery settings
CELERY_BROKER_URL = 'sqla+sqlite:///dojo.celerydb.sqlite'
CELERY_TASK_IGNORE_RESULT = True
CELERY_RESULT_BACKEND = 'db+sqlite:///dojo.celeryresults.sqlite'
CELERY_TIMEZONE = TIME_ZONE
CELERY_RESULT_EXPIRES = 86400
CELERY_BEAT_SCHEDULE_FILENAME = DOJO_ROOT + '/dojo.celery.beat.db'
CELERY_ACCEPT_CONTENT = ['pickle', 'json', 'msgpack', 'yaml']
CELERY_TASK_SERIALIZER = "pickle"

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
}

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
        'file_handler_debug': {
            'level': 'DEBUG',
            'filters': ['require_debug_true'],
            'class': 'logging.FileHandler',
            'filename': '%s/../django_app.log' % (DOJO_ROOT or '.',)
        },
        'file_handler': {
            'level': 'INFO',
            'filters': ['require_debug_false'],
            'class': 'logging.FileHandler',
            'filename': '%s/../django_app.log' % (DOJO_ROOT or '.',)
        },
    },
    'loggers': {
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
            'propagate': True,
        },
        'dojo': {
            'handlers': ['file_handler', 'file_handler_debug'],
            'level': 'DEBUG',
            'propagate': False,
        }
    }
}

# As we require `innodb_large_prefix = ON` for MySQL, we can silence the
# warning about large varchar with unique indices.
SILENCED_SYSTEM_CHECKS = ['mysql.E001']
