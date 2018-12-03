# Django settings for dojo project.

import base64
# REVIEW: Is this used?
from datetime import timedelta
import os

DEBUG = os.environ['DEFECT_DOJO_DEBUG'] == 'True' if 'DEFECT_DOJO_DEBUG' in os.environ else False
LOGIN_REDIRECT_URL = os.environ['DEFECT_DOJO_LOGIN_REDIRECT_URL'] if 'DEFECT_DOJO_LOGIN_REDIRECT_URL' in os.environ else '/'
# SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
# SECURE_SSL_REDIRECT = True
# SECURE_BROWSER_XSS_FILTER = True
SESSION_COOKIE_HTTPONLY = os.environ['DEFECT_DOJO_SESSION_COOKIE_HTTPONLY'] == 'True' if 'DEFECT_DOJO_SESSION_COOKIE_HTTPONLY' in os.environ else True
CSRF_COOKIE_HTTPONLY = os.environ['DEFECT_DOJO_CSRF_COOKIE_HTTPONLY'] == 'True' if 'DEFECT_DOJO_CSRF_COOKIE_HTTPONLY' in os.environ else True
TEST_RUNNER = os.environ['DEFECT_DOJO_TEST_RUNNER'] if 'DEFECT_DOJO_TEST_RUNNER' in os.environ else 'django.test.runner.DiscoverRunner'
URL_PREFIX = os.environ['DEFECT_DOJO_URL_PREFIX'] if 'DEFECT_DOJO_URL_PREFIX' in os.environ else ''

# Uncomment this line if you enable SSL
# SESSION_COOKIE_SECURE = True
# CSRF_COOKIE_SECURE = True

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

ADMINS = (
    (
        os.environ['DEFECT_DOJO_ADMIN_NAME']  if 'DEFECT_DOJO_ADMIN_NAME'  in os.environ else 'admin',
        os.environ['DEFECT_DOJO_ADMIN_EMAIL'] if 'DEFECT_DOJO_ADMIN_EMAIL' in os.environ else 'root@localhost'
    )
)

MANAGERS = ADMINS

# It is CRITICAL that DOJO_ROOT does not end with the trailing /.
# If you include it, you'll get ENOENT for @yarn_components.
# This is because os.path.dirname strips the last / instead of the
# last file name.
DOJO_ROOT = os.environ['DEFECT_DOJO_ROOT'] if 'DEFECT_DOJO_ROOT' in os.environ else os.environ['PWD'] + '/dojo'

DATABASES = {
    'default': {
        'ENGINE': os.environ['DEFECT_DOJO_DEFAULT_DATABASE_ENGINE'] if 'DEFECT_DOJO_DEFAULT_DATABASE_ENGINE' in os.environ else 'django.db.backends.mysql', # 'django.db.backends.mysql','django.db.backends.sqlite3' or 'django.db.backends.oracle'.
        'NAME': os.environ['DEFECT_DOJO_DEFAULT_DATABASE_NAME'] if 'DEFECT_DOJO_DEFAULT_DATABASE_NAME' in os.environ else 'dojodb', # Or path to database file if using sqlite3.
        # The following settings are not used with sqlite3:
        'USER': os.environ['DEFECT_DOJO_DEFAULT_DATABASE_USER'] if 'DEFECT_DOJO_DEFAULT_DATABASE_USER' in os.environ else 'dojo',
        'PASSWORD': os.environ['DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD'] if 'DEFECT_DOJO_DEFAULT_DATABASE_PASSWORD' in os.environ else 'dojo',
        'HOST': os.environ['DEFECT_DOJO_DEFAULT_DATABASE_HOST'] if 'DEFECT_DOJO_DEFAULT_DATABASE_HOST' in os.environ else '', # Empty for localhost through domain sockets or '127.0.0.1' for localhost through TCP.
        'PORT': os.environ['DEFECT_DOJO_DEFAULT_DATABASE_PORT'] if 'DEFECT_DOJO_DEFAULT_DATABASE_PORT' in os.environ else '' # Set to empty string for default.
    }
}

# Hosts/domain names that are valid for this site; required if DEBUG is False
# See https://docs.djangoproject.com/en/1.5/ref/settings/#allowed-hosts
ALLOWED_HOSTS = [ os.environ['DEFECT_DOJO_ALLOWED_HOSTS_GLOB'] ] if 'DEFECT_DOJO_ALLOWED_HOSTS_GLOB' in os.environ else [ 'localhost', '127.0.0.1' ]

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = os.environ['DEFECT_DOJO_TIME_ZONE'] if 'DEFECT_DOJO_TIME_ZONE' in os.environ else 'America/Chicago'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = os.environ['DEFECT_DOJO_LANGUAGE_CODE'] if 'DEFECT_DOJO_LANGUAGE_CODE' in os.environ else 'en-us'

SITE_ID = int(os.environ['DEFECT_DOJO_SITE_ID']) if 'DEFECT_DOJO_SITE_ID' in os.environ else 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = os.environ['DEFECT_DOJO_USE_I18N'] == 'True' if 'DEFECT_DOJO_USE_I18N' in os.environ else True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = os.environ['DEFECT_DOJO_USE_L10N'] == 'True' if 'DEFECT_DOJO_USE_L10N' in os.environ else True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = os.environ['DEFECT_DOJO_USE_TZ'] == 'True' if 'DEFECT_DOJO_USE_TZ' in os.environ else True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/var/www/example.com/media/"
MEDIA_ROOT = os.environ['DEFECT_DOJO_MEDIA_ROOT'] if 'DEFECT_DOJO_MEDIA_ROOT' in os.environ else os.environ['PWD'] + '/media/'

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://example.com/media/", "http://media.example.com/"
MEDIA_URL = os.environ['DEFECT_DOJO_MEDIA_URL'] if 'DEFECT_DOJO_MEDIA_URL' in os.environ else '/media/'

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/var/www/example.com/static/"
STATIC_ROOT = os.environ['DEFECT_DOJO_STATIC_ROOT'] if 'DEFECT_DOJO_STATIC_ROOT' in os.environ else os.environ['PWD'] + '/static/'

# URL prefix for static files.
# Example: "http://example.com/static/", "http://static.example.com/"
STATIC_URL = os.environ['DEFECT_DOJO_STATIC_URL'] if 'DEFECT_DOJO_STATIC_URL' in os.environ else '/static/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    os.path.join(os.path.dirname(DOJO_ROOT), 'components', 'node_modules', '@yarn_components'),
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

# Make this unique, and don't share it with anybody.
# SECRET_KEY = base64.b64encode(os.urandom(32))
SECRET_KEY = os.environ['DEFECT_DOJO_SECRET_KEY'] if 'DEFECT_DOJO_SECRET_KEY' else '8htr208jr0fi0a0sdfajth9v' # It's better than nothing...

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    # 'django.middleware.security.SecurityMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'dojo.middleware.LoginRequiredMiddleware',
    'dojo.middleware.TimezoneMiddleware'
)

ROOT_URLCONF = os.environ['DEFECT_DOJO_ROOT_URLCONF'] if 'DEFECT_DOJO_ROOT_URLCONF' in os.environ else 'dojo.urls'
LOGIN_URL = os.environ['DEFECT_DOJO_LOGIN_URL'] if 'DEFECT_DOJO_LOGIN_URL' in os.environ else '/login'
LOGIN_EXEMPT_URLS = (
    r'^%sstatic/' % URL_PREFIX,
    r'^%sapi/v1/' % URL_PREFIX,
    r'^%sajax/v1/' % URL_PREFIX,
    r'^%sreports/cover$' % URL_PREFIX,
    r'^%sfinding/image/(?P<token>[^/]+)$' % URL_PREFIX,
    r'^%sapi/v2/' % URL_PREFIX,
)

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = os.environ['DEFECT_DOJO_WSGI_APPLICATION'] if 'DEFECT_DOJO_WSGI_APPLICATION' in os.environ else 'dojo.wsgi.application'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'APP_DIRS': True,
        'OPTIONS': {
            'debug': DEBUG,
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

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
)

EMAIL_BACKEND = os.environ['DEFECT_DOJO_EMAIL_BACKEND'] if 'DEFECT_DOJO_EMAIL_BACKEND' in os.environ else 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = os.environ['DEFECT_DOJO_EMAIL_HOST'] if 'DEFECT_DOJO_EMAIL_HOST' in os.environ else 'smtpout.your_domain.com'
EMAIL_PORT = os.environ['DEFECT_DOJO_EMAIL_PORT'] if 'DEFECT_DOJO_EMAIL_PORT' in os.environ else '25' # REVIEW: This seems like it should be an integer rather than a string.
EMAIL_USE_TLS = os.environ['DEFECT_DOJO_EMAIL_USE_TLS'] == 'True' if 'DEFECT_DOJO_EMAIL_USE_TLS' in os.environ else True

PORT_SCAN_CONTACT_EMAIL = os.environ['DEFECT_DOJO_PORT_SCAN_CONTACT_EMAIL'] if 'DEFECT_DOJO_PORT_SCAN_CONTACT_EMAIL' in os.environ else 'root@localhost'
PORT_SCAN_RESULT_EMAIL_FROM = os.environ['DEFECT_DOJO_PORT_SCAN_RESULT_EMAIL_FROM'] if 'DEFECT_DOJO_PORT_SCAN_RESULT_EMAIL_FROM' in os.environ else 'root@localhost'
PORT_SCAN_EXTERNAL_UNIT_EMAIL_LIST = [ os.environ['DEFECT_DOJO_EXTERNAL_UNIT_EMAIL_LIST_1'] if 'DEFECT_DOJO_EXTERNAL_UNIT_EMAIL_LIST_1' in os.environ else 'root@localhost' ]
PORT_SCAN_SOURCE_IP = os.environ['DEFECT_DOJO_PORT_SCAN_SOURCE_IP'] if 'DEFECT_DOJO_PORT_SCAN_SOURCE_IP' in os.environ else '127.0.0.1'

# Used in a few places to prefix page headings and in email
# salutations
TEAM_NAME = os.environ['DEFECT_DOJO_TEAM_NAME'] if 'DEFECT_DOJO_TEAM_NAME' in os.environ else 'Security Engineering'

# Celery settings
CELERY_BROKER_URL = os.environ['DEFECT_DOJO_CELERY_BROKER_URL'] if 'DEFECT_DOJO_CELERY_BROKER_URL' in os.environ else 'sqla+sqlite:///dojo.celerydb.sqlite'
CELERY_TASK_IGNORE_RESULT = os.environ['DEFECT_DOJO_CELERY_TASK_IGNORE_RESULT'] == 'True' if 'DEFECT_DOJO_CELERY_TASK_IGNORE_RESULT' in os.environ else True
CELERY_RESULT_BACKEND = os.environ['DEFECT_DOJO_CELERY_RESULT_BACKEND'] if 'DEFECT_DOJO_CELERY_RESULT_BACKEND' in os.environ else 'db+sqlite:///dojo.celeryresults.sqlite'
CELERY_TIMEZONE = TIME_ZONE
CELERY_RESULT_EXPIRES = int(os.environ['DEFECT_DOJO_CELERY_RESULT_EXPIRES']) if 'DEFECT_DOJO_CELERY_RESULT_EXPIRES' in os.environ else 86400
CELERY_BEAT_SCHEDULE_FILENAME = os.environ['DEFECT_DOJO_CELERY_BEAT_SCHEDULE_FILENAME'] if 'DEFECT_DOJO_CELERY_BEAT_SCHEDULE_FILENAME' in os.environ else DOJO_ROOT + '/dojo.celery.beat.db'
CELERY_ACCEPT_CONTENT = ['pickle', 'json', 'msgpack', 'yaml']
CELERY_TASK_SERIALIZER = os.environ['DEFECT_DOJO_CELERY_TASK_SERIALIZER'] if 'DEFECT_DOJO_CELERY_TASK_SERIALIZER' in os.environ else 'pickle'

# Celery beat scheduled tasks
CELERY_BEAT_SCHEDULE = {
    'add-alerts': {
        'task': 'dojo.tasks.add_alerts',
        'schedule': timedelta(hours=1),
        'args': [timedelta(hours=1)]
    },
    'dedupe-delete': {
        'task': 'dojo.tasks.async_dupe_delete',
        'schedule': timedelta(hours=24),
        'args': [timedelta(hours=24)]
    },
}


# wkhtmltopdf settings
WKHTMLTOPDF_PATH = os.environ['DEFECT_DOJO_WKHTMLTOPDF_PATH'] if 'DEFECT_DOJO_WKHTMLTOPDF_PATH' in os.environ else '/usr/local/bin/wkhtmltopdf'

# django-tagging settings
FORCE_LOWERCASE_TAGS = os.environ['DEFECT_DOJO_FORCE_LOWERCASE_TAGS'] == 'True' if 'DEFECT_DOJO_FORCE_LOWERCASE_TAGS' in os.environ else True
MAX_TAG_LENGTH = int(os.environ['DEFECT_DOJO_MAX_TAG_LENGTH']) if 'DEFECT_DOJO_MAX_TAG_LENGTH' in os.environ else 25

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
