# In order to run the unit tests, it is required to create a settings file
# first;
# Do so by copying the file dojo/settings/settings_dist.py to
# dojo/settings/settings.py; Otherwise, the following import will not work
from dojo.settings.settings_dist import *

DEBUG = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'unittest.sqlite',
    }
}
