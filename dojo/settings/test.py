# myproject/settings/test.py
from .settings import *

DATABASES = {
            "default": {
                "ENGINE": "django.db.backends.postgresql",
                "NAME": "test_defectdojo",
                "USER": "defectdojo",
                "PASSWORD": "defectdojo",
                "HOST": "localhost",
                "PORT": "5432",
            }
}