import unittest
from django.core.wsgi import get_wsgi_application

import dojo.wsgi as wsgi


class TestWSGI(unittest.TestCase):
    def test_environ_set_default(self):
        self.assertEqual(wsgi.os.environ.get('DJANGO_SETTINGS_MODULE'), 'dojo.settings.settings')

    def test_application_is_callable(self):
        application = get_wsgi_application()
        self.assertTrue(callable(application))

    def test_is_debugger_listening(self):
        self.assertFalse(hasattr(wsgi.application, 'is_debugger_listening'))
