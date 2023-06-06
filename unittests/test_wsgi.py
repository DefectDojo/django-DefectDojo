import unittest
from django.core.wsgi import get_wsgi_application
import dojo.wsgi as wsgi
from unittest.mock import patch, MagicMock




class TestWSGI(unittest.TestCase):
    def test_environ_set_default(self):
        self.assertEqual(wsgi.os.environ.get('DJANGO_SETTINGS_MODULE'), 'dojo.settings.settings')

    def test_application_is_callable(self):
        application = get_wsgi_application()
        self.assertTrue(callable(application))

    

    def test_debugpy_configure_called(self):
        with self.assertRaises(AttributeError):
            wsgi.debugpy.configure()

    def test_debugpy_listen_called(self):
        with self.assertRaises(AttributeError):
            wsgi.debugpy.listen()

    def test_debugpy_wait_for_client_called(self):
        with self.assertRaises(AttributeError):
            wsgi.debugpy.wait_for_client()

  

if __name__ == '__main__':
    unittest.main()
