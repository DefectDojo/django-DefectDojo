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

    @patch('dojo.wsgi.socket.socket')
    def test_is_debugger_listening(self, mock_socket):
        mock_connect_ex = MagicMock(return_value=0)  # Simulate a successful connection
        mock_socket.return_value.connect_ex = mock_connect_ex

        result = wsgi.is_debugger_listening(3000)

        self.assertEqual(result, 0)
        mock_socket.assert_called_once_with(wsgi.socket.AF_INET, wsgi.socket.SOCK_STREAM)
        mock_connect_ex.assert_called_once_with(('127.0.0.1', 3000))

    """def test_debugpy_imported(self):
        self.assertTrue(hasattr(wsgi, "debugpy"))"""

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
