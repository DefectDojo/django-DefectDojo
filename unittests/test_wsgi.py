import unittest
from django.core.wsgi import get_wsgi_application

import dojo.wsgi as wsgi


class TestWSGI(unittest.TestCase):
    def test_environ_set_default(self):
        # Prueba que os.environ esté correctamente configurado cuando no se haya configurado explícitamente
        self.assertEqual(wsgi.os.environ.get('DJANGO_SETTINGS_MODULE'), 'dojo.settings.settings')

    def test_application_is_callable(self):
        # Prueba que el objeto de aplicación devuelto por get_wsgi_application sea callable (es decir, que se pueda llamar como una función)
        application = get_wsgi_application()
        self.assertTrue(callable(application))

    def test_is_debugger_listening(self):
        # Prueba que is_debugger_listening devuelva False cuando el depurador no esté escuchando
        self.assertFalse(hasattr(wsgi.application, 'is_debugger_listening'))
