import unittest
from dojo.settings.exception_filter import CustomExceptionReporterFilter # importar la clase CustomExceptionReporterFilter desde el módulo exception_filter en dojo.settings
from django.http import HttpRequest # importar la clase HttpRequest desde el módulo django.http

class TestCustomExceptionReporterFilter(unittest.TestCase): # definir una clase de prueba llamada TestCustomExceptionReporterFilter que hereda de unittest.TestCase
    def test_is_active(self): # definir un método de prueba llamado test_is_active que se encarga de probar el método is_active de la clase CustomExceptionReporterFilter
        filter = CustomExceptionReporterFilter() # crear una instancia de CustomExceptionReporterFilter y asignarla a la variable filter

        request = HttpRequest() # crear una instancia de HttpRequest y asignarla a la variable request

        self.assertEqual(filter.is_active(request), True) # probar que el método is_active de la instancia de CustomExceptionReporterFilter siempre retorna True usando el método assertEqual de self, que verifica que el valor de la expresión filter.is_active(request) sea igual a True. Si la expresión no es verdadera, el método de prueba fallará.```

