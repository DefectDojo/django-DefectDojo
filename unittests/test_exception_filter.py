import unittest
from dojo.settings.exception_filter import CustomExceptionReporterFilter 
from django.http import HttpRequest 

class TestCustomExceptionReporterFilter(unittest.TestCase): 
    def test_is_active(self):
        filter = CustomExceptionReporterFilter()

        request = HttpRequest()

        self.assertEqual(filter.is_active(request), True)

