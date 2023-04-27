import unittest
import os
from io import StringIO
from django.test import TestCase
from django.core.management import call_command
from dojo.models import Finding

class CsvFindingExportTest(TestCase):
    def setUp(self):
        Finding.objects.create(
            title='Test Finding',
            cwe='CWE-1234',
            severity='High',
            url='https://example.com/test',
            verified=True,
            active=True
        )
        self.file_path = 'test_finding_export.csv'

    def tearDown(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)

    def test_csv_finding_export(self):
        out = StringIO()
        call_command('csv_finding_export', self.file_path, stdout=out)
        output = out.getvalue()
        self.assertTrue('Test Finding' in output)
        self.assertTrue('CWE-1234' in output)
        self.assertTrue('High' in output)
        self.assertTrue('https://example.com/test' in output)

if __name__ == '__main__':
    unittest.main()
