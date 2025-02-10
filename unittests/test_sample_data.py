from django.core.management import call_command

from .dojo_test_case import DojoTestCase


class TestSampleData(DojoTestCase):
    def test_loaddata(self):
        """
        The expected command to generate the fixture file is as follows:

        python3 manage.py dumpdata \
            --exclude auth.permission \
            --exclude contenttypes \
            --exclude auditlog.logentry \
            --natural-foreign \
            --natural-primary \
            --indent 2 \
            > /app/dojo/fixtures/defect_dojo_sample_data.json
        """
        try:
            call_command("loaddata", "dojo/fixtures/defect_dojo_sample_data", verbosity=0)
        except Exception as e:
            self.assertEqual(False, True, e)
        self.assertEqual(True, True)
