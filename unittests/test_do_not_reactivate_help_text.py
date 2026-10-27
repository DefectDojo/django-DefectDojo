from django.test import SimpleTestCase
from django.utils.functional import Promise

from dojo.api_v2.serializers import ReImportScanSerializer
from dojo.forms import ReImportScanForm

EXPECTED = (
    "Keep closed findings closed when they appear in the report again, instead of reactivating them. "
    "New findings are still created, and open findings are processed as usual."
)


class TestDoNotReactivateHelpText(SimpleTestCase):

    """
    do_not_reactivate keeps a closed finding closed when the report has it again. It does not
    ignore active findings, which is what the old help said, and the help must be translatable.
    """

    def assert_help(self, help_text):
        self.assertIsInstance(help_text, Promise, "the help text must be wrapped in gettext_lazy")
        self.assertEqual(str(help_text), EXPECTED)
        self.assertNotIn("ignore active findings", str(help_text))

    def test_api_help_text(self):
        self.assert_help(ReImportScanSerializer().fields["do_not_reactivate"].help_text)

    def test_reimport_form_help_text(self):
        self.assert_help(ReImportScanForm.base_fields["do_not_reactivate"].help_text)
