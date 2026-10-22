from django.test import SimpleTestCase, override_settings

from dojo.checks import check_configuration_defaults

SHIPPED_SECRET = "hhZCp@D28z!n@NED*yB!ROMt+WzsY*iq"
SHIPPED_CREDENTIAL_KEY = "&91a*agLqesc*0DJ+2*bAbsUZfR*4nLw"
CONFIGURED_SECRET = "a-real-random-secret-key"
CONFIGURED_CREDENTIAL_KEY = "a-real-random-32-char-credential"


class ConfigurationDefaultChecksTest(SimpleTestCase):

    def _ids(self):
        return {warning.id for warning in check_configuration_defaults(None)}

    @override_settings(SECRET_KEY=SHIPPED_SECRET, CREDENTIAL_AES_256_KEY=SHIPPED_CREDENTIAL_KEY, ALLOWED_HOSTS=["*"], DEBUG=False)
    def test_shipped_values_are_reported(self):
        self.assertEqual({"dojo.W002", "dojo.W003", "dojo.W004"}, self._ids())

    @override_settings(SECRET_KEY=CONFIGURED_SECRET, CREDENTIAL_AES_256_KEY=CONFIGURED_CREDENTIAL_KEY, ALLOWED_HOSTS=["defectdojo.example.com"], DEBUG=False)
    def test_configured_values_are_quiet(self):
        self.assertEqual(set(), self._ids())

    @override_settings(SECRET_KEY=CONFIGURED_SECRET, CREDENTIAL_AES_256_KEY=".", ALLOWED_HOSTS=["*"], DEBUG=True)
    def test_settings_dist_placeholder_key_is_reported_and_wildcard_hosts_allowed_in_debug(self):
        self.assertEqual({"dojo.W003"}, self._ids())

    @override_settings(SECRET_KEY="", CREDENTIAL_AES_256_KEY=CONFIGURED_CREDENTIAL_KEY, ALLOWED_HOSTS=["defectdojo.example.com"], DEBUG=False)
    def test_an_empty_secret_key_does_not_break_the_check(self):
        # manage.py check runs in containers that set no SECRET_KEY, and reading an empty one raises.
        self.assertEqual(set(), self._ids())
