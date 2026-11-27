from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.test import RequestFactory, override_settings
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.models import System_Settings, User
from dojo.system_settings.ui.forms import SystemSettingsForm
from dojo.system_settings.ui.views import SystemSettingsView

from .dojo_test_case import DojoTestCase


def settings_row():
    settings = System_Settings.objects.filter().first() or System_Settings.objects.create()
    return System_Settings.objects.get(pk=settings.pk, no_cache=True)


def admin_user():
    return User.objects.create_user(username="settings-admin", password="pass", is_staff=True, is_superuser=True)  # noqa: S106


@override_settings(SECURE_SSL_REDIRECT=False)
class TestSystemSettingsApiCrossFieldRules(DojoTestCase):

    """The API refuses the same System Settings combinations the settings form refuses."""

    def setUp(self):
        token, _ = Token.objects.get_or_create(user=admin_user())
        self.url = f"/api/v2/system_settings/{settings_row().pk}/"
        self.api = APIClient()
        self.api.credentials(HTTP_AUTHORIZATION=f"Token {token.key}")
        self.set(
            minimum_password_length=9,
            maximum_password_length=48,
            enable_deduplication=False,
            false_positive_history=False,
            retroactive_false_positive_history=False,
        )

    def set(self, **values):
        settings = System_Settings.objects.get(no_cache=True)
        for name, value in values.items():
            setattr(settings, name, value)
        settings.save()

    def current(self, name):
        return getattr(System_Settings.objects.get(no_cache=True), name)

    def full_payload(self, **overrides):
        payload = self.api.get(self.url).json()
        payload.pop("id", None)
        # A plugin's serializer may add fields that read as null but refuse null on write.
        payload = {name: value for name, value in payload.items() if value is not None}
        payload.update(overrides)
        return payload

    def assert_refused(self, response, field, before):
        self.assertEqual(400, response.status_code, response.content)
        self.assertIn(field, response.json())
        for name, value in before.items():
            self.assertEqual(value, self.current(name), name)

    def test_minimum_above_maximum_password_length_is_refused(self):
        before = {"minimum_password_length": 9, "maximum_password_length": 48}
        response = self.api.patch(self.url, {"minimum_password_length": 20, "maximum_password_length": 10}, format="json")
        self.assert_refused(response, "minimum_password_length", before)
        response = self.api.put(self.url, self.full_payload(minimum_password_length=20, maximum_password_length=10), format="json")
        self.assert_refused(response, "minimum_password_length", before)

    def test_minimum_equal_to_maximum_password_length_is_refused(self):
        before = {"minimum_password_length": 9, "maximum_password_length": 48}
        response = self.api.patch(self.url, {"minimum_password_length": 20, "maximum_password_length": 20}, format="json")
        self.assert_refused(response, "minimum_password_length", before)
        response = self.api.put(self.url, self.full_payload(minimum_password_length=20, maximum_password_length=20), format="json")
        self.assert_refused(response, "minimum_password_length", before)

    def test_patch_of_one_side_is_checked_against_the_stored_other_side(self):
        self.set(maximum_password_length=20)
        response = self.api.patch(self.url, {"minimum_password_length": 25}, format="json")
        self.assert_refused(response, "minimum_password_length", {"minimum_password_length": 9})
        response = self.api.patch(self.url, {"maximum_password_length": 9}, format="json")
        self.assert_refused(response, "minimum_password_length", {"maximum_password_length": 20})

    def test_deduplication_with_false_positive_history_is_refused(self):
        before = {"enable_deduplication": False, "false_positive_history": False}
        response = self.api.patch(self.url, {"enable_deduplication": True, "false_positive_history": True}, format="json")
        self.assert_refused(response, "false_positive_history", before)
        response = self.api.put(self.url, self.full_payload(enable_deduplication=True, false_positive_history=True), format="json")
        self.assert_refused(response, "false_positive_history", before)
        # One half in the request, the other half already stored.
        self.set(enable_deduplication=True)
        response = self.api.patch(self.url, {"false_positive_history": True}, format="json")
        self.assert_refused(response, "false_positive_history", {"false_positive_history": False})

    def test_retroactive_without_false_positive_history_is_refused(self):
        before = {"retroactive_false_positive_history": False}
        response = self.api.patch(self.url, {"retroactive_false_positive_history": True}, format="json")
        self.assert_refused(response, "retroactive_false_positive_history", before)
        response = self.api.put(self.url, self.full_payload(retroactive_false_positive_history=True), format="json")
        self.assert_refused(response, "retroactive_false_positive_history", before)
        # Turning false positive history off while retroactive stays on.
        self.set(false_positive_history=True, retroactive_false_positive_history=True)
        response = self.api.patch(self.url, {"false_positive_history": False}, format="json")
        self.assert_refused(response, "retroactive_false_positive_history", {"false_positive_history": True})

    def test_valid_payloads_are_saved(self):
        response = self.api.patch(self.url, {"minimum_password_length": 12, "maximum_password_length": 40}, format="json")
        self.assertEqual(200, response.status_code, response.content)
        self.assertEqual((12, 40), (self.current("minimum_password_length"), self.current("maximum_password_length")))

        response = self.api.patch(
            self.url, {"false_positive_history": True, "retroactive_false_positive_history": True}, format="json",
        )
        self.assertEqual(200, response.status_code, response.content)
        self.assertTrue(self.current("retroactive_false_positive_history"))

        response = self.api.put(self.url, self.full_payload(enable_jira=False), format="json")
        self.assertEqual(200, response.status_code, response.content)

        # A PATCH that touches none of the ruled fields still saves.
        response = self.api.patch(self.url, {"enable_jira": False}, format="json")
        self.assertEqual(200, response.status_code, response.content)


@override_settings(SECURE_SSL_REDIRECT=False)
class TestSystemSettingsFormCrossFieldRules(DojoTestCase):

    """The settings page keeps refusing the same combinations, with the same warnings."""

    def setUp(self):
        self.user = admin_user()
        settings = settings_row()
        settings.minimum_password_length = 9
        settings.maximum_password_length = 48
        settings.enable_deduplication = False
        settings.false_positive_history = False
        settings.retroactive_false_positive_history = False
        settings.save()

    def post(self, **overrides):
        # Drive the page's own handler: the URL may be routed elsewhere by a plugin.
        form = SystemSettingsForm(instance=System_Settings.objects.get(no_cache=True))
        data = {}
        for field in form:
            value = field.value()
            if value is None or value is False:
                continue
            data[field.name] = value
        for name, value in overrides.items():
            if value is False:
                data.pop(name, None)
            else:
                data[name] = value
        request = RequestFactory().post("/system_settings", data)
        request.user = self.user
        request.session = {}
        request._messages = FallbackStorage(request)
        view = SystemSettingsView()
        _, valid = view.validate_form(request, view.get_context(request))
        self.assertTrue(valid)
        return [str(message) for message in get_messages(request)]

    def assert_warned(self, messages, text, field, *, before):
        self.assertEqual([f"Settings cannot be saved: {text}"], messages)
        self.assertEqual(before, getattr(System_Settings.objects.get(no_cache=True), field))

    def test_minimum_equal_to_maximum_is_warned(self):
        messages = self.post(minimum_password_length=20, maximum_password_length=20)
        self.assert_warned(
            messages,
            "Minimum required password length must be less than maximum required password length.",
            "minimum_password_length",
            before=9,
        )

    def test_deduplication_with_false_positive_history_is_warned(self):
        messages = self.post(enable_deduplication=True, false_positive_history=True)
        self.assert_warned(
            messages,
            "Deduplicate findings and False positive history can not be set at the same time.",
            "false_positive_history",
            before=False,
        )

    def test_retroactive_without_false_positive_history_is_warned(self):
        messages = self.post(retroactive_false_positive_history=True)
        self.assert_warned(
            messages,
            "Retroactive false positive history can not be set without False positive history.",
            "retroactive_false_positive_history",
            before=False,
        )

    def test_valid_settings_are_saved(self):
        messages = self.post(minimum_password_length=12, maximum_password_length=40)
        self.assertEqual(["Settings saved."], messages)
        self.assertEqual(12, System_Settings.objects.get(no_cache=True).minimum_password_length)
