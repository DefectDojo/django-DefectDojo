import datetime
from types import SimpleNamespace

from django.test import SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from dojo.announcement import github_star
from dojo.models import User, UserContactInfo
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures

NOW = datetime.datetime(2026, 10, 21, 12, 0, tzinfo=datetime.UTC)


def _user(days_old=30, state=None, *, authenticated=True):
    contact = SimpleNamespace(user_state_details={github_star.GITHUB_STAR_PROMPT_KEY: state}) if state else None
    return SimpleNamespace(
        is_authenticated=authenticated,
        date_joined=NOW - datetime.timedelta(days=days_old),
        usercontactinfo=contact,
    )


@override_settings(GITHUB_STAR_PROMPT_ENABLED=True)
class TestShouldShowGithubStarPrompt(SimpleTestCase):

    def test_shown_to_established_user(self):
        self.assertTrue(github_star.should_show_github_star_prompt(_user(), now=NOW))

    def test_hidden_for_new_user(self):
        self.assertFalse(github_star.should_show_github_star_prompt(_user(days_old=2), now=NOW))

    def test_hidden_for_anonymous(self):
        self.assertFalse(github_star.should_show_github_star_prompt(_user(authenticated=False), now=NOW))
        self.assertFalse(github_star.should_show_github_star_prompt(None, now=NOW))

    @override_settings(GITHUB_STAR_PROMPT_ENABLED=False)
    def test_hidden_when_disabled(self):
        self.assertFalse(github_star.should_show_github_star_prompt(_user(), now=NOW))

    def test_hidden_after_starring(self):
        self.assertFalse(github_star.should_show_github_star_prompt(_user(state={"starred": True}), now=NOW))

    def test_hidden_while_snoozed(self):
        until = (NOW + datetime.timedelta(days=5)).isoformat()
        self.assertFalse(github_star.should_show_github_star_prompt(_user(state={"snoozed_until": until}), now=NOW))

    def test_shown_again_after_snooze_expires(self):
        until = (NOW - datetime.timedelta(days=1)).isoformat()
        self.assertTrue(github_star.should_show_github_star_prompt(_user(state={"snoozed_until": until}), now=NOW))

    def test_corrupt_snooze_value_is_ignored(self):
        self.assertTrue(github_star.should_show_github_star_prompt(_user(state={"snoozed_until": "nope"}), now=NOW))


@versioned_fixtures
@override_settings(GITHUB_STAR_PROMPT_ENABLED=True)
class TestGithubStarPromptView(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.user = User.objects.get(username="admin")
        self.user.date_joined = timezone.now() - datetime.timedelta(days=30)
        self.user.save(update_fields=["date_joined"])
        self.client.force_login(self.user)
        self.url = reverse("github_star_prompt")

    def _state(self):
        contact = UserContactInfo.objects.filter(user=self.user).first()
        return (getattr(contact, "user_state_details", None) or {}).get(github_star.GITHUB_STAR_PROMPT_KEY)

    def test_prompt_rendered_for_established_user(self):
        response = self.client.get(reverse("home"), follow=True)
        self.assertContains(response, 'id="github-star-prompt"')
        self.assertContains(response, "Enjoying DefectDojo?")

    def test_star_records_and_redirects_to_github(self):
        response = self.client.post(self.url, {"choice": "star"})
        self.assertRedirects(response, github_star.GITHUB_REPO_URL, fetch_redirect_response=False)
        self.assertEqual(self._state(), {"starred": True})
        response = self.client.get(reverse("home"), follow=True)
        self.assertNotContains(response, 'id="github-star-prompt"')

    def test_later_snoozes(self):
        response = self.client.post(self.url, {"choice": "later"}, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        self.assertEqual(response.status_code, 204)
        until = datetime.datetime.fromisoformat(self._state()["snoozed_until"])
        self.assertGreater(until, timezone.now() + datetime.timedelta(days=29))
        response = self.client.get(reverse("home"), follow=True)
        self.assertNotContains(response, 'id="github-star-prompt"')

    def test_preserves_other_state_keys(self):
        contact = UserContactInfo.objects.get_or_create(user=self.user)[0]
        contact.user_state_details = {"other_flag": 1}
        contact.save(update_fields=["user_state_details"])
        self.client.post(self.url, {"choice": "later"}, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        contact.refresh_from_db()
        self.assertEqual(contact.user_state_details.get("other_flag"), 1)
        self.assertIn(github_star.GITHUB_STAR_PROMPT_KEY, contact.user_state_details)

    def test_unknown_choice_is_ignored(self):
        response = self.client.post(self.url, {"choice": "bogus"}, HTTP_X_REQUESTED_WITH="XMLHttpRequest")
        self.assertEqual(response.status_code, 204)
        self.assertIsNone(self._state())

    def test_get_not_allowed(self):
        self.assertEqual(self.client.get(self.url).status_code, 405)

    def test_requires_authentication(self):
        self.client.logout()
        response = self.client.post(self.url, {"choice": "star"})
        self.assertIn(response.status_code, (302, 403))
