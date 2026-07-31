import re

from django.test import override_settings
from django.urls import reverse

from dojo.models import Dojo_User, Finding, UserContactInfo
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures

# Opening tag of the findings result pane. [^>] also matches newlines, so a pane whose
# attributes are spread over several lines is still caught, and it cannot run past the
# end of the tag.
FINDINGS_PANE_TAG = re.compile(r'<div[^>]*\bid="tabs-1"[^>]*>')
CARRIES_ACTIVE = re.compile(r"\bactive\b")

# The stylesheet hides every result pane that does not carry the `active` class:
#     .tab-content > .tab-pane { display: none }
#     .tab-content > .tab-pane.active { display: block }
# so the pane of the tab the view opened on has to get that class from somewhere -- a
# literal class in the classic templates, an Alpine `:class` binding in the Tailwind
# ones. Alpine's x-show cannot do that job: it only clears the inline `display: none`
# it set itself, which leaves the class rule in force and the pane invisible. That is
# what made the whole results area render blank while the tab headers and their result
# counts rendered fine.
#
# Both UI trees are covered, because UIPreferenceLoader picks the tree per user and the
# panes are wired up differently in each. The status code assertion matters as much as
# the pane assertion for the Tailwind tree: an `id:` query leaves the view without a
# filter form, which used to make the filter panel raise while rendering.
#
# V3_FEATURE_LOCATIONS is pinned off to match OSS CI defaults, as in
# test_simple_search_scoping.py.


@override_settings(SECURE_SSL_REDIRECT=False, V3_FEATURE_LOCATIONS=False, WATSON_SEARCH_ENABLED=True)
@versioned_fixtures
class TestSimpleSearchTabPanes(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def _findings_pane_for_ui(self, *, use_tailwind):
        admin = Dojo_User.objects.get(username="admin")
        contact, _ = UserContactInfo.objects.get_or_create(user=admin)
        contact.ui_use_tailwind = use_tailwind
        contact.save()
        self.client.force_login(admin)

        # An `id:` query needs no watson index, so the findings tab opens deterministically.
        finding = Finding.objects.first()
        response = self.client.get(reverse("simple_search"), {"query": f"id:{finding.id}"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["activetab"], "findings")

        pane = FINDINGS_PANE_TAG.search(response.content.decode())
        self.assertIsNotNone(pane, "findings result pane did not render")
        return pane.group(0)

    def test_active_pane_is_displayable_in_tailwind_ui(self):
        self.assertRegex(self._findings_pane_for_ui(use_tailwind=True), CARRIES_ACTIVE)

    def test_active_pane_is_displayable_in_classic_ui(self):
        self.assertRegex(self._findings_pane_for_ui(use_tailwind=False), CARRIES_ACTIVE)
