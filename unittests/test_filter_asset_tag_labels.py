from dojo.filters import FindingFilter
from dojo.models import Finding
from unittests.dojo_test_case import DojoTestCase


class FindingTagFilterAssetLabelTest(DojoTestCase):

    """
    Regression test for the v3 Product->Asset relabel of the Asset-level AND tag
    filter on the finding list.

    The relabel (#13155, gated by ENABLE_V3_ORGANIZATION_ASSET_RELABEL, default on)
    moves filter copy into dojo/asset/labels.py. The OR variant
    (test__engagement__product__tags) gets its label set dynamically at render time
    by get_tags_label_from_model() -> "Tags (Asset)", so it was always fine. But the
    AND variant (test__engagement__product__tags_and) is static and was left
    hardcoded "Product Tags (AND)", so it rendered the legacy wording even with the
    relabel enabled - inconsistent with its siblings "Test Tags (AND)" /
    "Engagement Tags (AND)".

    These assert the RENDERED FindingFilter form field (not the static declared
    label, which the dynamic setter can override) carries the Asset vocabulary,
    which is the default in the test environment.
    """

    def _and_field(self):
        # Unscoped finding filter keeps every tag field (the scoped views delete the
        # OR field; the AND field is always present).
        return FindingFilter(queryset=Finding.objects.none()).form.fields["test__engagement__product__tags_and"]

    def test_asset_and_tag_filter_label_uses_asset_vocabulary(self):
        self.assertEqual(str(self._and_field().label), "Asset Tags (AND)")

    def test_asset_and_tag_filter_help_uses_asset_vocabulary(self):
        self.assertEqual(
            str(self._and_field().help_text),
            "Filter Findings by the selected Asset tags (AND logic)",
        )
