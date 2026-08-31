from crum import impersonate
from django.utils.timezone import now

from dojo.authorization.roles_permissions import Roles
from dojo.location.models import Location, LocationProductReference
from dojo.location.queries import annotate_location_counts_and_status, get_authorized_locations
from dojo.location.status import ProductLocationStatus
from dojo.models import (
    Dojo_User,
    Engagement,
    Finding,
    Product,
    Product_Member,
    Product_Type,
    Role,
    Test,
    Test_Type,
    User,
)
from dojo.url.filters import URLFilter
from dojo.url.models import URL
from unittests.dojo_test_case import DojoTestCase, skip_unless_v3, versioned_fixtures

SHARED_HOST = "joinscope-shared.example.com"
OWN_HOST = "joinscope-own.example.com"

VICTIM_PRODUCT_NAME = "JoinScope Product B"
VICTIM_PRODUCT_TAG = "joinscope-b-product-tag"
VICTIM_FINDING_TAG = "joinscope-b-finding-tag"
OWN_PRODUCT_NAME = "JoinScope Product A"
OWN_PRODUCT_TAG = "joinscope-a-product-tag"
OWN_FINDING_TAG = "joinscope-a-finding-tag"


@skip_unless_v3
@versioned_fixtures
class TestLocationFilterJoinScoping(DojoTestCase):

    """
    Two products sharing one deduplicated Location. The endpoint list filters join
    outward from the Location into products and findings, so a predicate must only
    ever be matched against references the caller is authorized for. Otherwise the
    shared row acts as an oracle for the other product's data.
    """

    fixtures = ["dojo_testdata.json"]

    @classmethod
    def setUpTestData(cls):
        prod_type, _ = Product_Type.objects.get_or_create(name="JoinScope PT")
        test_type, _ = Test_Type.objects.get_or_create(name="JoinScope Scan")

        def build(name, product_tag, finding_title, finding_tag):
            product = Product.objects.create(name=name, description=name, prod_type=prod_type)
            product.tags = [product_tag]
            product.save()
            engagement = Engagement.objects.create(
                product=product, name=f"{name} eng",
                target_start=now().date(), target_end=now().date(),
            )
            test = Test.objects.create(
                engagement=engagement, test_type=test_type,
                target_start=now(), target_end=now(),
            )
            finding = Finding.objects.create(
                test=test, title=finding_title, severity="High",
                numerical_severity="S1", active=True, verified=True,
            )
            finding.tags = [finding_tag]
            finding.save()
            return product, finding

        cls.product_a, finding_a = build(
            OWN_PRODUCT_NAME, OWN_PRODUCT_TAG, "JoinScope A Finding", OWN_FINDING_TAG)
        cls.product_b, finding_b = build(
            VICTIM_PRODUCT_NAME, VICTIM_PRODUCT_TAG, "JoinScope B Finding", VICTIM_FINDING_TAG)

        cls.alice = User.objects.create_user(
            username="joinscope_alice",
            password="not-a-real-secret",  # noqa: S106 - test fixture user
        )
        # Legacy authorization reads authorized_users, the role model reads Product_Member.
        cls.product_a.authorized_users.add(Dojo_User.objects.get(pk=cls.alice.pk))
        Product_Member.objects.create(
            product=cls.product_a, user=cls.alice, role=Role.objects.get(id=Roles.Reader))

        # One URL referenced by both products dedupes to a single Location row. Only
        # product B has a finding on it, so any match through a finding is B's.
        cls.shared = URL.get_or_create_from_values(
            protocol="https", host=SHARED_HOST, path="app").location
        cls.shared.associate_with_product(cls.product_a)
        cls.shared.associate_with_finding(finding_b, audit_time=now())

        # Control: a Location only product A references.
        cls.own = URL.get_or_create_from_values(
            protocol="https", host=OWN_HOST, path="x").location
        cls.own.associate_with_product(cls.product_a)
        cls.own.associate_with_finding(finding_a, audit_time=now())

        # Distinct statuses per product, so a status predicate that matches can only
        # have matched one of them.
        LocationProductReference.objects.filter(product=cls.product_a).update(
            status=ProductLocationStatus.Active)
        LocationProductReference.objects.filter(location=cls.shared, product=cls.product_b).update(
            status=ProductLocationStatus.Mitigated)

        cls.admin = User.objects.filter(is_superuser=True).first()

    def _matches(self, user, **params):
        """Location ids the endpoint list returns for these filter parameters."""
        with impersonate(user):
            base = annotate_location_counts_and_status(
                get_authorized_locations(
                    "view",
                    Location.objects.filter(id__in=[self.shared.id, self.own.id]),
                    user,
                ),
                user=user,
            )
            return set(URLFilter(params, queryset=base, user=user).qs.values_list("id", flat=True))

    def test_shared_location_is_a_single_row(self):
        """The premise: both products reference one deduplicated Location."""
        self.assertEqual(Location.objects.filter(url__host=SHARED_HOST).count(), 1)
        related = {p.name for p in self.shared.all_related_products()}
        self.assertEqual(related, {OWN_PRODUCT_NAME, VICTIM_PRODUCT_NAME})
        self.assertEqual(self._matches(self.alice), {self.shared.id, self.own.id})

    def test_other_products_data_never_matches(self):
        for label, params in (
            ("finding tag, exact", {"findings__finding__tags__name_exact": VICTIM_FINDING_TAG}),
            ("finding tag, prefix", {"findings__finding__tags__name_starts_with": "joinscope-b"}),
            ("finding tag, substring", {"findings__finding__tags__name_contains": "b-finding"}),
            ("finding tag, list", {"findings__finding__tags__name_includes": VICTIM_FINDING_TAG}),
            ("product name, exact", {"products__product__name_exact": VICTIM_PRODUCT_NAME}),
            ("product name, prefix", {"products__product__name_starts_with": VICTIM_PRODUCT_NAME}),
            ("product name, substring", {"products__product__name_contains": "Product B"}),
            ("product tag, exact", {"products__product__tags__name_exact": VICTIM_PRODUCT_TAG}),
            ("product tag, prefix", {"products__product__tags__name_starts_with": "joinscope-b"}),
            ("product id", {"products__product__id_equals": self.product_b.id}),
            ("product reference status", {"products__status_equals": [ProductLocationStatus.Mitigated]}),
            ("finding reference status", {"findings__status_equals": ["Active"]}),
        ):
            with self.subTest(label):
                self.assertNotIn(
                    self.shared.id, self._matches(self.alice, **params),
                    f"{label} matched through another product's reference",
                )

    def test_own_data_still_matches(self):
        both = {self.shared.id, self.own.id}
        for label, params, expected in (
            ("own product name", {"products__product__name_exact": OWN_PRODUCT_NAME}, both),
            ("own product name prefix", {"products__product__name_starts_with": OWN_PRODUCT_NAME}, both),
            ("own product tag", {"products__product__tags__name_exact": OWN_PRODUCT_TAG}, both),
            ("own product id", {"products__product__id_equals": self.product_a.id}, both),
            ("own finding tag", {"findings__finding__tags__name_exact": OWN_FINDING_TAG}, {self.own.id}),
            ("own reference status", {"products__status_equals": [ProductLocationStatus.Active]}, both),
        ):
            with self.subTest(label):
                self.assertEqual(self._matches(self.alice, **params), expected)

    def test_excluding_a_hidden_product_does_not_hide_the_callers_row(self):
        """A negated predicate must not fire on a reference the caller cannot see."""
        self.assertEqual(
            self._matches(self.alice, products__product__id_not_equals=self.product_b.id),
            {self.shared.id, self.own.id},
        )

    def test_superuser_still_sees_everything(self):
        self.assertEqual(
            self._matches(self.admin, products__product__name_exact=VICTIM_PRODUCT_NAME),
            {self.shared.id},
        )
        self.assertEqual(
            self._matches(self.admin, findings__finding__tags__name_exact=VICTIM_FINDING_TAG),
            {self.shared.id},
        )

    def test_url_filters_are_unaffected(self):
        self.assertEqual(
            self._matches(self.alice, url__host_exact=SHARED_HOST), {self.shared.id})
        self.assertEqual(
            self._matches(self.alice, url__host_contains="joinscope-own"), {self.own.id})
