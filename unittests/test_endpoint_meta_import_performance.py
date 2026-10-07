import re
from collections import Counter

from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.location.models import Location
from dojo.models import DojoMeta, Endpoint, Product
from unittests.dojo_test_case import DojoAPITestCase, skip_unless_v2, skip_unless_v3

# Two value sets, so a pass can change every tag and meta value without inventing new tag names.
VALUES_A = {"team": "red", "env": "prod", "owner": "alice"}
VALUES_B = {"team": "blue", "env": "qa", "owner": "bob"}


def build_csv(hosts, values):
    lines = ["hostname,team,env,owner"]
    lines.extend(f"{host},{values['team']},{values['env']},{values['owner']}" for host in hosts)
    return "\n".join(lines) + "\n"


class EndpointMetaImportQueryCountMixin:

    """
    Regression test for an N+1 on ``POST /api/v2/endpoint_meta_import/``.

    The importer looked up, tagged, saved and wrote metadata for every CSV row one
    query at a time (endpoint lookup, tag read, one get_or_create plus save per meta
    column, a full ``save()`` per endpoint), so a file of a few hundred hosts issued
    thousands of queries. The number of queries must not grow with the number of rows.
    """

    def setUp(self):
        token = Token.objects.get(user__username="admin")
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

    def import_csv(self, content, product=1, *, create_endpoints=True, create_tags=True, create_dojo_meta=True):
        payload = {
            "product": product,
            "create_endpoints": create_endpoints,
            "create_tags": create_tags,
            "create_dojo_meta": create_dojo_meta,
            "file": SimpleUploadedFile("meta.csv", content.encode("utf-8"), content_type="text/csv"),
        }
        response = self.client.post(reverse("endpointmetaimport-list"), payload, format="multipart")
        self.assertEqual(201, response.status_code, response.content[:1000])

    def count_import_queries(self, hosts, values, **kwargs):
        with CaptureQueriesContext(connection) as ctx:
            self.import_csv(build_csv(hosts, values), **kwargs)
        return [query["sql"] for query in ctx.captured_queries]

    def warm_up(self):
        # Make every tag name the passes below use exist first, so the measured passes
        # differ only in row count, not in how many distinct tags they create.
        self.import_csv(build_csv(["warm-a.example.com"], VALUES_A))
        self.import_csv(build_csv(["warm-b.example.com"], VALUES_B))

    def assert_constant(self, small, large, label):
        def shapes(queries):
            # pghistory prefixes writes with a per-request set_config call; compare what follows it.
            stripped = (re.sub(r"^SELECT set_config\(.*?true\);\s*", "", sql, flags=re.DOTALL) for sql in queries)
            numbered = (re.sub(r"\d+", "N", sql) for sql in stripped)
            return Counter(re.sub(r"N(\s*,\s*N)+", "N...", sql)[:200] for sql in numbered)

        extra = (shapes(large) - shapes(small)) + (shapes(small) - shapes(large))
        self.assertEqual(
            len(small),
            len(large),
            f"{label}: endpoint meta import issued {len(small)} queries for 10 hosts and {len(large)} for 40; "
            f"the count must not grow with the number of rows. Differing queries: {dict(extra)}",
        )


@skip_unless_v2
class EndpointMetaImportEndpointQueryCountTest(EndpointMetaImportQueryCountMixin, DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def test_query_count_does_not_grow_with_rows(self):
        self.warm_up()
        small_hosts = [f"small{i}.example.com" for i in range(10)]
        large_hosts = [f"large{i}.example.com" for i in range(40)]

        # Create pass: every host is new.
        self.assert_constant(
            self.count_import_queries(small_hosts, VALUES_A),
            self.count_import_queries(large_hosts, VALUES_A),
            "create",
        )
        # Update pass: every host exists and every tag and meta value changes.
        self.assert_constant(
            self.count_import_queries(small_hosts, VALUES_B),
            self.count_import_queries(large_hosts, VALUES_B),
            "update",
        )
        # Unchanged pass: re-importing the same file changes nothing.
        self.assert_constant(
            self.count_import_queries(small_hosts, VALUES_B),
            self.count_import_queries(large_hosts, VALUES_B),
            "unchanged",
        )

        self.assertEqual(10, Endpoint.objects.filter(product_id=1, host__startswith="small").count())
        self.assertEqual(40, Endpoint.objects.filter(product_id=1, host__startswith="large").count())
        for endpoint in Endpoint.objects.filter(product_id=1, host__in=small_hosts + large_hosts):
            self.assertEqual(
                {"team:blue", "env:qa", "owner:bob"},
                {tag.name for tag in endpoint.tags.all()},
                endpoint.host,
            )
            self.assertEqual(
                VALUES_B,
                dict(DojoMeta.objects.filter(endpoint=endpoint).values_list("name", "value")),
                endpoint.host,
            )


@skip_unless_v2
class EndpointMetaImportEndpointSemanticsTest(EndpointMetaImportQueryCountMixin, DojoAPITestCase):

    """Pins the per-row results of the import so batching cannot change them."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.product = Product.objects.create(
            name="Meta Import Semantics", description="meta import", prod_type_id=1,
            enable_product_tag_inheritance=True,
        )
        self.product.tags = ["inherited-tag"]
        self.product.save()
        self.other_product = Product.objects.get(id=2)

        self.endpoint = Endpoint.objects.create(host="sem1.example.com", product=self.product)
        self.endpoint.tags = ["team:old", "steam:keep", "other", "inherited-tag"]
        self.endpoint.save()
        DojoMeta.objects.create(endpoint=self.endpoint, name="team", value="old")
        DojoMeta.objects.create(endpoint=self.endpoint, name="env", value="stale")
        # Matching is exact on host and scoped to the product.
        self.other_case = Endpoint.objects.create(host="Sem1.example.com", product=self.product)
        self.other_product_endpoint = Endpoint.objects.create(host="sem1.example.com", product=self.other_product)

    def tag_names(self, endpoint, field="tags"):
        return {tag.name for tag in getattr(endpoint, field).all()}

    def meta(self, endpoint):
        return dict(DojoMeta.objects.filter(endpoint=endpoint).values_list("name", "value"))

    def test_rows_apply_in_order_with_existing_quirks(self):
        content = (
            "hostname,Team,team,env,owner\n"
            "sem1.example.com,Ops,red,,alice\n"
            "sem1.example.com,,blue,prod,\n"
            ",x,y,z,w\n"
            "new1.example.com,Dev,green,qa,bob\n"
        )
        self.import_csv(content, product=self.product.id)

        self.endpoint.refresh_from_db()
        # Row 1: "team" matches "steam:keep" first (substring test), so that tag is the one
        # replaced. Row 2 then replaces "team:old". Keys are matched case-sensitively while
        # tag names are stored lowercase, so "Team" never replaces anything.
        self.assertEqual(
            {"inherited-tag", "other", "owner:alice", "team:ops", "team:red", "team:blue", "env:prod"},
            self.tag_names(self.endpoint),
        )
        self.assertEqual({"Team": "Ops", "team": "blue", "env": "prod", "owner": "alice"}, self.meta(self.endpoint))

        created = Endpoint.objects.get(host="new1.example.com", product=self.product)
        self.assertEqual({"inherited-tag", "team:dev", "team:green", "env:qa", "owner:bob"}, self.tag_names(created))
        self.assertEqual({"inherited-tag"}, self.tag_names(created, "inherited_tags"))
        self.assertEqual({"Team": "Dev", "team": "green", "env": "qa", "owner": "bob"}, self.meta(created))

        # Tags left with no endpoint are deleted, as tagulous does on a per-instance save.
        tag_model = Endpoint.tags.tag_model
        self.assertFalse(tag_model.objects.filter(name__in=["steam:keep", "team:old"]).exists())
        self.assertEqual(1, tag_model.objects.get(name="team:red").count)

        # Only the product's inherited tag, which it got on creation.
        self.assertEqual({"inherited-tag"}, self.tag_names(self.other_case))
        self.assertEqual(set(), self.tag_names(self.other_product_endpoint))
        for untouched in (self.other_case, self.other_product_endpoint):
            self.assertEqual({}, self.meta(untouched))
        # The row without a hostname is skipped and nothing else is created.
        self.assertEqual(3, Endpoint.objects.filter(product=self.product).count())

    def test_flags_are_honoured(self):
        content = "hostname,team\nsem1.example.com,red\nmissing.example.com,blue\n"
        self.import_csv(content, product=self.product.id, create_endpoints=False, create_tags=False, create_dojo_meta=True)
        self.endpoint.refresh_from_db()
        self.assertEqual({"team:old", "steam:keep", "other", "inherited-tag"}, self.tag_names(self.endpoint))
        self.assertEqual({"team": "red", "env": "stale"}, self.meta(self.endpoint))
        self.assertFalse(Endpoint.objects.filter(host="missing.example.com").exists())

        self.import_csv(content, product=self.product.id, create_endpoints=False, create_tags=True, create_dojo_meta=False)
        self.endpoint.refresh_from_db()
        self.assertEqual({"team:red", "team:old", "other", "inherited-tag"}, self.tag_names(self.endpoint))
        self.assertEqual({"team": "red", "env": "stale"}, self.meta(self.endpoint))

    def _product_inheriting(self, name, tag):
        product = Product.objects.create(
            name=name, description="meta import", prod_type_id=1, enable_product_tag_inheritance=True,
        )
        product.tags = [tag]
        product.save()
        return product

    def test_inherited_tag_containing_a_key_is_kept(self):
        # A product tag that contains a CSV key ("team" in "team-payments") is what the
        # substring replacement picks first. The old per-row path put the inherited tag
        # straight back after every row, so it stays, and the row's tag is added.
        product = self._product_inheriting("Meta Import Inherited Substring", "team-payments")
        existing = Endpoint.objects.create(host="inherit.example.com", product=product)
        self.assertEqual({"team-payments"}, self.tag_names(existing))

        self.import_csv(
            "hostname,team\ninherit.example.com,red\nnew-inherit.example.com,red\nnew-inherit.example.com,blue\n",
            product=product.id,
        )

        existing.refresh_from_db()
        self.assertEqual({"team-payments", "team:red"}, self.tag_names(existing))
        self.assertEqual({"team-payments"}, self.tag_names(existing, "inherited_tags"))
        created = Endpoint.objects.get(host="new-inherit.example.com", product=product)
        # The second row replaced the inherited tag again (it sorts first), not "team:red".
        self.assertEqual({"team-payments", "team:red", "team:blue"}, self.tag_names(created))
        self.assertEqual({"team-payments"}, self.tag_names(created, "inherited_tags"))

    def test_host_whose_python_and_database_lowercase_differ_is_matched(self):
        # Python lowercases a dotted capital I differently from Postgres LOWER(); matching
        # must still find the existing endpoint instead of creating a second one.
        existing = Endpoint.objects.create(host="İstanbul.example.com", product=self.product)
        self.import_csv("hostname,team\nİstanbul.example.com,red\n", product=self.product.id)
        self.assertEqual(1, Endpoint.objects.filter(host="İstanbul.example.com", product=self.product).count())
        self.assertEqual({"team": "red"}, self.meta(existing))


@skip_unless_v3
class EndpointMetaImportLocationQueryCountTest(EndpointMetaImportQueryCountMixin, DojoAPITestCase):
    fixtures = ["dojo_testdata_locations.json"]

    def test_query_count_does_not_grow_with_rows(self):
        self.warm_up()
        small_hosts = [f"small{i}.example.com" for i in range(10)]
        large_hosts = [f"large{i}.example.com" for i in range(40)]
        # Creating a Location still goes through the URL and product-reference helpers one
        # host at a time, so only passes over existing locations are measured.
        self.import_csv(build_csv(small_hosts + large_hosts, VALUES_A))

        self.assert_constant(
            self.count_import_queries(small_hosts, VALUES_B),
            self.count_import_queries(large_hosts, VALUES_B),
            "update",
        )
        self.assert_constant(
            self.count_import_queries(small_hosts, VALUES_B),
            self.count_import_queries(large_hosts, VALUES_B),
            "unchanged",
        )
        for location in Location.objects.filter(url__host__in=small_hosts + large_hosts):
            self.assertEqual({"team:blue", "env:qa", "owner:bob"}, {tag.name for tag in location.tags.all()})
            self.assertEqual(
                VALUES_B,
                dict(DojoMeta.objects.filter(location=location, location_product_id=1).values_list("name", "value")),
            )
