import datetime

from django_test_migrations.contrib.unittest_case import MigratorTestCase
from django.utils import timezone


# TODO: These tests can be removed in 2.17.x or later
class TestOptiEndpointStatus(MigratorTestCase):
    migrate_from = ('dojo', '0171_jira_labels_per_product_and_engagement')
    migrate_to = ('dojo', '0172_optimize_usage_of_endpoint_status')

    def prepare(self):
        Product_Type = self.old_state.apps.get_model('dojo', 'Product_Type')
        Product = self.old_state.apps.get_model('dojo', 'Product')
        Engagement = self.old_state.apps.get_model('dojo', 'Engagement')
        Test = self.old_state.apps.get_model('dojo', 'Test')
        Finding = self.old_state.apps.get_model('dojo', 'Finding')
        Endpoint = self.old_state.apps.get_model('dojo', 'Endpoint')
        Endpoint_Status = self.old_state.apps.get_model('dojo', 'Endpoint_Status')

        self.prod_type = Product_Type.objects.create()
        self.product = Product.objects.create(prod_type=self.prod_type)
        self.engagement = Engagement.objects.create(
            product_id=self.product.pk,
            target_start=datetime.datetime(2020, 1, 1, tzinfo=timezone.utc),
            target_end=datetime.datetime(2022, 1, 1, tzinfo=timezone.utc)
        )
        self.test = Test.objects.create(
            engagement_id=self.engagement.pk,
            target_start=datetime.datetime(2020, 1, 1, tzinfo=timezone.utc),
            target_end=datetime.datetime(2022, 1, 1, tzinfo=timezone.utc),
            test_type_id=1
        )
        from django.contrib.auth import get_user_model
        user = get_user_model().objects.create().pk

        self.finding = Finding.objects.create(test_id=self.test.pk, reporter_id=user).pk
        self.endpoint = Endpoint.objects.create(host='foo.bar', product_id=self.product.pk).pk
        self.endpoint_status = Endpoint_Status.objects.create(
                finding_id=self.finding,
                endpoint_id=self.endpoint
        ).pk
        Endpoint.objects.get(id=self.endpoint).endpoint_status.add(
            Endpoint_Status.objects.get(id=self.endpoint_status)
        )
        Finding.objects.get(id=self.finding).endpoint_status.add(
            Endpoint_Status.objects.get(id=self.endpoint_status)
        )
        Finding.objects.get(id=self.finding).endpoints.add(
            Endpoint.objects.get(id=self.endpoint).pk
        )

        self.presudotest_before_migration()

    def case_add_status_endpoint(self, endpoint, status):
        endpoint.endpoint_status.add(status)

    def case_add_status_finding(self, finding, status):
        finding.endpoint_status.add(status)

    def case_from_finding_get_endpoints(self, finding):
        return finding.endpoints.all()

    def case_add_endpoint_finding(self, finding, endpoint):
        finding.endpoints.add(endpoint)

    def case_list_with_status_finding(self, finding):
        return finding.status_finding

    def case_list_with_status_endpoint(self, endpoint):
        return endpoint.status_endpoint

    def presudotest_before_migration(self):
        Finding = self.old_state.apps.get_model('dojo', 'Finding')
        Endpoint = self.old_state.apps.get_model('dojo', 'Endpoint')
        Endpoint_Status = self.old_state.apps.get_model('dojo', 'Endpoint_Status')

        with self.subTest('Old: Add existing EPS to endpoint'):
            self.case_add_status_endpoint(
                Endpoint.objects.get(id=self.endpoint),
                Endpoint_Status.objects.get(id=self.endpoint_status),
            )

        with self.subTest('Old: Add existing EPS to finding'):
            self.case_add_status_finding(
                Finding.objects.get(id=self.finding),
                Endpoint_Status.objects.get(id=self.endpoint_status),
            )

        with self.subTest('Old: From finding get endpoints'):
            ep = self.case_from_finding_get_endpoints(
                Finding.objects.get(id=self.finding),
            ).all()
            self.assertEqual(ep.all().count(), 1, ep)

        with self.subTest('Old: Add existing endpoint to finding'):
            self.case_add_endpoint_finding(
                Finding.objects.get(id=self.finding),
                Endpoint.objects.get(id=self.endpoint).pk,
            )

        with self.subTest('Old: List EPS from finding'):
            eps = self.case_list_with_status_finding(
                Finding.objects.get(id=self.finding),
            )
            self.assertEqual(eps.all().count(), 1, ep)
            self.assertIsInstance(eps.all().first(), Endpoint_Status)

        with self.subTest('Old: List EPS from endpoint'):
            with self.assertRaises(AttributeError) as exc:
                eps = self.case_list_with_status_endpoint(
                    Endpoint.objects.get(id=self.endpoint),
                )
            self.assertEqual(str(exc.exception), "'Endpoint' object has no attribute 'status_endpoint'")

    def test_after_migration(self):
        Finding = self.new_state.apps.get_model('dojo', 'Finding')
        Endpoint = self.new_state.apps.get_model('dojo', 'Endpoint')
        Endpoint_Status = self.new_state.apps.get_model('dojo', 'Endpoint_Status')

        with self.subTest('New: Add existing EPS to endpoint'):
            with self.assertRaises(AttributeError) as exc:
                self.case_add_status_endpoint(
                    Endpoint.objects.get(id=self.endpoint),
                    Endpoint_Status.objects.get(id=self.endpoint_status),
                )
            self.assertEqual(str(exc.exception), "'Endpoint' object has no attribute 'endpoint_status'")

        with self.subTest('New: Add existing EPS to finding'):
            with self.assertRaises(AttributeError) as exc:
                self.case_add_status_endpoint(
                    Finding.objects.get(id=self.finding),
                    Endpoint_Status.objects.get(id=self.endpoint_status),
                )
            self.assertEqual(str(exc.exception), "'Finding' object has no attribute 'endpoint_status'")

        with self.subTest('New: From finding get endpoints'):
            ep = self.case_from_finding_get_endpoints(
                Finding.objects.get(id=self.finding),
            ).all()
            self.assertEqual(ep.all().count(), 1, ep)

        with self.subTest('New: Add existing endpoint to finding'):
            # Yes, this method is still available. It could create Endpoint_Status with default values
            self.case_add_endpoint_finding(
                Finding.objects.get(id=self.finding),
                Endpoint.objects.get(id=self.endpoint),
            )

        with self.subTest('New: List EPS from finding'):
            eps = self.case_list_with_status_finding(
                Finding.objects.get(id=self.finding),
            )
            self.assertEqual(eps.all().count(), 1, ep)
            self.assertIsInstance(eps.all().first(), Endpoint_Status)

        with self.subTest('New: List EPS from endpoint'):
            eps = self.case_list_with_status_endpoint(
                Endpoint.objects.get(id=self.endpoint),
            )
            self.assertEqual(eps.all().count(), 1, ep)
            self.assertIsInstance(eps.all().first(), Endpoint_Status)
