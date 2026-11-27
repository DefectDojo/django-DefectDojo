"""
``register_prefetch_serializer``: the override point a plugin uses to render a prefetched model with its own serializer.

The prefetcher finds a model's serializer in ``dojo.api_v2.serializers`` only, so without it a plugin whose API renders
a model differently (computed fields read another way) had no way to make ``?prefetch=<field>`` agree with its own
endpoint. A registered serializer is used for the model wherever it is prefetched, and is handed every object of the
model the response prefetches as ``context["prefetched_objects"]``, so it can read what it needs for all of them once.
"""

from types import SimpleNamespace
from unittest import mock

from crum import impersonate
from django.utils.timezone import now
from rest_framework import serializers

from dojo.api_v2 import prefetch_registry as registry
from dojo.api_v2.prefetch import prefetcher as prefetcher_module
from dojo.api_v2.serializers import TestSerializer, UserStubSerializer
from dojo.models import Dojo_User, Engagement, Finding, Product, Product_Type, Test, Test_Type
from unittests.dojo_test_case import DojoTestCase


class _RecordingTestSerializer(TestSerializer):

    """A Test serializer that says it rendered the test, and which tests it was handed."""

    seen = serializers.SerializerMethodField()

    class Meta(TestSerializer.Meta):
        pass

    def get_seen(self, obj):
        return sorted(test.pk for test in self.context["prefetched_objects"])


class _RecordingUserSerializer(UserStubSerializer):

    seen = serializers.SerializerMethodField()

    class Meta(UserStubSerializer.Meta):
        fields = [*UserStubSerializer.Meta.fields, "seen"]

    def get_seen(self, obj):
        return sorted(user.pk for user in self.context["prefetched_objects"])


class PrefetchSerializerRegistryTest(DojoTestCase):

    @classmethod
    def setUpTestData(cls):
        cls.admin = Dojo_User.objects.create(username="prefetch-registry-admin", is_superuser=True, is_staff=True)
        cls.reviewer = Dojo_User.objects.create(username="prefetch-registry-reviewer")
        product = Product.objects.create(
            name="PrefetchRegistry Product",
            description="prefetch serializer registry",
            prod_type=Product_Type.objects.create(name="PrefetchRegistry PT"),
        )
        engagement = Engagement.objects.create(
            name="PrefetchRegistry Engagement", product=product, target_start=now(), target_end=now(),
        )
        test_type = Test_Type.objects.create(name="PrefetchRegistry Scan")
        cls.findings = []
        for i in range(2):
            test = Test.objects.create(engagement=engagement, test_type=test_type, target_start=now(), target_end=now())
            cls.findings.append(Finding.objects.create(
                test=test, title=f"PrefetchRegistry finding {i}", severity="High", reporter=cls.admin,
            ))

    def setUp(self):
        patcher = mock.patch.dict(registry._REGISTERED_SERIALIZERS, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _prefetch(self, entries, fields):
        prefetcher = prefetcher_module._Prefetcher(request=SimpleNamespace(user=self.admin))
        with impersonate(self.admin):
            prefetcher.prefetch_entries(entries, fields)
        return prefetcher.prefetched_data

    def test_without_a_registration_the_module_serializer_is_used(self):
        self.assertIs(prefetcher_module._Prefetcher()._find_serializer(Test), TestSerializer)

    def test_a_registration_without_override_keeps_the_first(self):
        registry.register_prefetch_serializer(Test, _RecordingTestSerializer)
        registry.register_prefetch_serializer(Test, TestSerializer)
        self.assertIs(prefetcher_module._Prefetcher()._find_serializer(Test), _RecordingTestSerializer)

    def test_a_registration_with_override_replaces_it(self):
        registry.register_prefetch_serializer(Test, TestSerializer)
        registry.register_prefetch_serializer(Test, _RecordingTestSerializer, override=True)
        self.assertIs(prefetcher_module._Prefetcher()._find_serializer(Test), _RecordingTestSerializer)

    def test_a_dotted_path_is_imported_on_first_use(self):
        path = f"{__name__}._RecordingTestSerializer"
        registry.register_prefetch_serializer(Test, path)
        self.assertEqual(registry._REGISTERED_SERIALIZERS[Test], path)
        self.assertIs(prefetcher_module._Prefetcher()._find_serializer(Test), _RecordingTestSerializer)
        self.assertIs(registry._REGISTERED_SERIALIZERS[Test], _RecordingTestSerializer)

    def test_a_single_relation_is_rendered_by_the_registered_serializer_with_every_prefetched_object(self):
        registry.register_prefetch_serializer(Test, _RecordingTestSerializer)
        findings = list(Finding.objects.filter(pk__in=[finding.pk for finding in self.findings]).order_by("id"))
        test_ids = sorted({finding.test_id for finding in findings})
        self.assertEqual(len(test_ids), 2)

        data = self._prefetch(findings, ["test"])

        self.assertEqual(sorted(data["test"]), test_ids)
        for rendered in data["test"].values():
            self.assertEqual(rendered["seen"], test_ids)

    def test_a_many_relation_is_rendered_by_the_registered_serializer_with_every_prefetched_object(self):
        registry.register_prefetch_serializer(Dojo_User, _RecordingUserSerializer)
        users = [self.admin, self.reviewer]
        findings = list(Finding.objects.filter(pk__in=[finding.pk for finding in self.findings]).order_by("id"))
        findings[0].reviewers.set(users[:1])
        findings[1].reviewers.set(users)

        data = self._prefetch(findings, ["reviewers"])

        user_ids = sorted(user.pk for user in users)
        self.assertEqual(sorted(data["reviewers"]), user_ids)
        for rendered in data["reviewers"].values():
            self.assertEqual(rendered["seen"], user_ids)
