from contextlib import nullcontext
from datetime import datetime, timedelta
from unittest.mock import MagicMock, Mock, patch
from types import SimpleNamespace

from django.test import SimpleTestCase
from django.utils import timezone
from rest_framework.parsers import JSONParser
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory

from dojo.api_v2.cross_approval.permissions import IsCrossApprovalReviewer, IsCrossApprovalSubmitter
from dojo.api_v2.cross_approval.helpers import (
    _get_findings,
    check_new_findings_to_cross_approval_exclusion_list,
    delete_cross_approval_request_task,
    revert_cross_approval_exclusion,
)
from dojo.api_v2.cross_approval.serializers import (
    CrossApprovalExclusionSerializer,
    CrossApprovalRequestSerializer,
)
from dojo.api_v2.cross_approval.views import CrossApprovalRequestViewSet
from dojo.engine_tools.cross_approval_views import crossapproval_list


class CrossApprovalExclusionSerializerTest(SimpleTestCase):
    def valid_payload(self):
        return {
            "id": "#sym:vulnerability_id",
            "cve_id": "#sym:vulnerability_id",
            "where": "all",
            "create_date": "2026-08-23",
            "expired_date": "2026-08-24",
            "priority": "high",
            "severity": "medium",
            "hu": "HU-1",
            "reason": "Supplier exception",
            "component": {
                "type": "image",
                "values": ["registry.example.com/base:1.0"],
            },
        }

    def test_accepts_exclusion_payload(self):
        serializer = CrossApprovalExclusionSerializer(data=self.valid_payload())

        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["vulnerability_id"], "#sym:vulnerability_id")
        self.assertEqual(serializer.validated_data["component_type"], "image")
        self.assertEqual(serializer.validated_data["component_values"], ["registry.example.com/base:1.0"])

    def test_defaults_empty_where_to_all(self):
        payload = self.valid_payload()
        payload["where"] = ""
        serializer = CrossApprovalExclusionSerializer(data=payload)

        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["where"], "all")

    def test_accepts_list_values_for_where_priority_and_severity(self):
        payload = self.valid_payload()
        payload["where"] = ["tenable", "prisma", "tenable"]
        payload["priority"] = ["high", "critical", "high"]
        payload["severity"] = ["medium", "critical"]
        with patch(
            "dojo.api_v2.cross_approval.serializers.GeneralSettings.get_value",
            return_value=["tenable", "prisma", "gitleaks"],
        ):
            serializer = CrossApprovalExclusionSerializer(data=payload)

            self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.validated_data["where"], "tenable,prisma")
        self.assertEqual(serializer.validated_data["priority"], "high,critical")
        self.assertEqual(serializer.validated_data["severity"], "medium,critical")

    def test_rejects_where_values_not_in_configured_options(self):
        payload = self.valid_payload()
        payload["where"] = "tenable,unknown"
        with patch(
            "dojo.api_v2.cross_approval.serializers.GeneralSettings.get_value",
            return_value=["tenable", "prisma", "gitleaks"],
        ):
            serializer = CrossApprovalExclusionSerializer(data=payload)

            self.assertFalse(serializer.is_valid())
        self.assertIn("where", serializer.errors)
        self.assertIn("unsupported", str(serializer.errors["where"][0]).lower())

    def test_rejects_expired_date_before_create_date(self):
        payload = self.valid_payload()
        payload["expired_date"] = "2026-08-22"
        serializer = CrossApprovalExclusionSerializer(data=payload)

        self.assertFalse(serializer.is_valid())
        self.assertIn("non_field_errors", serializer.errors)

    def test_representation_exposes_component_without_x86_image_name(self):
        exclusion = SimpleNamespace(
            pk=1,
            vulnerability_id="CVE-2026-18374",
            where="all",
            create_date=datetime.strptime("07092026", "%d%m%Y").date(),
            expired_date=datetime.strptime("06112026", "%d%m%Y").date(),
            expired_at=None,
            priority="high",
            severity="medium",
            hu="6580577",
            reason="Ace base image vulnerability",
            component_type="image",
            component_values=[
                "artifactory.apps.bancolombia.com/integracion/ace-mqclient:13.0.8.2-r1"
            ],
        )

        data = CrossApprovalExclusionSerializer(exclusion).data

        self.assertIn("component", data)
        self.assertNotIn("x86.image.name", data)


class CrossApprovalRequestSerializerTest(SimpleTestCase):
    def test_requires_owner(self):
        with patch(
            "dojo.api_v2.cross_approval.serializers.CrossApprovalExclusion.objects.filter"
        ) as exclusions_filter:
            exclusions_filter.return_value.select_related.return_value.first.return_value = None
            serializer = CrossApprovalRequestSerializer(data={
                "exclusions": [CrossApprovalExclusionSerializerTest().valid_payload()],
            })

            self.assertFalse(serializer.is_valid())
            self.assertIn("owner", serializer.errors)

    def test_accepts_owner_field(self):
        with patch(
            "dojo.api_v2.cross_approval.serializers.CrossApprovalExclusion.objects.filter"
        ) as exclusions_filter:
            exclusions_filter.return_value.select_related.return_value.first.return_value = None
            serializer = CrossApprovalRequestSerializer(data={
                "owner": "ace",
                "exclusions": [CrossApprovalExclusionSerializerTest().valid_payload()],
            })

            self.assertTrue(serializer.is_valid(), serializer.errors)
            self.assertEqual(serializer.validated_data["owner"], "ace")

    def test_allows_priority_and_severity_to_be_omitted(self):
        payload = CrossApprovalExclusionSerializerTest().valid_payload()
        payload.pop("priority")
        serializer = CrossApprovalExclusionSerializer(data=payload)

        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_rejects_identical_exclusions_in_one_request(self):
        payload = CrossApprovalExclusionSerializerTest().valid_payload()
        serializer = CrossApprovalRequestSerializer(data={
            "owner": "x86",
            "exclusions": [payload, payload],
        })

        self.assertFalse(serializer.is_valid())
        self.assertIn("exclusions", serializer.errors)

    def test_allows_same_vulnerability_id_with_different_exclusion_fields(self):
        payload = CrossApprovalExclusionSerializerTest().valid_payload()
        second_payload = {**payload, "reason": "Different reason"}
        with patch(
            "dojo.api_v2.cross_approval.serializers.CrossApprovalExclusion.objects.filter"
        ) as exclusions_filter:
            serializer = CrossApprovalRequestSerializer(data={
                "owner": "x86",
                "exclusions": [payload, second_payload],
            })

            self.assertTrue(serializer.is_valid(), serializer.errors)
        exclusions_filter.assert_called_once_with(
            vulnerability_id__in={"#sym:vulnerability_id"},
            request__owner="x86",
        )

    def test_rejects_identical_exclusion_already_created_for_owner(self):
        payload = CrossApprovalExclusionSerializerTest().valid_payload()
        existing_exclusion = SimpleNamespace(
            vulnerability_id="#sym:vulnerability_id",
            component_type="image",
            component_values=["registry.example.com/base:1.0"],
            where="all",
            create_date=datetime.strptime("2026-08-23", "%Y-%m-%d").date(),
            expired_date=datetime.strptime("2026-08-24", "%Y-%m-%d").date(),
            priority="high",
            severity="medium",
            hu="HU-1",
            reason="Supplier exception",
        )
        with patch(
            "dojo.api_v2.cross_approval.serializers.CrossApprovalExclusion.objects.filter"
        ) as exclusions_filter:
            exclusions_filter.return_value.select_related.return_value = [existing_exclusion]
            serializer = CrossApprovalRequestSerializer(data={
                "owner": "x86",
                "exclusions": [payload],
            })

            self.assertFalse(serializer.is_valid())
        self.assertIn("exclusions", serializer.errors)

    def test_conflict_validation_is_scoped_by_owner(self):
        payload = CrossApprovalExclusionSerializerTest().valid_payload()
        with patch(
            "dojo.api_v2.cross_approval.serializers.CrossApprovalExclusion.objects.filter"
        ) as exclusions_filter:
            exclusions_filter.return_value.select_related.return_value.first.return_value = None

            serializer = CrossApprovalRequestSerializer(data={
                "owner": "ace",
                "exclusions": [payload],
            })

            self.assertTrue(serializer.is_valid(), serializer.errors)
            exclusions_filter.assert_called_once_with(
                vulnerability_id__in={"#sym:vulnerability_id"},
                request__owner="ace",
            )


class CrossApprovalHelpersTest(SimpleTestCase):
    def test_get_findings_matches_any_priority_or_severity_and_images(self):
        matching_finding = SimpleNamespace(
            priority_classification="High",
            severity="Low",
        )
        matching_by_severity = SimpleNamespace(
            priority_classification="Medium Low",
            severity="Critical",
        )
        non_matching_finding = SimpleNamespace(
            priority_classification="Medium Low",
            severity="Info",
        )
        findings = MagicMock()
        findings.prefetch_related.return_value = findings
        findings.filter.return_value = findings
        findings.distinct.return_value = findings
        findings.__iter__ = Mock(return_value=iter([
            matching_finding,
            matching_by_severity,
            non_matching_finding,
        ]))
        exclusion = SimpleNamespace(
            vulnerability_id="VULN-1",
            where="tenable, prisma, gitleaks",
            priority="high, very critical",
            severity="critical, medium",
            component_type="image",
            component_values=["registry.example.com/base:1.0"],
        )

        with patch("dojo.api_v2.cross_approval.helpers.Finding.objects.filter", return_value=findings):
            result = _get_findings(exclusion)

        self.assertEqual(result, [matching_finding, matching_by_severity])
        self.assertEqual(findings.filter.call_count, 2)
        findings.distinct.assert_called_once_with()
        self.assertIn("tags__name__iexact", str(findings.filter.call_args_list[1].args[0]))
        self.assertIn("tenable", str(findings.filter.call_args_list[1].args[0]))
        self.assertIn("prisma", str(findings.filter.call_args_list[1].args[0]))
        self.assertIn("gitleaks", str(findings.filter.call_args_list[1].args[0]))

    def test_revert_keeps_whitelist_when_another_active_exclusion_covers_finding(self):
        finding = MagicMock(pk=10)
        exclusion = SimpleNamespace(
            pk=3,
            vulnerability_id="VULN-1",
            request_id=7,
            request=SimpleNamespace(owner="x86"),
        )
        other_exclusion = SimpleNamespace(pk=4)
        findings = MagicMock()
        findings.prefetch_related.return_value = [finding]

        with (
            patch("dojo.api_v2.cross_approval.helpers.get_user"),
            patch("dojo.api_v2.cross_approval.helpers.get_note"),
            patch("dojo.api_v2.cross_approval.helpers.Finding.objects.filter", return_value=findings),
            patch(
                "dojo.api_v2.cross_approval.helpers.CrossApprovalExclusion.objects.filter"
            ) as exclusions_filter,
            patch(
                "dojo.api_v2.cross_approval.helpers._get_findings",
                return_value=[finding],
            ) as get_findings,
        ):
            exclusions_filter.return_value.exclude.return_value = [other_exclusion]
            revert_cross_approval_exclusion(exclusion)

        get_findings.assert_called_once_with(other_exclusion, active_only=False)
        finding.tags.remove.assert_not_called()

    def test_check_new_findings_queues_current_approved_exclusions(self):
        exclusions = [SimpleNamespace(pk=3), SimpleNamespace(pk=5)]

        with (
            patch(
                "dojo.api_v2.cross_approval.helpers.CrossApprovalExclusion.objects.filter",
                return_value=exclusions,
            ),
            patch("dojo.api_v2.cross_approval.helpers.apply_cross_approval_exclusion.delay") as delay,
        ):
            check_new_findings_to_cross_approval_exclusion_list()

        delay.assert_any_call(3)
        delay.assert_any_call(5)
        self.assertEqual(delay.call_count, 2)


class CrossApprovalRequestValidationViewTest(SimpleTestCase):
    def test_post_validates_a_complete_exclusion(self):
        payload = CrossApprovalExclusionSerializerTest().valid_payload()
        request = Request(APIRequestFactory().post(
            "/api/v2/crossapproval_requests/validate-vulnerability-id/",
            {"owner": "x86", "exclusion": payload},
            format="json",
        ), parsers=[JSONParser()])
        with patch(
            "dojo.api_v2.cross_approval.views.find_identical_exclusion",
            return_value=None,
        ) as find_identical:
            response = CrossApprovalRequestViewSet().validate_vulnerability_id(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["vulnerability_id"], "#sym:vulnerability_id")
        self.assertEqual(response.data["conflicts"], [])
        self.assertEqual(find_identical.call_args.args[0], "x86")
        self.assertEqual(
            find_identical.call_args.args[1]["component_values"],
            ["registry.example.com/base:1.0"],
        )

    def test_reports_conflicting_request_id_and_status(self):
        request = Request(APIRequestFactory().get(
            "/api/v2/crossapproval_requests/validate-vulnerability-id/",
            {"vulnerability_id": "VULN-1", "owner": "x86"},
        ))
        exclusion = SimpleNamespace(
            request_id=9,
            request=SimpleNamespace(status="rejected"),
        )
        with patch(
            "dojo.api_v2.cross_approval.views.CrossApprovalExclusion.objects.filter"
        ) as exclusions_filter:
            exclusions_filter.return_value.select_related.return_value = [exclusion]
            response = CrossApprovalRequestViewSet().validate_vulnerability_id(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["conflicts"], [{"request_id": 9, "status": "rejected"}])

    def test_requires_owner_to_validate_vulnerability_id(self):
        request = Request(APIRequestFactory().get(
            "/api/v2/crossapproval_requests/validate-vulnerability-id/",
            {"vulnerability_id": "VULN-1"},
        ))

        response = CrossApprovalRequestViewSet().validate_vulnerability_id(request)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["detail"], "owner is required.")

    def test_lists_owners_from_general_settings_list(self):
        request = Request(APIRequestFactory().get(
            "/api/v2/crossapproval_requests/owners/",
        ))
        with patch(
            "dojo.api_v2.cross_approval.views.GeneralSettings.get_value",
            return_value=["x86", " ace ", "", "x86"],
        ):
            response = CrossApprovalRequestViewSet().owners(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["owners"], ["x86", "ace"])

    def test_lists_default_owners_when_general_settings_is_empty(self):
        request = Request(APIRequestFactory().get(
            "/api/v2/crossapproval_requests/owners/",
        ))
        with patch(
            "dojo.api_v2.cross_approval.views.GeneralSettings.get_value",
            return_value=[],
        ):
            response = CrossApprovalRequestViewSet().owners(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["owners"], ["x86", "ace"])

    def test_lists_where_options_from_general_settings(self):
        request = Request(APIRequestFactory().get(
            "/api/v2/crossapproval_requests/where-options/",
        ))
        with patch(
            "dojo.api_v2.cross_approval.views.GeneralSettings.get_value",
            return_value=["engine_container", " engine_secret ", "", "engine_container"],
        ):
            response = CrossApprovalRequestViewSet().where_options(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["where_options"],
            ["engine_container", "engine_secret"],
        )

    def test_lists_empty_where_options_when_general_settings_is_empty(self):
        request = Request(APIRequestFactory().get(
            "/api/v2/crossapproval_requests/where-options/",
        ))
        with patch(
            "dojo.api_v2.cross_approval.views.GeneralSettings.get_value",
            return_value=[],
        ):
            response = CrossApprovalRequestViewSet().where_options(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["where_options"], [])

    def test_filters_request_queryset_by_id_cve_status_and_owner(self):
        request = Request(APIRequestFactory().get(
            "/api/v2/crossapproval_requests/",
            {"id": "7", "cve": "CVE-1", "status": "approved", "owner": "x86"},
        ))
        queryset = MagicMock()
        queryset.filter.return_value = queryset
        queryset.distinct.return_value = queryset
        view = CrossApprovalRequestViewSet()
        view.request = request

        with patch.object(CrossApprovalRequestViewSet, "queryset", queryset):
            result = view.get_queryset()

        self.assertEqual(result, queryset)
        queryset.filter.assert_any_call(pk="7")
        queryset.filter.assert_any_call(exclusions__vulnerability_id__icontains="CVE-1")
        queryset.filter.assert_any_call(status="approved")
        queryset.filter.assert_any_call(owner__icontains="x86")
        queryset.distinct.assert_called_once_with()

    def test_invalid_request_id_filter_returns_empty_queryset(self):
        request = Request(APIRequestFactory().get(
            "/api/v2/crossapproval_requests/",
            {"id": "not-a-number"},
        ))
        queryset = MagicMock()
        queryset.none.return_value = queryset
        queryset.distinct.return_value = queryset
        view = CrossApprovalRequestViewSet()
        view.request = request

        with patch.object(CrossApprovalRequestViewSet, "queryset", queryset):
            result = view.get_queryset()

        self.assertEqual(result, queryset)
        queryset.none.assert_called_once_with()

    def test_groups_unique_components_across_requests(self):
        active_expiration = timezone.localdate() + timedelta(days=1)
        first_exclusion = SimpleNamespace(
            vulnerability_id="VULN-1",
            component_type="image",
            component_values=["registry.example.com/base:1.0", "registry.example.com/base:1.0"],
            expired_at=None,
            expired_date=active_expiration,
            create_date=datetime.strptime("23082026", "%d%m%Y").date(),
        )
        second_exclusion = SimpleNamespace(
            vulnerability_id="VULN-2",
            component_type="image",
            component_values=["registry.example.com/base:1.0", "registry.example.com/api:2.0"],
            expired_at=None,
            expired_date=active_expiration,
            create_date=datetime.strptime("24082026", "%d%m%Y").date(),
        )
        expired_exclusion = SimpleNamespace(
            vulnerability_id="VULN-3",
            component_type="image",
            component_values=["registry.example.com/base:1.0"],
            expired_at=timezone.now(),
            expired_date=active_expiration,
        )
        date_expired_exclusion = SimpleNamespace(
            vulnerability_id="VULN-4",
            component_type="image",
            component_values=["registry.example.com/base:1.0"],
            expired_at=None,
            expired_date=timezone.localdate() - timedelta(days=1),
        )
        requests = [
            SimpleNamespace(
                owner="x86",
                exclusions=SimpleNamespace(
                    all=Mock(return_value=[first_exclusion, expired_exclusion])
                ),
            ),
            SimpleNamespace(
                owner="ace",
                exclusions=SimpleNamespace(
                    all=Mock(return_value=[second_exclusion, date_expired_exclusion])
                ),
            ),
        ]
        queryset = MagicMock()
        approved_queryset = MagicMock()
        queryset.filter.return_value = approved_queryset
        approved_queryset.prefetch_related.return_value = requests
        view = CrossApprovalRequestViewSet()
        view.get_queryset = Mock(return_value=queryset)
        view.filter_queryset = Mock(return_value=queryset)
        view.paginate_queryset = Mock(return_value=[
            {
                "owner": "ace",
                "component": {
                    "type": "image",
                    "values": ["registry.example.com/base:1.0"],
                },
                "added_date": "24082026",
                "exclusion_count": 1,
                "vulnerability_exclusions": [
                    {"vulnerability_id": "VULN-2", "exclusions": [{"cve_id": "VULN-2"}]},
                ],
            },
            {
                "owner": "x86",
                "component": {
                    "type": "image",
                    "values": ["registry.example.com/base:1.0"],
                },
                "added_date": "23082026",
                "exclusion_count": 1,
                "vulnerability_exclusions": [
                    {"vulnerability_id": "VULN-1", "exclusions": [{"cve_id": "VULN-1"}]},
                ],
            },
        ])
        view.get_paginated_response = Mock(
            return_value=Response(
                {
                    "count": 2,
                    "next": None,
                    "previous": None,
                    "results": [
                        {
                            "owner": "ace",
                            "component": {
                                "type": "image",
                                "values": ["registry.example.com/base:1.0"],
                            },
                            "added_date": "24082026",
                            "exclusion_count": 1,
                            "vulnerability_exclusions": [
                                {"vulnerability_id": "VULN-2", "exclusions": [{"cve_id": "VULN-2"}]},
                            ],
                        },
                        {
                            "owner": "x86",
                            "component": {
                                "type": "image",
                                "values": ["registry.example.com/base:1.0"],
                            },
                            "added_date": "23082026",
                            "exclusion_count": 1,
                            "vulnerability_exclusions": [
                                {"vulnerability_id": "VULN-1", "exclusions": [{"cve_id": "VULN-1"}]},
                            ],
                        }
                    ],
                }
            )
        )

        with patch(
            "dojo.api_v2.cross_approval.views.CrossApprovalExclusionSerializer",
            side_effect=lambda exclusion: SimpleNamespace(
                data={
                    "id": exclusion.vulnerability_id,
                    "component": {
                        "type": exclusion.component_type,
                        "values": exclusion.component_values,
                    },
                }
            ),
        ):
            response = view.components(Request(APIRequestFactory().get(
                "/api/v2/crossapproval_requests/components/",
                {"component_value": "base", "component_type": "image"},
            )))

        self.assertEqual(response.status_code, 200)
        queryset.filter.assert_called_once_with(status="approved")
        self.assertEqual(response.data["count"], 2)
        self.assertEqual(response.data["next"], None)
        self.assertEqual(response.data["previous"], None)
        self.assertEqual(len(response.data["results"]), 2)
        self.assertEqual(
            {result["owner"] for result in response.data["results"]},
            {"ace", "x86"},
        )

    def test_components_filters_by_owner_and_returns_added_date(self):
        active_expiration = timezone.localdate() + timedelta(days=1)
        x86_exclusion = SimpleNamespace(
            vulnerability_id="VULN-1",
            component_type="image",
            component_values=["registry.example.com/base:1.0"],
            expired_at=None,
            expired_date=active_expiration,
            create_date=datetime.strptime("23082026", "%d%m%Y").date(),
        )
        ace_exclusion = SimpleNamespace(
            vulnerability_id="VULN-2",
            component_type="image",
            component_values=["registry.example.com/base:1.0"],
            expired_at=None,
            expired_date=active_expiration,
            create_date=datetime.strptime("24082026", "%d%m%Y").date(),
        )
        requests = [
            SimpleNamespace(
                owner="x86",
                exclusions=SimpleNamespace(all=Mock(return_value=[x86_exclusion])),
            ),
            SimpleNamespace(
                owner="ace",
                exclusions=SimpleNamespace(all=Mock(return_value=[ace_exclusion])),
            ),
        ]
        queryset = MagicMock()
        approved_queryset = MagicMock()
        queryset.filter.return_value = approved_queryset
        approved_queryset.prefetch_related.return_value = requests
        view = CrossApprovalRequestViewSet()
        view.get_queryset = Mock(return_value=queryset)
        view.filter_queryset = Mock(return_value=queryset)
        view.paginate_queryset = Mock(return_value=None)

        with patch(
            "dojo.api_v2.cross_approval.views.CrossApprovalExclusionSerializer",
            side_effect=lambda exclusion: SimpleNamespace(
                data={
                    "id": exclusion.vulnerability_id,
                    "cve_id": exclusion.vulnerability_id,
                    "component": {
                        "type": exclusion.component_type,
                        "values": exclusion.component_values,
                    },
                }
            ),
        ):
            response = view.components(Request(APIRequestFactory().get(
                "/api/v2/crossapproval_requests/components/",
                {"component_type": "image", "owner": "x86"},
            )))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]["owner"], "x86")
        self.assertEqual(response.data[0]["added_date"], "23082026")


class CrossApprovalPermissionTest(SimpleTestCase):
    def _user(self):
        return SimpleNamespace(
            is_superuser=False,
            groups=SimpleNamespace(filter=Mock(return_value=SimpleNamespace(exists=Mock(return_value=False)))),
        )

    def test_submitter_permission_uses_configured_cross_approval_groups(self):
        user = self._user()
        with (
            patch(
                "dojo.api_v2.cross_approval.permissions.GeneralSettings.get_value",
                return_value=["cross-approval-group"],
            ),
            patch(
                "dojo.api_v2.cross_approval.permissions._is_in_group",
                return_value=True,
            ) as is_in_group,
        ):
            result = IsCrossApprovalSubmitter().has_permission(SimpleNamespace(user=user), None)

        self.assertTrue(result)
        is_in_group.assert_called_once_with(user, "cross-approval-group")

    def test_reviewer_permission_is_separate_from_submitter_permission(self):
        user = self._user()
        request = SimpleNamespace(user=user)

        with patch(
            "dojo.api_v2.cross_approval.permissions._is_in_group",
            side_effect=lambda current_user, group: group == "reviewers",
        ):
            with patch("dojo.api_v2.cross_approval.permissions.settings.REVIEWER_GROUP_NAME", "reviewers"):
                with patch("dojo.api_v2.cross_approval.permissions.settings.APPROVER_GROUP_NAME", "approvers"):
                    result = IsCrossApprovalReviewer().has_permission(request, None)

        self.assertTrue(result)
 
    def test_cross_approval_html_endpoint_allows_authenticated_readers(self):
        request = APIRequestFactory().get("/cross-approval/")
        request.session = {}
        request.user = SimpleNamespace(
            is_authenticated=True,
            is_superuser=False,
            groups=SimpleNamespace(filter=Mock(return_value=SimpleNamespace(exists=Mock(return_value=False)))),
        )

        with (
            patch("dojo.engine_tools.cross_approval_views.render") as render,
            patch("dojo.engine_tools.cross_approval_views.is_cross_approval_submitter", return_value=False),
            patch("dojo.engine_tools.cross_approval_views.is_cross_approval_reviewer", return_value=False),
        ):
            crossapproval_list(request)

        render.assert_called_once()


class CrossApprovalRequestWorkflowViewTest(SimpleTestCase):
    def _view_for(self, instance):
        view = CrossApprovalRequestViewSet()
        view.get_object = Mock(return_value=instance)
        view.get_serializer = Mock(return_value=SimpleNamespace(data={"id": 7}))
        return view

    def test_approve_records_status_and_queues_exclusions(self):
        instance = SimpleNamespace(pk=7, status="pending", save=Mock())
        view = self._view_for(instance)
        request = SimpleNamespace(user=SimpleNamespace(username="maintainer"))

        with (
            patch("dojo.api_v2.cross_approval.views.log_status_change") as log_change,
            patch("dojo.api_v2.cross_approval.views.apply_request_exclusions") as apply_exclusions,
            patch("dojo.api_v2.cross_approval.views.notify_request_status") as notify,
        ):
            response = view._set_status(request, "approved")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(instance.status, "approved")
        log_change.assert_called_once_with(instance, request.user, "pending", "approved")
        apply_exclusions.assert_called_once_with(instance)
        notify.assert_called_once()

    def test_create_notifies_maintainers(self):
        instance = SimpleNamespace(pk=7)
        serializer = SimpleNamespace(save=Mock(return_value=instance))
        view = CrossApprovalRequestViewSet()

        with patch("dojo.api_v2.cross_approval.views.notify_request_status") as notify:
            view.perform_create(serializer)

        serializer.save.assert_called_once_with()
        notify.assert_called_once_with(
            instance,
            "cross_approval_created",
            "Cross-approval request 7 created",
        )

    def test_destroy_queues_approved_request_deletion_after_commit(self):
        instance = SimpleNamespace(
            pk=7,
            status="approved",
            save=Mock(),
        )
        view = CrossApprovalRequestViewSet()

        with (
            patch("dojo.api_v2.cross_approval.views.transaction.atomic", return_value=nullcontext()),
            patch("dojo.api_v2.cross_approval.views.transaction.on_commit") as on_commit,
            patch("dojo.api_v2.cross_approval.views.delete_cross_approval_request_task.delay") as delete_task,
        ):
            view.perform_destroy(instance)

        self.assertEqual(instance.status, "deleting")
        instance.save.assert_called_once_with(update_fields=["status"])
        on_commit.assert_called_once()
        on_commit.call_args.args[0]()
        delete_task.assert_called_once_with(7, True)

    def test_delete_task_reverts_exclusions_before_deleting_request(self):
        exclusion = SimpleNamespace(pk=3)
        cross_approval_request = SimpleNamespace(
            pk=7,
            exclusions=SimpleNamespace(iterator=Mock(return_value=[exclusion])),
            delete=Mock(),
        )
        request_queryset = SimpleNamespace(first=Mock(return_value=cross_approval_request))

        with (
            patch(
                "dojo.api_v2.cross_approval.helpers.CrossApprovalRequest.objects.filter",
                return_value=request_queryset,
            ),
            patch("dojo.api_v2.cross_approval.helpers.revert_cross_approval_exclusion") as revert,
            patch("dojo.api_v2.cross_approval.helpers.notify_request_status") as notify,
        ):
            delete_cross_approval_request_task.run(7, True)

        revert.assert_called_once_with(exclusion, exclude_request_id=7)
        notify.assert_called_once_with(
            cross_approval_request,
            "cross_approval_deleted",
            "Cross-approval request 7 deleted",
        )
        cross_approval_request.delete.assert_called_once_with()

    def test_expire_exclusion_serializes_a_refreshed_request(self):
        exclusion = SimpleNamespace(pk=3)
        instance = SimpleNamespace(
            pk=7,
            status="approved",
            exclusions=SimpleNamespace(
                filter=Mock(return_value=SimpleNamespace(first=Mock(return_value=exclusion))),
            ),
        )
        refreshed_instance = SimpleNamespace(status="approved")
        view = self._view_for(instance)
        view.get_object.side_effect = [instance, refreshed_instance]
        request = SimpleNamespace(data={"exclusion_id": 3}, user=SimpleNamespace())

        with (
            patch("dojo.api_v2.cross_approval.views.expire_cross_approval_exclusion"),
            patch("dojo.api_v2.cross_approval.views.notify_request_status") as notify,
        ):
            response = view.expire_exclusion(request)

        self.assertEqual(response.status_code, 200)
        notify.assert_called_once_with(
            instance,
            "cross_approval_expired",
            "Cross-approval request 7 exclusion expired",
        )
        view.get_serializer.assert_called_once_with(refreshed_instance)

    def test_expire_request_notifies_maintainers(self):
        instance = SimpleNamespace(pk=7, status="approved")
        view = self._view_for(instance)
        request = SimpleNamespace(user=SimpleNamespace())

        with (
            patch("dojo.api_v2.cross_approval.views.expire_request_exclusions") as expire_request,
            patch("dojo.api_v2.cross_approval.views.notify_request_status") as notify,
        ):
            response = view.expire(request)

        self.assertEqual(response.status_code, 200)
        expire_request.assert_called_once_with(instance)
        notify.assert_called_once_with(
            instance,
            "cross_approval_expired",
            "Cross-approval request 7 expired",
        )

    def test_reopen_exclusion_serializes_a_refreshed_request(self):
        exclusion = SimpleNamespace(pk=3)
        instance = SimpleNamespace(
            pk=7,
            status="approved",
            exclusions=SimpleNamespace(
                filter=Mock(return_value=SimpleNamespace(first=Mock(return_value=exclusion))),
            ),
        )
        refreshed_instance = SimpleNamespace(status="approved")
        view = self._view_for(instance)
        view.get_object.side_effect = [instance, refreshed_instance]
        request = SimpleNamespace(data={"exclusion_id": 3}, user=SimpleNamespace())

        with (
            patch(
                "dojo.api_v2.cross_approval.views.reopen_cross_approval_exclusion",
                return_value=True,
            ),
            patch("dojo.api_v2.cross_approval.views.notify_request_status") as notify,
        ):
            response = view.reopen_exclusion(request)

        self.assertEqual(response.status_code, 200)
        notify.assert_called_once_with(
            instance,
            "cross_approval_reopened",
            "Cross-approval request 7 exclusion reopened",
        )
        view.get_serializer.assert_called_once_with(refreshed_instance)