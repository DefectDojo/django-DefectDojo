"""
Tests for metrics database queries
"""

from datetime import date, datetime, timezone
from unittest.mock import patch
import pytz

from django.test import RequestFactory
from django.urls import reverse

from dojo.metrics import views
from dojo.models import User
from .dojo_test_case import DojoTestCase


class MockMessages:
    def add(*args, **kwargs):
        pass


class FindingQueriesTest(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        user = User.objects.get(username='user1')
        self.request = RequestFactory().get(reverse('metrics'))
        self.request.user = user
        self.request._messages = MockMessages()

    def test_finding_queries_no_data(self):
        user3 = User.objects.get(username='user3')
        self.request.user = user3

        product_types = []
        finding_queries = views.finding_querys(
            product_types,
            self.request
        )

        self.assertSequenceEqual(
            finding_queries['all'].values(),
            [],
        )

    @patch('django.utils.timezone.now')
    def test_finding_queries(self, mock_timezone):
        mock_datetime = datetime(2020, 12, 9, tzinfo=timezone.utc)
        mock_timezone.return_value = mock_datetime

        # Queries over Finding and Risk_Acceptance
        with self.assertNumQueries(36):
            product_types = []
            finding_queries = views.finding_querys(
                product_types,
                self.request
            )

            self.assertSequenceEqual(
                list(finding_queries.keys()),
                [
                    'all',
                    'closed',
                    'accepted',
                    'accepted_count',
                    'top_ten',
                    'monthly_counts',
                    'weekly_counts',
                    'weeks_between',
                    'start_date',
                    'end_date',
                ]
            )

            # Assert that we get expected querysets back. This is to be used to
            # support refactoring, in attempt of lowering the query count.
            self.assertSequenceEqual(
                finding_queries['all'].qs.values(),
                [
                    {'id': 226, 'title': 'Test Endpoint Mitigation - Finding F1 Without Endpoints', 'date': date(2022, 10, 15), 'sla_start_date': None, 'cwe': None, 'cve': None, 'cvssv3': None, 'cvssv3_score': None, 'url': None, 'severity': 'Info', 'description': 'vulnerability', 'mitigation': '', 'impact': '', 'steps_to_reproduce': '', 'severity_justification': '', 'references': '', 'test_id': 89, 'active': True, 'verified': True, 'false_p': False, 'duplicate': False, 'duplicate_finding_id': None, 'out_of_scope': False, 'risk_accepted': False, 'under_review': False, 'last_status_update': None, 'review_requested_by_id': None, 'under_defect_review': False, 'defect_review_requested_by_id': None, 'is_mitigated': False, 'thread_id': 0, 'mitigated': None, 'mitigated_by_id': None, 'reporter_id': 1, 'numerical_severity': 'S4', 'last_reviewed': None, 'last_reviewed_by_id': None, 'param': None, 'payload': None, 'hash_code': 'a6dd6bd359ff0b504a21b8a7ae5e59f1b40dd0fa1715728bd58de8f688f01b19', 'line': None, 'file_path': '', 'component_name': None, 'component_version': None, 'static_finding': False, 'dynamic_finding': True, 'created': datetime(2022, 10, 15, 23, 12, 52, 966000, tzinfo=pytz.UTC), 'scanner_confidence': None, 'sonarqube_issue_id': None, 'unique_id_from_tool': None, 'vuln_id_from_tool': None, 'sast_source_object': None, 'sast_sink_object': None, 'sast_source_line': None, 'sast_source_file_path': None, 'nb_occurences': None, 'publish_date': None, 'service': None, 'planned_remediation_date': None, 'test__engagement__product__prod_type__member': True, 'test__engagement__product__member': True, 'test__engagement__product__prod_type__authorized_group': False, 'test__engagement__product__authorized_group': False},
                    {'id': 227, 'title': 'Test Endpoint Mitigation - Finding F2 With Many Endpoints', 'date': date(2022, 10, 15), 'sla_start_date': None, 'cwe': None, 'cve': None, 'cvssv3': None, 'cvssv3_score': None, 'url': None, 'severity': 'Info', 'description': 'vulnerability', 'mitigation': '', 'impact': '', 'steps_to_reproduce': '', 'severity_justification': '', 'references': '', 'test_id': 89, 'active': True, 'verified': True, 'false_p': False, 'duplicate': False, 'duplicate_finding_id': None, 'out_of_scope': False, 'risk_accepted': False, 'under_review': False, 'last_status_update': None, 'review_requested_by_id': None, 'under_defect_review': False, 'defect_review_requested_by_id': None, 'is_mitigated': False, 'thread_id': 0, 'mitigated': None, 'mitigated_by_id': None, 'reporter_id': 1, 'numerical_severity': 'S4', 'last_reviewed': None, 'last_reviewed_by_id': None, 'param': None, 'payload': None, 'hash_code': 'fde7dd425475851bd90a21e376eccbe753f84f94680c4394521a831846bd3aeb', 'line': None, 'file_path': '', 'component_name': None, 'component_version': None, 'static_finding': False, 'dynamic_finding': True, 'created': datetime(2022, 10, 15, 23, 13, 23, 760000, tzinfo=pytz.UTC), 'scanner_confidence': None, 'sonarqube_issue_id': None, 'unique_id_from_tool': None, 'vuln_id_from_tool': None, 'sast_source_object': None, 'sast_sink_object': None, 'sast_source_line': None, 'sast_source_file_path': None, 'nb_occurences': None, 'publish_date': None, 'service': None, 'planned_remediation_date': None, 'test__engagement__product__prod_type__member': True, 'test__engagement__product__member': True, 'test__engagement__product__prod_type__authorized_group': False, 'test__engagement__product__authorized_group': False},
                    {'id': 228, 'title': 'Test Endpoint Mitigation - Finding F3 EPS False Positive', 'date': date(2022, 10, 15), 'sla_start_date': None, 'cwe': None, 'cve': None, 'cvssv3': None, 'cvssv3_score': None, 'url': None, 'severity': 'Info', 'description': 'vulnerability', 'mitigation': '', 'impact': '', 'steps_to_reproduce': '', 'severity_justification': '', 'references': '', 'test_id': 89, 'active': True, 'verified': True, 'false_p': False, 'duplicate': False, 'duplicate_finding_id': None, 'out_of_scope': False, 'risk_accepted': False, 'under_review': False, 'last_status_update': None, 'review_requested_by_id': None, 'under_defect_review': False, 'defect_review_requested_by_id': None, 'is_mitigated': False, 'thread_id': 0, 'mitigated': None, 'mitigated_by_id': None, 'reporter_id': 1, 'numerical_severity': 'S4', 'last_reviewed': None, 'last_reviewed_by_id': None, 'param': None, 'payload': None, 'hash_code': '24cd769b8b4404d95b689902931317a614c3803bbd5b161e36076eaa6a08c672', 'line': None, 'file_path': '', 'component_name': None, 'component_version': None, 'static_finding': False, 'dynamic_finding': True, 'created': datetime(2022, 10, 15, 23, 13, 49, 275000, tzinfo=pytz.UTC), 'scanner_confidence': None, 'sonarqube_issue_id': None, 'unique_id_from_tool': None, 'vuln_id_from_tool': None, 'sast_source_object': None, 'sast_sink_object': None, 'sast_source_line': None, 'sast_source_file_path': None, 'nb_occurences': None, 'publish_date': None, 'service': None, 'planned_remediation_date': None, 'test__engagement__product__prod_type__member': True, 'test__engagement__product__member': True, 'test__engagement__product__prod_type__authorized_group': False, 'test__engagement__product__authorized_group': False},
                    {'id': 229, 'title': 'Test Endpoint Mitigation - Finding F4 EPS Out of Scope', 'date': date(2022, 10, 15), 'sla_start_date': None, 'cwe': None, 'cve': None, 'cvssv3': None, 'cvssv3_score': None, 'url': None, 'severity': 'Info', 'description': 'vulnerability', 'mitigation': '', 'impact': '', 'steps_to_reproduce': '', 'severity_justification': '', 'references': '', 'test_id': 89, 'active': True, 'verified': True, 'false_p': False, 'duplicate': False, 'duplicate_finding_id': None, 'out_of_scope': False, 'risk_accepted': False, 'under_review': False, 'last_status_update': None, 'review_requested_by_id': None, 'under_defect_review': False, 'defect_review_requested_by_id': None, 'is_mitigated': False, 'thread_id': 0, 'mitigated': None, 'mitigated_by_id': None, 'reporter_id': 1, 'numerical_severity': 'S4', 'last_reviewed': None, 'last_reviewed_by_id': None, 'param': None, 'payload': None, 'hash_code': 'ab2a512956a76441ac537b0e78316709413be2599d37283caa7e20d92f8fa9fe', 'line': None, 'file_path': '', 'component_name': None, 'component_version': None, 'static_finding': False, 'dynamic_finding': True, 'created': datetime(2022, 10, 15, 23, 14, 13, 898000, tzinfo=pytz.UTC), 'scanner_confidence': None, 'sonarqube_issue_id': None, 'unique_id_from_tool': None, 'vuln_id_from_tool': None, 'sast_source_object': None, 'sast_sink_object': None, 'sast_source_line': None, 'sast_source_file_path': None, 'nb_occurences': None, 'publish_date': None, 'service': None, 'planned_remediation_date': None, 'test__engagement__product__prod_type__member': True, 'test__engagement__product__member': True, 'test__engagement__product__prod_type__authorized_group': False, 'test__engagement__product__authorized_group': False},
                    {'id': 230, 'title': 'Test Endpoint Mitigation - Finding F5 EPS Risk Accepted', 'date': date(2022, 10, 15), 'sla_start_date': None, 'cwe': None, 'cve': None, 'cvssv3': None, 'cvssv3_score': None, 'url': None, 'severity': 'Info', 'description': 'vulnerability', 'mitigation': '', 'impact': '', 'steps_to_reproduce': '', 'severity_justification': '', 'references': '', 'test_id': 89, 'active': True, 'verified': True, 'false_p': False, 'duplicate': False, 'duplicate_finding_id': None, 'out_of_scope': False, 'risk_accepted': False, 'under_review': False, 'last_status_update': None, 'review_requested_by_id': None, 'under_defect_review': False, 'defect_review_requested_by_id': None, 'is_mitigated': False, 'thread_id': 0, 'mitigated': None, 'mitigated_by_id': None, 'reporter_id': 1, 'numerical_severity': 'S4', 'last_reviewed': None, 'last_reviewed_by_id': None, 'param': None, 'payload': None, 'hash_code': '9a80eb44b140b5d11adaac4e478f3cb74c92625a42892ab8cba4fbba72e6d733', 'line': None, 'file_path': '', 'component_name': None, 'component_version': None, 'static_finding': False, 'dynamic_finding': True, 'created': datetime(2022, 10, 15, 23, 14, 38, 406000, tzinfo=pytz.UTC), 'scanner_confidence': None, 'sonarqube_issue_id': None, 'unique_id_from_tool': None, 'vuln_id_from_tool': None, 'sast_source_object': None, 'sast_sink_object': None, 'sast_source_line': None, 'sast_source_file_path': None, 'nb_occurences': None, 'publish_date': None, 'service': None, 'planned_remediation_date': None, 'test__engagement__product__prod_type__member': True, 'test__engagement__product__member': True, 'test__engagement__product__prod_type__authorized_group': False, 'test__engagement__product__authorized_group': False},
                    {'id': 231, 'title': 'Test Endpoint Mitigation - Finding F6 Mitigated', 'date': date(2022, 10, 15), 'sla_start_date': None, 'cwe': None, 'cve': None, 'cvssv3': None, 'cvssv3_score': None, 'url': None, 'severity': 'Info', 'description': 'vulnerability', 'mitigation': '', 'impact': '', 'steps_to_reproduce': '', 'severity_justification': '', 'references': '', 'test_id': 89, 'active': False, 'verified': True, 'false_p': False, 'duplicate': False, 'duplicate_finding_id': None, 'out_of_scope': False, 'risk_accepted': False, 'under_review': False, 'last_status_update': None, 'review_requested_by_id': None, 'under_defect_review': False, 'defect_review_requested_by_id': None, 'is_mitigated': True, 'thread_id': 0, 'mitigated': datetime(2022, 10, 15, 23, 17, 3, 431000, tzinfo=pytz.UTC), 'mitigated_by_id': 1, 'reporter_id': 1, 'numerical_severity': 'S4', 'last_reviewed': datetime(2022, 10, 15, 23, 17, 3, 431000, tzinfo=pytz.UTC), 'last_reviewed_by_id': 1, 'param': None, 'payload': None, 'hash_code': '6eb2b8bffe1ca07719a7249ef18403057a5bc0c834866b0a49d0f706bcec913e', 'line': None, 'file_path': '', 'component_name': None, 'component_version': None, 'static_finding': False, 'dynamic_finding': True, 'created': datetime(2022, 10, 15, 23, 15, 34, 814000, tzinfo=pytz.UTC), 'scanner_confidence': None, 'sonarqube_issue_id': None, 'unique_id_from_tool': None, 'vuln_id_from_tool': None, 'sast_source_object': None, 'sast_sink_object': None, 'sast_source_line': None, 'sast_source_file_path': None, 'nb_occurences': None, 'publish_date': None, 'service': None, 'planned_remediation_date': None, 'test__engagement__product__prod_type__member': True, 'test__engagement__product__member': True, 'test__engagement__product__prod_type__authorized_group': False, 'test__engagement__product__authorized_group': False}
                ]
                # [{'id': 226, 'title': 'Test Endpoint Mitigation - Finding F1 Without Endpoints', 'date': date(2022, 10, 15), 'sla_start_date': None, 'cwe': None, 'cve': None, 'cvssv3': None, 'cvssv3_score': None, 'url': None, 'severity': 'Info', 'description': 'vulnerability', 'mitigation': '', 'impact': '', 'steps_to_reproduce': '', 'severity_justification': '', 'references': '', 'test_id': 89, 'active': True, 'verified': True, 'false_p': False, 'duplicate': False, 'duplicate_finding_id': None, 'out_of_scope': False, 'risk_accepted': False, 'under_review': False, 'last_status_update': None, 'review_requested_by_id': None, 'under_defect_review': False, 'defect_review_requested_by_id': None, 'is_mitigated': False, 'thread_id': 0, 'mitigated': None, 'mitigated_by_id': None, 'reporter_id': 1, 'numerical_severity': 'S4', 'last_reviewed': None, 'last_reviewed_by_id': None, 'param': None, 'payload': None, 'hash_code': 'a6dd6bd359ff0b504a21b8a7ae5e59f1b40dd0fa1715728bd58de8f688f01b19', 'line': None, 'file_path': '', 'component_name': None, 'component_version': None, 'static_finding': False, 'dynamic_finding': True, 'created': datetime(2022, 10, 15, 23, 12, 52, 966000, tzinfo=pytz.UTC), 'scanner_confidence': None, 'sonarqube_issue_id': None, 'unique_id_from_tool': None, 'vuln_id_from_tool': None, 'sast_source_object': None, 'sast_sink_object': None, 'sast_source_line': None, 'sast_source_file_path': None, 'nb_occurences': None, 'publish_date': None, 'service': None, 'planned_remediation_date': None, 'test__engagement__product__prod_type__member': True, 'test__engagement__product__member': True, 'test__engagement__product__prod_type__authorized_group': False, 'test__engagement__product__authorized_group': False}]
            )
            self.assertSequenceEqual(
                finding_queries['closed'].values(),
                [{'id': 231, 'title': 'Test Endpoint Mitigation - Finding F6 Mitigated', 'date': date(2022, 10, 15), 'sla_start_date': None, 'cwe': None, 'cve': None, 'cvssv3': None, 'cvssv3_score': None, 'url': None, 'severity': 'Info', 'description': 'vulnerability', 'mitigation': '', 'impact': '', 'steps_to_reproduce': '', 'severity_justification': '', 'references': '', 'test_id': 89, 'active': False, 'verified': True, 'false_p': False, 'duplicate': False, 'duplicate_finding_id': None, 'out_of_scope': False, 'risk_accepted': False, 'under_review': False, 'last_status_update': None, 'review_requested_by_id': None, 'under_defect_review': False, 'defect_review_requested_by_id': None, 'is_mitigated': True, 'thread_id': 0, 'mitigated': datetime(2022, 10, 15, 23, 17, 3, 431000, tzinfo=pytz.UTC), 'mitigated_by_id': 1, 'reporter_id': 1, 'numerical_severity': 'S4', 'last_reviewed': datetime(2022, 10, 15, 23, 17, 3, 431000, tzinfo=pytz.UTC), 'last_reviewed_by_id': 1, 'param': None, 'payload': None, 'hash_code': '6eb2b8bffe1ca07719a7249ef18403057a5bc0c834866b0a49d0f706bcec913e', 'line': None, 'file_path': '', 'component_name': None, 'component_version': None, 'static_finding': False, 'dynamic_finding': True, 'created': datetime(2022, 10, 15, 23, 15, 34, 814000, tzinfo=pytz.UTC), 'scanner_confidence': None, 'sonarqube_issue_id': None, 'unique_id_from_tool': None, 'vuln_id_from_tool': None, 'sast_source_object': None, 'sast_sink_object': None, 'sast_source_line': None, 'sast_source_file_path': None, 'nb_occurences': None, 'publish_date': None, 'service': None, 'planned_remediation_date': None, 'test__engagement__product__prod_type__member': True, 'test__engagement__product__member': True, 'test__engagement__product__prod_type__authorized_group': False, 'test__engagement__product__authorized_group': False}]
            )
            self.assertSequenceEqual(
                finding_queries['accepted'].values(),
                []
            )
            self.assertSequenceEqual(
                list(finding_queries['accepted_count'].values()),
                [None, None, None, None, None, None]
            )
            self.assertSequenceEqual(
                finding_queries['top_ten'].values(),
                []
            )
            self.assertSequenceEqual(
                list(finding_queries['monthly_counts'].values()),
                [
                    [
                        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'],
                        [1661990400000, datetime(2022, 9, 1, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0, 0],
                        [1664582400000, datetime(2022, 10, 1, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0, 1]
                    ],
                    [
                        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'],
                        [1661990400000, datetime(2022, 9, 1, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0],
                        [1664582400000, datetime(2022, 10, 1, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0]
                    ],
                    [
                        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'],
                        [1661990400000, datetime(2022, 9, 1, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0],
                        [1664582400000, datetime(2022, 10, 1, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0]
                    ]
                ]
            )
            self.assertDictEqual(
                finding_queries['weekly_counts'],
                {
                    'opened_per_period': [
                        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'],
                        [1665360000000, datetime(2022, 10, 10, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0, 1],
                        [1665964800000, datetime(2022, 10, 17, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0, 0],
                        [1666569600000, datetime(2022, 10, 24, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0, 0]
                    ],
                    'accepted_per_period': [
                        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'],
                        [1665360000000, datetime(2022, 10, 10, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0],
                        [1665964800000, datetime(2022, 10, 17, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0],
                        [1666569600000, datetime(2022, 10, 24, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0]
                    ],
                    'active_per_period': [
                        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'],
                        [1665360000000, datetime(2022, 10, 10, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0],
                        [1665964800000, datetime(2022, 10, 17, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0],
                        [1666569600000, datetime(2022, 10, 24, 0, 0, tzinfo=pytz.UTC), 0, 0, 0, 0, 0]
                    ]
                }
            )
            self.assertEqual(finding_queries['weeks_between'], 2)
            self.assertIsInstance(finding_queries['start_date'], datetime)
            self.assertIsInstance(finding_queries['end_date'], datetime)


class EndpointQueriesTest(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    def setUp(self):
        user = User.objects.get(username='user1')
        self.request = RequestFactory().get(reverse('metrics'))
        self.request.user = user
        self.request._messages = MockMessages()

    def test_endpoint_queries_no_data(self):
        user3 = User.objects.get(username='user3')
        self.request.user = user3

        product_types = []
        endpoint_queries = views.endpoint_querys(
            product_types,
            self.request
        )

        self.assertSequenceEqual(
            endpoint_queries['all'].values(),
            [],
        )

    def test_endpoint_queries(self):
        # Queries over Finding and Endpoint_Status
        with self.assertNumQueries(69):
            product_types = []
            endpoint_queries = views.endpoint_querys(
                product_types,
                self.request
            )

            self.assertSequenceEqual(
                list(endpoint_queries.keys()),
                [
                    'all',
                    'closed',
                    'accepted',
                    'accepted_count',
                    'top_ten',
                    'monthly_counts',
                    'weekly_counts',
                    'weeks_between',
                    'start_date',
                    'end_date',
                ]
            )

            # Assert that we get expected querysets back. This is to be used to
            # support refactoring, in attempt of lowering the query count.
            self.assertSequenceEqual(
                endpoint_queries['all'].values(),
                [
                    {'id': 1, 'date': date(2020, 7, 1), 'last_modified': datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), 'mitigated': False, 'mitigated_time': None, 'mitigated_by_id': None, 'false_positive': False, 'out_of_scope': False, 'risk_accepted': False, 'endpoint_id': 2, 'finding_id': 2, 'endpoint__product__prod_type__member': False, 'endpoint__product__member': True, 'endpoint__product__prod_type__authorized_group': False, 'endpoint__product__authorized_group': False},
                    {'id': 3, 'date': date(2020, 7, 1), 'last_modified': datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), 'mitigated': False, 'mitigated_time': None, 'mitigated_by_id': None, 'false_positive': True, 'out_of_scope': False, 'risk_accepted': False, 'endpoint_id': 5, 'finding_id': 228, 'endpoint__product__prod_type__member': True, 'endpoint__product__member': True, 'endpoint__product__prod_type__authorized_group': False, 'endpoint__product__authorized_group': False},
                    {'id': 4, 'date': date(2020, 7, 1), 'last_modified': datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), 'mitigated': False, 'mitigated_time': None, 'mitigated_by_id': None, 'false_positive': False, 'out_of_scope': True, 'risk_accepted': False, 'endpoint_id': 5, 'finding_id': 229, 'endpoint__product__prod_type__member': True, 'endpoint__product__member': True, 'endpoint__product__prod_type__authorized_group': False, 'endpoint__product__authorized_group': False},
                    {'id': 5, 'date': date(2020, 7, 1), 'last_modified': datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), 'mitigated': False, 'mitigated_time': None, 'mitigated_by_id': None, 'false_positive': False, 'out_of_scope': False, 'risk_accepted': True, 'endpoint_id': 5, 'finding_id': 230, 'endpoint__product__prod_type__member': True, 'endpoint__product__member': True, 'endpoint__product__prod_type__authorized_group': False, 'endpoint__product__authorized_group': False},
                    {'id': 7, 'date': date(2020, 7, 1), 'last_modified': datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), 'mitigated': False, 'mitigated_time': None, 'mitigated_by_id': None, 'false_positive': False, 'out_of_scope': False, 'risk_accepted': False, 'endpoint_id': 7, 'finding_id': 227, 'endpoint__product__prod_type__member': True, 'endpoint__product__member': True, 'endpoint__product__prod_type__authorized_group': False, 'endpoint__product__authorized_group': False},
                    {'id': 8, 'date': date(2020, 7, 1), 'last_modified': datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), 'mitigated': False, 'mitigated_time': None, 'mitigated_by_id': None, 'false_positive': False, 'out_of_scope': False, 'risk_accepted': False, 'endpoint_id': 8, 'finding_id': 231, 'endpoint__product__prod_type__member': True, 'endpoint__product__member': True, 'endpoint__product__prod_type__authorized_group': False, 'endpoint__product__authorized_group': False}
                ],
            )
            self.assertSequenceEqual(
                endpoint_queries['closed'].values(),
                [],
            )
            self.assertSequenceEqual(
                endpoint_queries['accepted'].values(),
                [{'id': 5, 'date': date(2020, 7, 1), 'last_modified': datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), 'mitigated': False, 'mitigated_time': None, 'mitigated_by_id': None, 'false_positive': False, 'out_of_scope': False, 'risk_accepted': True, 'endpoint_id': 5, 'finding_id': 230, 'endpoint__product__prod_type__member': True, 'endpoint__product__member': True, 'endpoint__product__prod_type__authorized_group': False, 'endpoint__product__authorized_group': False}],
            )
            self.assertSequenceEqual(
                list(endpoint_queries['accepted_count'].values()),
                [1, 0, 0, 0, 0, 1],
            )
            self.assertSequenceEqual(
                endpoint_queries['top_ten'].values(),
                [],
            )
            self.assertSequenceEqual(
                list(endpoint_queries['monthly_counts'].values()),
                [
                    [
                        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'],
                        [1590969600000, datetime(2020, 6, 1, 0, 0, tzinfo=timezone.utc), 0, 0, 0, 0, 0, 0],
                        [1593561600000, datetime(2020, 7, 1, 0, 0, tzinfo=timezone.utc), 0, 1, 0, 0, 1, 0],
                    ],
                    [
                        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'],
                        [1590969600000, datetime(2020, 6, 1, 0, 0, tzinfo=timezone.utc), 0, 0, 0, 0, 0],
                        [1593561600000, datetime(2020, 7, 1, 0, 0, tzinfo=timezone.utc), 0, 0, 0, 0, 0]
                    ],
                    [
                        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'],
                        [1590969600000, datetime(2020, 6, 1, 0, 0, tzinfo=timezone.utc), 0, 0, 0, 0, 0],
                        [1593561600000, datetime(2020, 7, 1, 0, 0, tzinfo=timezone.utc), 0, 1, 0, 0, 1],
                    ]
                ],
            )
            self.assertSequenceEqual(
                list(endpoint_queries['weekly_counts'].values()),
                [
                    [
                        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'],
                        [1593388800000, datetime(2020, 6, 29, 0, 0, tzinfo=timezone.utc), 0, 1, 0, 0, 1, 0],
                        [1593993600000, datetime(2020, 7, 6, 0, 0, tzinfo=timezone.utc), 0, 0, 0, 0, 0, 0],
                        [1594598400000, datetime(2020, 7, 13, 0, 0, tzinfo=timezone.utc), 0, 0, 0, 0, 0, 0]
                    ],
                    [
                        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'],
                        [1593388800000, datetime(2020, 6, 29, 0, 0, tzinfo=timezone.utc), 0, 0, 0, 0, 0],
                        [1593993600000, datetime(2020, 7, 6, 0, 0, tzinfo=timezone.utc), 0, 0, 0, 0, 0],
                        [1594598400000, datetime(2020, 7, 13, 0, 0, tzinfo=timezone.utc), 0, 0, 0, 0, 0]
                    ],
                    [
                        ['Timestamp', 'Date', 'S0', 'S1', 'S2', 'S3', 'Total', 'Closed'],
                        [1593388800000, datetime(2020, 6, 29, 0, 0, tzinfo=timezone.utc), 0, 1, 0, 0, 1],
                        [1593993600000, datetime(2020, 7, 6, 0, 0, tzinfo=timezone.utc), 0, 1, 0, 0, 1],
                        [1594598400000, datetime(2020, 7, 13, 0, 0, tzinfo=timezone.utc), 0, 1, 0, 0, 1]
                    ]
                ],
            )
            self.assertEqual(endpoint_queries['weeks_between'], 2)
            self.assertEqual(endpoint_queries['start_date'], datetime(2020, 7, 1, 0, 0, tzinfo=timezone.utc))
            self.assertEqual(endpoint_queries['end_date'], datetime(2020, 7, 1, 0, 0, tzinfo=timezone.utc))
