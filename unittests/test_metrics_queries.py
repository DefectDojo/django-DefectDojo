"""Tests for metrics database queries"""

from datetime import date, datetime, timezone
from unittest.mock import patch

import pytz
from django.test import RequestFactory
from django.urls import reverse

from dojo.metrics import utils
from dojo.models import User

from .dojo_test_case import DojoTestCase


class MockMessages:
    def add(*args, **kwargs):
        pass


####
# Test Findings data
####
FINDING_1 = {"id": 4, "title": "High Impact Test Finding", "date": date(2018, 1, 1), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "High", "description": "test finding", "mitigation": "test mitigation", "impact": "High", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 3, "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 2, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "5d368a051fdec959e08315a32ef633ba5711bed6e8e75319ddee2cab4d4608c7", "line": None, "file_path": "", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": None, "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_2 = {"id": 5, "title": "High Impact Test Finding", "date": date(2018, 1, 1), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "High", "description": "test finding", "mitigation": "test mitigation", "impact": "High", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 3, "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 2, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "5d368a051fdec959e08315a32ef633ba5711bed6e8e75319ddee2cab4d4608c7", "line": None, "file_path": "", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": None, "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_3 = {"id": 6, "title": "High Impact Test Finding", "date": date(2018, 1, 1), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "High", "description": "test finding", "mitigation": "test mitigation", "impact": "High", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 3, "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 2, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "5d368a051fdec959e08315a32ef633ba5711bed6e8e75319ddee2cab4d4608c7", "line": None, "file_path": "", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": None, "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_4 = {"id": 7, "title": "DUMMY FINDING", "date": date(2017, 12, 31), "sla_start_date": None, "sla_expiration_date": None, "cwe": 1, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": "http://www.example.com", "severity": "High", "description": "TEST finding", "mitigation": "MITIGATION", "impact": "High", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 3, "active": False, "verified": False, "false_p": False, "duplicate": False, "duplicate_finding_id": None, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 2, "under_defect_review": False, "defect_review_requested_by_id": 2, "is_mitigated": False, "thread_id": 1, "mitigated": None, "mitigated_by_id": None, "reporter_id": 2, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "c89d25e445b088ba339908f68e15e3177b78d22f3039d1bfea51c4be251bf4e0", "line": 100, "file_path": "", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": None, "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_5 = {"id": 24, "title": "Low Impact Test Finding", "date": date(2018, 1, 1), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "Low", "description": "test finding", "mitigation": "test mitigation", "impact": "Low", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 33, "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 22, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "9aca00affd340c4da02c934e7e3106a45c6ad0911da479daae421b3b28a2c1aa", "line": 123, "file_path": "/dev/urandom", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": None, "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_6 = {"id": 125, "title": "Low Impact Test Finding", "date": date(2018, 1, 1), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "Low", "description": "test finding", "mitigation": "test mitigation", "impact": "Low", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 55, "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": None, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "9aca00affd340c4da02c934e7e3106a45c6ad0911da479daae421b3b28a2c1aa", "line": 123, "file_path": "/dev/urandom", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": "12345", "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_7 = {"id": 225, "title": "UID Impact Test Finding", "date": date(2018, 1, 1), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "Low", "description": "test finding", "mitigation": "test mitigation", "impact": "Low", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 77, "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 224, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "6f8d0bf970c14175e597843f4679769a4775742549d90f902ff803de9244c7e1", "line": 123, "file_path": "/dev/urandom", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": "6789", "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_8 = {"id": 240, "title": "High Impact Test Finding", "date": date(2018, 1, 1), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "High", "description": "test finding", "mitigation": "test mitigation", "impact": "High", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 3, "active": True, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 2, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "5d368a051fdec959e08315a32ef633ba5711bed6e8e75319ddee2cab4d4608c7", "line": None, "file_path": "", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": None, "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_9 = {"id": 241, "title": "High Impact Test Finding", "date": date(2018, 1, 1), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "High", "description": "test finding", "mitigation": "test mitigation", "impact": "High", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 3, "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 2, "out_of_scope": False, "risk_accepted": True, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "5d368a051fdec959e08315a32ef633ba5711bed6e8e75319ddee2cab4d4608c7", "line": None, "file_path": "", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": None, "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_10 = {"id": 242, "title": "High Impact Test Finding", "date": date(2018, 1, 1), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "High", "description": "test finding", "mitigation": "test mitigation", "impact": "High", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 3, "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 2, "out_of_scope": False, "risk_accepted": True, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "5d368a051fdec959e08315a32ef633ba5711bed6e8e75319ddee2cab4d4608c7", "line": None, "file_path": "", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": None, "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_11 = {"id": 243, "title": "DUMMY FINDING", "date": date(2017, 12, 31), "sla_start_date": None, "sla_expiration_date": None, "cwe": 1, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": "http://www.example.com", "severity": "High", "description": "TEST finding", "mitigation": "MITIGATION", "impact": "High", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 3, "active": False, "verified": False, "false_p": False, "duplicate": False, "duplicate_finding_id": None, "out_of_scope": False, "risk_accepted": True, "under_review": False, "last_status_update": None, "review_requested_by_id": 2, "under_defect_review": False, "defect_review_requested_by_id": 2, "is_mitigated": True, "thread_id": 1, "mitigated": None, "mitigated_by_id": None, "reporter_id": 2, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "c89d25e445b088ba339908f68e15e3177b78d22f3039d1bfea51c4be251bf4e0", "line": 100, "file_path": "", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": None, "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_12 = {"id": 244, "title": "Low Impact Test Finding", "date": date(2017, 12, 29), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "Low", "description": "test finding", "mitigation": "test mitigation", "impact": "Low", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 33, "active": True, "verified": True, "false_p": False, "duplicate": False, "duplicate_finding_id": None, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "9aca00affd340c4da02c934e7e3106a45c6ad0911da479daae421b3b28a2c1aa", "line": 123, "file_path": "/dev/urandom", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": None, "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_13 = {"id": 245, "title": "Low Impact Test Finding", "date": date(2017, 12, 27), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "Low", "description": "test finding", "mitigation": "test mitigation", "impact": "Low", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 33, "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 22, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "9aca00affd340c4da02c934e7e3106a45c6ad0911da479daae421b3b28a2c1aa", "line": 123, "file_path": "/dev/urandom", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": None, "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_14 = {"id": 246, "title": "Low Impact Test Finding", "date": date(2018, 1, 2), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "Low", "description": "test finding", "mitigation": "test mitigation", "impact": "Low", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 33, "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 22, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "9aca00affd340c4da02c934e7e3106a45c6ad0911da479daae421b3b28a2c1aa", "line": 123, "file_path": "/dev/urandom", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": None, "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_15 = {"id": 247, "title": "Low Impact Test Finding", "date": date(2018, 1, 3), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "Low", "description": "test finding", "mitigation": "test mitigation", "impact": "Low", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 55, "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": None, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "9aca00affd340c4da02c934e7e3106a45c6ad0911da479daae421b3b28a2c1aa", "line": 123, "file_path": "/dev/urandom", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": "12345", "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_16 = {"id": 248, "title": "UID Impact Test Finding", "date": date(2017, 12, 27), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "Low", "description": "test finding", "mitigation": "test mitigation", "impact": "Low", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 77, "active": True, "verified": True, "false_p": False, "duplicate": False, "duplicate_finding_id": None, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": True, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "6f8d0bf970c14175e597843f4679769a4775742549d90f902ff803de9244c7e1", "line": 123, "file_path": "/dev/urandom", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": "6789", "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}
FINDING_17 = {"id": 249, "title": "UID Impact Test Finding", "date": date(2018, 1, 4), "sla_start_date": None, "sla_expiration_date": None, "cwe": None, "cve": None, "epss_score": None, "epss_percentile": None, "cvssv3": None, "cvssv3_score": None, "url": None, "severity": "Low", "description": "test finding", "mitigation": "test mitigation", "impact": "Low", "steps_to_reproduce": None, "severity_justification": None, "references": "", "test_id": 77, "active": False, "verified": False, "false_p": False, "duplicate": True, "duplicate_finding_id": 224, "out_of_scope": False, "risk_accepted": False, "under_review": False, "last_status_update": None, "review_requested_by_id": 1, "under_defect_review": False, "defect_review_requested_by_id": 1, "is_mitigated": False, "thread_id": 11, "mitigated": None, "mitigated_by_id": None, "reporter_id": 1, "numerical_severity": "S0", "last_reviewed": None, "last_reviewed_by_id": None, "param": None, "payload": None, "hash_code": "6f8d0bf970c14175e597843f4679769a4775742549d90f902ff803de9244c7e1", "line": 123, "file_path": "/dev/urandom", "component_name": None, "component_version": None, "static_finding": False, "dynamic_finding": False, "created": datetime(2017, 12, 1, 0, 0, tzinfo=timezone.utc), "scanner_confidence": None, "sonarqube_issue_id": None, "unique_id_from_tool": "6789", "vuln_id_from_tool": None, "sast_source_object": None, "sast_sink_object": None, "sast_source_line": None, "sast_source_file_path": None, "nb_occurences": None, "publish_date": None, "service": None, "planned_remediation_date": None, "planned_remediation_version": None, "effort_for_fixing": None, "test__engagement__product__prod_type__member": False, "test__engagement__product__member": True, "test__engagement__product__prod_type__authorized_group": False, "test__engagement__product__authorized_group": False}


ALL_FINDINGS = [FINDING_1, FINDING_2, FINDING_3, FINDING_4, FINDING_5, FINDING_6, FINDING_7, FINDING_8, FINDING_9,
                FINDING_10, FINDING_11, FINDING_12, FINDING_13, FINDING_14, FINDING_15, FINDING_16, FINDING_17]
CLOSED_FINDINGS = [FINDING_11, FINDING_16]
ACCEPTED_FINDINGS = [FINDING_9, FINDING_10, FINDING_11]


class FindingQueriesTest(DojoTestCase):
    fixtures = ["dojo_testdata.json", "unit_metrics_additional_data.json"]

    def setUp(self):
        user = User.objects.get(username="user1")
        self.request = RequestFactory().get(reverse("metrics"), {
            "start_date": "2017-12-26",
            "end_date": "2018-01-05",
        })
        self.request.user = user
        self.request._messages = MockMessages()

    def test_finding_queries_no_data(self):
        user3 = User.objects.get(username="user3")
        self.request.user = user3

        product_types = []
        finding_queries = utils.finding_queries(
            product_types,
            self.request,
        )

        self.assertSequenceEqual(
            finding_queries["all"].values(),
            [],
        )

    @patch("django.utils.timezone.now")
    def test_finding_queries(self, mock_timezone):
        mock_datetime = datetime(2020, 12, 9, tzinfo=timezone.utc)
        mock_timezone.return_value = mock_datetime

        # Queries over Finding
        with self.assertNumQueries(27):
            product_types = []
            finding_queries = utils.finding_queries(
                product_types,
                self.request,
            )
            self.assertSequenceEqual(
                list(finding_queries.keys()),
                [
                    "all",
                    "closed",
                    "accepted",
                    "accepted_count",
                    "top_ten",
                    "monthly_counts",
                    "weekly_counts",
                    "weeks_between",
                    "start_date",
                    "end_date",
                    "form",
                ],
            )
            # Assert that we get expected querysets back. This is to be used to
            # support refactoring, in attempt of lowering the query count.
            self.assertSequenceEqual(finding_queries["all"].values(), ALL_FINDINGS)
            self.assertSequenceEqual(finding_queries["closed"].values(), CLOSED_FINDINGS)
            self.assertSequenceEqual(finding_queries["accepted"].values(), ACCEPTED_FINDINGS)

            self.assertSequenceEqual(
                finding_queries["accepted_count"],
                {"total": 3, "critical": 0, "high": 3, "medium": 0, "low": 0, "info": 0},
            )
            self.assertSequenceEqual(
                finding_queries["top_ten"].values(),
                [],
            )
            self.assertEqual(
                finding_queries["monthly_counts"],
                {
                    "opened_per_period": [
                        {"epoch": 1509494400000, "grouped_date": date(2017, 11, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "closed": 0},
                        {"epoch": 1512086400000, "grouped_date": date(2017, 12, 1), "critical": 0, "high": 2, "medium": 0, "low": 3, "info": 0, "total": 5, "closed": 2},
                        {"epoch": 1514764800000, "grouped_date": date(2018, 1, 1), "critical": 0, "high": 6, "medium": 0, "low": 6, "info": 0, "total": 12, "closed": 0},
                    ],
                    "active_per_period": [
                        {"epoch": 1509494400000, "grouped_date": date(2017, 11, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1512086400000, "grouped_date": date(2017, 12, 1), "critical": 0, "high": 0, "medium": 0, "low": 2, "info": 0, "total": 2},
                        {"epoch": 1514764800000, "grouped_date": date(2018, 1, 1), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1},
                    ],
                    "accepted_per_period": [
                        {"epoch": 1509494400000, "grouped_date": date(2017, 11, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1512086400000, "grouped_date": date(2017, 12, 1), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1},
                        {"epoch": 1514764800000, "grouped_date": date(2018, 1, 1), "critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0, "total": 2},
                    ],
                },
            )
            self.assertEqual(
                finding_queries["weekly_counts"],
                {
                    "opened_per_period": [
                        {"epoch": 1513555200000, "grouped_date": date(2017, 12, 18), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "closed": 0},
                        {"epoch": 1514160000000, "grouped_date": date(2017, 12, 25), "critical": 0, "high": 2, "medium": 0, "low": 3, "info": 0, "total": 5, "closed": 2},
                        {"epoch": 1514764800000, "grouped_date": date(2018, 1, 1), "critical": 0, "high": 6, "medium": 0, "low": 6, "info": 0, "total": 12, "closed": 0},
                    ],
                    "active_per_period": [
                        {"epoch": 1513555200000, "grouped_date": date(2017, 12, 18), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1514160000000, "grouped_date": date(2017, 12, 25), "critical": 0, "high": 0, "medium": 0, "low": 2, "info": 0, "total": 2},
                        {"epoch": 1514764800000, "grouped_date": date(2018, 1, 1), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1},
                    ],
                    "accepted_per_period": [
                        {"epoch": 1513555200000, "grouped_date": date(2017, 12, 18), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1514160000000, "grouped_date": date(2017, 12, 25), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "total": 1},
                        {"epoch": 1514764800000, "grouped_date": date(2018, 1, 1), "critical": 0, "high": 2, "medium": 0, "low": 0, "info": 0, "total": 2},
                    ],
                },
            )
            self.assertEqual(finding_queries["weeks_between"], 2)
            self.assertIsInstance(finding_queries["start_date"], datetime)
            self.assertIsInstance(finding_queries["end_date"], datetime)


class EndpointQueriesTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        user = User.objects.get(username="user1")
        self.request = RequestFactory().get(reverse("metrics"))
        self.request.user = user
        self.request._messages = MockMessages()

    def test_endpoint_queries_no_data(self):
        user3 = User.objects.get(username="user3")
        self.request.user = user3

        product_types = []
        endpoint_queries = utils.endpoint_queries(
            product_types,
            self.request,
        )

        self.assertSequenceEqual(
            endpoint_queries["all"].values(),
            [],
        )

    def test_endpoint_queries(self):
        # Queries over Finding and Endpoint_Status
        with self.assertNumQueries(43):
            product_types = []
            endpoint_queries = utils.endpoint_queries(
                product_types,
                self.request,
            )

            self.assertSequenceEqual(
                list(endpoint_queries.keys()),
                [
                    "all",
                    "closed",
                    "accepted",
                    "accepted_count",
                    "top_ten",
                    "monthly_counts",
                    "weekly_counts",
                    "weeks_between",
                    "start_date",
                    "end_date",
                    "form",
                ],
            )

            # Assert that we get expected querysets back. This is to be used to
            # support refactoring, in attempt of lowering the query count.
            self.assertSequenceEqual(
                endpoint_queries["all"].values(),
                [
                    {"id": 1, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": False, "out_of_scope": False, "risk_accepted": False, "endpoint_id": 2, "finding_id": 2, "endpoint__product__prod_type__member": False, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False},
                    {"id": 3, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": True, "out_of_scope": False, "risk_accepted": False, "endpoint_id": 5, "finding_id": 228, "endpoint__product__prod_type__member": True, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False},
                    {"id": 4, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": False, "out_of_scope": True, "risk_accepted": False, "endpoint_id": 5, "finding_id": 229, "endpoint__product__prod_type__member": True, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False},
                    {"id": 5, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": False, "out_of_scope": False, "risk_accepted": True, "endpoint_id": 5, "finding_id": 230, "endpoint__product__prod_type__member": True, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False},
                    {"id": 7, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": False, "out_of_scope": False, "risk_accepted": False, "endpoint_id": 7, "finding_id": 227, "endpoint__product__prod_type__member": True, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False},
                    {"id": 8, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": False, "out_of_scope": False, "risk_accepted": False, "endpoint_id": 8, "finding_id": 231, "endpoint__product__prod_type__member": True, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False},
                ],
            )
            self.assertSequenceEqual(
                endpoint_queries["closed"].values(),
                [],
            )
            self.assertSequenceEqual(
                endpoint_queries["accepted"].values(),
                [{"id": 5, "date": date(2020, 7, 1), "last_modified": datetime(2020, 7, 1, 17, 45, 39, 791907, tzinfo=pytz.UTC), "mitigated": False, "mitigated_time": None, "mitigated_by_id": None, "false_positive": False, "out_of_scope": False, "risk_accepted": True, "endpoint_id": 5, "finding_id": 230, "endpoint__product__prod_type__member": True, "endpoint__product__member": True, "endpoint__product__prod_type__authorized_group": False, "endpoint__product__authorized_group": False}],
            )
            self.assertSequenceEqual(
                list(endpoint_queries["accepted_count"].values()),
                [1, 0, 0, 0, 0, 1],
            )
            self.assertSequenceEqual(
                endpoint_queries["top_ten"].values(),
                [],
            )
            self.assertEqual(
                list(endpoint_queries["monthly_counts"].values()),
                [
                    [
                        {"epoch": 1590969600000, "grouped_date": date(2020, 6, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "closed": 0},
                        {"epoch": 1593561600000, "grouped_date": date(2020, 7, 1), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 5, "total": 6, "closed": 0},
                        {"epoch": 1596240000000, "grouped_date": date(2020, 8, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "closed": 0},
                    ],
                    [
                        {"epoch": 1590969600000, "grouped_date": date(2020, 6, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1593561600000, "grouped_date": date(2020, 7, 1), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 4, "total": 5},
                        {"epoch": 1596240000000, "grouped_date": date(2020, 8, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                    ],
                    [
                        {"epoch": 1590969600000, "grouped_date": date(2020, 6, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1593561600000, "grouped_date": date(2020, 7, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1, "total": 1},
                        {"epoch": 1596240000000, "grouped_date": date(2020, 8, 1), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                    ],
                ],
            )
            self.assertEqual(
                list(endpoint_queries["weekly_counts"].values()),
                [
                    [
                        {"epoch": 1592784000000, "grouped_date": date(2020, 6, 22), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "closed": 0},
                        {"epoch": 1593388800000, "grouped_date": date(2020, 6, 29), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 5, "total": 6, "closed": 0},
                        {"epoch": 1593993600000, "grouped_date": date(2020, 7, 6), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0, "closed": 0},
                    ],
                    [
                        {"epoch": 1592784000000, "grouped_date": date(2020, 6, 22), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1593388800000, "grouped_date": date(2020, 6, 29), "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 4, "total": 5},
                        {"epoch": 1593993600000, "grouped_date": date(2020, 7, 6), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                    ],
                    [
                        {"epoch": 1592784000000, "grouped_date": date(2020, 6, 22), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                        {"epoch": 1593388800000, "grouped_date": date(2020, 6, 29), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 1, "total": 1},
                        {"epoch": 1593993600000, "grouped_date": date(2020, 7, 6), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0},
                    ],
                ],
            )
            self.assertEqual(endpoint_queries["weeks_between"], 2)
            self.assertEqual(endpoint_queries["start_date"], datetime(2020, 7, 1, 0, 0, tzinfo=timezone.utc))
            self.assertEqual(endpoint_queries["end_date"], datetime(2020, 7, 1, 0, 0, tzinfo=timezone.utc))
