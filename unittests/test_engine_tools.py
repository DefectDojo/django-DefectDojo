import datetime
from unittest.mock import Mock, patch
from django.test import TestCase
from django.contrib.auth.models import User
from django.conf import settings
from django.utils import timezone
from dojo.models import (
    Finding,
    Test,
    Engagement,
    Product,
    Product_Type,
    Test_Type,
    Dojo_Group,
    Dojo_Group_Member,
    Notes,
    Role,
)
from dojo.engine_tools.models import FindingExclusion, FindingExclusionDiscussion
from dojo.engine_tools.helpers import (
    get_reviewers_members,
    get_approvers_members,
    get_note,
    has_valid_comments,
    check_prisma_and_tenable_cve,
    remove_finding_from_list,
    get_severity_risk_map,
    calculate_priority_epss_kev_finding,
    download_epss_data,
    format_data,
    generate_cve_kev_dict,
    list_and_read_parquet_files_from_s3,
    combine_parquet_dataframes,
)
import pandas as pd
import io
import gzip


class GetReviewersMembersTest(TestCase):
    def setUp(self):
        self.reviewer_group = Dojo_Group.objects.create(
            name=settings.REVIEWER_GROUP_NAME
        )
        self.user1 = User.objects.create_user(
            username="reviewer1", email="reviewer1@test.com"
        )
        self.user2 = User.objects.create_user(
            username="reviewer2", email="reviewer2@test.com"
        )
        self.role, _ = Role.objects.get_or_create(name="Reader")
        Dojo_Group_Member.objects.create(group=self.reviewer_group, user=self.user1, role=self.role)
        Dojo_Group_Member.objects.create(group=self.reviewer_group, user=self.user2, role=self.role)

    def test_get_reviewers_members_returns_usernames(self):
        reviewers = get_reviewers_members()
        self.assertEqual(len(reviewers), 2)
        self.assertIn("reviewer1", reviewers)
        self.assertIn("reviewer2", reviewers)

    def test_get_reviewers_members_empty_group(self):
        self.reviewer_group.dojo_group_member_set.all().delete()
        reviewers = get_reviewers_members()
        self.assertEqual(len(reviewers), 0)


class GetApproversMembersTest(TestCase):
    def setUp(self):
        self.approver_group = Dojo_Group.objects.create(
            name=settings.APPROVER_GROUP_NAME
        )
        self.user1 = User.objects.create_user(
            username="approver1", email="approver1@test.com"
        )
        self.role, _ = Role.objects.get_or_create(name="Writer")
        Dojo_Group_Member.objects.create(group=self.approver_group, user=self.user1, role=self.role)

    def test_get_approvers_members_returns_usernames(self):
        approvers = get_approvers_members()
        self.assertEqual(len(approvers), 1)
        self.assertIn("approver1", approvers)


class GetNoteTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testuser")

    def test_get_note_creates_new_note(self):
        message = "Test note message"
        note = get_note(self.user, message)
        self.assertEqual(note.author, self.user)
        self.assertEqual(note.entry, message)

    def test_get_note_retrieves_existing_note(self):
        message = "Test note message"
        existing_note = Notes.objects.create(author=self.user, entry=message)
        note = get_note(self.user, message)
        self.assertEqual(note.id, existing_note.id)


class HasValidCommentsTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testuser")
        self.superuser = User.objects.create_superuser(
            username="superuser", email="super@test.com", password="password"
        )
        self.product_type = Product_Type.objects.create(name="Test Type")
        self.product = Product.objects.create(
            name="Test Product", prod_type=self.product_type
        )
        self.finding_exclusion = FindingExclusion.objects.create(
            type="white_list",
            unique_id_from_tool="CVE-2021-1234",
            created_by=self.user,
            status="Pending",
        )

    def test_has_valid_comments_superuser_always_true(self):
        result = has_valid_comments(self.finding_exclusion, self.superuser)
        self.assertTrue(result)

    def test_has_valid_comments_with_discussion(self):
        FindingExclusionDiscussion.objects.create(
            finding_exclusion=self.finding_exclusion,
            author=self.user,
            content="Test comment",
        )
        result = has_valid_comments(self.finding_exclusion, self.user)
        self.assertTrue(result)

    def test_has_valid_comments_without_discussion(self):
        result = has_valid_comments(self.finding_exclusion, self.user)
        self.assertFalse(result)


class CheckPrismaAndTenableCVETest(TestCase):
    def setUp(self):
        self.product_type = Product_Type.objects.create(name="Test Type")
        self.product = Product.objects.create(
            name="Test Product", prod_type=self.product_type
        )
        self.engagement = Engagement.objects.create(
            name="Test Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now()
        )
        self.test_type, _ = Test_Type.objects.get_or_create(name="Test Type Check")
        self.test = Test.objects.create(
            title="Test",
            engagement=self.engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now()
        )

    @patch('dojo.engine_tools.helpers.Constants')
    def test_has_prisma_findings(self, mock_constants):
        # Mock the Constants enum values
        mock_constants.TAG_PRISMA.value = "prisma_tag"
        mock_constants.ENGINE_CONTAINER_TAG.value = "container_tag"
        mock_constants.TAG_TENABLE.value = "tenable_tag"
        
        user = User.objects.create_user(username="testuser")
        finding = Finding.objects.create(
            title="Test Finding",
            test=self.test,
            cve="CVE-2021-1234",
            active=True,
            severity="High",
            reporter=user
        )
        finding.tags.add("prisma_tag")

        has_prisma, has_tenable = check_prisma_and_tenable_cve("CVE-2021-1234")
        self.assertTrue(has_prisma)
        self.assertFalse(has_tenable)

    @patch('dojo.engine_tools.helpers.Constants')
    def test_has_tenable_findings(self, mock_constants):
        # Mock the Constants enum values
        mock_constants.TAG_PRISMA.value = "prisma_tag"
        mock_constants.ENGINE_CONTAINER_TAG.value = "container_tag"
        mock_constants.TAG_TENABLE.value = "tenable_tag"
        
        user = User.objects.create_user(username="testuser2")
        finding = Finding.objects.create(
            title="Test Finding",
            test=self.test,
            cve="CVE-2021-1234",
            active=True,
            severity="High",
            reporter=user
        )
        finding.tags.add("tenable_tag")

        has_prisma, has_tenable = check_prisma_and_tenable_cve("CVE-2021-1234")
        self.assertFalse(has_prisma)
        self.assertTrue(has_tenable)


class RemoveFindingFromListTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testuser")
        self.product_type = Product_Type.objects.create(name="Test Type")
        self.product = Product.objects.create(
            name="Test Product", prod_type=self.product_type
        )
        self.engagement = Engagement.objects.create(
            name="Test Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now()
        )
        self.test_type, _ = Test_Type.objects.get_or_create(name="Test Type Remove")
        self.test = Test.objects.create(
            title="Test",
            engagement=self.engagement,
            test_type=self.test_type,
            target_start=timezone.now(),
            target_end=timezone.now()
        )
        self.finding = Finding.objects.create(
            title="Test Finding",
            test=self.test,
            cve="CVE-2021-1234",
            active=False,
            severity="High",
            risk_status="On Whitelist",
            reporter=self.user
        )
        self.finding.tags.add("white_list")
        self.note = Notes.objects.create(author=self.user, entry="Test note")

    def test_remove_from_whitelist(self):
        finding = remove_finding_from_list(self.finding, self.note, "white_list")
        self.assertTrue(finding.active)
        self.assertIsNone(finding.risk_status)
        self.assertNotIn("white_list", finding.tags.get_tag_list())

    def test_remove_from_blacklist(self):
        self.finding.tags.add("black_list")
        self.finding.risk_status = "On Blacklist"
        finding = remove_finding_from_list(self.finding, self.note, "black_list")
        self.assertIsNone(finding.risk_status)
        self.assertNotIn("black_list", finding.tags.get_tag_list())


class GetSeverityRiskMapTest(TestCase):
    @patch('dojo.engine_tools.helpers.settings')
    def test_returns_correct_structure(self, mock_settings):
        mock_settings.PRIORIZATION_FIELD_WEIGHTS = {
            "P_Critical": 1.0,
            "P_High": 0.75,
            "P_Medium": 0.5,
            "P_Low": 0.25,
        }
        risk_map = get_severity_risk_map()
        self.assertIn("Standard", risk_map)
        self.assertIn("Discreet", risk_map)
        self.assertIn("Stable", risk_map)
        self.assertIn("Low", risk_map["Standard"])
        self.assertIn("Medium", risk_map["Standard"])
        self.assertIn("High", risk_map["Standard"])
        self.assertIn("Critical", risk_map["Standard"])

    @patch('dojo.engine_tools.helpers.settings')
    def test_returns_float_values(self, mock_settings):
        mock_settings.PRIORIZATION_FIELD_WEIGHTS = {
            "P_Critical": 1.0,
            "P_High": 0.75,
            "P_Medium": 0.5,
            "P_Low": 0.25,
        }
        risk_map = get_severity_risk_map()
        for severity_type in risk_map.values():
            for value in severity_type.values():
                self.assertIsInstance(value, float)


class DownloadEPSSDataTest(TestCase):
    @patch("dojo.engine_tools.helpers.requests.get")
    def test_download_epss_data_success(self, mock_get):
        # Create mock CSV data with header lines
        csv_data = "#model_version:v2023.03.01,score_date:2025-12-04\ncve,epss,percentile\nCVE-2021-1234,0.5,0.75\nCVE-2021-5678,0.3,0.60"
        compressed_data = gzip.compress(csv_data.encode())

        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = compressed_data
        mock_get.return_value = mock_response

        result = download_epss_data(backward_day=0, cve_cutoff="CVE-2021-0000")

        self.assertIsNotNone(result)
        self.assertIn("CVE-2021-1234", result)
        self.assertEqual(result["CVE-2021-1234"]["epss"], "0.5")
        self.assertEqual(result["CVE-2021-1234"]["percentil"], "0.75")

    @patch("dojo.engine_tools.helpers.requests.get")
    def test_download_epss_data_failure(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = download_epss_data(backward_day=0, cve_cutoff="CVE-2021-0000")
        self.assertIsNone(result)


class FormatDataTest(TestCase):
    def test_format_data_success(self):
        csv_data = "header1,header2\nheader3,header4\nCVE-2021-1234,0.5,0.75\nCVE-2021-5678,0.3,0.60"
        result = format_data(csv_data, "CVE-2021-0000")

        self.assertIsNotNone(result)
        self.assertEqual(len(result), 2)
        self.assertIn("CVE-2021-1234", result)

    def test_format_data_with_cutoff(self):
        csv_data = "header1,header2\nheader3,header4\nCVE-2021-1234,0.5,0.75\nCVE-2020-5678,0.3,0.60"
        result = format_data(csv_data, "CVE-2021-0000")

        self.assertEqual(len(result), 1)
        self.assertIn("CVE-2021-1234", result)
        self.assertNotIn("CVE-2020-5678", result)

    def test_format_data_empty_data(self):
        result = format_data(None, "CVE-2021-0000")
        self.assertIsNone(result)


class GenerateCVEKEVDictTest(TestCase):
    @patch("dojo.engine_tools.helpers.requests.get")
    def test_generate_cve_kev_dict_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "catalogVersion": "1.0",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-1234",
                    "dateAdded": "2021-11-03",
                    "knownRansomwareCampaignUse": "Known",
                },
                {
                    "cveID": "CVE-2021-5678",
                    "dateAdded": "2021-12-01",
                    "knownRansomwareCampaignUse": "Unknown",
                },
            ],
        }
        mock_get.return_value = mock_response

        result = generate_cve_kev_dict()

        self.assertEqual(len(result), 2)
        self.assertIn("CVE-2021-1234", result)
        self.assertEqual(result["CVE-2021-1234"]["dateAdded"], "2021-11-03")
        self.assertTrue(result["CVE-2021-1234"]["knownRansomwareCampaignUse"])
        self.assertFalse(result["CVE-2021-5678"]["knownRansomwareCampaignUse"])

    @patch("dojo.engine_tools.helpers.requests.get")
    def test_generate_cve_kev_dict_failure(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = generate_cve_kev_dict()
        self.assertEqual(result, {})


class ListAndReadParquetFilesFromS3Test(TestCase):
    @patch("dojo.engine_tools.helpers.boto3.client")
    def test_list_and_read_parquet_files_success(self, mock_boto_client):
        # Mock S3 client
        mock_s3 = Mock()
        mock_boto_client.return_value = mock_s3

        # Mock list_objects_v2 response
        mock_s3.list_objects_v2.return_value = {
            "Contents": [
                {
                    "Key": "path/file1.parquet",
                    "LastModified": datetime.datetime.now(),
                    "Size": 1024,
                },
                {
                    "Key": "path/file2.parquet",
                    "LastModified": datetime.datetime.now(),
                    "Size": 2048,
                },
            ]
        }

        # Mock get_object response with parquet data for first file, error for second
        df = pd.DataFrame({"cve": ["CVE-2021-1234"], "prediction": [0.75]})
        buffer = io.BytesIO()
        df.to_parquet(buffer)
        buffer.seek(0)

        # First call succeeds, second fails
        mock_s3.get_object.side_effect = [
            {"Body": Mock(read=lambda: buffer.read())},
            Exception("Could not open Parquet input source '<Buffer>': Parquet file size is 0 bytes")
        ]

        result = list_and_read_parquet_files_from_s3("test-bucket", "path/")

        # Only 1 file was successfully read
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], pd.DataFrame)

    @patch("dojo.engine_tools.helpers.boto3.client")
    def test_list_and_read_parquet_files_no_files(self, mock_boto_client):
        mock_s3 = Mock()
        mock_boto_client.return_value = mock_s3
        mock_s3.list_objects_v2.return_value = {}

        result = list_and_read_parquet_files_from_s3("test-bucket", "path/")
        self.assertEqual(result, [])


class CombineParquetDataframesTest(TestCase):
    def test_combine_dataframes_success(self):
        df1 = pd.DataFrame({"cve": ["CVE-2021-1234"], "prediction": [0.75]})
        df2 = pd.DataFrame({"cve": ["CVE-2021-5678"], "prediction": [0.60]})

        result = combine_parquet_dataframes([df1, df2])

        self.assertEqual(len(result), 2)
        self.assertIn("CVE-2021-1234", result["cve"].values)
        self.assertIn("CVE-2021-5678", result["cve"].values)

    def test_combine_dataframes_empty_list(self):
        result = combine_parquet_dataframes([])
        self.assertTrue(result.empty)


class CalculatePriorityEPSSKEVFindingTest(TestCase):
    def setUp(self):
        self.product_type = Product_Type.objects.create(name="Test Type")
        self.product = Product.objects.create(
            name="Test Product", prod_type=self.product_type
        )
        self.engagement = Engagement.objects.create(
            name="Test Engagement",
            product=self.product,
            target_start=timezone.now(),
            target_end=timezone.now()
        )
        self.test_type, _ = Test_Type.objects.get_or_create(name="Tenable Scan")
        self.test = Test.objects.create(
            title="Test",
            engagement=self.engagement,
            test_type=self.test_type,
            scan_type="Tenable Scan",
            target_start=timezone.now(),
            target_end=timezone.now()
        )
        self.user = User.objects.create_user(username="testuser")
        self.finding = Finding.objects.create(
            title="Test Finding",
            test=self.test,
            cve="CVE-2021-1234",
            active=True,
            severity="High",
            reporter=self.user
        )
        self.finding.tags.add("tenable_tag")

    @patch('dojo.engine_tools.helpers.settings')
    def test_calculate_priority_with_risk_score(self, mock_settings):
        mock_settings.PRIORIZATION_FIELD_WEIGHTS = {
            "P_Critical": 1.0,
            "P_High": 0.75,
            "P_Medium": 0.5,
            "P_Low": 0.25,
        }
        severity_risk_map = get_severity_risk_map()
        df_risk_score = pd.DataFrame(
            {"cve": ["CVE-2021-1234"], "prediction": [8.5]}
        )
        epss_dict = {"CVE-2021-1234": {"epss": "0.5", "percentil": "0.75"}}
        kev_dict = {
            "CVE-2021-1234": {
                "dateAdded": "2021-11-03",
                "knownRansomwareCampaignUse": True,
            }
        }

        result = calculate_priority_epss_kev_finding(
            self.finding, severity_risk_map, df_risk_score, epss_dict, kev_dict
        )

        priority, epss_score, epss_percentile, known_exploited, ransomware_used, kev_date_added, cve_greater = (
            result
        )

        self.assertEqual(priority, 8.5)
        self.assertEqual(epss_score, "0.5")
        self.assertEqual(epss_percentile, "0.75")
        self.assertTrue(known_exploited)
        self.assertTrue(ransomware_used)
        self.assertEqual(kev_date_added, "2021-11-03")
        self.assertEqual(cve_greater, "CVE-2021-1234")

    @patch('dojo.engine_tools.helpers.settings')
    def test_calculate_priority_without_risk_score(self, mock_settings):
        mock_settings.PRIORIZATION_FIELD_WEIGHTS = {
            "P_Critical": 1.0,
            "P_High": 0.75,
            "P_Medium": 0.5,
            "P_Low": 0.25,
        }
        severity_risk_map = get_severity_risk_map()
        df_risk_score = pd.DataFrame()
        epss_dict = {}
        kev_dict = {}

        result = calculate_priority_epss_kev_finding(
            self.finding, severity_risk_map, df_risk_score, epss_dict, kev_dict
        )

        priority = result[0]
        self.assertEqual(priority, severity_risk_map["Standard"]["High"])