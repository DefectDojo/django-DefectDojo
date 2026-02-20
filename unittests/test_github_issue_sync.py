import contextlib
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from dojo.github import add_external_issue_github
from dojo.models import (
    Development_Environment,
    Dojo_User,
    Engagement,
    Finding,
    GITHUB_Conf,
    GITHUB_PKey,
    Product,
    Product_Type,
    Test,
    Test_Type,
)


class TestGHESupport(TestCase):
    def setUp(self):
        self.conf = GITHUB_Conf.objects.create(
            configuration_name="GHE Test",
            api_key="ghp_123",
            base_url="https://ghe.example.com/api/v3",
        )

        self.user, _ = Dojo_User.objects.get_or_create(username="admin", is_superuser=True)
        self.ptype = Product_Type.objects.create(name="Test Type")

        self.prod = Product.objects.create(
            name="Test Product",
            prod_type=self.ptype,
        )

        self.test_type = Test_Type.objects.create(name="Manual Code Review")
        self.dev_env = Development_Environment.objects.create(name="Development")
        self.eng = Engagement.objects.create(product=self.prod, target_start=timezone.now().date(), target_end=timezone.now().date(), engagement_type="Interactive", status="In Progress")
        self.test = Test.objects.create(engagement=self.eng, test_type=self.test_type, environment=self.dev_env, target_start=timezone.now(), target_end=timezone.now())
        self.find = Finding.objects.create(
            test=self.test,
            title="TestFinding",
            severity="High",
            numerical_severity="S1",
            description="Test Description",
            static_finding=True,
            active=True,
            verified=True,
            reporter=self.user,
        )

        GITHUB_PKey.objects.create(
            product=self.prod,
            git_conf=self.conf,
            git_project="my-org/my-repo",
        )

    def test_github_inititalization_with_base_url(self):
        with patch("dojo.github.Github") as mock_github, patch("dojo.utils.get_system_setting") as mock_setting:
            mock_setting.return_value = True

            mock_instance = mock_github.return_value
            mock_repo = MagicMock()
            mock_instance.get_repo.return_value = mock_repo

            with contextlib.suppress(Exception):
                add_external_issue_github(self.find, self.prod, self.eng)

            _, kwargs = mock_github.call_args
            self.assertEqual(kwargs.get("base_url"), "https://ghe.example.com/api/v3")
            self.assertEqual(kwargs.get("auth").token, "ghp_123")

    def test_add_issue_works_without_base_url(self):
        """Verify backwards compatibility: no base_url should not pass the argument"""
        with patch("dojo.github.Github") as mock_github, patch("dojo.utils.get_system_setting") as mock_setting:
            mock_setting.return_value = True
            self.conf.base_url = ""
            self.conf.save()

            with contextlib.suppress(Exception):
                add_external_issue_github(self.find, self.prod, self.eng)

            _, kwargs = mock_github.call_args
            self.assertNotIn("base_url", kwargs)
