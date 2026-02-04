import json
import logging
import time
from importlib import import_module
from importlib.util import find_spec
from inspect import isclass
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError
from django.urls import reverse
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from unittests.test_dashboard import User

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    help = (
        "Reimport a specific unittest scan by filename into an existing test. "
        "Automatically deduces scan type from path."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "test_id",
            type=int,
            help="ID of the test to reimport into",
        )
        parser.add_argument(
            "scan_file",
            type=str,
            help="Path to scan file relative to unittests/scans/ (e.g., 'jfrog_xray_unified/very_many_vulns.json')",
        )
        parser.add_argument(
            "--minimum-severity",
            type=str,
            default="Low",
            choices=["Critical", "High", "Medium", "Low", "Info"],
            help="Minimum severity to import (default: Low)",
        )
        parser.add_argument(
            "--active",
            action="store_true",
            default=True,
            help="Mark findings as active (default: True)",
        )
        parser.add_argument(
            "--verified",
            action="store_true",
            default=False,
            help="Mark findings as verified (default: False)",
        )
        parser.add_argument(
            "--close-old-findings",
            action="store_true",
            default=False,
            help="Close findings not present in the new scan (default: False)",
        )
        parser.add_argument(
            "--tags",
            action="append",
            default=[],
            help=(
                "Tag(s) to apply to the test (repeat --tags to add multiple). "
                "Example: --tags perf --tags jfrog"
            ),
        )

    def get_test_admin(self):
        return User.objects.get(username="admin")

    def reimport_scan(self, payload, expected_http_status_code=201):
        testuser = self.get_test_admin()
        token = Token.objects.get(user=testuser)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        response = client.post(reverse("reimportscan-list"), payload)
        if expected_http_status_code != response.status_code:
            msg = f"Expected HTTP status code {expected_http_status_code}, got {response.status_code}: {response.content[:1000]}"
            raise CommandError(msg)
        return json.loads(response.content)

    def deduce_scan_type_from_path(self, scan_file_path):
        """
        Deduce the scan type from the file path by finding the corresponding parser.

        Args:
            scan_file_path: Path like 'zap/zap_sample.json' or 'jfrog_xray_unified/very_many_vulns.json'

        Returns:
            tuple: (scan_type, parser_class) or raises CommandError if not found

        """
        # Extract the directory name (parser module name)
        path_parts = Path(scan_file_path).parts
        if len(path_parts) < 2:
            msg = f"Scan file path must include directory: {scan_file_path}"
            raise CommandError(msg)

        module_name = path_parts[0]

        # Try to find and load the parser module
        try:
            if not find_spec(f"dojo.tools.{module_name}.parser"):
                msg = f"No parser module found for '{module_name}'"
                raise CommandError(msg)

            module = import_module(f"dojo.tools.{module_name}.parser")

            # Find the parser class
            parser_class = None
            expected_class_name = module_name.replace("_", "") + "parser"

            for attribute_name in dir(module):
                attribute = getattr(module, attribute_name)
                if isclass(attribute) and attribute_name.lower() == expected_class_name:
                    parser_class = attribute
                    break

            if not parser_class:
                msg = f"No parser class found in module '{module_name}'"
                raise CommandError(msg)

            # Get the scan type from the parser
            parser_instance = parser_class()
            scan_types = parser_instance.get_scan_types()

            if not scan_types:
                msg = f"Parser '{module_name}' has no scan types"
                raise CommandError(msg)

            return scan_types[0], parser_class

        except ImportError as e:
            msg = f"Failed to import parser module '{module_name}': {e}"
            raise CommandError(msg)

    def reimport_unittest_scan(self, test_id, scan_file, minimum_severity, active, verified, close_old_findings, tags):
        """
        Reimport a specific unittest scan file into an existing test.

        Args:
            test_id: ID of the test to reimport into
            scan_file: Path to scan file relative to unittests/scans/
            minimum_severity: Minimum severity level
            active: Whether findings should be active
            verified: Whether findings should be verified
            close_old_findings: Whether to close findings not in the new scan
            tags: List of tags to apply

        """
        # Validate scan file exists
        scan_path = Path("unittests/scans") / scan_file
        if not scan_path.exists():
            msg = f"Scan file not found: {scan_path}"
            raise CommandError(msg)

        # Deduce scan type from path
        scan_type, _parser_class = self.deduce_scan_type_from_path(scan_file)

        logger.info(f"Reimporting scan '{scan_file}' using scan type '{scan_type}'")
        logger.info(f"Target: Test ID {test_id}")

        # Reimport the scan
        with scan_path.open(encoding="utf-8") as testfile:
            payload = {
                "test": test_id,
                "minimum_severity": minimum_severity,
                "scan_type": scan_type,
                "file": testfile,
                "version": "1.0.1",
                "active": active,
                "verified": verified,
                "close_old_findings": close_old_findings,
            }

            if tags:
                payload["tags"] = tags

            result = self.reimport_scan(payload)

        logger.info(f"Successfully reimported scan. Test ID: {result.get('test')}")
        logger.info(f"Reimport summary: {result.get('scan_save_message', 'No summary available')}")

        return result

    def handle(self, *args, **options):
        test_id = options["test_id"]
        scan_file = options["scan_file"]
        minimum_severity = options["minimum_severity"]
        active = options["active"]
        verified = options["verified"]
        close_old_findings = options["close_old_findings"]
        tags = options["tags"]

        start_time = time.time()

        try:
            self.reimport_unittest_scan(
                test_id=test_id,
                scan_file=scan_file,
                minimum_severity=minimum_severity,
                active=active,
                verified=verified,
                close_old_findings=close_old_findings,
                tags=tags,
            )

            end_time = time.time()
            duration = end_time - start_time

            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully reimported '{scan_file}' into test ID {test_id} "
                    f"(took {duration:.2f} seconds)",
                ),
            )

        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            logger.exception(f"Failed to reimport scan '{scan_file}' after {duration:.2f} seconds")
            msg = f"Reimport failed after {duration:.2f} seconds: {e}"
            raise CommandError(msg)
