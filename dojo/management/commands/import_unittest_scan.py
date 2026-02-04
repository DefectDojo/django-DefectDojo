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
        "Import a specific unittest scan by filename. "
        "Automatically deduces scan type from path and creates product/engagement using auto_create_context."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "scan_file",
            type=str,
            help="Path to scan file relative to unittests/scans/ (e.g., 'zap/zap_sample.json')",
        )
        parser.add_argument(
            "--product-name",
            type=str,
            default="command import",
            help="Product name to import into (default: 'command import')",
        )
        parser.add_argument(
            "--engagement-name",
            type=str,
            default="command import",
            help="Engagement name to import into (default: 'command import')",
        )
        parser.add_argument(
            "--product-type-name",
            type=str,
            default="command import",
            help="Product type name to use (default: 'command import')",
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
            "--tags",
            action="append",
            default=[],
            help=(
                "Tag(s) to apply to the imported Test (repeat --tags to add multiple). "
                "Example: --tags perf --tags jfrog"
            ),
        )

    def get_test_admin(self):
        return User.objects.get(username="admin")

    def import_scan(self, payload, expected_http_status_code=201):
        testuser = self.get_test_admin()
        token = Token.objects.get(user=testuser)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        response = client.post(reverse("importscan-list"), payload)
        if expected_http_status_code != response.status_code:
            msg = f"Expected HTTP status code {expected_http_status_code}, got {response.status_code}: {response.content[:1000]}"
            raise CommandError(msg)
        return json.loads(response.content)

    def deduce_scan_type_from_path(self, scan_file_path):
        """
        Deduce the scan type from the file path by finding the corresponding parser.

        Args:
            scan_file_path: Path like 'zap/zap_sample.json' or 'stackhawk/stackhawk_sample.json'

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

    def import_unittest_scan(self, scan_file, product_name, engagement_name, product_type_name,
                           minimum_severity, active, verified, tags):
        """
        Import a specific unittest scan file.

        Args:
            scan_file: Path to scan file relative to unittests/scans/
            product_name: Name of product to create/use
            engagement_name: Name of engagement to create/use
            product_type_name: Name of product type to create/use
            minimum_severity: Minimum severity level
            active: Whether findings should be active
            verified: Whether findings should be verified

        """
        # Validate scan file exists
        scan_path = Path("unittests/scans") / scan_file
        if not scan_path.exists():
            msg = f"Scan file not found: {scan_path}"
            raise CommandError(msg)

        # Deduce scan type from path
        scan_type, _parser_class = self.deduce_scan_type_from_path(scan_file)

        logger.info(f"Importing scan '{scan_file}' using scan type '{scan_type}'")
        logger.info(f"Target: Product '{product_name}' -> Engagement '{engagement_name}'")

        # Import the scan using auto_create_context
        with scan_path.open(encoding="utf-8") as testfile:
            payload = {
                "minimum_severity": minimum_severity,
                "scan_type": scan_type,
                "file": testfile,
                "version": "1.0.1",
                "active": active,
                "verified": verified,
                "apply_tags_to_findings": True,
                "apply_tags_to_endpoints": True,
                "auto_create_context": True,
                "product_type_name": product_type_name,
                "product_name": product_name,
                "engagement_name": engagement_name,
                "close_old_findings": False,
            }

            if tags:
                payload["tags"] = tags

            result = self.import_scan(payload)

        logger.info(f"Successfully imported scan. Test ID: {result.get('test_id')}")
        logger.info(f"Import summary: {result.get('scan_save_message', 'No summary available')}")

        return result

    def handle(self, *args, **options):
        scan_file = options["scan_file"]
        product_name = options["product_name"]
        engagement_name = options["engagement_name"]
        product_type_name = options["product_type_name"]
        minimum_severity = options["minimum_severity"]
        active = options["active"]
        verified = options["verified"]
        tags = options["tags"]

        start_time = time.time()

        try:
            self.import_unittest_scan(
                scan_file=scan_file,
                product_name=product_name,
                engagement_name=engagement_name,
                product_type_name=product_type_name,
                minimum_severity=minimum_severity,
                active=active,
                verified=verified,
                tags=tags,
            )

            end_time = time.time()
            duration = end_time - start_time

            self.stdout.write(
                self.style.SUCCESS(
                    f"Successfully imported '{scan_file}' into product '{product_name}' "
                    f"(took {duration:.2f} seconds)",
                ),
            )

        except Exception as e:
            end_time = time.time()
            duration = end_time - start_time
            logger.exception(f"Failed to import scan '{scan_file}' after {duration:.2f} seconds")
            msg = f"Import failed after {duration:.2f} seconds: {e}"
            raise CommandError(msg)
