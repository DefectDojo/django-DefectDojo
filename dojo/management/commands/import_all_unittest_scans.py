import json
import logging
import os
from datetime import datetime
from importlib import import_module
from importlib.util import find_spec
from inspect import isclass
from pathlib import Path

from django.core.management.base import BaseCommand
from django.urls import reverse
from django.utils import timezone
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

import dojo.tools.factory
from dojo.models import Engagement, Product, Product_Type
from unittests.test_dashboard import User

logger = logging.getLogger(__name__)


class Command(BaseCommand):

    help = (
        "EXPERIMENTAL: May be changed/deprecated/removed without prior notice. "
        "Command to import all scans available in unittests folder"
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--product-name-prefix",
            type=lambda s: s if len(s) <= 250 else parser.error("product-name-prefix must be at most 250 characters"),
            help="Prefix to use for product names, defaults to 'All scans <today>'. Max length 250 characters.",
        )
        parser.add_argument(
            "--include-very-big-scans",
            action="store_true",
            default=False,
            help="Include very big scans like jfrog_xray very_many_vulns.json (default: False)",
        )
        parser.add_argument("--tests-per-engagement", type=int, default=10, help="Number of tests per engagement before a new engagement is created, defaults to 10")
        parser.add_argument("--engagements-per-product", type=int, default=50, help="Number of engagements per product before a new product is created, defaults to 50")
        parser.add_argument("--products-per-product-type", type=int, default=15, help="Number of products per product type before a new product type is created, defaults to 15")
        parser.add_argument("--number-of-runs", type=int, default=1, help="Number of times to run the import of all sample scans, defaults to 1")

    def get_test_admin(self, *args, **kwargs):
        return User.objects.get(username="admin")

    def import_scan(self, payload, expected_http_status_code):
        testuser = self.get_test_admin()
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        response = self.client.post(reverse("importscan-list"), payload)
        if expected_http_status_code != response.status_code:
            msg = f"Expected HTTP status code {expected_http_status_code}, got {response.status_code}: {response.content[:1000]}"
            raise AssertionError(
            msg,
            )
        return json.loads(response.content)

    def import_scan_with_params(self, filename, scan_type="ZAP Scan", engagement=1, minimum_severity="Low", *, active=True, verified=False,
                                push_to_jira=None, endpoint_to_add=None, tags=None, close_old_findings=False, group_by=None, engagement_name=None,
                                product_name=None, product_type_name=None, auto_create_context=None, expected_http_status_code=201, test_title=None,
                                scan_date=None, service=None, force_active=True, force_verified=True):

        with (Path("unittests/scans") / filename).open(encoding="utf-8") as testfile:
            payload = {
                    "minimum_severity": minimum_severity,
                    "scan_type": scan_type,
                    "file": testfile,
                    "version": "1.0.1",
                    "close_old_findings": close_old_findings,
            }

            if active is not None:
                payload["active"] = active

            if verified is not None:
                payload["verified"] = verified

            if engagement:
                payload["engagement"] = engagement

            if engagement_name:
                payload["engagement_name"] = engagement_name

            if product_name:
                payload["product_name"] = product_name

            if product_type_name:
                payload["product_type_name"] = product_type_name

            if auto_create_context:
                payload["auto_create_context"] = auto_create_context

            if push_to_jira is not None:
                payload["push_to_jira"] = push_to_jira

            if endpoint_to_add is not None:
                payload["endpoint_to_add"] = endpoint_to_add

            if tags is not None:
                payload["tags"] = tags

            if group_by is not None:
                payload["group_by"] = group_by

            if test_title is not None:
                payload["test_title"] = test_title

            if scan_date is not None:
                payload["scan_date"] = scan_date

            if service is not None:
                payload["service"] = service

            return self.import_scan(payload, expected_http_status_code)

    def import_all_unittest_scans(self, product_name_prefix=None, tests_per_engagement=10, engagements_per_product=50, products_per_product_type=15, *, include_very_big_scans=False, **kwargs):
        logger.info(f"product_name_prefix: {product_name_prefix}, tests_per_engagement: {tests_per_engagement}, engagements_per_product: {engagements_per_product}, products_per_product_type: {products_per_product_type}")
        product_type_prefix = "Sample scans " + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        product_type_index = 1

        product_index = 1
        engagement_index = 1
        tests_index = 1

        error_count = 0
        error_messages = {}
        # iterate through the modules in the current package
        package_dir = str(Path(dojo.tools.factory.__file__).resolve().parent)
        for module_name in os.listdir(package_dir):  # noqa: PTH208
            if tests_index > tests_per_engagement:
                tests_index = 1
                engagement_index += 1

            if engagement_index > engagements_per_product:
                engagement_index = 1
                product_index += 1

            if product_index > products_per_product_type:
                product_index = 1
                product_type_index += 1

            prod_type, _ = Product_Type.objects.get_or_create(name=product_type_prefix + f" {product_type_index}")
            prod, _ = Product.objects.get_or_create(prod_type=prod_type, name=product_name_prefix + f" {product_type_index}:{product_index}", description="Sample scans for unittesting")
            eng, _ = Engagement.objects.get_or_create(product=prod, name="Sample scan engagement" + f" {engagement_index}", target_start=timezone.now(), target_end=timezone.now())

            # check if it's dir
            if (Path(package_dir) / module_name).is_dir():
                try:
                    # check if it's a Python module
                    if find_spec(f"dojo.tools.{module_name}.parser"):
                        # import the module and iterate through its attributes
                        module = import_module(f"dojo.tools.{module_name}.parser")
                        for attribute_name in dir(module):
                            attribute = getattr(module, attribute_name)
                            if isclass(attribute) and attribute_name.lower() == module_name.replace("_", "") + "parser":
                                logger.debug(f"Loading {module_name} parser")
                                scan_dir = Path("unittests") / "scans" / module_name
                                for scan_file in scan_dir.glob("*.json"):
                                    if include_very_big_scans or scan_file.name != "very_many_vulns.json":  # jfrog_xray file is huge and takes too long to import
                                        try:
                                            logger.info(f"Importing scan {scan_file.name} using {module_name} parser into {prod.name}:{eng.name}")
                                            parser = attribute()
                                            # with scan_file.open(encoding="utf-8") as f:
                                            #     findings = parser.get_findings(f, Test())
                                            result = self.import_scan_with_params(
                                                filename=module_name + "/" + scan_file.name,
                                                scan_type=parser.get_scan_types()[0],
                                                engagement=eng.id,
                                            )
                                            # logger.debug(f"Result of import: {result}")
                                            # raise Exception(f"Scan {scan_file.name} is not expected to be imported, but it was.")
                                            logger.debug(f"Imported findings from {module_name + scan_file.name}")
                                            tests_index += 1
                                        except Exception as e:
                                            logger.error(f"Error importing scan {module_name + scan_file.name}: {e}")
                                            error_count += 1
                                            error_messages[module_name + "/" + scan_file.name] = result.get("message", str(e))

                except:
                    logger.exception(f"failed to load {module_name}")
                    raise

        logger.error(f"Error count: {error_count}")
        for scan, message in error_messages.items():
            logger.error(f"Error importing scan {scan}: {message}")

    def handle(self, *args, **options):
        logger.info("EXPERIMENTAL: This command may be changed/deprecated/removed without prior notice.")
        for i in range(options.get("number_of_runs", 1)):
            product_name_prefix = options.get("product_name_prefix")
            if not product_name_prefix:
                today = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                product_name_prefix = f"Sample scan product {i + 1} {today}"
            self.import_all_unittest_scans(
                product_name_prefix=product_name_prefix,
                tests_per_engagement=options.get("tests_per_engagement"),
                engagements_per_product=options.get("engagements_per_product"),
                products_per_product_type=options.get("products_per_product_type"),
                include_very_big_scans=options.get("include_very_big_scans"),
            )
