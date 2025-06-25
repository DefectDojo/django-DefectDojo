import json
import logging
import os
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
        "Command to import all scans available in unittests folder"
    )

    def get_test_admin(self, *args, **kwargs):
        return User.objects.get(username="admin")

    def import_scan(self, payload, expected_http_status_code):
        testuser = self.get_test_admin()
        token = Token.objects.get(user=testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)

        logger.debug("import_scan payload %s", payload)
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

    def handle(self, *args, **options):
        prod_type = Product_Type.objects.first()
        prod, _ = Product.objects.get_or_create(prod_type=prod_type, name="prod name")
        eng, _ = Engagement.objects.get_or_create(product=prod, name="valentijn engagement", target_start=timezone.now(), target_end=timezone.now())

        error_count = 0
        error_messages = {}
        # iterate through the modules in the current package
        package_dir = str(Path(dojo.tools.factory.__file__).resolve().parent)
        for module_name in os.listdir(package_dir):  # noqa: PTH208
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
                                logger.info(f"Loading {module_name} parser")
                                scan_dir = Path("unittests") / "scans" / module_name
                                for scan_file in scan_dir.glob("*.json"):
                                    if scan_file.name != "report_invalid.json":  # meterian
                                        if scan_file.name != "single_finding_no_libraryId.json":  # checkmarx_osa
                                            if scan_file.name not in ["issue_7897.json", "empty_with_error.json", "many_vuln_npm7.json"]:  # npm_audit  # noqa: PLR6201
                                                if scan_file.name != "threat_composer_no_threats_with_error.json":  # threat_composer
                                                    if scan_file.name != "very_many_vulns.json":  # jfrog_xray
                                                        try:
                                                            logger.debug(f"Importing scan {scan_file.name} using {module_name} parser")
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
                                                            logger.info(f"Imported findings from {module_name + scan_file.name}")
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


# errors:

# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:154] Error count: 18
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan generic/generic_empty.json: Expected HTTP status code 201, got 400: b'{"message":"[\\"Required fields are missing: [\'description\', \'severity\', \'title\']\\"]","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan generic/test_with_image_no_ext.json: Expected HTTP status code 201, got 400: b'{"message":"[\'Unsupported extension. Supported extensions are as follows: .txt, .pdf, .json, .xml, .csv, .yml, .png, .jpeg, .sarif, .xlsx, .doc, .html, .js, .nessus, .zip, .fpr\']","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan generic/generic_invalid.json: Expected HTTP status code 201, got 400: b'{"message":"[\\"Not allowed fields are present: [\'invalid_field\', \'last_status_update\']\\"]","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan whitehat_sentinel/empty_file.json: Expected HTTP status code 201, got 400: b'{"message":"[\'collection key not present or there were not findings present.\']","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan gitlab_api_fuzzing/gitlab_api_fuzzing_invalid.json: Expected HTTP status code 201, got 500: b'{"message":"Internal server error, check logs for details","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan burp_graphql/null_title.json: Expected HTTP status code 201, got 400: b'{"message":"[\'Issue does not have a name\']","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan stackhawk/oddly_familiar_json_that_isnt_us.json: Expected HTTP status code 201, got 400: b'{"message":"[\' Unexpected JSON format provided. Need help? Check out the StackHawk Docs at https://docs.stackhawk.com/workflow-integrations/defect-dojo.html\']","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan stackhawk/invalid.json: Expected HTTP status code 201, got 400: b'{"message":"[\' Unexpected JSON format provided. Need help? Check out the StackHawk Docs at https://docs.stackhawk.com/workflow-integrations/defect-dojo.html\']","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan kubehunter/empty.json: Expected HTTP status code 201, got 400: b'{"message":"[\'Expecting value: line 1 column 1 (char 0)\']","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan threagile/bad_formatted_risks_file.json: Expected HTTP status code 201, got 500: b'{"message":"Internal server error, check logs for details","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan hydra/oddly_familiar_json_that_isnt_us.json: Expected HTTP status code 201, got 400: b'{"message":"[\\"Unexpected JSON format provided. That doesn\'t look like a Hydra scan!\\"]","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan hydra/invalid.json: Expected HTTP status code 201, got 400: b'{"message":"[\\"Unexpected JSON format provided. That doesn\'t look like a Hydra scan!\\"]","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan anchore_enterprise/invalid_checks_format.json: Expected HTTP status code 201, got 400: b'{"message":"[\\"Invalid format: \'result\' key not found\\"]","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan risk_recon/bad_key.json: Expected HTTP status code 201, got 500: b'{"message":"Internal server error, check logs for details","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan risk_recon/bad_url.json: Expected HTTP status code 201, got 500: b'{"message":"Internal server error, check logs for details","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan osv_scanner/some_findings.json: Expected HTTP status code 201, got 500: b'{"message":"Internal server error, check logs for details","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan coverity_api/wrong.json: Expected HTTP status code 201, got 400: b'{"message":"[\\"(\'Report file is not a well-formed Coverity REST view report\', \'wrong.json\')\\"]","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
# [25/Jun/2025 18:06:15] ERROR [dojo.management.commands.import_all_unittest_scans:156] Error importing scan govulncheck/empty.json: Expected HTTP status code 201, got 400: b'{"message":"[\'Invalid JSON format\']","pro":["Pro comes with support. Try today for free or email us at hello@defectdojo.com"]}'
