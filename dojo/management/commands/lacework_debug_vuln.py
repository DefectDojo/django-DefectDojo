"""
Management command to dump raw Lacework vulnerability data for debugging.

Usage:
    python manage.py lacework_debug_vuln --tool-config <ID>

This will fetch one vulnerability and print its full JSON structure
so you can see what fields are available for mapping.
"""

import json
import logging
from datetime import UTC, datetime, timedelta

from django.core.management.base import BaseCommand, CommandError

from dojo.models import Tool_Configuration
from dojo.tools.api_lacework.api_client import LaceworkAPI

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Dump raw Lacework vulnerability data for debugging field mapping"

    def add_arguments(self, parser):
        parser.add_argument(
            "--tool-config",
            type=int,
            required=True,
            help="ID of the Tool Configuration for Lacework",
        )
        parser.add_argument(
            "--type",
            type=str,
            default="containers",
            choices=["containers", "hosts"],
            help="Type of vulnerabilities to dump (default: containers)",
        )

    def handle(self, *args, **options):
        tool_config_id = options["tool_config"]
        vuln_type = options["type"]

        try:
            tool_config = Tool_Configuration.objects.get(id=tool_config_id)
        except Tool_Configuration.DoesNotExist:
            msg = f"Tool Configuration with id {tool_config_id} not found"
            raise CommandError(
                msg,
            )

        self.stdout.write(f"Using Tool Configuration: {tool_config.name}")
        self.stdout.write(f"  URL: {tool_config.url}")

        client = LaceworkAPI(tool_config)

        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(hours=24)
        start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        if vuln_type == "containers":
            self.stdout.write("\nFetching container vulnerabilities...")
            vulns = client.search_container_vulnerabilities(
                start_time=start_time_str,
                end_time=end_time_str,
            )
        else:
            self.stdout.write("\nFetching host vulnerabilities...")
            vulns = client.search_host_vulnerabilities(
                start_time=start_time_str,
                end_time=end_time_str,
            )

        if not vulns:
            self.stdout.write(self.style.WARNING("No vulnerabilities found"))
            return

        self.stdout.write(f"Total vulnerabilities: {len(vulns)}")

        # Find first vulnerability that actually has a CVE/vulnId
        vuln = None
        for v in vulns:
            if v.get("vulnId") and v.get("severity"):
                vuln = v
                break

        if not vuln:
            self.stdout.write(self.style.WARNING("No vulnerability with CVE data found"))
            return

        self.stdout.write(f"\nSelected vulnerability: {vuln.get('vulnId')} ({vuln.get('severity')})\n")
        self.stdout.write(
            self.style.SUCCESS(
                f"\n=== Full JSON structure of 1 {vuln_type} vulnerability ===\n",
            ),
        )
        self.stdout.write(json.dumps(vuln, indent=2, default=str))

        self.stdout.write(
            self.style.SUCCESS(
                "\n=== TOP-LEVEL FIELDS ===\n",
            ),
        )
        for key, value in vuln.items():
            if not isinstance(value, (dict, list)):
                self.stdout.write(f"  {key}: {value}")
            else:
                self.stdout.write(f"  {key}: ({type(value).__name__})")

        # Analyze available fields for mapping
        self.stdout.write(
            self.style.SUCCESS(
                "\n=== ANALYSIS ===\n",
            ),
        )
        self.stdout.write(f"vulnId (CVE): {vuln.get('vulnId', 'N/A')}")
        self.stdout.write(f"severity: {vuln.get('severity', 'N/A')}")
        self.stdout.write(f"status: {vuln.get('status', 'N/A')}")
        self.stdout.write(f"riskScore: {vuln.get('riskScore', 'N/A')}")
        self.stdout.write(f"cveRiskScore: {vuln.get('cveRiskScore', 'N/A')}")
        self.stdout.write(f"startTime: {vuln.get('startTime', 'N/A')}")
        self.stdout.write(f"endTime: {vuln.get('endTime', 'N/A')}")
        self.stdout.write(f"evalGuid: {vuln.get('evalGuid', 'N/A')}")
        self.stdout.write(f"imageId: {vuln.get('imageId', 'N/A')}")

        # FeatureKey details
        fk = vuln.get("featureKey", {})
        self.stdout.write(f"\n  featureKey.name: {fk.get('name', 'N/A')}")
        self.stdout.write(f"  featureKey.namespace: {fk.get('namespace', 'N/A')}")
        if fk.get("version"):
            self.stdout.write(f"  featureKey.version: {fk['version']}")
        if fk.get("version_installed"):
            self.stdout.write(f"  featureKey.version_installed: {fk['version_installed']}")
        if fk.get("version_format"):
            self.stdout.write(f"  featureKey.version_format: {fk['version_format']}")
        if fk.get("src"):
            self.stdout.write(f"  featureKey.src: {fk['src']}")
        if fk.get("introduced_in"):
            self.stdout.write(f"  featureKey.introduced_in: {fk['introduced_in']}")
        if fk.get("layer"):
            self.stdout.write(f"  featureKey.layer: {fk['layer']}")
        if fk.get("package_active"):
            self.stdout.write(f"  featureKey.package_active: {fk['package_active']}")
        if fk.get("package_path"):
            self.stdout.write(f"  featureKey.package_path: {fk['package_path']}")

        # FixInfo
        fi = vuln.get("fixInfo", {})
        self.stdout.write(f"\n  fixInfo.fix_available: {fi.get('fix_available', 'N/A')}")
        self.stdout.write(f"  fixInfo.fixed_version: {fi.get('fixed_version', 'N/A')}")

        # CveProps
        cp = vuln.get("cveProps", {})
        self.stdout.write(f"\n  cveProps.description: {cp.get('description', 'N/A')[:100]}...")
        self.stdout.write(f"  cveProps.link: {cp.get('link', 'N/A')}")
        self.stdout.write(f"  cveProps.source: {cp.get('source', 'N/A')}")

        # Metadata
        meta = cp.get("metadata", {})
        nvd = meta.get("NVD", {})
        rbs = meta.get("RBS", {})
        self.stdout.write(f"\n  metadata.NVD.CVSSv3.Score: {nvd.get('CVSSv3', {}).get('Score', 'N/A')}")
        self.stdout.write(f"  metadata.NVD.CVSSv2.Score: {nvd.get('CVSSv2', {}).get('Score', 'N/A')}")
        self.stdout.write(f"  metadata.RBS.CVSSv3.Score: {rbs.get('CVSSv3', {}).get('Score', 'N/A')}")
        self.stdout.write(f"  metadata.RBS.cwe_id: {rbs.get('cwe_id', 'N/A')}")

        # EvalCtx for containers
        ec = vuln.get("evalCtx", {})
        if ec:
            self.stdout.write(f"\n  evalCtx.collector_type: {ec.get('collector_type', 'N/A')}")
            ii = ec.get("image_info", {})
            if ii:
                self.stdout.write(f"  evalCtx.image_info.repo: {ii.get('repo', 'N/A')}")
                self.stdout.write(f"  evalCtx.image_info.registry: {ii.get('registry', 'N/A')}")
                self.stdout.write(f"  evalCtx.image_info.tags: {ii.get('tags', 'N/A')}")
                self.stdout.write(f"  evalCtx.image_info.digest: {ii.get('digest', 'N/A')}")
                self.stdout.write(f"  evalCtx.image_info.status: {ii.get('status', 'N/A')}")
                self.stdout.write(f"  evalCtx.image_info.type: {ii.get('type', 'N/A')}")
                self.stdout.write(f"  evalCtx.image_info.size: {ii.get('size', 'N/A')}")

        # Machine info for hosts
        machine_tags = vuln.get("machineTags", {})
        if machine_tags:
            self.stdout.write(f"\n  machineTags.Hostname: {machine_tags.get('Hostname', 'N/A')}")
            self.stdout.write(f"  machineTags.VmProvider: {machine_tags.get('VmProvider', 'N/A')}")
            self.stdout.write(f"  machineTags.InstanceId: {machine_tags.get('InstanceId', 'N/A')}")
            self.stdout.write(f"  machineTags.Region: {machine_tags.get('Region', 'N/A')}")

        # Additional fields
        self.stdout.write("\n  additional top-level keys:")
        for key in sorted(vuln.keys()):
            self.stdout.write(f"    - {key}")
