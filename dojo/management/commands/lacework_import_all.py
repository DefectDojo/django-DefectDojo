"""
Management command to import all Lacework vulnerabilities, auto-creating
Products per repository, Engagements, and Tests.

Usage:
    python manage.py lacework_import_all --tool-config <tool_config_id>

Optional:
    --include-hosts          Also import host vulnerabilities (default: true)
    --include-containers     Also import container vulnerabilities (default: true)
    --product-type-name      Product Type name for auto-created products (default: "Lacework")
    --engagement-name        Engagement name template (default: "Lacework Scan {date}")
"""

import logging
from datetime import datetime, timedelta, timezone

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from dojo.models import (
    Development_Environment,
    Engagement,
    Product,
    Product_Type,
    Test,
    Test_Type,
    Tool_Configuration,
)
from dojo.tools.api_lacework.api_client import LaceworkAPI
from dojo.tools.api_lacework.importer import LaceworkApiImporter

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Import all Lacework vulnerabilities, auto-creating Products per repository."

    def add_arguments(self, parser):
        parser.add_argument(
            "--tool-config",
            type=int,
            required=True,
            help="ID of the Tool Configuration for Lacework",
        )

    def _parse_extras(self, extras: str | None) -> dict:
        """Parse the Tool Configuration Extras field for options.
        
        Returns a dict with keys: include_containers, include_hosts
        """
        result = {
            "include_containers": True,
            "include_hosts": True,
        }
        if not extras:
            return result
        for entry in extras.split(","):
            entry = entry.strip().lower()
            if "=" in entry:
                key, value = entry.split("=", 1)
                key = key.strip()
                value = value.strip().lower()
                if key == "include_containers":
                    result["include_containers"] = value == "true"
                elif key == "include_hosts":
                    result["include_hosts"] = value == "true"
        return result

    def handle(self, *args, **options):
        tool_config_id = options["tool_config"]

        # Get Tool Configuration
        try:
            tool_config = Tool_Configuration.objects.get(id=tool_config_id)
        except Tool_Configuration.DoesNotExist:
            raise CommandError(
                f"Tool Configuration with id {tool_config_id} not found"
            )

        # Read configuration from Tool Configuration Extras
        extras_config = self._parse_extras(tool_config.extras)
        include_containers = extras_config["include_containers"]
        include_hosts = extras_config["include_hosts"]

        self.stdout.write(f"Using Tool Configuration: {tool_config.name}")
        self.stdout.write(f"  URL: {tool_config.url}")
        self.stdout.write(f"  Include containers: {include_containers}")
        self.stdout.write(f"  Include hosts: {include_hosts}")
        self.stdout.write(f"  Extras: {tool_config.extras or '(empty)'}")

        # Get or create Product Type
        product_type, _ = Product_Type.objects.get_or_create(name="Lacework")
        self.stdout.write(f"Using Product Type: {product_type.name}")

        # Get or create Development Environment
        dev_env, _ = Development_Environment.objects.get_or_create(name="Development")

        # Get or create Test Type
        test_type, _ = Test_Type.objects.get_or_create(name="Lacework API Import")
        self.stdout.write(f"Using Test Type: {test_type.name}")

        # Initialize Lacework API client
        client = LaceworkAPI(tool_config)

        # Override include flags with options
        client.include_containers = include_containers
        client.include_hosts = include_hosts

        # Calculate time range
        hours = 24
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours)
        start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        # --- Import container vulnerabilities ---
        if include_containers:
            self.stdout.write(
                f"\nFetching container vulnerabilities from {start_time_str} to {end_time_str}..."
            )
            try:
                container_vulns = client.search_container_vulnerabilities(
                    start_time=start_time_str,
                    end_time=end_time_str,
                )
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Found {len(container_vulns)} container vulnerabilities"
                    )
                )
            except Exception as e:
                self.stderr.write(
                    self.style.ERROR(
                        f"Failed to fetch container vulnerabilities: {e}"
                    )
                )
                container_vulns = []

            # Group container vulns by repository
            container_by_repo = self._group_container_vulns_by_repo(container_vulns)
            self.stdout.write(
                f"Found {len(container_by_repo)} unique container repositories"
            )

            for repo_name, vulns in container_by_repo.items():
                self._import_vulns_to_product(
                    client=client,
                    repo_name=repo_name,
                    vulns=vulns,
                    product_type=product_type,
                    dev_env=dev_env,
                    test_type=test_type,
                    engagement_template="Lacework Scan {date}",
                    is_container=True,
                )
        else:
            self.stdout.write("Container vulnerabilities import is disabled.")

        # --- Import host vulnerabilities ---
        if include_hosts:
            self.stdout.write(
                f"\nFetching host vulnerabilities from {start_time_str} to {end_time_str}..."
            )
            try:
                host_vulns = client.search_host_vulnerabilities(
                    start_time=start_time_str,
                    end_time=end_time_str,
                )
                self.stdout.write(
                    self.style.SUCCESS(
                        f"Found {len(host_vulns)} host vulnerabilities"
                    )
                )
            except Exception as e:
                self.stderr.write(
                    self.style.ERROR(
                        f"Failed to fetch host vulnerabilities: {e}"
                    )
                )
                host_vulns = []

            # Group host vulns by hostname/machine
            host_by_machine = self._group_host_vulns_by_machine(host_vulns)
            self.stdout.write(
                f"Found {len(host_by_machine)} unique host machines"
            )

            for machine_name, vulns in host_by_machine.items():
                self._import_vulns_to_product(
                    client=client,
                    repo_name=machine_name,
                    vulns=vulns,
                    product_type=product_type,
                    dev_env=dev_env,
                    test_type=test_type,
                    engagement_template="Lacework Scan {date}",
                    is_container=False,
                )
        else:
            self.stdout.write("Host vulnerabilities import is disabled.")

        self.stdout.write(self.style.SUCCESS("\nImport completed successfully."))

    def _group_container_vulns_by_repo(self, vulns: list) -> dict:
        """Group container vulnerabilities by repository name."""
        grouped = {}
        for vuln in vulns:
            eval_ctx = vuln.get("evalCtx", {})
            image_info = eval_ctx.get("image_info", {})
            repo = image_info.get("repo", "unknown")
            if repo not in grouped:
                grouped[repo] = []
            grouped[repo].append(vuln)
        return grouped

    def _group_host_vulns_by_machine(self, vulns: list) -> dict:
        """Group host vulnerabilities by machine hostname."""
        grouped = {}
        for vuln in vulns:
            machine_tags = vuln.get("machineTags", {})
            hostname = machine_tags.get("Hostname", "unknown")
            if hostname not in grouped:
                grouped[hostname] = []
            grouped[hostname].append(vuln)
        return grouped

    @transaction.atomic
    def _import_vulns_to_product(
        self,
        client,
        repo_name: str,
        vulns: list,
        product_type,
        dev_env,
        test_type,
        engagement_template: str,
        is_container: bool,
    ):
        """Import vulnerabilities into a Product, auto-creating if needed."""
        source_type = "container" if is_container else "host"
        display_name = f"Lacework {source_type}: {repo_name}"

        # Sanitize product name (max 255 chars)
        product_name = repo_name[:255]

        # Get or create Product
        try:
            product, created = Product.objects.get_or_create(
                name=product_name,
                defaults={
                    "prod_type": product_type,
                    "description": f"Auto-created from Lacework {source_type} import",
                },
            )
            if created:
                self.stdout.write(
                    self.style.SUCCESS(f"  Created Product: {product_name}")
                )
            else:
                self.stdout.write(f"  Using existing Product: {product_name}")
        except Exception as e:
            self.stderr.write(
                self.style.ERROR(f"  Failed to get/create Product {product_name}: {e}")
            )
            return

        # Create Engagement
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        engagement_name = engagement_template.replace("{date}", today)
        try:
            engagement, created = Engagement.objects.get_or_create(
                name=engagement_name,
                product=product,
                defaults={
                    "target_start": datetime.now(timezone.utc).date(),
                    "target_end": datetime.now(timezone.utc).date(),
                    "active": True,
                    "status": "In Progress",
                },
            )
            if created:
                self.stdout.write(f"    Created Engagement: {engagement_name}")
            else:
                self.stdout.write(f"    Using existing Engagement: {engagement_name}")
        except Exception as e:
            self.stderr.write(
                self.style.ERROR(
                    f"    Failed to get/create Engagement {engagement_name}: {e}"
                )
            )
            return

        # Create Test
        try:
            test, created = Test.objects.get_or_create(
                engagement=engagement,
                test_type=test_type,
                defaults={
                    "title": f"{source_type.capitalize()} scan {today}",
                    "target_start": datetime.now(timezone.utc),
                    "target_end": datetime.now(timezone.utc),
                    "description": f"Lacework {source_type} vulnerabilities for {repo_name}",
                },
            )
            if created:
                self.stdout.write(f"    Created Test: {test.title}")
            else:
                self.stdout.write(f"    Using existing Test: {test.title}")
        except Exception as e:
            self.stderr.write(
                self.style.ERROR(f"    Failed to get/create Test: {e}")
            )
            return

        # Create Findings from vulnerabilities
        importer = LaceworkApiImporter()
        if is_container:
            new_findings = [
                importer._create_finding_from_container_vuln(v, test)
                for v in vulns
                if v.get("vulnId")
            ]
        else:
            new_findings = [
                importer._create_finding_from_host_vuln(v, test)
                for v in vulns
                if v.get("vulnId")
            ]

        # Filter out None values
        new_findings = [f for f in new_findings if f is not None]

        if not new_findings:
            self.stdout.write("    No findings to import")
            return

        # Save findings
        findings_created = 0
        findings_updated = 0
        for finding in new_findings:
            try:
                existing = test.finding_set.filter(
                    vuln_id_from_tool=finding.vuln_id_from_tool,
                    component_name=finding.component_name,
                    file_path=finding.file_path,
                ).first()
                if existing:
                    # Update existing finding
                    for field in [
                        "severity", "description", "references",
                        "component_version", "cvssv3_score", "cvssv3",
                        "fix_available", "fix_version", "active", "verified",
                    ]:
                        setattr(existing, field, getattr(finding, field))
                    existing.save()
                    findings_updated += 1
                else:
                    finding.save()
                    findings_created += 1
            except Exception as e:
                self.stderr.write(
                    self.style.ERROR(
                        f"    Failed to save finding {finding.title}: {e}"
                    )
                )

        self.stdout.write(
            self.style.SUCCESS(
                f"    Created {findings_created} findings, "
                f"updated {findings_updated} existing findings"
            )
        )