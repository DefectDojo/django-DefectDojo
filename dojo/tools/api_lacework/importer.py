"""
Lacework API Importer for DefectDojo.

This module handles the import of container and host vulnerabilities from
Lacework API v2.0 into DefectDojo Findings.

It follows the same pattern as SonarQubeApiImporter from dojo/tools/api_sonarqube/.
"""

import logging
from datetime import UTC, datetime, timedelta

from django.conf import settings
from django.core.exceptions import ValidationError

from dojo.models import Finding

from .api_client import LaceworkAPI

logger = logging.getLogger(__name__)


class LaceworkApiImporter:
    SCAN_LACEWORK = "Lacework API Import"

    def get_findings(self, filename, test):
        """
        Main entry point for importing Lacework vulnerabilities.

        Args:
            filename: Ignored (API-based import, no file needed)
            test: Test instance to associate findings with

        Returns:
            list[Finding]: List of Finding instances (not yet saved)

        """
        items = []

        # Get client to check which vulnerability types are enabled
        # (options come from the Extras field in Tool Configuration)
        try:
            client, _config = self.prepare_client(test)
        except Exception:
            client = None

        include_containers = client.include_containers if client else True
        include_hosts = client.include_hosts if client else True

        # Import container vulnerabilities
        if include_containers:
            try:
                items.extend(self.import_container_vulnerabilities(test))
            except Exception as e:
                logger.exception("Failed to import container vulnerabilities")
                self._notify_failure(test, "Container vulnerabilities import", str(e))
        else:
            logger.info("Container vulnerabilities import is disabled via Extras config")

        # Import host vulnerabilities
        if include_hosts:
            try:
                items.extend(self.import_host_vulnerabilities(test))
            except Exception as e:
                logger.exception("Failed to import host vulnerabilities")
                self._notify_failure(test, "Host vulnerabilities import", str(e))
        else:
            logger.info("Host vulnerabilities import is disabled via Extras config")

        return items

    @staticmethod
    def prepare_client(test):
        """
        Prepare the Lacework API client from the test's configuration.

        Similar to SonarQubeApiImporter.prepare_client.

        Args:
            test: Test instance with associated API scan configuration

        Returns:
            tuple[LaceworkAPI, APIScanConfiguration]: The client and config

        Raises:
            ValidationError: If configuration is missing or invalid

        """
        product = test.engagement.product

        if test.api_scan_configuration:
            config = test.api_scan_configuration
            # Validate that the config belongs to this product
            if config.product != product:
                msg = (
                    "Product API Scan Configuration and Product do not match. "
                    f'Product: "{product.name}" ({product.id}), '
                    f'config.product: "{config.product.name}" ({config.product.id})'
                )
                raise ValidationError(msg)
        else:
            sqqs = product.product_api_scan_configuration_set.filter(
                product=product,
                tool_configuration__tool_type__name="Lacework",
            )
            if sqqs.count() == 1:
                config = sqqs.first()
            elif sqqs.count() > 1:
                msg = (
                    "More than one Product API Scan Configuration has been configured, but none has been "
                    "chosen. Please specify which one should be used. "
                    f'Product: "{product.name}" ({product.id})'
                )
                raise ValidationError(msg)
            else:
                msg = (
                    "There are no API Scan Configurations for this Product.\n"
                    "Please add at least one API Scan Configuration for Lacework to this Product. "
                    f'Product: "{product.name}" ({product.id})'
                )
                raise ValidationError(msg)

        return LaceworkAPI(tool_config=config.tool_configuration), config

    def import_container_vulnerabilities(self, test):
        """
        Import container vulnerabilities from Lacework.

        Fetches vulnerabilities using search_container_vulnerabilities()
        and maps each one to a Finding instance.

        Args:
            test: Test instance for the current engagement

        Returns:
            list[Finding]: List of Finding instances

        """
        items = []
        client, config = self.prepare_client(test)

        # Calculate time range (last 24 hours by default, or configured)
        hours = getattr(settings, "LACEWORK_API_IMPORTER_TIMEDELTA_HOURS", 24)
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(hours=hours)

        start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        logger.info(
            "Fetching container vulnerabilities from %s to %s",
            start_time_str,
            end_time_str,
        )

        # Filter by repository pattern from Service key 1 (API Scan Configuration)
        filters = None
        if config and config.service_key_1:
            repo_pattern = config.service_key_1
            filters = [
                {
                    "field": "evalCtx.image_info.repo",
                    "expression": "like",
                    "value": f"%{repo_pattern}%",
                },
            ]
            logger.info(
                "Filtering container vulnerabilities by repository pattern: %s",
                repo_pattern,
            )
        else:
            logger.info(
                "No repository filter configured (Service key 1 is empty). Importing ALL container vulnerabilities.",
            )

        vulnerabilities = client.search_container_vulnerabilities(
            start_time=start_time_str,
            end_time=end_time_str,
            filters=filters,
        )

        logger.info("Found %d container vulnerabilities", len(vulnerabilities))

        for vuln in vulnerabilities:
            try:
                finding = self._create_finding_from_container_vuln(vuln, test)
                if finding:
                    items.append(finding)
            except Exception as e:
                logger.warning(
                    "Failed to process container vulnerability %s: %s",
                    vuln.get("vulnId", "unknown"),
                    e,
                )

        return items

    def import_host_vulnerabilities(self, test):
        """
        Import host vulnerabilities from Lacework.

        Fetches vulnerabilities using search_host_vulnerabilities()
        and maps each one to a Finding instance.

        Args:
            test: Test instance for the current engagement

        Returns:
            list[Finding]: List of Finding instances

        """
        items = []
        client, config = self.prepare_client(test)

        # Calculate time range
        hours = getattr(settings, "LACEWORK_API_IMPORTER_TIMEDELTA_HOURS", 24)
        end_time = datetime.now(UTC)
        start_time = end_time - timedelta(hours=hours)

        start_time_str = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_time_str = end_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        logger.info(
            "Fetching host vulnerabilities from %s to %s",
            start_time_str,
            end_time_str,
        )

        # Filter by hostname pattern from Service key 1 (API Scan Configuration)
        filters = None
        if config and config.service_key_1:
            hostname_pattern = config.service_key_1
            filters = [
                {
                    "field": "machineTags.Hostname",
                    "expression": "rlike",
                    "value": f".*{hostname_pattern}.*",
                },
            ]
            logger.info(
                "Filtering host vulnerabilities by hostname pattern: %s",
                hostname_pattern,
            )
        else:
            logger.info(
                "No hostname filter configured (Service key 1 is empty). Importing ALL host vulnerabilities.",
            )

        vulnerabilities = client.search_host_vulnerabilities(
            start_time=start_time_str,
            end_time=end_time_str,
            filters=filters,
        )

        logger.info("Found %d host vulnerabilities", len(vulnerabilities))

        for vuln in vulnerabilities:
            try:
                finding = self._create_finding_from_host_vuln(vuln, test)
                if finding:
                    items.append(finding)
            except Exception as e:
                logger.warning(
                    "Failed to process host vulnerability %s: %s",
                    vuln.get("vulnId", "unknown"),
                    e,
                )

        return items

    def _build_common_finding(
        self,
        vuln: dict,
        test,
        source_type: str,
        unique_id_parts: list[str],
    ) -> tuple[dict, str, bool]:
        """
        Build common finding fields shared by container and host vulns.

        Args:
            vuln: Vulnerability dict from Lacework API
            test: Test instance
            source_type: "container" or "host"
            unique_id_parts: Parts to build unique_id (vulnId + ...)

        Returns:
            tuple of (fields_dict, unique_id, is_active)

        """
        vuln_id = vuln.get("vulnId", "")

        # --- Severity ---
        # If no direct severity field, infer from risk scores
        severity_str = vuln.get("severity", "")
        if not severity_str:
            risk_score = vuln.get("riskScore") or vuln.get("cveRiskScore") or 0
            if risk_score >= 9.0:
                severity_str = "Critical"
            elif risk_score >= 7.0:
                severity_str = "High"
            elif risk_score >= 4.0:
                severity_str = "Medium"
            elif risk_score >= 1.0:
                severity_str = "Low"
            else:
                severity_str = "Info"
        severity = self._convert_lacework_severity(severity_str)

        # --- Description ---
        cve_props = vuln.get("cveProps", {})
        description = cve_props.get("description", "No description provided")

        # Add introduced_in to description if available (for containers)
        feature_props = vuln.get("featureProps", {})
        introduced_in = feature_props.get("introduced_in", "")
        if introduced_in:
            description += f"\n\n**Introduced in:** {introduced_in}"

        # --- References ---
        references = ""
        link = cve_props.get("link", "")
        source = cve_props.get("source", "")
        if link:
            references = f"[CVE Reference]({link}) "
        if source:
            references += f"\n*Source: {source}*"
        if vuln_id and vuln_id.startswith("CVE-"):
            references += f"\nhttps://nvd.nist.gov/vuln/detail/{vuln_id}"

        # --- Component info ---
        feature_key = vuln.get("featureKey", {})
        component_name = feature_key.get("name", "")
        namespace = feature_key.get("namespace", "")
        # Container uses "version", host uses "version_installed"
        version_val = feature_key.get("version") or feature_key.get("version_installed", "")

        # Package path from featureProps (more specific than just namespace)
        pkg_path = feature_props.get("src", namespace)

        # --- Fix info ---
        fix_info = vuln.get("fixInfo", {})
        fix_available = bool(fix_info.get("fix_available", 0))
        fixed_version = fix_info.get("fixed_version", "")

        # --- CVSS score ---
        cvss_score, cvss_vector = self._extract_cvss_score(vuln)

        # --- CWE ---
        cwe = self._extract_cwe(vuln)

        # --- Status (active/mitigated) ---
        status = vuln.get("status", "").upper()
        is_active = status != "GOOD"  # GOOD = resolved/mitigated
        is_verified = status == "VULNERABLE" or is_active

        # --- Unique ID for dedup ---
        unique_id = f"{source_type}:{'|'.join(unique_id_parts)}"

        # --- Tags ---
        tags_parts = []
        package_status = vuln.get("packageStatus", "")
        if package_status:
            tags_parts.append(f"pkg:{package_status}")

        eval_ctx = vuln.get("evalCtx", {})
        request_source = eval_ctx.get("request_source", "")
        if request_source:
            tags_parts.append(f"scanner:{request_source}")

        integration_props = eval_ctx.get("integration_props", {})
        intg_name = integration_props.get("NAME", "")
        if intg_name:
            tags_parts.append(f"integration:{intg_name}")

        feed = feature_props.get("feed", "")
        if feed:
            tags_parts.append(f"feed:{feed}")

        fields = {
            "title": f"{vuln_id} in {component_name}" if component_name else vuln_id,
            "vuln_id_from_tool": vuln_id,
            "description": description,
            "test": test,
            "severity": severity,
            "references": references,
            "component_name": component_name or None,
            "component_version": version_val or None,
            "file_path": pkg_path or namespace or None,
            "cwe": cwe,
            "cvssv3_score": cvss_score,
            "cvssv3": cvss_vector or None,
            "fix_available": fix_available,
            "fix_version": fixed_version or None,
            "static_finding": True,
            "dynamic_finding": False,
            "active": is_active,
            "verified": is_verified,
            "false_p": False,
            "duplicate": False,
            "out_of_scope": False,
            "unique_id_from_tool": f"lacework:{unique_id}",
        }

        return fields, unique_id, is_active

    def _create_finding_from_container_vuln(self, vuln: dict, test) -> Finding | None:
        """Create a Finding from a Lacework container vulnerability."""
        vuln_id = vuln.get("vulnId", "")
        if not vuln_id:
            return None

        # Image info
        eval_ctx = vuln.get("evalCtx", {})
        image_info = eval_ctx.get("image_info", {})
        repo = image_info.get("repo", "")
        image_tags = image_info.get("tags", [])

        # Build unique_id_parts: vulnId, repo, namespace, component_name
        feature_key = vuln.get("featureKey", {})
        namespace = feature_key.get("namespace", "")
        component_name = feature_key.get("name", "")

        unique_id_parts = [vuln_id, repo, namespace, component_name]

        fields, _unique_id, _is_active = self._build_common_finding(
            vuln,
            test,
            "container",
            unique_id_parts,
        )

        # Add container-specific tags
        tags_parts = []
        fields["title"]

        if repo not in str(tags_parts):
            tags_parts.append(repo)
        if image_tags:
            tags_parts.extend(image_tags)

        return Finding(**fields)

    def _create_finding_from_host_vuln(self, vuln: dict, test) -> Finding | None:
        """Create a Finding from a Lacework host vulnerability."""
        vuln_id = vuln.get("vulnId", "")
        if not vuln_id:
            return None

        # Machine info
        mid = vuln.get("mid", "")
        machine_tags = vuln.get("machineTags", {})
        _hostname = machine_tags.get("Hostname", "")
        _vm_provider = machine_tags.get("VmProvider", "")

        # Build unique_id_parts: vulnId, mid, namespace, component_name
        feature_key = vuln.get("featureKey", {})
        namespace = feature_key.get("namespace", "")
        component_name = feature_key.get("name", "")

        unique_id_parts = [str(vuln_id), str(mid), namespace, component_name]

        fields, _unique_id, _is_active = self._build_common_finding(
            vuln,
            test,
            "host",
            unique_id_parts,
        )

        return Finding(**fields)

    @staticmethod
    def _convert_lacework_severity(lw_severity: str) -> str:
        """Convert Lacework severity to DefectDojo severity."""
        mapping = {
            "Critical": "Critical",
            "High": "High",
            "Medium": "Medium",
            "Low": "Low",
            "Info": "Info",
        }
        return mapping.get(lw_severity, "Info")

    @staticmethod
    def _extract_cvss_score(vuln: dict) -> tuple:
        """Extract CVSSv3 score and vector from a vulnerability."""
        cve_props = vuln.get("cveProps", {})
        metadata = cve_props.get("metadata", {})

        # Try NVD CVSSv3 first
        nvd = metadata.get("NVD", {})
        cvssv3 = nvd.get("CVSSv3", {})
        if cvssv3:
            score = cvssv3.get("Score")
            vector = cvssv3.get("Vectors")
            if score is not None and score > 0:
                return (float(score), vector)

        # Fallback to RBS (Rapid7)
        rbs = metadata.get("RBS", {})
        cvssv3_rbs = rbs.get("CVSSv3", {})
        if cvssv3_rbs:
            score = cvssv3_rbs.get("Score")
            vector = cvssv3_rbs.get("Vectors")
            if score is not None and score > 0:
                return (float(score), vector)

        # Fallback to riskScore from Lacework
        risk_score = vuln.get("riskScore") or vuln.get("cveRiskScore")
        if risk_score is not None:
            return (float(risk_score), None)

        return (None, None)

    @staticmethod
    def _extract_cwe(vuln: dict) -> int | None:
        """Extract CWE ID from a vulnerability."""
        cve_props = vuln.get("cveProps", {})
        metadata = cve_props.get("metadata", {})
        rbs = metadata.get("RBS", {})
        cwe_map = rbs.get("cwe_id", {})

        # Find the CWE from the map
        for cwe_str in cwe_map.values():
            if cwe_str and cwe_str.startswith("CWE-"):
                try:
                    return int(cwe_str.replace("CWE-", ""))
                except (ValueError, TypeError):
                    continue

        return None

    @staticmethod
    def _notify_failure(test, import_type: str, error_message: str):
        """Send a notification about an import failure."""
        from dojo.notifications.helper import create_notification  # noqa: PLC0415

        create_notification(
            event="other",
            title=f"Lacework {import_type} failed",
            description=(
                f"Lacework {import_type} failed for product '{test.engagement.product.name}': {error_message}"
            ),
            icon="exclamation-triangle",
            source="Lacework API",
            obj=test.engagement.product,
        )
