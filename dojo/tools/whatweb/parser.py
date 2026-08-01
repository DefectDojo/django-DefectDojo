import json

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData

# WhatWeb identifies what a URL is running. That is inventory rather than a weakness, so everything
# imports at Info - the same treatment ffuf's discovered paths and nmap's open ports get. Disclosed
# versions are the part worth triaging, and they are in the description.
DEFAULT_SEVERITY = "Info"

# Plugins that describe the network WhatWeb reached over rather than the technology it found. They are
# still reported, but under their own heading, so a reader is not told that "Country: RESERVED" is
# something the target is running.
NETWORK_PLUGINS = ("IP", "Country")

# The fields a plugin uses to report what it matched, in the order they read best.
PLUGIN_FIELDS = ("version", "string", "module", "account", "filepath", "model", "firmware")


class WhatWebParser:

    """Parses the JSON log produced by `whatweb --log-json`."""

    def get_scan_types(self):
        return ["WhatWeb Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "WhatWeb Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON log produced by `whatweb --log-json=report.json <target>`."

    def get_findings(self, filename, test):
        data = json.load(filename)
        if not isinstance(data, list):
            msg = f"A WhatWeb JSON log is an array of scanned targets; got a {type(data).__name__}."
            raise TypeError(msg)

        findings = []
        for entry in data:
            if not isinstance(entry, dict):
                msg = "Every entry in a WhatWeb log must be an object."
                raise TypeError(msg)
            findings.append(self.build_finding(entry, test))
        return findings

    def build_finding(self, entry, test):
        """
        One finding per TARGET, not per plugin.

        WhatWeb fingerprints anything it can reach - a 404 page still yields five plugins - and
        several of those are metadata it adds itself. A finding per plugin would report "Country:
        RESERVED" as though the site were running it, so the technologies are listed together under
        the URL that has them.
        """
        target = entry.get("target") or ""
        status = entry.get("http_status")

        finding = Finding(
            test=test,
            title=f"Technologies identified: {target}" if target else "Technologies identified",
            severity=DEFAULT_SEVERITY,
            description=self.build_description(entry, target, status),
            static_finding=False,
            # WhatWeb requests a live URL rather than reading a file.
            dynamic_finding=True,
        )
        if target:
            # Finding.__init__ creates unsaved_locations OR unsaved_endpoints depending on
            # V3_FEATURE_LOCATIONS, and only the matching importer reads it, so the location is
            # built and attached the way the nmap parser does it.
            if settings.V3_FEATURE_LOCATIONS:
                finding.unsaved_locations = [LocationData.url(url=target)]
            else:
                # TODO: Delete this after the move to Locations
                finding.unsaved_endpoints = [Endpoint.from_uri(target)]
        return finding

    def build_description(self, entry, target, status):
        plugins = entry.get("plugins") or {}
        technologies = {
            name: detail for name, detail in plugins.items() if name not in NETWORK_PLUGINS
        }
        network = {name: plugins[name] for name in NETWORK_PLUGINS if name in plugins}

        parts = []
        if target:
            parts.append(f"**URL:** {target}")
        if status is not None:
            parts.append(f"**Status:** {status}")

        if technologies:
            parts.append(f"**Technologies ({len(technologies)}):**")
            parts.extend(
                f"- {name}{self.plugin_detail(detail)}"
                for name, detail in sorted(technologies.items())
            )
        if network:
            parts.append("**Network:**")
            parts.extend(
                f"- {name}{self.plugin_detail(detail)}" for name, detail in sorted(network.items())
            )
        if agent := ((entry.get("request_config") or {}).get("headers") or {}).get("User-Agent"):
            parts.append(f"**User agent:** {agent}")
        return "\n".join(parts)

    def plugin_detail(self, detail):
        """Render whichever fields a plugin populated; a bare detection has none."""
        if not isinstance(detail, dict):
            return f": {detail}"
        rendered = []
        for field in PLUGIN_FIELDS:
            values = detail.get(field)
            if not values:
                continue
            if not isinstance(values, list):
                values = [values]
            rendered.append(f"{field} {', '.join(str(value) for value in values)}")
        return f": {'; '.join(rendered)}" if rendered else ""
