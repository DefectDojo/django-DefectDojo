import json

from dojo.models import Endpoint, Finding

# httpx reports what a URL is running and what it answered with. That is inventory rather than a
# weakness - the same call the WhatWeb parser makes - so everything imports at Info. Disclosed
# versions are the part worth triaging, and they are in the description.
DEFAULT_SEVERITY = "Info"


class HttpxParser:

    """Parses the JSON Lines output of `httpx -json`."""

    def get_scan_types(self):
        return ["httpx Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "httpx Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the JSON Lines output of `httpx -json` (one object per line, not a JSON array). "
            "Run it with -tech-detect to carry the technologies it identified."
        )

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        findings = {}
        for raw in content.splitlines():
            line = raw.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError as error:
                msg = f"httpx output is JSON Lines; a line could not be parsed: {error}"
                raise ValueError(msg) from error
            if not isinstance(record, dict):
                # A whole JSON array on one line lands here rather than in the decode error above,
                # and confusing the two formats is the likeliest mistake, so say which is expected.
                msg = (
                    "httpx output is JSON Lines - one object per line, not a JSON array; "
                    f"got a {type(record).__name__} on a line."
                )
                raise TypeError(msg)

            # With -probe httpx reports what it could NOT reach as well. A probe that failed is the
            # absence of a result, not a finding.
            if record.get("failed"):
                continue

            url = (record.get("url") or record.get("input") or "").strip()
            if not url:
                continue
            # httpx reports each input once, but the same URL can be given twice in a target list.
            if url not in findings:
                findings[url] = self.build_finding(record, url, test)
        return list(findings.values())

    def build_finding(self, record, url, test):
        status = record.get("status_code")

        finding = Finding(
            test=test,
            title=f"{url} (HTTP {status})" if status is not None else url,
            severity=DEFAULT_SEVERITY,
            description=self.build_description(record, url, status),
            static_finding=False,
            # httpx probes a running service rather than reading files.
            dynamic_finding=True,
        )
        # httpx reports the full URL it probed, so the endpoint needs no reconstructing.
        finding.unsaved_endpoints = [Endpoint.from_uri(url)]
        return finding

    def build_description(self, record, url, status):
        parts = [f"**URL:** {url}"]
        if status is not None:
            parts.append(f"**Status:** {status}")
        if title := record.get("title"):
            parts.append(f"**Page title:** {title}")
        if webserver := record.get("webserver"):
            # The Server header, which is where a disclosed version usually shows up.
            parts.append(f"**Server:** {webserver}")
        if technologies := record.get("tech"):
            # -tech-detect reports "Name:Version" where it could identify one.
            parts.append(f"**Technologies:** {', '.join(str(item) for item in technologies)}")
        if content_type := record.get("content_type"):
            parts.append(f"**Content type:** {content_type}")
        if method := record.get("method"):
            parts.append(f"**Method:** {method}")
        if length := record.get("content_length"):
            parts.append(f"**Content length:** {length}")
        if addresses := record.get("a"):
            # The A records httpx resolved the host to.
            parts.append(f"**Resolved to:** {', '.join(str(item) for item in addresses)}")
        if location := record.get("location"):
            parts.append(f"**Redirects to:** {location}")
        # The timestamp and the response duration are deliberately left out: both change on every run
        # of an unchanged target, and neither says anything about what was found.
        return "\n".join(parts)
