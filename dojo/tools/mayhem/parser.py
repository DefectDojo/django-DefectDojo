import logging
import re

from django.utils.translation import gettext as _

from dojo.tools.sarif.parser import (
    SarifParser,
    get_codeFlowsDescription,
    get_snippet,
)

logger = logging.getLogger(__name__)

CWE_REGEX = r"cwe-\d+"


class MayhemParser(SarifParser):

    """
    Mayhem SARIF Parser

    This class extends the existing SARIF parser, but with some minor
    modifications to better support the structure of Mayhem SARIF reports.
    """

    def get_scan_types(self):
        return ["Mayhem SARIF Report"]

    def get_description_for_scan_types(self, scan_type):
        return "Mayhem SARIF reports from code or API runs."

    def get_finding_type(self):
        """Mayhem findings are dynamic, not static"""
        return (False, True)

    def get_finding_title(self, result, rule, location):
        """Get and clean the title text for Mayhem SARIF reports."""
        # Get the default title first
        title = super().get_finding_title(result, rule, location)

        if not title:
            return ""

        # Remove links (and add limit to avoid catastrophic backtracking)
        link_regex = r"\[[^\]]{1,100}?\]\([^)]{1,200}?\)"
        title = re.sub(link_regex, "", title)

        # Remove URL encoded characters
        url_encoding_regex = r"&#x\d+;"
        title = re.sub(url_encoding_regex, "", title)

        # Remove single or double quotes
        quotes_regex = r"[\"']"
        title = re.sub(quotes_regex, "", title)

        # Remove TDID
        tdid_regex = r"TDID-\d+\s*-\s*|TDID-\d+-"
        title = re.sub(tdid_regex, "", title)

        return title.strip()

    def get_finding_description(self, result, rule, location):
        """Custom description formatting for Mayhem SARIF reports with markdown support"""
        description = ""
        message = ""
        if "message" in result:
            message = self._get_message_from_multiformatMessageString(
                result["message"], rule,
            )
            description += f"**Result message:** {message}\n"
        if get_snippet(location) is not None:
            description += f"**Snippet:**\n```\n{get_snippet(location)}\n```\n"
        if rule is not None:
            if "name" in rule:
                description += f"**{_('Rule name')}:** {rule.get('name')}\n"
            shortDescription = ""
            if "shortDescription" in rule:
                shortDescription = self._get_message_from_multiformatMessageString(
                    rule["shortDescription"], rule,
                )
                if shortDescription != message:
                    description += f"**{_('Rule short description')}:** {shortDescription}\n"
            if "fullDescription" in rule:
                fullDescription = self._get_message_from_multiformatMessageString(
                    rule["fullDescription"], rule,
                )
                if fullDescription not in {message, shortDescription}:
                    description += f"**{_('Rule full description')}:** {fullDescription}\n"
        if "markdown" in result["message"]:
            markdown = self._get_message_from_multiformatMessageString(
                result["message"], rule, content_type="markdown",
            )
            # Replace "Details" with "Link" in the markdown
            markdown = markdown.replace("Details", "Link")
            description += f"**{_('Additional Details')}:**\n{markdown}\n"
            description += "_(Unprintable characters are replaced with '?'; please see Mayhem for full reproducer.)_"
        if len(result.get("codeFlows", [])) > 0:
            description += get_codeFlowsDescription(result["codeFlows"])

        return description.removesuffix("\n")

    def _get_message_from_multiformatMessageString(self, data, rule, content_type="text"):
        """
        Get a message from multimessage struct

        Differs from Sarif implementation in that it handles markdown, specifies content_type
        """
        if content_type == "markdown" and "markdown" in data:
            # handle markdown content
            markdown = data.get("markdown")
            # strip "headings" or anything that changes text size
            heading_regex = r"^#+\s*"
            markdown = re.sub(heading_regex, "", markdown, flags=re.MULTILINE)
            # replace non-unicode characters with "?"
            non_unicode_regex = r"[^\x09\x0A\x0D\x20-\x7E]"
            markdown = re.sub(non_unicode_regex, "?", markdown)
            return markdown.strip()
        if content_type == "text" and "text" in data:
            # handle text content
            text = data.get("text")
            if rule is not None and "id" in data:
                text = rule["messageStrings"][data["id"]].get("text")
                arguments = data.get("arguments", [])
                # argument substitution
                for i in range(6):  # the specification limit to 6
                    substitution_str = "{" + str(i) + "}"
                    if substitution_str in text and i < len(arguments):
                        text = text.replace(substitution_str, arguments[i])
            return text
        return ""
