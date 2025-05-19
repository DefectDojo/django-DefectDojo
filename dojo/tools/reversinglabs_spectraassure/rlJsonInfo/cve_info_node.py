import datetime
import logging

from typing import (
    List,
)

logger = logging.getLogger(__name__)


class CveInfoNode:
    """
    Here we collect info that can be easily mapped to a DefectDojo Finding

    """

    cve: str
    comp_uuid: str
    dep_uuid: str | None
    #
    scan_date: datetime.date
    scan_tool: str
    scan_tool_version: str
    #
    original_file: str
    original_file_sha256: str

    title: str
    description: str
    #
    cvss_version: int
    score: float
    score_severity: str  # score mapped to severity
    #
    # this is always the component
    component_file_path: str  # this is always the component
    component_file_sha256: str
    component_file_purl: str
    component_file_name: str
    component_file_version: str

    # this can be the component or the dependency name -> see component_type
    component_type: str  # component or dependency
    component_name: str
    component_version: str
    component_purl: str
    str | None
    #
    unique_id_from_tool: str | None
    vuln_id_from_tool: str | None
    #
    active: bool
    tags: List[str]
    impact: str | None

    def __init__(self) -> None:
        self.tags = []
        self.impact = None

    def __str__(self) -> str:
        return f"{self.__dict__}"

    def _make_title_cin(
        self,
        cve: str,
        with_sha256: bool = False,
    ) -> str:
        logger.debug("")

        purl = self.component_purl
        if self.component_type == "component":
            purl = self.component_file_purl

        if purl != "":
            self.title = " ".join(
                [
                    f"{cve}",
                    f"on {self.component_type}",
                    f"purl: {purl}",
                ],
            )
        else:
            self.title = " ".join(
                [
                    f"{cve}",
                    f"on {self.component_type}",
                    f"name: {self.component_name}",
                    f"version: {self.component_version}",
                ],
            )
        if self.component_type == "component":
            if with_sha256:
                self.title += f" (sha256: {self.component_file_sha256})"

        return self.title

    def _make_description_cin(
        self,
        cve: str,
        purl: str,
    ) -> str:
        def bold(s: str) -> str:
            return f"**{s}**"

        def italic(s: str) -> str:
            return f"*{s}*"

        def item(s: str) -> str:
            return f"* {s}"

        if self.component_type == "component":

            self.description = " ".join(
                [
                    f"On {self.component_type}",
                    f"purl: {purl}",
                    f"version: {self.component_version}",
                    f"path: {self.component_file_path}",
                    f"(sha256: {self.component_file_sha256})",
                ],
            )
            return self.description

        purl = self.component_file_purl
        if purl == "":
            purl = self.component_file_name + "@" + self.component_file_version

        self.description = " ".join(
            [
                "On component",
                f"purl: {purl}",
                f"path: {self.component_file_path}",
                f"(sha256: {self.component_file_sha256})",
            ],
        )
        return self.description
