import datetime as dt
import logging

logger = logging.getLogger(__name__)

SHORT_SHA256 = 8


def sha256_tag(sha256: str | None) -> str:
    # Titles carry a short sha256: one component name can stand for several different binaries
    # (HxD ships a build per language, all at the same path), which would otherwise be identical rows.
    return f"(sha256 {sha256[:SHORT_SHA256]})" if sha256 else ""


class CveInfoNode:
    def __init__(self) -> None:
        self.active: bool = True
        self.title: str = ""
        self.description: str = ""

        self.component_file_name: str = ""
        self.component_file_path: str = ""
        self.component_file_purl: str = ""
        self.component_file_sha256: str = ""
        self.component_file_version: str = ""
        self.component_name: str = ""
        self.component_purl: str = ""
        self.component_type: str = "component"
        self.component_version: str = ""
        self.comp_uuid: str = ""

        self.cve: str | None = None
        self.vuln_id_from_tool: str = ""

        self.dep_uuid: str | None = None
        self.impact: str = ""

        self.scan_date: dt.date = dt.datetime.now(tz=dt.UTC).date()

        self.cvss_version: int = 0
        self.score: float | None = None  # base score; cvss_version says which (v3 or v4) field it goes to
        self.score_severity: str = "Info"  # score mapped to severity

        self.tags: list[str] = []
        self.known_exploited: bool = False

    def __str__(self) -> str:
        return f"{self.__dict__}"

    def make_title_cin(
        self,
        cve: str,
    ) -> str:
        logger.debug("make_title_cin")

        tt: list[str] = [
            f"{cve}",
            f"on {self.component_type}:",  # no trailing space: the parts are joined with ' '
        ]

        purl = self.component_purl
        if self.component_type == "component":
            purl = self.component_file_purl

        if purl:
            tt.append(f"purl: {purl}")
        else:
            # leave out empty parts: an empty name or version must not leave a double space in the title
            if self.component_name:
                tt.append(self.component_name)
            if self.component_version:
                tt.append(f"version {self.component_version}")

        tag = sha256_tag(self.component_file_sha256)
        if tag:
            tt.append(tag)

        self.title = " ".join(tt)
        return self.title

    def append_summary(
        self,
        dd: list[str],
        summary: str | None = None,
    ) -> str:
        logger.debug("append_summary")

        if summary:
            dd.insert(0, f"*{summary}*\n")
        self.description = "\n".join(dd)
        return self.description

    @staticmethod
    def _append_item(dd: list[str], name: str, version: str) -> None:
        # without a name there is nothing to show as item: keep only the version
        if name:
            item = f"{name} {version}" if version else name
            dd.append(f"**item: {item}**")
        elif version:
            dd.append(f"- version {version}")

    def make_description_cin(
        self,
        *,
        purl: str,
        summary: str | None = None,
    ) -> str:
        logger.debug("make_description_cin")

        # both branches describe the component the vulnerability was found in:
        # by its purl, or without one by its name as 'item: <name> <version>'
        dd: list[str] = []
        if self.component_type == "component":
            dd.append(f"## For {self.component_type}\n")
            if purl:
                dd.append(f"**purl: {purl}**")
                if self.component_version:
                    dd.append(f"- version {self.component_version}")
            else:
                self._append_item(dd, self.component_file_name, self.component_version)
        else:
            dd.append("## For component\n")

            purl = self.component_file_purl
            if purl:
                dd.append(f"**purl: {purl}**")
            else:
                self._append_item(dd, self.component_file_name, self.component_file_version)

        # common ----
        if self.component_file_path:
            dd.append(f"- path: {self.component_file_path}")
        if self.component_file_sha256:
            dd.append(f"- sha256: {self.component_file_sha256}")
        dd.append("\n")

        return self.append_summary(dd, summary)
