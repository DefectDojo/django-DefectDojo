import json
from dojo.models import Endpoint, Finding


class NiktoJSONParser(object):
    def process_json(self, file, test):
        data = json.load(file)
        if len(data) == 1 and isinstance(data, list):
            data = data[0]
        dupes = dict()
        host = data.get("host")
        port = data.get("port")
        if port is not None:
            port = int(port)
        for vulnerability in data.get("vulnerabilities", []):
            description = "\n".join([
                f"**id:** `{vulnerability.get('id')}`",
                f"**msg:** `{vulnerability.get('msg')}`",
                f"**HTTP Method:** `{vulnerability.get('method')}`",
            ])
            if vulnerability.get('OSVDB') is not None:
                description += "\n" + f"**OSVDB:** `{vulnerability.get('OSVDB')}`"
            finding = Finding(
                title=vulnerability.get("msg"),
                severity="Info",  # Nikto doesn't assign severity, default to Info
                description=description,
                vuln_id_from_tool=vulnerability.get("id"),
                nb_occurences=1,
                references=vulnerability.get("references")
            )
            # manage if we have an ID from OSVDB
            if "OSVDB" in vulnerability and "0" != vulnerability.get("OSVDB"):
                finding.unique_id_from_tool = "OSVDB-" + vulnerability.get(
                    "OSVDB"
                )
                finding.description += "\n*This finding is marked as medium as there is a link to OSVDB*"
                finding.severity = "Medium"
            # build the endpoint
            endpoint = Endpoint(
                host=host,
                port=port,
                path=vulnerability.get("url"),
            )
            finding.unsaved_endpoints = [endpoint]
            # internal de-duplication
            dupe_key = finding.severity + finding.title
            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.description += "\n-----\n" + finding.description
                find.unsaved_endpoints.append(endpoint)
                find.unique_id_from_tool = (
                    None  # as it is an aggregated finding we erase ids
                )
                find.vuln_id_from_tool = (
                    None  # as it is an aggregated finding we erase ids
                )
                find.nb_occurences += 1
            else:
                dupes[dupe_key] = finding
        return list(dupes.values())
