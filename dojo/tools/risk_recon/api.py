import requests
from django.conf import settings


class RiskReconAPI:
    def __init__(self, api_key, endpoint, data):
        self.key = api_key
        self.url = endpoint
        self.data = data
        self.findings = []
        self.toe_map = {}

        if not self.key:
            msg = (
                "Please supply a Risk Recon API key. \n"
                "This can be generated in the system admin panel. \n"
                "See https://documentation.defectdojo.com/integrations/import/#risk-recon-api-importer \n"
            )
            raise Exception(msg)
        if not self.url:
            msg = (
                "Please supply a Risk Recon API url. \n"
                "A general url is https://api.riskrecon.com/v1/ \n"
                "See https://documentation.defectdojo.com/integrations/import/#risk-recon-api-importer \n"
            )
            raise Exception(msg)
        if self.url.endswith("/"):
            self.url = endpoint[:-1]
        self.session = requests.Session()
        self.map_toes()
        self.get_findings()

    def map_toes(self):
        response = self.session.get(
            url=f"{self.url}/toes",
            headers={"accept": "application/json", "Authorization": self.key},
            timeout=settings.REQUESTS_TIMEOUT,
        )

        if response.ok:
            comps = {}
            data = response.json()
            if isinstance(self.data, list):
                for company in self.data:
                    name = company.get("name", None)
                    filters = company.get("filters", None)
                    if name:
                        comps[name] = filters
            name_list = comps.keys()
            for item in data:
                toe_id = item.get("toe_id", None)
                name = item.get("toe_short_name", None)
                if not comps or name in name_list:
                    filters = comps.get(name)
                    self.toe_map[toe_id] = filters or self.data
        else:
            msg = f"Unable to query Target of Evaluations due to {response.status_code} - {response.content}"
            raise Exception(msg)

    def filter_finding(self, finding):
        filters = self.toe_map[finding["toe_id"]]
        if not filters:
            return False

        for filter_item in filters:
            filter_list = filters.get(filter_item, None)
            if filter_list and finding[filter_item] not in filter_list:
                return True

        return False

    def get_findings(self):
        for toe in self.toe_map:
            response = self.session.get(
                url=f"{self.url}/findings/{toe}",
                headers={
                    "accept": "application/json",
                    "Authorization": self.key,
                },
                timeout=settings.REQUESTS_TIMEOUT,
            )

            if response.ok:
                data = response.json()
                for finding in data:
                    if not self.filter_finding(finding):
                        self.findings.append(finding)
            else:
                msg = f"Unable to collect findings from toe: {toe} due to {response.status_code} - {response.content}"
                raise Exception(msg)
