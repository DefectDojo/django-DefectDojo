import requests
from urllib.parse import urlencode
from dojo.models import Tool_Type


class BugcrowdAPI:
    """
    A simple client for the bugcrowd.io API
    """

    bugcrowd_api_url = "https://api.bugcrowd.com"
    default_headers = {
        "Accept": "application/vnd.bugcrowd+json",
        "User-Agent": "DefectDojo",
        "Bugcrowd-Version": "2021-10-28",
    }

    def __init__(self, tool_config):
        Tool_Type.objects.get_or_create(name="Bugcrowd API")

        self.session = requests.Session()
        if tool_config.authentication_type == "API":
            self.api_token = tool_config.api_key
            self.session.headers.update(
                {"Authorization": "Token {}".format(self.api_token)}
            )
            self.session.headers.update(self.default_headers)
        else:
            raise Exception(
                "bugcrowd Authentication type {} not supported".format(
                    tool_config.authentication_type
                )
            )

    def get_findings(self, program, target):
        """
        Returns the findings in a paginated iterator for a given bugcrowd program and target, if target is *, everything is returned
        :param program:
        :param target:
        :return:
        """
        params_default = {
            "filter[duplicate]": "false",
            "filter[program]": program,
            "page[limit]": 100,
            "page[offset]": 0,
            "include": "monetary_rewards,target,program,external_issues",
            "sort": "submitted-desc",
        }

        if target:
            params = params_default
            params["filter[target]"] = target
            params_encoded = urlencode(params)
        else:
            params_encoded = urlencode(params_default)

        next = "{}/submissions?{}".format(self.bugcrowd_api_url, params_encoded)
        while next != "":
            response = self.session.get(url=next)
            response.raise_for_status()
            if response.ok:
                data = response.json()
                if len(data["data"]) != 0:
                    yield data["data"]

                # When we hit the end of the submissions, break out
                if len(data["data"]) == 0:
                    next = ""
                    break

                # Otherwise, keep updating next link
                next = "{}{}".format(self.bugcrowd_api_url, data["links"]["next"])
            else:
                next = "over"

    def test_connection(self):
        # Request programs
        response_programs = self.session.get(
            url="{}/programs".format(self.bugcrowd_api_url)
        )
        response_programs.raise_for_status()

        # Request submissions to validate the org token
        response_subs = self.session.get(
            url="{}/submissions".format(self.bugcrowd_api_url)
        )
        response_subs.raise_for_status()
        if response_programs.ok and response_subs.ok:
            data = response_programs.json().get("data")
            data_subs = response_subs.json().get("meta")
            total_subs = str(data_subs["total_hits"])

            progs = list(filter(lambda prog: prog["type"] == "program", data))
            program_names = ", ".join(
                list(map(lambda p: p["attributes"]["code"], progs))
            )
            # Request targets to validate the org token
            response_targets = self.session.get(
                url="{}/targets".format(self.bugcrowd_api_url)
            )
            response_targets.raise_for_status()
            if response_targets.ok:
                data_targets = response_targets.json().get("data")
                targets = list(
                    filter(lambda prog: prog["type"] == "target", data_targets)
                )
                target_names = ", ".join(
                    list(map(lambda p: p["attributes"]["name"], targets))
                )
                return f'With {total_subs} submissions, you have access to the "{ program_names }" programs, \
                    you can use these as Service key 1 for filtering submissions \
                        You also have targets "{ target_names }" that can be used in Service key 2'
            else:
                raise Exception(
                    "Bugcrowd API test not successful, no targets were defined in Bugcrowd which is used for filtering, check your configuration, HTTP response was: {}".format(
                        response_targets.text
                    )
                )
        else:
            raise Exception(
                "Bugcrowd API test not successful, could not retrieve the programs or submissions, check your configuration, HTTP response for programs was: {}, HTTP response for submissions was: {}".format(
                    response_programs.text, response_subs.text
                )
            )

    def test_product_connection(self, api_scan_configuration):
        submissions = []
        submission_gen = self.get_findings(
            api_scan_configuration.service_key_1, api_scan_configuration.service_key_2
        )
        for page in submission_gen:
            submissions = submissions + page
        submission_number = len(submissions)
        return f'You have access to "{submission_number}" submissions (no duplicates)\
            in Bugcrowd in the Program code "{api_scan_configuration.service_key_1}" \
            and Target "{api_scan_configuration.service_key_2}" (leave service key 2 empty to get all submissions in program)'
