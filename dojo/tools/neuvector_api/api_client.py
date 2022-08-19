import json
import requests

from dojo.models import Tool_Configuration, Tool_Type


class NeuVectorAPI:
    def __init__(self, tool_config=None):
        tool_type, _ = Tool_Type.objects.get_or_create(name='NeuVector')

        if not tool_config:
            try:
                tool_config = Tool_Configuration.objects.get(tool_type=tool_type)
            except Tool_Configuration.DoesNotExist:
                raise Exception(
                    'No NeuVector tool is configured. \n'
                    'Create a new Tool at Settings -> Tool Configuration'
                )
            except Tool_Configuration.MultipleObjectsReturned:
                raise Exception(
                    'More than one Tool Configuration for NeuVector exists. \n'
                    'Please specify at Product configuration which one should be used.'
                )

        self.nv_api_url = tool_config.url
        if tool_config.authentication_type == "Password":
            self.nv_user = tool_config.username
            self.nv_pass = tool_config.password
        else:
            raise Exception('NeuVector Authentication type {} not supported'.format(tool_config.authentication_type))

        self.login()

    def login(self):
        """
        Login on NeuVector and get token.
        :return:
        """
        url = '{}/v1/auth'.format(self.nv_api_url)
        headers = {
            'User-Agent': 'DefectDojo',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        params = {
            "password": {
                "username": self.nv_user,
                "password": self.nv_pass
            }
        }
        resp = requests.post(url, headers=headers, data=json.dumps(params))
        if resp.ok:
            self.nv_token = resp.json().get('token').get('token')
        else:
            raise Exception("Unable to authenticate on NeuVector due to {} - {}".format(
                resp.status_code, resp.content.decode("utf-8")
            ))

    def logout(self):
        """
        Logout from NeuVector.
        :return:
        """
        url = '{}/v1/auth'.format(self.nv_api_url)
        headers = {
            'User-Agent': 'DefectDojo',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Auth-Token': self.nv_token
        }
        requests.delete(url, headers=headers)

    def get_all_vp(self):
        """
        Returns all vulnerability profiles with 'default' name.
        """
        url = '{}/v1/vulnerability/profile/default'.format(self.nv_api_url)
        headers = {
            'User-Agent': 'DefectDojo',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Auth-Token': self.nv_token
        }
        resp = requests.get(url, headers=headers)
        if resp.ok:
            return resp.json().get('profile').get('entries')
        else:
            raise Exception("Unable to fetch vulnerability profiles due to {} - {}".format(
                resp.status_code, resp.content.decode("utf-8")
            ))

    def create_vulnerability_profile(self, vp_id, name, comment, namespaces=[], images=[]):
        """
        Creates a vulnerability profile in 'default' name with the provided parameters.
        """
        url = '{}/v1/vulnerability/profile/default/entry'.format(self.nv_api_url)
        headers = {
            'User-Agent': 'DefectDojo',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Auth-Token': self.nv_token
        }
        params = {
            "config": {
                "id": vp_id,
                "name": name,
                "comment": comment,
                "days": 0,
                "domains": namespaces,
                "images": images
            }
        }
        resp = requests.post(url, headers=headers, data=json.dumps(params))
        if resp.ok:
            return
        else:
            raise Exception("Unable to create a vulnerability profile due to {} - {}. data: {}".format(
                resp.status_code, resp.content.decode("utf-8"), json.dumps(params)
            ))

    def update_vulnerability_profile(self, vp_id, name, comment, namespaces=[], images=[]):
        """
        Updates a vulnerability profile in 'default' name with the provided parameters.
        """
        url = '{}/v1/vulnerability/profile/default'.format(self.nv_api_url)
        headers = {
            'User-Agent': 'DefectDojo',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Auth-Token': self.nv_token
        }
        params = {
            "config": {
                "name": "default",
                "entries": [
                    {
                        "id": vp_id,
                        "name": name,
                        "comment": comment,
                        "days": 0,
                        "domains": namespaces,
                        "images": images
                    }
                ]
            }
        }
        resp = requests.post(url, headers=headers, data=json.dumps(params))
        if resp.ok:
            return
        else:
            raise Exception("Unable to update a vulnerability profile due to {} - {}. data: {}".format(
                resp.status_code, resp.content.decode("utf-8"), json.dumps(params)
            ))

    def delete_vulnerability_profile(self, vp_id):
        """
        Deletes vulnerability profile in 'default' name.
        """
        url = '{}/v1/vulnerability/profile/default/entry/{}'.format(self.nv_api_url, vp_id)
        headers = {
            'User-Agent': 'DefectDojo',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Auth-Token': self.nv_token
        }
        resp = requests.delete(url, headers=headers)
        if resp.ok:
            return
        else:
            raise Exception("Unable to delete vulnerability profile due to {} - {}".format(
                resp.status_code, resp.content.decode("utf-8")
            ))

    def test_connection(self):
        """
        Returns number of namespaces or raises error.
        """
        url = '{}/v1/domain'.format(self.nv_api_url)
        headers = {
            'User-Agent': 'DefectDojo',
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'X-Auth-Token': self.nv_token
        }
        resp = requests.get(url, headers=headers)
        if resp.ok:
            num_namespaces = len(resp.json().get('domains'))
            return f'You have access to {num_namespaces} namespaces'
        else:
            raise Exception("Unable to connect to NeuVector due to {} - {}, token: {}".format(
                resp.status_code, resp.content.decode("utf-8"), self.nv_token
            ))
