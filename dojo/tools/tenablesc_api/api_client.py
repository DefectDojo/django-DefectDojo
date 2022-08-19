import json
import logging
import requests

from dojo.models import Tool_Configuration, Tool_Type

from tenable.sc import TenableSC

logger = logging.getLogger(__name__)


class TenableScAPI:
    def __init__(self, tool_config=None):
        tool_type, _ = Tool_Type.objects.get_or_create(name='Tenable SC')

        if not tool_config:
            try:
                tool_config = Tool_Configuration.objects.get(tool_type=tool_type)
            except Tool_Configuration.DoesNotExist:
                raise Exception(
                    'No Tenable SC tool is configured. \n'
                    'Create a new Tool at Settings -> Tool Configuration'
                )
            except Tool_Configuration.MultipleObjectsReturned:
                raise Exception(
                    'More than one Tool Configuration for Nessus exists. \n'
                    'Please specify at Product configuration which one should be used.'
                )

        sc_url = tool_config.url
        if tool_config.authentication_type == "Password":
            sc_a_key = tool_config.username
            sc_s_key = tool_config.password
        else:
            raise Exception('Tenable SC Authentication type {} not supported'.format(tool_config.authentication_type))

        # due to invalid certificates configuration on sc.netcetera.com we have
        # to explicitly do insecure connections
        validate_cert = False
        self.sc = TenableSC(url=sc_url, retries=1,
                            ssl_verify=validate_cert,
                            access_key=sc_a_key, secret_key=sc_s_key)

        try:
            self.login()
        except:
            logger.exception('something bad happened during authentication on Tenable.SC')
            raise

    def login(self):
        """
        Login on Nessus and get token.
        :return:
        """
        try:
            self.sc.login()
        except:
            logger.exception('something bad happened during authentication on Tenable.SC')
            raise

    def logout(self):
        """
        Logout from NeuVector.
        :return:
        """
        try:
            self.sc.logout()
        except:
            logger.exception('something bad happened during authentication on Tenable.SC')
            raise

    def get_all_ar(self):
        """
        Returns all accepted risks from all repos.
        """
        ar_list = None
        try:
            ar_list = self.sc.accept_risks.list()
        except:
            logger.exception('can not fetch accepted risks from Tenable.SC')
            raise
        return ar_list

    def create_ar_rule(self, plugin_id, repo_id, asset_list, comment):
        """
        Creates an accept risk rule. In all repositories.
        """
        try:
            rule = None
            if len(asset_list) == 0:
                rule = self.sc.accept_risks.create(plugin_id, repos=[repo_id], comments=comment)
            else:
                ips = []
                for asset in asset_list:
                    ips.append(asset['ip'])
                # we just take a port from the first asset, only one port is expected anyway
                rule = self.sc.accept_risks.create(plugin_id, repos=[repo_id], ips=ips, port=asset_list[0]['port'], comments=comment)

            self.sc.accept_risks.apply(rule['id'], 0)
        except:
            logger.exception('can not create accept risk rule on Tenable.SC')
            raise

    def update_ar_rule(self, rule_id, plugin_id, repo_id, asset_list, comment):
        """
        Updates an accept risk rule.
        """
        try:
            self.sc.accept_risks.delete(rule_id)
        except:
            logger.exception('can not delete accept risk rule from Tenable.SC')
            raise

        self.create_ar_rule(plugin_id, repo_id, asset_list, comment)

    def delete_ar_rule(self, rule_id):
        """
        Deletes vulnerability profile in 'default' name.
        """
        try:
            self.sc.accept_risks.delete(rule_id)
        except:
            logger.exception('can not delete accept risk rule from Tenable.SC')
            raise

    def test_connection(self):
        """
        Returns current user details.
        """
        try:
            user = self.sc.current.user()
            return f'User info: {user}'
        except:
            raise Exception("can't fetch current user details")
