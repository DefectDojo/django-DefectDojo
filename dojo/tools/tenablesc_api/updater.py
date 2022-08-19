import logging
import json
import ipaddress

from dojo.tools.tenablesc_api.api_client import TenableScAPI
from dojo.models import Risk_Acceptance

logger = logging.getLogger(__name__)


def find_id(client, plugin_id, repo_id, asset_list):
    ars = client.get_all_ar()
    for ar in ars:
        if ar['plugin']['id'] != plugin_id:
            continue
        # we only support assets defined explicitly by their addresses or rules
        # that do not specify assets
        if ar['hostType'] != 'ip' and ar['hostType'] != 'all':
            continue
        # if we know repository, compare it
        if repo_id:
            if ar['repository']['id'] != repo_id:
                continue
        # validate that the rule covers one of the expected asssets
        if ar['hostType'] == 'ip':
            # accepted risk may have IP addresses in the following format:
            # 192.168.25.27-192.168.25.30,192.168.25.40 *sigh*, we have to
            # parse it at first
            ipn = []
            for entry in ar['hostValue'].split(','):
                ip_range = entry.split('-', 1)

                if len(ip_range) == 2:
                    start_ip = ipaddress.ip_address(ip_range[0])
                    end_ip = ipaddress.ip_address(ip_range[1])
                    while start_ip <= end_ip:
                        ipn.append(start_ip)
                        start_ip += 1
                else:
                    ipn.append(ipaddress.ip_address(ip_range[0]))

            for asset in asset_list:
                # we do not compare port as Tenable does not support port
                # per-host: there is only one port for several IP addresses
                if ipaddress.ip_address(asset['ip']) in ipn:
                    return ar['id']
        # special case of all assets
        if len(asset_list) == 0 and ar['hostType'] == 'all':
            return ar['id']
    return ""

def get_repository_id(client, finding):
    # find repository ID from notes
    notes = finding.test.notes.all()
    # apparently, the latest note has index 0
    last_note = notes[0]
    # it has JSON structure in it, like that:
    # {"scan_instance_id": "3228", "repository_id": "15", "orig_url":
    # "https://tenable_host/#scan_results/view/3228"}
    note_json = json.loads(last_note.entry)
    if note_json and 'repository_id' in note_json:
        return note_json['repository_id']
    return None

def get_assets(client, finding):
    assets = []

    for ep in finding.endpoints.all():
        asset = {
            'ip': ep.host,
            'port': ep.port if ep.port != None else 0,
        }
        # if endpoint happend to be referenced by DNS, we can't do anything
        # about that due to limitation of Tenable.SC: we need an IP address in
        # order to reference it properly. on the other hand, DefectDojo does
        # not have an additional field for IP address.
        try:
            ipaddress.ip_address(asset['ip'])
            assets.append(asset)
        except:
            pass

    return assets

def produce_comment(finding):
    comment = "risk accepted in DefectDojo"

    ra = finding.risk_acceptance
    if ra.recommendation:
        for i in Risk_Acceptance.TREATMENT_CHOICES:
            if i[0] == ra.recommendation:
                comment += "; recommendation: " + i[1]
    if ra.recommendation_details:
        comment += "; recommendation details: " + ra.recommendation_details
    if ra.decision:
        for i in Risk_Acceptance.TREATMENT_CHOICES:
            if i[0] == ra.decision:
                comment += "; decision: " + i[1]
    if ra.decision_details:
        comment += "; decision details: " + ra.decision_details
    if ra.accepted_by:
        comment += "; accepted by: " + ra.accepted_by
    if ra.updated:
        comment += "; updated on: " + ra.updated.strftime("%Y-%m-%d, %H:%M:%S")
    if ra.owner:
        comment += "; owner: " + ra.owner.get_full_name()

    return comment


class TenableScApiUpdater():
    @staticmethod
    def prepare_client():
        return TenableScAPI()

    def delete_client(self, client):
        client.logout()

    def update_risk_acceptance(self, finding):
        ar_plugin_id = finding.vuln_id_from_tool
        if len(ar_plugin_id) == 0:
            logger.info("finding does not have ID information")
            return

        client = self.prepare_client()

        repo_id = get_repository_id(client, finding)

        asset_list = get_assets(client, finding)

        ar_id = find_id(client, ar_plugin_id, repo_id, asset_list)

        logger.debug("update_risk_acceptance. plugin id: {}, existing ar id: {}, repo id: {}, assets: {}.".format(ar_plugin_id, ar_id, repo_id, asset_list))

        if finding.risk_accepted:
            ar_comment = produce_comment(finding)
            # if there is no existing rule, create one
            if len(ar_id) == 0:
                logger.debug('creating an accept risk rule')
                client.create_ar_rule(ar_plugin_id, repo_id, asset_list, ar_comment)
            else:
                logger.debug('updating an accept risk rule')
                # update an existing rule
                # in fact, only comment will be updated
                client.update_ar_rule(ar_id, ar_plugin_id, repo_id, asset_list, ar_comment)

        if not finding.risk_accepted:
            logger.debug('risk not accepted')
            # if profile does not exist, nothing to delete
            if len(ar_id) > 0:
                logger.debug('deleting an accept risk rule')
                client.delete_ar_rule(ar_id)

        self.delete_client(client)

    def check_remove_risk_acceptance(self, finding):
        ar_plugin_id = finding.vuln_id_from_tool
        if len(ar_plugin_id) == 0:
            logger.info("finding does not have ID information")
            return

        client = self.prepare_client()

        repo_id = get_repository_id(client, finding)

        asset_list = get_assets(client, finding)

        ar_id = find_id(client, ar_plugin_id, repo_id, asset_list)

        logger.debug("check_remove_risk_acceptance. plugin id: {}, existing ar id: {}, repo id: {}, assets: {}.".format(ar_plugin_id, ar_id, repo_id, asset_list))

        # if accept risk rule does not exist, nothing to delete
        if len(ar_id) > 0:
            logger.debug('deleting an accept risk rule')
            client.delete_ar_rule(ar_id)

        self.delete_client(client)
