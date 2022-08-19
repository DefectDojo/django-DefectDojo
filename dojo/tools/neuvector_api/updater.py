import logging
import json

from django.core.exceptions import ValidationError
from dojo.tools.neuvector_api.api_client import NeuVectorAPI
from dojo.tools.neuvector.parser import NEUVECTOR_IMAGE_SCAN_ENGAGEMENT_NAME
from dojo.tools.neuvector.parser import NEUVECTOR_CONTAINER_SCAN_ENGAGEMENT_NAME
from dojo.models import Risk_Acceptance

logger = logging.getLogger(__name__)


def determine_namespaces(finding):
    namespaces = []
    if finding.test.engagement.name != NEUVECTOR_CONTAINER_SCAN_ENGAGEMENT_NAME:
        return namespaces

    test = finding.test.title
    # test name example: "namespace_name / deployment_name"
    t = test.split(" / ")
    if len(t) == 2:
        namespaces.append(t[0])
    else:
        # do not append strings like 'unknown' as it creates incorrect
        # filter
        pass
    return namespaces

def determine_images(finding):
    images = []
    if finding.test.engagement.name != NEUVECTOR_IMAGE_SCAN_ENGAGEMENT_NAME:
        return images

    # image name can be extracted from notes only, a note example:

    # {"scan_timestamp":1661429956,"used_by":"workload_name","base_os":"alpine:3.16.2","workload_image":"image_path","labels":{...
    notes = finding.test.notes.all()
    # apparently, the latest note has index 0
    last_note = notes[0]
    note_json = json.loads(last_note.entry)
    if 'workload_image' in note_json:
        # indeed, only one image. initially, it was assumed that there could be
        # several images for a single finding/test
        images.append(note_json['workload_image'])

    return images

def find_free_id(client):
    vps = client.get_all_vp()
    if (not vps) or (len(vps) == 0):
        return 1000
    # we assume that identifiers are sorted
    vp_id = vps[-1]['id']
    vp_id += 1
    return vp_id

def find_id(client, name, namespaces=[], images=[]):
    ns_set_orig = set(namespaces)
    im_set_orig = set(images)
    vps = client.get_all_vp()
    for vp in vps:
        if vp['name'] == name:
            if (ns_set_orig == set(vp['domains'])) and (im_set_orig == set(vp['images'])):
                return vp['id']
    return -1

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


class NeuVectorApiUpdater():
    @staticmethod
    def prepare_client():
        return NeuVectorAPI()

    def delete_client(self, client):
        client.logout()

    def update_risk_acceptance(self, finding):
        client = self.prepare_client()
        # finding title is "CVE-XXX: short description"
        # we need only CVE part which is vulnerability['name'] in NV scan result
        vp_name = finding.title.split(':')[0]
        vp_namespaces = determine_namespaces(finding)
        vp_images = determine_images(finding)
        # find existing profile. we consider profiles as different even if they
        # differ only in namespace/image filters
        vp_id = find_id(client, name=vp_name, namespaces=vp_namespaces, images=vp_images)

        logger.debug('update_risk_acceptance %s, id: %d', vp_name, vp_id)
        if finding.risk_accepted:
            vp_comment = produce_comment(finding)
            # if there is no existing profile, create one
            if vp_id < 0:
                logger.debug('creating a vulnerability profile')
                vp_id = find_free_id(client)
                client.create_vulnerability_profile(vp_id=vp_id, name=vp_name, comment=vp_comment, namespaces=vp_namespaces, images=vp_images)
            else:
                logger.debug('updating a vulnerability profile')
                # update an existing profile
                # in fact, only comment will be updated
                client.update_vulnerability_profile(vp_id=vp_id, name=vp_name, comment=vp_comment, namespaces=vp_namespaces, images=vp_images)

        if not finding.risk_accepted:
            logger.debug('risk not accepted')
            # if profile does not exist, nothing to delete
            if vp_id > 0:
                logger.debug('deleting a vulnerability profile')
                client.delete_vulnerability_profile(vp_id)

        self.delete_client(client)

    def check_remove_risk_acceptance(self, finding):
        client = self.prepare_client()
        # finding title is "CVE-XXX: short description"
        # we need only CVE part which is vulnerability['name'] in NV scan result
        vp_name = finding.title.split(':')[0]
        vp_namespaces = determine_namespaces(finding)
        vp_images = determine_images(finding)
        # find existing profile. we consider profiles as different even if they
        # differ only in namespace/image filters
        vp_id = find_id(client, name=vp_name, namespaces=vp_namespaces, images=vp_images)

        logger.debug("check_remove_risk_acceptance {}, id: {}, namespaces: {}, images: {}".format(vp_name, vp_id, vp_namespaces, vp_images))

        # if profile does not exist, nothing to delete
        if vp_id > 0:
            logger.debug('deleting a vulnerability profile')
            client.delete_vulnerability_profile(vp_id)

        self.delete_client(client)
