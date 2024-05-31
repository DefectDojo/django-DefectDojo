import logging
from dojo.api_v2.api_error import ApiError
from django.conf import settings
from dojo.models import (
    Test,
    Finding,
    Engagement,
    TransferFinding,
    TransferFindingFinding,
    Test,
    System_Settings,
    Notes,
)
from dojo.authorization.authorization import user_has_global_permission
from dojo.notifications.helper import create_notification
from dojo.risk_acceptance.notification import Notification
from dojo.user.queries import get_user
from django.urls import reverse
logger = logging.getLogger(__name__)


def transfer_findings(transfer_finding_findings: TransferFindingFinding, serializer):

    """Transfer Findign update Status

    Args:
        transfer_finding_findings (TransferFindingFinding): Transfer Finding Finding model object
        request (dict): Request Body for example { "findings": { "0001": { "risk_status": "Transfer Rejected", "finding_related: 1}}}
    """

    request_findings = serializer.validated_data["findings"]
    test = None
    system_settings = System_Settings.objects.get()
    for transfer_finding_finding in transfer_finding_findings:
        finding = transfer_finding_finding.findings
        finding_id = str(finding.id)
        if finding_id in request_findings:
            dict_findings = request_findings[finding_id]
            if dict_findings:
                if (dict_findings["risk_status"] == "Transfer Accepted"
                    and finding.risk_status in ["Transfer Rejected", "Risk Active", "Transfer Pending", "Risk Expired"]):
                    finding.risk_status = dict_findings["risk_status"]
                    finding.active = False
                    if not test:
                        test = created_test(
                            origin_finding=finding,
                            transfer_finding=transfer_finding_finding.transfer_findings,
                        )
                    transfer_finding(
                        origin_finding=finding,
                        finding_related_id=dict_findings["related_finding"] if dict_findings.get("related_finding", None) else None,
                        transfer_finding=transfer_finding_finding.transfer_findings,
                        test=test,
                        transferfinding_findigns=transfer_finding_findings,
                        system_settings=system_settings
                    )

                    send_notification_transfer_finding(
                        transfer_findings=transfer_finding_finding.transfer_findings,
                        status="accepted"
                    )
                elif dict_findings["risk_status"] == "Transfer Rejected":
                    finding.risk_status = dict_findings["risk_status"]
                    finding.active = True
                    send_notification_transfer_finding(
                        transfer_findings=transfer_finding_finding.transfer_findings,
                        status="rejected"
                    )
                finding.save()
        else:
            logger.warning(f"Finding not Found: {finding.id}")


def created_test(origin_finding: Finding, transfer_finding: TransferFinding) -> Test:
    test: Test = None
    tests = transfer_finding.destination_engagement.test_set.all().order_by('-id')
    if tests:
        test = tests[0]
        logger.debug(f"Select test {test.id} for transfer finding")
    else:
        test = Test.objects.create(
            engagement=transfer_finding.destination_engagement,
            test_type=origin_finding.test.test_type,
            target_start=origin_finding.test.target_start,
            target_end=origin_finding.test.target_end,
        )
        logger.debug(f"Created new test {test.id} for transfer finding")
    return test


def transfer_finding(
    origin_finding: Finding,
    finding_related_id,
    transfer_finding: TransferFinding,
    test: Test,
    transferfinding_findigns: TransferFindingFinding,
    system_settings: System_Settings
):
    finding_related = None
    if finding_related_id:
        try:
            finding_related = Finding.objects.get(id=finding_related_id)
        except Exception as e:
            logger.error(e)
            raise ApiError.not_found(datail=f" {e} : finding_related: {finding_related_id}")

    if isinstance(origin_finding, Finding) and isinstance(transfer_finding.destination_engagement, Engagement):

        add_finding_related(transferfinding_findigns,
                            origin_finding,
                            test,
                            finding_related=finding_related)

        if transfer_finding.destination_product_type.name == system_settings.orphan_findings:
            logger.debug("Removed orphan findings {origin_finding.id}")
            origin_finding.delete()
            origin_finding.save()
            send_notification_transfer_finding(transfer_finding, status="removed")
    else:
        if not transfer_finding.destination_engagement:
            raise ApiError.bad_request("You must select an engagement")


def add_finding_related(
    transfer_finding_findings: TransferFindingFinding,
    origin_finding: Finding,
    test: Test,
    finding_related
):
    """Add new finding related to transferFindingFinding

    Args:
        transfer_finding_findings (TransferFindingFinding): Relation manytomany between transferFinding and Finding model
        origin_finding (Finding): Finding of product origin
        test (Test): new test created
    """
    flag_result_proccess = False
    system_user = get_user(settings.SYSTEM_USER)
    for transferfinding_finding in transfer_finding_findings:
        if (transferfinding_finding.findings == origin_finding):
            if finding_related is None:
                # Create a new finding related
                finding_related = Finding(
                    test=test,
                    title=origin_finding.title,
                    cve=origin_finding.cve,
                    severity=origin_finding.severity,
                    verified=origin_finding.verified,
                    description=origin_finding.description,
                    mitigation=origin_finding.mitigation,
                    impact=origin_finding.impact,
                    reporter=origin_finding.reporter,
                    numerical_severity=origin_finding.numerical_severity,
                    static_finding=origin_finding.static_finding,
                    dynamic_finding=origin_finding.dynamic_finding,
                    risk_status="Risk Active",
                    tags="Transferred",
                )
                finding_related.save()
                transferfinding_finding.finding_related = finding_related
                transferfinding_finding.save()
                flag_result_proccess = True
                break
            else:
                transferfinding_finding.finding_related = finding_related
                transferfinding_finding.save()
                flag_result_proccess = True

            if system_user and flag_result_proccess:
                note = Notes(author=system_user,
                            entry=f"This finding has been related to the finding with ID {origin_finding.id}.")
                note.save()
                finding_related.notes.add(note)
                break
            else:
                message = f"""Does not meet validation criteria to relate or create a new finding:
                    {transferfinding_finding.findings.id}, {transferfinding_finding.finding_related.id}"""
                logger.error(message)
                raise ApiError.precondition_required(detail=message)
        

def send_notification_transfer_finding(transfer_findings, status="accepted"):
    logger.debug("Send notification transfer_finding id {transfer_findings.id}")
    dict_rule = {"accepted": {"icon": "check-circle", "color_icon": "#096C11"},
                 "rejected": {"icon": "times-circle", "color_icon": "#b97a0c"},
                 "removed": {"icon": "times-circle", "color_icon": "#B90C0C"},
                 "pending": {"icon": "bell", "color_icon": "#1B30DE"}}

    pid = transfer_findings.origin_product.id
    create_notification(
        event="transfer_finding",
        title=f"{transfer_findings.title[:30]} {status}",
        icon=dict_rule[status]["icon"],
        color_icon=dict_rule[status]["color_icon"],
        recipients=[transfer_findings.owner.get_username()],
        url=reverse("view_transfer_finding", args=(pid,)),
    )


def close_or_reactive_related_finding(event: str, parent_finding: Finding, notes: str, send_notification: bool):
    transfer_finding_findings = TransferFindingFinding.objects.filter(finding_related=parent_finding)
    system_user = get_user(settings.SYSTEM_USER)
    for transfer_finding_finding in transfer_finding_findings:
        if event == "close":
            transfer_finding_finding.findings.active = False
            transfer_finding_finding.findings.out_of_scope = True
            note = Notes(entry=notes, author=system_user)
            note.save()
            logger.debug(f"(Transfer Finding) finding {parent_finding.id} and related finding {transfer_finding_finding.findings.id} are closed")
            transfer_finding_finding.findings.notes.add(note)
            transfer_finding_finding.findings.save()
            if send_notification:
                Notification.send_notification(
                    event="other",
                    subject=f"✅temporarily accepted by the parent finding {parent_finding.id} (policies for the transfer of findings)👌",
                    description=f"temporarily accepted by the parent finding <b>{parent_finding.title}</b> with id <b>{parent_finding.id}</b>",
                    finding=parent_finding,
                    user_names=[transfer_finding_finding.transfer_findings.owner.get_username()])
        if event == "reactive":
            transfer_finding_finding.findings.active = True
            transfer_finding_finding.findings.out_of_scope = False
            note = Notes(entry=notes, author=system_user)
            note.save()
            logger.debug(f"(Transfer Finding) finding {parent_finding.id} and related finding {transfer_finding_finding.findings.id} are reactivated")
            transfer_finding_finding.findings.notes.add(note)
            transfer_finding_finding.findings.save()
            if send_notification:
                Notification.send_notification(
                    event="other",
                    subject=f"✅This finding has been reactivated for the finding parent {parent_finding.id} (policies for the transfer of findings)👌",
                    description=f"The finding has been reactivated for the finding parent <b>{parent_finding.title}</b> with id <b>{parent_finding.id}</b>",
                    finding=parent_finding,
                    user_names=[transfer_finding_finding.transfer_findings.owner.get_username()])


def destroy_and_reset_finding_related(transfer_finding_finding):
    try:
        if transfer_finding_finding.finding_related:
            transfer_finding_finding.finding_related.delete()

        if transfer_finding_finding.findings:
            transfer_finding_finding.findings.risk_status = "Risk Active"
            transfer_finding_finding.findings.active = True
            transfer_finding_finding.findings.out_of_scope = False
            transfer_finding_finding.findings.save()

    except Exception as e:
        logger.error(e)
        ApiError.internal_server_error(detail=e)


def enable_flow_transfer_finding():
    return ["Risk Active"]
