import base64
import logging

import dojo.finding.helper as finding_helper
import dojo.jira_link.helper as jira_helper
import dojo.notifications.helper as notifications_helper
from dojo.decorators import dojo_async_task
from dojo.celery import app
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core import serializers
from django.core.files.base import ContentFile
from django.utils import timezone
from dojo.importers import utils as importer_utils
from dojo.importers.reimporter import utils as reimporter_utils
from dojo.models import BurpRawRequestResponse, FileUpload, Finding, Notes, Test_Import
from dojo.tools.factory import get_parser
from dojo.utils import get_current_user, is_finding_groups_enabled
from django.db.models import Q

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


def add_note_if_not_exists(finding, test, user, text):
    existing_note = finding.notes.filter(
        entry=text % test.test_type, author=user
    )
    if len(existing_note) == 0:
        note = Notes(
            entry=text % test.test_type, author=user
        )
        note.save()
        finding.notes.add(note)


class DojoDefaultReImporter(object):
    @dojo_async_task
    @app.task(ignore_result=False)
    def process_parsed_findings(
        self,
        test,
        parsed_findings,
        scan_type,
        user,
        active=None,
        verified=None,
        minimum_severity=None,
        endpoints_to_add=None,
        push_to_jira=None,
        group_by=None,
        now=timezone.now(),
        service=None,
        scan_date=None,
        do_not_reactivate=False,
        create_finding_groups_for_all_findings=True,
        apply_tags_to_findings=False,
        **kwargs,
    ):

        reimported_findings = parsed_findings
        original_findings = list(test.finding_set.all())
        new_findings = []
        finding_count = 0
        reactivated_count = 0
        reactivated_items = []
        unchanged_count = 0
        unchanged_findings = []

        logger.debug("starting reimport of %i items.", len(reimported_findings) if reimported_findings else 0)
        deduplication_algorithm = test.deduplication_algorithm

        group_names_to_findings_dict = {}
        logger.debug(
            "STEP 1: looping over findings from the reimported report and trying to match them to existing findings"
        )
        deduplicationLogger.debug(
            "Algorithm used for matching new findings to existing findings: %s",
            deduplication_algorithm,
        )
        for index, reimported_finding in enumerate(reimported_findings):
            # FIXME hack to remove when all parsers have unit tests for this attribute
            if reimported_finding.severity.lower().startswith("info") and reimported_finding.severity != "Info":
                reimported_finding.severity = "Info"

            reimported_finding.numerical_severity = Finding.get_numerical_severity(reimported_finding.severity)

            if minimum_severity and (
                Finding.SEVERITIES[reimported_finding.severity] > Finding.SEVERITIES[minimum_severity]
            ):
                # finding's severity is below the configured threshold : ignoring the finding
                continue

            # existing findings may be from before we had component_name/version fields
            component_name = (
                reimported_finding.component_name if hasattr(reimported_finding, "component_name") else None
            )
            component_version = (
                reimported_finding.component_version if hasattr(reimported_finding, "component_version") else None
            )

            if not hasattr(reimported_finding, "test"):
                reimported_finding.test = test

            if service:
                reimported_finding.service = service

            if reimported_finding.dynamic_finding:
                for e in reimported_finding.unsaved_endpoints:
                    try:
                        e.clean()
                    except ValidationError as err:
                        logger.warning(
                            "DefectDojo is storing broken endpoint because cleaning wasn't successful: "
                            "{}".format(err)
                        )

            reimported_finding.hash_code = reimported_finding.compute_hash_code()
            deduplicationLogger.debug("item's hash_code: %s", reimported_finding.hash_code)

            existing_findings = reimporter_utils.match_new_finding_to_existing_finding(
                reimported_finding, test, deduplication_algorithm
            )
            deduplicationLogger.debug(
                "found %i findings matching with current new finding", len(existing_findings)
            )

            if existing_findings:
                # existing findings found
                existing_finding = existing_findings[0]
                if existing_finding.is_mitigated:
                    # if the reimported item has a mitigation time, we can compare
                    if reimported_finding.is_mitigated:
                        unchanged_findings.append(existing_finding)
                        unchanged_count += 1
                        if reimported_finding.mitigated:
                            logger.debug(
                                "item mitigated time: "
                                + str(reimported_finding.mitigated.timestamp())
                            )
                            logger.debug(
                                "finding mitigated time: "
                                + str(existing_finding.mitigated.timestamp())
                            )
                            if reimported_finding.mitigated.timestamp() == existing_finding.mitigated.timestamp():
                                logger.debug(
                                    "New imported finding and already existing finding have the same mitigation date, will skip as they are the same."
                                )
                            else:
                                logger.debug(
                                    "New imported finding and already existing finding are both mitigated but have different dates, not taking action"
                                )
                                # TODO: implement proper date-aware reimporting mechanism, if an imported finding is closed more recently than the defectdojo finding, then there might be details in the scanner that should be added
                    # existing_finding is mitigated but reimported_finding is not
                    else:
                        if do_not_reactivate:
                            logger.debug(
                                "%i: skipping reactivating by user's choice do_not_reactivate: %i:%s:%s:%s",
                                index,
                                existing_finding.id,
                                existing_finding,
                                existing_finding.component_name,
                                existing_finding.component_version,
                            )
                            add_note_if_not_exists(existing_finding, test, user, "Finding has skipped reactivation from %s re-upload with user decision do_not_reactivate.")
                            existing_finding.save(dedupe_option=False)
                        else:
                            # i.e. Reactivate findings
                            if existing_finding.false_p or existing_finding.out_of_scope or existing_finding.risk_accepted:
                                #  If the existing_finding in DD is in one of the above states,
                                #  we no longer sync the scanners state similar to do_not_reactivate=True
                                unchanged_findings.append(existing_finding)
                                unchanged_count += 1
                            else:
                                logger.debug(
                                    "%i: reactivating: %i:%s:%s:%s",
                                    index,
                                    existing_finding.id,
                                    existing_finding,
                                    existing_finding.component_name,
                                    existing_finding.component_version,
                                )
                                existing_finding.mitigated = None
                                existing_finding.is_mitigated = False
                                existing_finding.mitigated_by = None
                                existing_finding.active = True
                                if verified is not None:
                                    existing_finding.verified = verified
                                # existing findings may be from before we had component_name/version fields
                                existing_finding.component_name = (
                                    existing_finding.component_name
                                    if existing_finding.component_name
                                    else component_name
                                )
                                existing_finding.component_version = (
                                    existing_finding.component_version
                                    if existing_finding.component_version
                                    else component_version
                                )

                                # don't dedupe before endpoints are added
                                existing_finding.save(dedupe_option=False)
                                note = Notes(
                                    entry="Re-activated by %s re-upload." % scan_type, author=user
                                )
                                note.save()

                                endpoint_statuses = existing_finding.status_finding.exclude(
                                    Q(false_positive=True)
                                    | Q(out_of_scope=True)
                                    | Q(risk_accepted=True)
                                )
                                reimporter_utils.chunk_endpoints_and_reactivate(endpoint_statuses)

                                existing_finding.notes.add(note)
                                reactivated_items.append(existing_finding)
                                reactivated_count += 1
                # Existing finding is not mitigated
                else:
                    logger.debug(
                        "Reimported item matches a finding that is currently open."
                    )
                    if reimported_finding.is_mitigated:
                        logger.debug(
                            "Reimported mitigated item matches a finding that is currently open, closing."
                        )
                        # TODO: Implement a date comparison for opened defectdojo findings before closing them by reimporting, as they could be force closed by the scanner but a DD user forces it open ?
                        logger.debug(
                            "%i: closing: %i:%s:%s:%s",
                            index,
                            existing_finding.id,
                            existing_finding,
                            existing_finding.component_name,
                            existing_finding.component_version,
                        )
                        existing_finding.mitigated = reimported_finding.mitigated
                        existing_finding.is_mitigated = True
                        existing_finding.mitigated_by = reimported_finding.mitigated_by
                        existing_finding.active = False
                        if verified is not None:
                            existing_finding.verified = verified
                        add_note_if_not_exists(existing_finding, test, user, "Mitigated by %s re-upload.")
                        existing_finding.save(dedupe_option=False)
                    #  reimported_finding is not mitigated but is risk accepted by the scanner
                    elif reimported_finding.risk_accepted:
                        # A risk accepted finding is not explicitly mitigated, so we need to add it to avoid mitigation
                        # as otherwise it will get mitigated in close_old_findings
                        # keeps https://github.com/DefectDojo/django-DefectDojo/pull/7447 behaviour the same
                        unchanged_findings.append(existing_finding)
                        unchanged_count += 1
                        if not existing_finding.risk_accepted:
                            #  If the existing_finding in DD is not risk accepted
                            #  then we risk accept it and set it to inactive
                            logger.debug('Reimported risk_accepted item matches '
                                         'a finding that is currently not risk_accepted.')
                            logger.debug('%i: risk accepting: %i:%s:%s:%s', index, existing_finding.id,
                                         existing_finding, existing_finding.component_name,
                                         existing_finding.component_version)
                            existing_finding.risk_accepted = reimported_finding.risk_accepted
                            existing_finding.active = False
                            if verified is not None:
                                existing_finding.verified = verified
                            note = Notes(
                                entry="Risk accepted by %s re-upload." % test.test_type, author=user
                            )
                            note.save()
                            existing_finding.notes.add(note)
                            existing_finding.save(dedupe_option=False)
                    # If the scanner says the reimported_finding is either
                    # (false positive or out of scope but not risk accepted or mitigated)
                    # we take over these values and close the finding
                    elif reimported_finding.false_p or reimported_finding.out_of_scope:
                        logger.debug('Reimported false positive or out of scope'
                                     ' item matches a finding that is currently open, closing.')
                        logger.debug('%i: closing: %i:%s:%s:%s', index, existing_finding.id, existing_finding, existing_finding.component_name, existing_finding.component_version)
                        existing_finding.false_p = reimported_finding.false_p
                        existing_finding.out_of_scope = reimported_finding.out_of_scope
                        existing_finding.active = False
                        if verified is not None:
                            existing_finding.verified = verified
                        # because existing_finding is not added to unchanged_items,
                        # it will get mitigated in close_old_findings
                    else:
                        # if finding is the same but list of affected was changed,
                        # finding is marked as unchanged. This is a known issue
                        unchanged_findings.append(existing_finding)
                        unchanged_count += 1

                    if (component_name is not None and not existing_finding.component_name) or (
                        component_version is not None and not existing_finding.component_version
                    ):
                        existing_finding.component_name = (
                            existing_finding.component_name
                            if existing_finding.component_name
                            else component_name
                        )
                        existing_finding.component_version = (
                            existing_finding.component_version
                            if existing_finding.component_version
                            else component_version
                        )
                        existing_finding.save(dedupe_option=False)

                if existing_finding.dynamic_finding:
                    logger.debug(
                        "Re-import found an existing dynamic finding for this new finding. Checking the status of endpoints"
                    )
                    reimporter_utils.update_endpoint_status(existing_finding, reimported_finding, user)
            else:
                # no existing finding, found
                reimported_finding.reporter = user
                reimported_finding.last_reviewed = timezone.now()
                reimported_finding.last_reviewed_by = user

                if active is not None:
                    # indicates an override. Otherwise, do not change the value of item.active
                    reimported_finding.active = active

                if verified is not None:
                    # indicates an override. Otherwise, do not change the value of verified
                    reimported_finding.verified = verified

                # if scan_date was provided, override value from parser
                if scan_date:
                    reimported_finding.date = scan_date.date()

                # Save it. Don't dedupe before endpoints are added.
                reimported_finding.save(dedupe_option=False)
                logger.debug(
                    "%i: reimport created new finding as no existing finding match: %i:%s:%s:%s",
                    index,
                    reimported_finding.id,
                    reimported_finding,
                    reimported_finding.component_name,
                    reimported_finding.component_version,
                )

                # only new items get auto grouped to avoid confusion around already existing items that are already grouped
                if is_finding_groups_enabled() and group_by:
                    # If finding groups are enabled, group all findings by group name
                    name = finding_helper.get_group_by_group_name(reimported_finding, group_by)
                    if name is not None:
                        if name in group_names_to_findings_dict:
                            group_names_to_findings_dict[name].append(reimported_finding)
                        else:
                            group_names_to_findings_dict[name] = [reimported_finding]

                new_findings.append(reimported_finding)
                existing_finding = reimported_finding

                if hasattr(reimported_finding, "unsaved_req_resp"):
                    for req_resp in reimported_finding.unsaved_req_resp:
                        burp_rr = BurpRawRequestResponse(
                            finding=existing_finding,
                            burpRequestBase64=base64.b64encode(
                                req_resp["req"].encode("utf-8")
                            ),
                            burpResponseBase64=base64.b64encode(
                                req_resp["resp"].encode("utf-8")
                            ),
                        )
                        burp_rr.clean()
                        burp_rr.save()

                if reimported_finding.unsaved_request and reimported_finding.unsaved_response:
                    burp_rr = BurpRawRequestResponse(
                        finding=existing_finding,
                        burpRequestBase64=base64.b64encode(
                            reimported_finding.unsaved_request.encode()
                        ),
                        burpResponseBase64=base64.b64encode(
                            reimported_finding.unsaved_response.encode()
                        ),
                    )
                    burp_rr.clean()
                    burp_rr.save()

            # for existing findings: make sure endpoints are present or created
            if existing_finding:
                finding_count += 1
                importer_utils.chunk_endpoints_and_disperse(
                    existing_finding, test, reimported_finding.unsaved_endpoints
                )
                if endpoints_to_add:
                    importer_utils.chunk_endpoints_and_disperse(
                        existing_finding, test, endpoints_to_add
                    )

                if reimported_finding.unsaved_tags:
                    existing_finding.tags = reimported_finding.unsaved_tags

                if reimported_finding.unsaved_files:
                    for unsaved_file in reimported_finding.unsaved_files:
                        data = base64.b64decode(unsaved_file.get("data"))
                        title = unsaved_file.get("title", "<No title>")
                        (
                            file_upload,
                            file_upload_created,
                        ) = FileUpload.objects.get_or_create(
                            title=title,
                        )
                        file_upload.file.save(title, ContentFile(data))
                        file_upload.save()
                        existing_finding.files.add(file_upload)

                if existing_finding.unsaved_vulnerability_ids:
                    importer_utils.handle_vulnerability_ids(existing_finding)

                # existing findings may be from before we had component_name/version fields
                existing_finding.component_name = (
                    existing_finding.component_name if existing_finding.component_name else component_name
                )
                existing_finding.component_version = (
                    existing_finding.component_version
                    if existing_finding.component_version
                    else component_version
                )

                # finding = new finding or existing finding still in the upload report
                # to avoid pushing a finding group multiple times, we push those outside of the loop
                if is_finding_groups_enabled() and group_by:
                    existing_finding.save()
                else:
                    existing_finding.save(push_to_jira=push_to_jira)

        to_mitigate = (
            set(original_findings) - set(reactivated_items) - set(unchanged_findings)
        )
        # due to #3958 we can have duplicates inside the same report
        # this could mean that a new finding is created and right after
        # that it is detected as the 'matched existing finding' for a
        # following finding in the same report
        # this means untouched can have this finding inside it,
        # while it is in fact a new finding. So we substract new_items
        untouched = set(unchanged_findings) - set(to_mitigate) - set(new_findings)

        for (group_name, existing_findings) in group_names_to_findings_dict.items():
            finding_helper.add_findings_to_auto_group(group_name, existing_findings, group_by, create_finding_groups_for_all_findings, **kwargs)
            if push_to_jira:
                if existing_findings[0].finding_group is not None:
                    jira_helper.push_to_jira(existing_findings[0].finding_group)
                else:
                    jira_helper.push_to_jira(existing_findings[0])

        if is_finding_groups_enabled() and push_to_jira:
            for finding_group in set(
                [
                    finding.finding_group
                    for finding in reactivated_items + unchanged_findings
                    if finding.finding_group is not None and not finding.is_mitigated
                ]
            ):
                jira_helper.push_to_jira(finding_group)

        sync = kwargs.get("sync", False)
        if not sync:
            serialized_new_items = [
                serializers.serialize(
                    "json",
                    [
                        finding,
                    ],
                )
                for finding in new_findings
            ]
            serialized_reactivated_items = [
                serializers.serialize(
                    "json",
                    [
                        finding,
                    ],
                )
                for finding in reactivated_items
            ]
            serialized_to_mitigate = [
                serializers.serialize(
                    "json",
                    [
                        finding,
                    ],
                )
                for finding in to_mitigate
            ]
            serialized_untouched = [
                serializers.serialize(
                    "json",
                    [
                        finding,
                    ],
                )
                for finding in untouched
            ]
            return (
                serialized_new_items,
                serialized_reactivated_items,
                serialized_to_mitigate,
                serialized_untouched,
            )

        return new_findings, reactivated_items, to_mitigate, untouched

    def close_old_findings(
        self, test, to_mitigate, scan_date_time, user, push_to_jira=None
    ):
        logger.debug("IMPORT_SCAN: Closing findings no longer present in scan report")
        mitigated_findings = []
        for finding in to_mitigate:
            if not finding.mitigated or not finding.is_mitigated:
                logger.debug("mitigating finding: %i:%s", finding.id, finding)
                finding.mitigated = scan_date_time
                finding.is_mitigated = True
                finding.mitigated_by = user
                finding.active = False

                endpoint_status = finding.status_finding.all()
                reimporter_utils.mitigate_endpoint_status(
                    endpoint_status, user, kwuser=user, sync=True
                )

                # to avoid pushing a finding group multiple times, we push those outside of the loop
                if is_finding_groups_enabled() and finding.finding_group:
                    # don't try to dedupe findings that we are closing
                    finding.save(dedupe_option=False)
                else:
                    finding.save(push_to_jira=push_to_jira, dedupe_option=False)

                add_note_if_not_exists(finding, test, user, "Mitigated by %s re-upload.")
                mitigated_findings.append(finding)

        if is_finding_groups_enabled() and push_to_jira:
            for finding_group in set(
                [
                    finding.finding_group
                    for finding in to_mitigate
                    if finding.finding_group is not None
                ]
            ):
                jira_helper.push_to_jira(finding_group)

        return mitigated_findings

    def reimport_scan(
        self,
        scan,
        scan_type,
        test,
        active=None,
        verified=None,
        tags=None,
        minimum_severity=None,
        user=None,
        endpoints_to_add=None,
        scan_date=None,
        version=None,
        branch_tag=None,
        build_id=None,
        commit_hash=None,
        push_to_jira=None,
        close_old_findings=True,
        group_by=None,
        api_scan_configuration=None,
        service=None,
        do_not_reactivate=False,
        create_finding_groups_for_all_findings=True,
        apply_tags_to_findings=False,
    ):

        logger.debug(f"REIMPORT_SCAN: parameters: {locals()}")

        user = user or get_current_user()

        now = timezone.now()

        if api_scan_configuration:
            if api_scan_configuration.product != test.engagement.product:
                raise ValidationError(
                    "API Scan Configuration has to be from same product as the Test"
                )
            if test.api_scan_configuration != api_scan_configuration:
                test.api_scan_configuration = api_scan_configuration
                test.save()

        # check if the parser that handle the scan_type manage tests
        parser = get_parser(scan_type)
        if hasattr(parser, "get_tests"):
            logger.debug("REIMPORT_SCAN parser v2: Create parse findings")
            try:
                tests = parser.get_tests(scan_type, scan)
            except ValueError as e:
                logger.warning(e)
                raise ValidationError(e)
            # for now we only consider the first test in the list and artificially aggregate all findings of all tests
            # this is the same as the old behavior as current import/reimporter implementation doesn't handle the case
            # when there is more than 1 test
            parsed_findings = []
            for test_raw in tests:
                parsed_findings.extend(test_raw.findings)
        else:
            logger.debug("REIMPORT_SCAN: Parse findings")
            try:
                parsed_findings = parser.get_findings(scan, test)
            except ValueError as e:
                logger.warning(e)
                raise ValidationError(e)

        logger.debug("REIMPORT_SCAN: Processing findings")
        new_findings = []
        reactivated_findings = []
        findings_to_mitigate = []
        untouched_findings = []
        if settings.ASYNC_FINDING_IMPORT:
            chunk_list = importer_utils.chunk_list(parsed_findings)
            results_list = []
            # First kick off all the workers
            for findings_list in chunk_list:
                result = self.process_parsed_findings(
                    test,
                    findings_list,
                    scan_type,
                    user,
                    active=active,
                    verified=verified,
                    minimum_severity=minimum_severity,
                    endpoints_to_add=endpoints_to_add,
                    push_to_jira=push_to_jira,
                    group_by=group_by,
                    now=now,
                    service=service,
                    scan_date=scan_date,
                    sync=False,
                    do_not_reactivate=do_not_reactivate,
                    create_finding_groups_for_all_findings=create_finding_groups_for_all_findings,
                )

                # Since I dont want to wait until the task is done right now, save the id
                # So I can check on the task later
                results_list += [result]
            # After all tasks have been started, time to pull the results
            logger.debug("REIMPORT_SCAN: Collecting Findings")
            for results in results_list:
                (
                    serial_new_findings,
                    serial_reactivated_findings,
                    serial_findings_to_mitigate,
                    serial_untouched_findings,
                ) = results.get()
                new_findings += [
                    next(serializers.deserialize("json", finding)).object
                    for finding in serial_new_findings
                ]
                reactivated_findings += [
                    next(serializers.deserialize("json", finding)).object
                    for finding in serial_reactivated_findings
                ]
                findings_to_mitigate += [
                    next(serializers.deserialize("json", finding)).object
                    for finding in serial_findings_to_mitigate
                ]
                untouched_findings += [
                    next(serializers.deserialize("json", finding)).object
                    for finding in serial_untouched_findings
                ]
            logger.debug("REIMPORT_SCAN: All Findings Collected")
            # Indicate that the test is not complete yet as endpoints will still be rolling in.
            test.percent_complete = 50
            test.save()
            importer_utils.update_test_progress(test)
        else:
            (
                new_findings,
                reactivated_findings,
                findings_to_mitigate,
                untouched_findings,
            ) = self.process_parsed_findings(
                test,
                parsed_findings,
                scan_type,
                user,
                active=active,
                verified=verified,
                minimum_severity=minimum_severity,
                endpoints_to_add=endpoints_to_add,
                push_to_jira=push_to_jira,
                group_by=group_by,
                now=now,
                service=service,
                scan_date=scan_date,
                sync=True,
                do_not_reactivate=do_not_reactivate,
                create_finding_groups_for_all_findings=create_finding_groups_for_all_findings,
            )

        closed_findings = []
        if close_old_findings:
            logger.debug(
                "REIMPORT_SCAN: Closing findings no longer present in scan report"
            )
            closed_findings = self.close_old_findings(
                test,
                findings_to_mitigate,
                scan_date,
                user=user,
                push_to_jira=push_to_jira,
            )

        logger.debug("REIMPORT_SCAN: Updating test/engagement timestamps")
        importer_utils.update_timestamps(
            test, version, branch_tag, build_id, commit_hash, now, scan_date
        )

        logger.debug("REIMPORT_SCAN: Updating test tags")
        importer_utils.update_tags(test, tags)

        test_import = None
        if settings.TRACK_IMPORT_HISTORY:
            logger.debug("REIMPORT_SCAN: Updating Import History")
            test_import = importer_utils.update_import_history(
                Test_Import.REIMPORT_TYPE,
                active,
                verified,
                tags,
                minimum_severity,
                endpoints_to_add,
                version,
                branch_tag,
                build_id,
                commit_hash,
                push_to_jira,
                close_old_findings,
                test,
                new_findings,
                closed_findings,
                reactivated_findings,
                untouched_findings,
            )
        if apply_tags_to_findings and tags:
            for finding in test_import.findings_affected.all():
                for tag in tags:
                    finding.tags.add(tag)
        logger.debug("REIMPORT_SCAN: Generating notifications")

        updated_count = (
            len(closed_findings) + len(reactivated_findings) + len(new_findings)
        )
        notifications_helper.notify_scan_added(
            test,
            updated_count,
            new_findings=new_findings,
            findings_mitigated=closed_findings,
            findings_reactivated=reactivated_findings,
            findings_untouched=untouched_findings,
        )

        logger.debug("REIMPORT_SCAN: Done")

        return (
            test,
            updated_count,
            len(new_findings),
            len(closed_findings),
            len(reactivated_findings),
            len(untouched_findings),
            test_import,
        )
