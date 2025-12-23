import logging
from operator import attrgetter

import hyperlink
from django.conf import settings
from django.db.models import Prefetch
from django.db.models.query_utils import Q

from dojo.celery import app
from dojo.decorators import dojo_async_task, dojo_model_from_id, dojo_model_to_id
from dojo.models import Finding, System_Settings

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")


def get_finding_models_for_deduplication(finding_ids):
    """
    Load findings with optimal prefetching for deduplication operations.
    This avoids N+1 queries when accessing test, engagement, product, endpoints, and original_finding.

    Args:
        finding_ids: A list of Finding IDs

    Returns:
        A list of Finding models with related objects prefetched

    """
    if not finding_ids:
        logger.debug("get_finding_models_for_deduplication called with no finding_ids")
        return []

    return list(
        Finding.objects.filter(id__in=finding_ids)
        .select_related("test", "test__engagement", "test__engagement__product", "test__test_type")
        .prefetch_related(
            "endpoints",
            # Prefetch duplicates of each finding to avoid N+1 when set_duplicate iterates
            Prefetch(
                "original_finding",
                queryset=Finding.objects.only("id", "duplicate_finding_id").order_by("-id"),
            ),
        ),
    )


@dojo_model_to_id
@dojo_async_task
@app.task
@dojo_model_from_id
def do_dedupe_finding_task(new_finding, *args, **kwargs):
    return do_dedupe_finding(new_finding, *args, **kwargs)


@dojo_async_task
@app.task
def do_dedupe_batch_task(finding_ids, *args, **kwargs):
    """
    Async task to deduplicate a batch of findings. The findings are assumed to be in the same test.
    Similar to post_process_findings_batch but focused only on deduplication.
    """
    # Load findings with proper prefetching
    findings = get_finding_models_for_deduplication(finding_ids)

    if not findings:
        logger.debug(f"no findings found for batch deduplication with IDs: {finding_ids}")
        return

    # Batch dedupe
    dedupe_batch_of_findings(findings)


def do_dedupe_finding(new_finding, *args, **kwargs):
    from dojo.utils import get_custom_method  # noqa: PLC0415 -- circular import
    if dedupe_method := get_custom_method("FINDING_DEDUPE_METHOD"):
        return dedupe_method(new_finding, *args, **kwargs)

    try:
        enabled = System_Settings.objects.get(no_cache=True).enable_deduplication
    except System_Settings.DoesNotExist:
        logger.warning("system settings not found")
        enabled = False

    if enabled:
        deduplicationLogger.debug("dedupe for: " + str(new_finding.id)
                    + ":" + str(new_finding.title))
        deduplicationAlgorithm = new_finding.test.deduplication_algorithm
        deduplicationLogger.debug("deduplication algorithm: " + deduplicationAlgorithm)
        if deduplicationAlgorithm == settings.DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL:
            deduplicate_unique_id_from_tool(new_finding)
        elif deduplicationAlgorithm == settings.DEDUPE_ALGO_HASH_CODE:
            deduplicate_hash_code(new_finding)
        elif deduplicationAlgorithm == settings.DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE:
            deduplicate_uid_or_hash_code(new_finding)
        else:
            deduplicationLogger.debug("no configuration per parser found; using legacy algorithm")
            deduplicate_legacy(new_finding)
    else:
        deduplicationLogger.debug("dedupe: skipping dedupe because it's disabled in system settings get()")
    return None


def deduplicate_legacy(new_finding):
    _dedupe_batch_legacy([new_finding])


def deduplicate_unique_id_from_tool(new_finding):
    _dedupe_batch_unique_id([new_finding])


def deduplicate_hash_code(new_finding):
    _dedupe_batch_hash_code([new_finding])


def deduplicate_uid_or_hash_code(new_finding):
    _dedupe_batch_uid_or_hash([new_finding])


def set_duplicate(new_finding, existing_finding):
    deduplicationLogger.debug(f"new_finding.status(): {new_finding.id} {new_finding.status()}")
    deduplicationLogger.debug(f"existing_finding.status(): {existing_finding.id} {existing_finding.status()}")
    if existing_finding.duplicate:
        deduplicationLogger.debug("existing finding: %s:%s:duplicate=%s;duplicate_finding=%s", existing_finding.id, existing_finding.title, existing_finding.duplicate, existing_finding.duplicate_finding.id if existing_finding.duplicate_finding else "None")
        msg = "Existing finding is a duplicate"
        raise Exception(msg)
    if existing_finding.id == new_finding.id:
        msg = "Can not add duplicate to itself"
        raise Exception(msg)
    if is_duplicate_reopen(new_finding, existing_finding):
        msg = "Found a regression. Ignore this so that a new duplicate chain can be made"
        raise Exception(msg)
    if new_finding.duplicate and finding_mitigated(existing_finding):
        msg = "Skip this finding as we do not want to attach a new duplicate to a mitigated finding"
        raise Exception(msg)

    deduplicationLogger.debug("Setting new finding " + str(new_finding.id) + " as a duplicate of existing finding " + str(existing_finding.id))
    new_finding.duplicate = True
    new_finding.active = False
    new_finding.verified = False
    new_finding.duplicate_finding = existing_finding

    # Make sure transitive duplication is flattened
    # if A -> B and B is made a duplicate of C here, afterwards:
    # A -> C and B -> C should be true
    # Ordering is ensured by the prefetch in post_process_findings_batch
    # (we prefetch "original_finding" ordered by -id), so avoid calling
    # order_by here to prevent bypassing the prefetch cache.
    for find in new_finding.original_finding.all():
        new_finding.original_finding.remove(find)
        set_duplicate(find, existing_finding)
    # Only add test type to found_by if it is not already present.
    # This is efficient because `found_by` is prefetched for candidates via `build_dedupe_scope_queryset()`.
    test_type = getattr(getattr(new_finding, "test", None), "test_type", None)
    if test_type is not None and test_type not in existing_finding.found_by.all():
        existing_finding.found_by.add(test_type)

    # existing_finding.found_by.add(new_finding.test.test_type)

    logger.debug("saving new finding: %d", new_finding.id)
    super(Finding, new_finding).save()
    logger.debug("saving existing finding: %d", existing_finding.id)
    super(Finding, existing_finding).save()


def is_duplicate_reopen(new_finding, existing_finding) -> bool:
    return finding_mitigated(existing_finding) and finding_not_human_set_status(existing_finding) and not finding_mitigated(new_finding)


def finding_mitigated(finding: Finding) -> bool:
    return finding.active is False and (finding.is_mitigated is True or finding.mitigated is not None)


def finding_not_human_set_status(finding: Finding) -> bool:
    return finding.out_of_scope is False and finding.false_p is False


def set_duplicate_reopen(new_finding, existing_finding):
    logger.debug("duplicate reopen existing finding")
    existing_finding.mitigated = new_finding.mitigated
    existing_finding.is_mitigated = new_finding.is_mitigated
    existing_finding.active = new_finding.active
    existing_finding.verified = new_finding.verified
    existing_finding.notes.create(author=existing_finding.reporter,
                                    entry="This finding has been automatically re-opened as it was found in recent scans.")
    existing_finding.save()


def is_deduplication_on_engagement_mismatch(new_finding, to_duplicate_finding):
    if new_finding.test.engagement != to_duplicate_finding.test.engagement:
        deduplication_mismatch = new_finding.test.engagement.deduplication_on_engagement \
            or to_duplicate_finding.test.engagement.deduplication_on_engagement
        if deduplication_mismatch:
            deduplicationLogger.debug(f"deduplication_mismatch: {deduplication_mismatch} for new_finding {new_finding.id} and to_duplicate_finding {to_duplicate_finding.id} with test.engagement {new_finding.test.engagement.id} and {to_duplicate_finding.test.engagement.id}")
        return deduplication_mismatch
    return False


def get_endpoints_as_url(finding):
    return [hyperlink.parse(str(e)) for e in finding.endpoints.all()]


def are_urls_equal(url1, url2, fields):
    deduplicationLogger.debug("Check if url %s and url %s are equal in terms of %s.", url1, url2, fields)
    for field in fields:
        if (field == "scheme" and url1.scheme != url2.scheme) or (field == "host" and url1.host != url2.host):
            return False
        if (field == "port" and url1.port != url2.port) or (field == "path" and url1.path != url2.path) or (field == "query" and url1.query != url2.query) or (field == "fragment" and url1.fragment != url2.fragment) or (field == "userinfo" and url1.userinfo != url2.userinfo) or (field == "user" and url1.user != url2.user):
            return False
    return True


def are_endpoints_duplicates(new_finding, to_duplicate_finding):
    fields = settings.DEDUPE_ALGO_ENDPOINT_FIELDS
    if len(fields) == 0:
        deduplicationLogger.debug("deduplication by endpoint fields is disabled")
        return True

    list1 = get_endpoints_as_url(new_finding)
    list2 = get_endpoints_as_url(to_duplicate_finding)

    deduplicationLogger.debug(
        f"Starting deduplication by endpoint fields for finding {new_finding.id} with urls {list1} and finding {to_duplicate_finding.id} with urls {list2}",
    )
    if list1 == [] and list2 == []:
        return True

    for l1 in list1:
        for l2 in list2:
            if are_urls_equal(l1, l2, fields):
                return True

    deduplicationLogger.debug(f"endpoints are not duplicates: {new_finding.id} and {to_duplicate_finding.id}")
    return False


def build_dedupe_scope_queryset(test):
    scope_on_engagement = test.engagement.deduplication_on_engagement
    if scope_on_engagement:
        scope_q = Q(test__engagement=test.engagement)
    else:
        # Product scope limited to current product, but exclude engagements that opted into engagement-scoped dedupe
        scope_q = Q(test__engagement__product=test.engagement.product) & (
            Q(test__engagement=test.engagement)
            | Q(test__engagement__deduplication_on_engagement=False)
        )

    return (
        Finding.objects.filter(scope_q)
        .select_related("test", "test__engagement", "test__test_type")
        .prefetch_related("endpoints", "found_by")
    )


def find_candidates_for_deduplication_hash(test, findings):
    base_queryset = build_dedupe_scope_queryset(test)
    hash_codes = {f.hash_code for f in findings if getattr(f, "hash_code", None) is not None}
    if not hash_codes:
        return {}
    existing_qs = (
        base_queryset.filter(hash_code__in=hash_codes)
        .exclude(hash_code=None)
        .exclude(duplicate=True)
        .order_by("id")
    )
    existing_by_hash = {}
    for ef in existing_qs:
        existing_by_hash.setdefault(ef.hash_code, []).append(ef)
    deduplicationLogger.debug(f"Found {len(existing_by_hash)} existing findings by hash codes")
    return existing_by_hash


def find_candidates_for_deduplication_unique_id(test, findings):
    base_queryset = build_dedupe_scope_queryset(test)
    unique_ids = {f.unique_id_from_tool for f in findings if getattr(f, "unique_id_from_tool", None) is not None}
    if not unique_ids:
        return {}
    existing_qs = base_queryset.filter(unique_id_from_tool__in=unique_ids).exclude(unique_id_from_tool=None).exclude(duplicate=True).order_by("id")
    # unique_id_from_tool can only apply to the same test_type because it is parser dependent
    existing_qs = existing_qs.filter(test__test_type=test.test_type)
    existing_by_uid = {}
    for ef in existing_qs:
        existing_by_uid.setdefault(ef.unique_id_from_tool, []).append(ef)
    deduplicationLogger.debug(f"Found {len(existing_by_uid)} existing findings by unique IDs")
    return existing_by_uid


def find_candidates_for_deduplication_uid_or_hash(test, findings):
    base_queryset = build_dedupe_scope_queryset(test)
    hash_codes = {f.hash_code for f in findings if getattr(f, "hash_code", None) is not None}
    unique_ids = {f.unique_id_from_tool for f in findings if getattr(f, "unique_id_from_tool", None) is not None}
    if not hash_codes and not unique_ids:
        return {}, {}

    cond = Q()
    if hash_codes:
        cond |= Q(hash_code__isnull=False, hash_code__in=hash_codes)
    if unique_ids:
        # unique_id_from_tool can only apply to the same test_type because it is parser dependent
        uid_q = Q(unique_id_from_tool__isnull=False, unique_id_from_tool__in=unique_ids) & Q(test__test_type=test.test_type)
        cond |= uid_q

    existing_qs = base_queryset.filter(cond).exclude(duplicate=True).order_by("id")

    existing_by_hash = {}
    existing_by_uid = {}
    for ef in existing_qs:
        if ef.hash_code is not None:
            existing_by_hash.setdefault(ef.hash_code, []).append(ef)
        if ef.unique_id_from_tool is not None:
            existing_by_uid.setdefault(ef.unique_id_from_tool, []).append(ef)
    deduplicationLogger.debug(f"Found {len(existing_by_uid)} existing findings by unique IDs")
    deduplicationLogger.debug(f"Found {len(existing_by_hash)} existing findings by hash codes")
    return existing_by_uid, existing_by_hash


def find_candidates_for_deduplication_legacy(test, findings):
    base_queryset = build_dedupe_scope_queryset(test)
    titles = {f.title for f in findings if getattr(f, "title", None)}
    cwes = {f.cwe for f in findings if getattr(f, "cwe", 0)}
    cwes.discard(0)
    if not titles and not cwes:
        return {}, {}

    existing_qs = base_queryset.filter(Q(title__in=titles) | Q(cwe__in=cwes)).exclude(duplicate=True).order_by("id")

    by_title = {}
    by_cwe = {}
    for ef in existing_qs:
        if ef.title:
            by_title.setdefault(ef.title, []).append(ef)
        if getattr(ef, "cwe", 0):
            by_cwe.setdefault(ef.cwe, []).append(ef)
    deduplicationLogger.debug(f"Found {len(by_title)} existing findings by title")
    deduplicationLogger.debug(f"Found {len(by_cwe)} existing findings by CWE")
    deduplicationLogger.debug(f"Found {len(existing_qs)} existing findings by title or CWE")
    return by_title, by_cwe


def _is_candidate_older(new_finding, candidate):
    # Ensure the newer finding is marked as duplicate of the older finding
    is_older = candidate.id < new_finding.id
    if not is_older:
        deduplicationLogger.debug(f"candidate is newer than or equal to new finding: {new_finding.id} and candidate {candidate.id}")
    return is_older


def match_hash_candidate(new_finding, candidates_by_hash):
    if new_finding.hash_code is None:
        return None
    possible_matches = candidates_by_hash.get(new_finding.hash_code, [])
    deduplicationLogger.debug(f"Finding {new_finding.id}: Found {len(possible_matches)} findings with same hash_code, ids={[(c.id, c.hash_code) for c in possible_matches]}")

    for candidate in possible_matches:
        if not _is_candidate_older(new_finding, candidate):
            continue
        if is_deduplication_on_engagement_mismatch(new_finding, candidate):
            deduplicationLogger.debug("deduplication_on_engagement_mismatch, skipping dedupe.")
            continue
        if are_endpoints_duplicates(new_finding, candidate):
            return candidate
    return None


def match_unique_id_candidate(new_finding, candidates_by_uid):
    if new_finding.unique_id_from_tool is None:
        return None

    possible_matches = candidates_by_uid.get(new_finding.unique_id_from_tool, [])
    deduplicationLogger.debug(f"Finding {new_finding.id}: Found {len(possible_matches)} findings with same unique_id_from_tool, ids={[(c.id, c.unique_id_from_tool) for c in possible_matches]}")
    for candidate in possible_matches:
        if not _is_candidate_older(new_finding, candidate):
            deduplicationLogger.debug("UID: newer candidate, skipping dedupe.")
            continue
        if is_deduplication_on_engagement_mismatch(new_finding, candidate):
            deduplicationLogger.debug("deduplication_on_engagement_mismatch, skipping dedupe.")
            continue
        return candidate
    return None


def match_uid_or_hash_candidate(new_finding, candidates_by_uid, candidates_by_hash):
    # Combine UID and hash candidates and walk oldest-first
    uid_list = candidates_by_uid.get(new_finding.unique_id_from_tool, []) if new_finding.unique_id_from_tool is not None else []
    hash_list = candidates_by_hash.get(new_finding.hash_code, []) if new_finding.hash_code is not None else []
    deduplicationLogger.debug("Finding %s: UID_OR_HASH: uid_list ids=%s hash_list ids=%s", new_finding.id, [c.id for c in uid_list], [c.id for c in hash_list])
    combined_by_id = {c.id: c for c in uid_list}
    for c in hash_list:
        combined_by_id.setdefault(c.id, c)
    deduplicationLogger.debug("Finding %s: UID_OR_HASH: combined candidate ids (sorted)=%s", new_finding.id, sorted(combined_by_id.keys()))
    for candidate_id in sorted(combined_by_id.keys()):
        candidate = combined_by_id[candidate_id]
        if not _is_candidate_older(new_finding, candidate):
            continue
        if is_deduplication_on_engagement_mismatch(new_finding, candidate):
            deduplicationLogger.debug("deduplication_on_engagement_mismatch, skipping dedupe.")
            return None
        if are_endpoints_duplicates(new_finding, candidate):
            deduplicationLogger.debug("UID_OR_HASH: endpoints match, returning candidate %s with test_type %s unique_id_from_tool %s hash_code %s", candidate.id, candidate.test.test_type, candidate.unique_id_from_tool, candidate.hash_code)
            return candidate
        deduplicationLogger.debug("UID_OR_HASH: endpoints mismatch, skipping candidate %s", candidate.id)
    return None


def match_legacy_candidate(new_finding, candidates_by_title, candidates_by_cwe):
    # ---------------------------------------------------------
    # 1) Collects all the findings that have the same:
    #      (title  and static_finding and dynamic_finding)
    #      or (CWE and static_finding and dynamic_finding)
    #    as the new one
    #    (this is "cond1")
    # ---------------------------------------------------------
    candidates = []
    if getattr(new_finding, "title", None):
        candidates.extend(candidates_by_title.get(new_finding.title, []))
    if getattr(new_finding, "cwe", 0):
        candidates.extend(candidates_by_cwe.get(new_finding.cwe, []))

    for candidate in candidates:
        if not _is_candidate_older(new_finding, candidate):
            continue
        if is_deduplication_on_engagement_mismatch(new_finding, candidate):
            deduplicationLogger.debug(
                "deduplication_on_engagement_mismatch, skipping dedupe.")
            continue

        flag_endpoints = False
        flag_line_path = False

        # ---------------------------------------------------------
        # 2) If existing and new findings have endpoints: compare them all
        #    Else look at line+file_path
        #    (if new finding is not static, do not deduplicate)
        # ---------------------------------------------------------

        if candidate.endpoints.count() != 0 and new_finding.endpoints.count() != 0:
            list1 = [str(e) for e in new_finding.endpoints.all()]
            list2 = [str(e) for e in candidate.endpoints.all()]
            if all(x in list1 for x in list2):
                deduplicationLogger.debug("%s: existing endpoints are present in new finding", candidate.id)
                flag_endpoints = True
        elif new_finding.static_finding and new_finding.file_path and len(new_finding.file_path) > 0:
            if str(candidate.line) == str(new_finding.line) and candidate.file_path == new_finding.file_path:
                deduplicationLogger.debug("%s: file_path and line match", candidate.id)
                flag_line_path = True
            else:
                deduplicationLogger.debug("no endpoints on one of the findings and file_path doesn't match; Deduplication will not occur")
        else:
            deduplicationLogger.debug("find.static/dynamic: %s/%s", candidate.static_finding, candidate.dynamic_finding)
            deduplicationLogger.debug("new_finding.static/dynamic: %s/%s", new_finding.static_finding, new_finding.dynamic_finding)
            deduplicationLogger.debug("find.file_path: %s", candidate.file_path)
            deduplicationLogger.debug("new_finding.file_path: %s", new_finding.file_path)
            deduplicationLogger.debug("no endpoints on one of the findings and the new finding is either dynamic or doesn't have a file_path; Deduplication will not occur")

        flag_hash = candidate.hash_code == new_finding.hash_code

        deduplicationLogger.debug(
            "deduplication flags for new finding (" + ("dynamic" if new_finding.dynamic_finding else "static") + ") " + str(new_finding.id) + " and existing finding " + str(candidate.id)
            + " flag_endpoints: " + str(flag_endpoints) + " flag_line_path:" + str(flag_line_path) + " flag_hash:" + str(flag_hash))

        if (flag_endpoints or flag_line_path) and flag_hash:
            return candidate
    return None


def _dedupe_batch_hash_code(findings):
    if not findings:
        return
    test = findings[0].test
    candidates_by_hash = find_candidates_for_deduplication_hash(test, findings)
    if not candidates_by_hash:
        return
    for new_finding in findings:
        deduplicationLogger.debug(f"deduplication start for finding {new_finding.id} with DEDUPE_ALGO_HASH_CODE")
        match = match_hash_candidate(new_finding, candidates_by_hash)
        if match:
            try:
                set_duplicate(new_finding, match)
            except Exception as e:
                deduplicationLogger.debug(str(e))


def _dedupe_batch_unique_id(findings):
    if not findings:
        return
    test = findings[0].test
    candidates_by_uid = find_candidates_for_deduplication_unique_id(test, findings)
    if not candidates_by_uid:
        return
    for new_finding in findings:
        deduplicationLogger.debug(f"deduplication start for finding {new_finding.id} with DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL")
        match = match_unique_id_candidate(new_finding, candidates_by_uid)
        if match:
            try:
                set_duplicate(new_finding, match)
            except Exception as e:
                deduplicationLogger.debug(str(e))


def _dedupe_batch_uid_or_hash(findings):
    if not findings:
        return

    test = findings[0].test
    candidates_by_uid, existing_by_hash = find_candidates_for_deduplication_uid_or_hash(test, findings)
    if not (candidates_by_uid or existing_by_hash):
        return
    for new_finding in findings:
        deduplicationLogger.debug(f"deduplication start for finding {new_finding.id} with DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE")
        if new_finding.duplicate:
            continue

        match = match_uid_or_hash_candidate(new_finding, candidates_by_uid, existing_by_hash)
        if match:
            try:
                set_duplicate(new_finding, match)
            except Exception as e:
                deduplicationLogger.debug(str(e))
                continue


def _dedupe_batch_legacy(findings):
    if not findings:
        return
    test = findings[0].test
    candidates_by_title, candidates_by_cwe = find_candidates_for_deduplication_legacy(test, findings)
    if not (candidates_by_title or candidates_by_cwe):
        return
    for new_finding in findings:
        deduplicationLogger.debug(f"deduplication start for finding {new_finding.id} with DEDUPE_ALGO_LEGACY")
        match = match_legacy_candidate(new_finding, candidates_by_title, candidates_by_cwe)
        if match:
            try:
                set_duplicate(new_finding, match)
            except Exception as e:
                deduplicationLogger.debug(str(e))


def dedupe_batch_of_findings(findings, *args, **kwargs):
    """Batch deduplicate a list of findings. The findings are assumed to be in the same test."""
    # Pro has customer implementation which will call the Pro dedupe methods, but also the normal OS dedupe methods.
    from dojo.utils import get_custom_method  # noqa: PLC0415 -- circular import
    if batch_dedupe_method := get_custom_method("FINDING_DEDUPE_BATCH_METHOD"):
        deduplicationLogger.debug(f"Using custom deduplication method: {batch_dedupe_method.__name__}")
        return batch_dedupe_method(findings, *args, **kwargs)

    if not findings:
        logger.debug("dedupe_batch_of_findings called with no findings")
        return None

    enabled = System_Settings.objects.get().enable_deduplication

    if enabled:
        # sort findings by id to ensure deduplication is deterministic/reproducible
        findings = sorted(findings, key=attrgetter("id"))

        test = findings[0].test
        dedup_alg = test.deduplication_algorithm

        if dedup_alg == settings.DEDUPE_ALGO_HASH_CODE:
            logger.debug(f"deduplicating finding batch with DEDUPE_ALGO_HASH_CODE - {len(findings)} findings")
            _dedupe_batch_hash_code(findings)
        elif dedup_alg == settings.DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL:
            logger.debug(f"deduplicating finding batch with DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL - {len(findings)} findings")
            _dedupe_batch_unique_id(findings)
        elif dedup_alg == settings.DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE:
            logger.debug(f"deduplicating finding batch with DEDUPE_ALGO_UNIQUE_ID_FROM_TOOL_OR_HASH_CODE - {len(findings)} findings")
            _dedupe_batch_uid_or_hash(findings)
        else:
            logger.debug(f"deduplicating finding batch with LEGACY - {len(findings)} findings")
            _dedupe_batch_legacy(findings)
    else:
        deduplicationLogger.debug("dedupe: skipping dedupe because it's disabled in system settings get()")
    return None
