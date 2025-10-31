import base64
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from functools import lru_cache
from typing import Self

import redis
from django.conf import settings
from django.utils.functional import cached_property

from dojo.models import Finding

logger = logging.getLogger(__name__)

DD_TEST = os.getenv("DD_TEST", "False").lower() == "true"
USER_MODES_KEY = "finding_groups_user_modes"
LAST_FINDING_CHANGE = "finding_groups_last_finding_change"
LAST_FINDING_UPDATE = "finding_groups_last_update"


class GroupMode(StrEnum):
    VULN_ID_FROM_TOOL = "vuln_id_from_tool"
    TITLE = "title"
    CVE = "cve"


@dataclass
class DynamicFindingGroups:
    finding_group_id: str
    name: str = ""
    severity: str = "Info"
    main_finding_id: int | None = None
    finding_ids: set[int] = field(default_factory=set)

    def to_dict(self) -> dict:
        data = asdict(self)
        data["finding_ids"] = list(data["finding_ids"])
        return data

    @staticmethod
    def from_dict(data: dict) -> Self:
        data["finding_ids"] = set(data.get("finding_ids", []))
        return DynamicFindingGroups(**data)

    @staticmethod
    def load_from_id(finding_group_id: str, fg_key: str) -> Self | None:
        redis_client = get_redis_client()
        finding_group_data = redis_client.hget(fg_key, finding_group_id)
        if finding_group_data:
            return DynamicFindingGroups.from_dict(json.loads(finding_group_data))
        return None

    def update_sev_sla(self, finding: Finding) -> None:
        if Finding.get_number_severity(finding.severity) > Finding.get_number_severity(self.severity):
            self.severity = finding.severity
            self.main_finding_id = finding.id

    def add(self, finding: Finding) -> None:
        self.update_sev_sla(finding)
        self.finding_ids.add(finding.id)

    # This method is used when we filter findings in a finding group
    def reconfig_finding_group(self) -> None:
        self.severity = "Info"
        findings = Finding.objects.filter(id__in=self.finding_ids)
        for finding in findings:
            self.update_sev_sla(finding)

    @staticmethod
    def get_group_names(finding: Finding, mode: GroupMode) -> list[str] | None:
        if mode == GroupMode.VULN_ID_FROM_TOOL:
            if finding.vuln_id_from_tool:
                return [finding.vuln_id_from_tool]
        if mode == GroupMode.TITLE:
            if finding.title:
                return [finding.title]
        if mode == GroupMode.CVE:
            cves = [
                cve for cve in finding.vulnerability_id_set.values_list("vulnerability_id", flat=True)
                if cve
            ]
            if cves:
                return cves
        return None

    @staticmethod
    def get_fg_key(mode: GroupMode) -> str:
        return f"finding_groups_{mode.value}"

    @staticmethod
    def get_id_map_key(mode: GroupMode) -> str:
        return f"finding_groups_id_to_finding_group_{mode.value}"

    @staticmethod
    def set_last_finding_change() -> None:
        if DD_TEST:
            logger.info("Redis is not used in test environment, skipping.")
            return
        redis_client = get_redis_client()
        redis_client.set(LAST_FINDING_CHANGE, datetime.now().isoformat())

    @staticmethod
    def set_last_update(mode: GroupMode, timestamp: datetime | None = None) -> None:
        if timestamp is None:
            return
        redis_client = get_redis_client()
        redis_client.hset(LAST_FINDING_UPDATE, mode.value, timestamp.isoformat())

    @staticmethod
    def add_finding(finding: Finding, mode: GroupMode) -> None:
        finding_groups = DynamicFindingGroups.get_group_names(finding, mode)
        if not finding_groups:
            return
        redis_client = get_redis_client()
        for finding_group_name in finding_groups:
            finding_group_id = base64.b64encode(finding_group_name.encode()).decode()
            fg_key = DynamicFindingGroups.get_fg_key(mode)
            id_map_key = DynamicFindingGroups.get_id_map_key(mode)

            finding_group = DynamicFindingGroups.load_from_id(finding_group_id, fg_key)
            if not finding_group:
                finding_group = DynamicFindingGroups(
                    finding_group_id=finding_group_id,
                    name=finding_group_name,
                )

            if finding.id not in finding_group.finding_ids:
                finding_group.add(finding)

            redis_client.hset(fg_key, finding_group_id, json.dumps(finding_group.to_dict()))
            group_ids_raw = redis_client.hget(id_map_key, finding.id)
            group_ids = json.loads(group_ids_raw) if group_ids_raw else []
            if finding_group_id not in group_ids:
                group_ids.append(finding_group_id)
            redis_client.hset(id_map_key, finding.id, json.dumps(group_ids))

    @cached_property
    def sla_days_remaining_internal(self):
        findings = Finding.objects.filter(id__in=self.finding_ids, active=True)
        if not findings:
            return None
        return min([find.sla_days_remaining() for find in findings if find.sla_days_remaining()], default=None)

    @property
    def sla_days_remaining(self) -> int | None:
        return self.sla_days_remaining_internal


@lru_cache(maxsize=1)
def get_redis_client() -> redis.Redis:
    host = getattr(settings, "REDIS_HOST", "redis")
    port = getattr(settings, "REDIS_PORT", 6379)
    return redis.Redis(host=host, port=port, decode_responses=True)


def get_user_mode(user_id: int) -> GroupMode | None:
    redis_client = get_redis_client()
    value = redis_client.hget(USER_MODES_KEY, str(user_id))
    if value and value not in [m.value for m in GroupMode]:
        logger.warning(f"Invalid group mode '{value}' found in Redis for user {user_id}, resetting to None.")
        redis_client.hdel(USER_MODES_KEY, str(user_id))
        return None
    return GroupMode(value) if value else None


def set_user_mode(user_id: int, mode: GroupMode) -> None:
    redis_client = get_redis_client()
    redis_client.hset(USER_MODES_KEY, str(user_id), mode.value)
    logger.info(f"User {user_id} dynamic finding groups mode set to {mode.value}")


def load_or_rebuild_finding_groups(mode: GroupMode) -> dict[str, DynamicFindingGroups]:
    redis_client = get_redis_client()
    fg_key = DynamicFindingGroups.get_fg_key(mode)
    id_map_key = DynamicFindingGroups.get_id_map_key(mode)

    if not redis_client.exists(LAST_FINDING_CHANGE):
        DynamicFindingGroups.set_last_finding_change()
    last_finding_change_raw = redis_client.get(LAST_FINDING_CHANGE)
    try:
        last_finding_change_time = datetime.fromisoformat(last_finding_change_raw)
    except ValueError:
        logger.warning(f"Invalid datetime format in Redis for {LAST_FINDING_CHANGE}: {last_finding_change_raw}, resetting last finding change.")
        DynamicFindingGroups.set_last_finding_change()
        last_finding_change_raw = redis_client.get(LAST_FINDING_CHANGE)
        last_finding_change_time = datetime.fromisoformat(last_finding_change_raw) if last_finding_change_raw else None

    try:
        last_groups_update_time = redis_client.hget(LAST_FINDING_UPDATE, mode.value)
        last_groups_update_time = datetime.fromisoformat(last_groups_update_time) if last_groups_update_time else None
    except ValueError:
        logger.warning(f"Invalid datetime format in Redis for {LAST_FINDING_UPDATE}: {last_groups_update_time}")
        last_groups_update_time = None

    # Check if finding_groups and id_map exist in Redis
    # Check if last update is the same as last finding change
    # If not, rebuild them
    if (
        not redis_client.exists(fg_key)
        or not redis_client.exists(id_map_key)
        or last_groups_update_time != last_finding_change_time
    ):
        if not last_finding_change_time:
            logger.warning("Last finding change is not set, setting it to now.")
        elif last_groups_update_time and last_finding_change_time < last_groups_update_time:
            logger.warning("Last finding change is older than last update, they should be equal or last finding change should be newer.")
        redis_client.delete(fg_key, id_map_key)
        for finding in Finding.objects.all():
            DynamicFindingGroups.add_finding(finding, mode)
        DynamicFindingGroups.set_last_update(mode, last_finding_change_time)

    return _load_finding_groups_from_redis(fg_key, redis_client)


def _load_finding_groups_from_redis(fg_key: str, redis_client: redis.Redis) -> dict[str, DynamicFindingGroups]:
    finding_groups_data = redis_client.hgetall(fg_key)
    if finding_groups_data:
        return {
            key: DynamicFindingGroups.from_dict(json.loads(value))
            for key, value in finding_groups_data.items()
        }
    return {}
