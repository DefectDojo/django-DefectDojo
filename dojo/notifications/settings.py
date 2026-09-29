NOTIFICATIONS_ENV_DEFAULTS: dict[str, tuple] = {
    "DD_SLA_NOTIFY_ACTIVE":               (bool, False),
    "DD_SLA_NOTIFY_ACTIVE_VERIFIED_ONLY": (bool, False),
    "DD_SLA_NOTIFY_WITH_JIRA_ONLY":       (bool, False),
    "DD_SLA_NOTIFY_PRE_BREACH":           (int, 3),
    "DD_SLA_NOTIFY_POST_BREACH":          (int, 7),
    "DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP": (list, ["user_mentioned", "review_requested"]),
    "DD_ALERT_REFRESH":                   (bool, True),
    "DD_DISABLE_ALERT_COUNTER":           (bool, False),
    "DD_MAX_ALERTS_PER_USER":             (int, 999),
    # Caps how many findings notify_scan_added() lists per category (new/mitigated/
    # reactivated/untouched, and their *_duplicate variants) in a scan_added
    # notification. A report that touches thousands of findings should not template
    # all of them into an email/webhook body -- the notification's finding_count
    # still reflects the true total, only the listed rows are capped.
    "DD_NOTIFICATION_SCAN_ADDED_MAX_FINDINGS": (int, 100),
}

_ENV_TO_SETTING = {
    "DD_SLA_NOTIFY_ACTIVE":               "SLA_NOTIFY_ACTIVE",
    "DD_SLA_NOTIFY_ACTIVE_VERIFIED_ONLY": "SLA_NOTIFY_ACTIVE_VERIFIED_ONLY",
    "DD_SLA_NOTIFY_WITH_JIRA_ONLY":       "SLA_NOTIFY_WITH_JIRA_ONLY",
    "DD_SLA_NOTIFY_PRE_BREACH":           "SLA_NOTIFY_PRE_BREACH",
    "DD_SLA_NOTIFY_POST_BREACH":          "SLA_NOTIFY_POST_BREACH",
    "DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP": "NOTIFICATIONS_SYSTEM_LEVEL_TRUMP",
    "DD_ALERT_REFRESH":                   "ALERT_REFRESH",
    "DD_DISABLE_ALERT_COUNTER":           "DISABLE_ALERT_COUNTER",
    "DD_MAX_ALERTS_PER_USER":             "MAX_ALERTS_PER_USER",
    "DD_NOTIFICATION_SCAN_ADDED_MAX_FINDINGS": "NOTIFICATION_SCAN_ADDED_MAX_FINDINGS",
}


def populate_settings(env, target: dict) -> None:
    for env_var, setting_name in _ENV_TO_SETTING.items():
        target[setting_name] = env(env_var)
