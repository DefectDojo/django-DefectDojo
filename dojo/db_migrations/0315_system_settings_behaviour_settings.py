# Behaviour settings an instance can keep in its System Settings instead of the environment.
# Every field is nullable and starts empty, which means "use the deployment's DD_* setting", so no
# instance changes behaviour until someone saves a value.

import django.core.validators
from django.db import migrations, models

import dojo.system_settings.behaviour


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0314_sla_configuration_day_bounds"),
    ]

    operations = [
        migrations.AddField(
            model_name="system_settings",
            name="editable_mitigated_data",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Let superusers edit when a finding was mitigated and by whom. Empty uses DD_EDITABLE_MITIGATED_DATA.",
                null=True,
                verbose_name="Editable mitigated data",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="disable_finding_merge",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Hide merging findings from the findings list. Empty uses DD_DISABLE_FINDING_MERGE.",
                null=True,
                verbose_name="Disable finding merge",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="track_import_history",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Record which findings each import and reimport touched. Empty uses DD_TRACK_IMPORT_HISTORY.",
                null=True,
                verbose_name="Track import history",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="delete_preview",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="List the objects a delete removes before it runs. Empty uses DD_DELETE_PREVIEW.",
                null=True,
                verbose_name="Delete preview",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="duplicate_cluster_cascade_delete",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Deleting an original finding also deletes its duplicates. Empty uses DD_DUPLICATE_CLUSTER_CASCADE_DELETE.",
                null=True,
                verbose_name="Delete duplicate clusters",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="use_first_seen",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Parsers that report both dates use the first-seen date as the finding date. Empty uses DD_USE_FIRST_SEEN.",
                null=True,
                verbose_name="Use first seen date",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="qualys_legacy_severity_parsing",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Map Qualys severities with the legacy 1 to 5 table. Empty uses DD_QUALYS_LEGACY_SEVERITY_PARSING.",
                null=True,
                verbose_name="Qualys legacy severity parsing",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="qualys_was_unique_id",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Give Qualys WAS findings a unique id from the tool. Empty uses DD_QUALYS_WAS_UNIQUE_ID.",
                null=True,
                verbose_name="Qualys WAS unique id",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="qualys_was_weakness_is_vuln",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Import Qualys WAS weaknesses as findings. Empty uses DD_QUALYS_WAS_WEAKNESS_IS_VULN.",
                null=True,
                verbose_name="Qualys WAS weakness is a vulnerability",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="sonarqube_api_parser_hotspots",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Import security hotspots from the SonarQube API. Empty uses DD_SONARQUBE_API_PARSER_HOTSPOTS.",
                null=True,
                verbose_name="SonarQube API hotspots",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="jira_webhook_allow_finding_group_reopen",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Let a Jira webhook reopen a finding group's findings. Empty uses DD_JIRA_WEBHOOK_ALLOW_FINDING_GROUP_REOPEN.",
                null=True,
                verbose_name="Jira webhook reopens finding groups",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="alert_refresh",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Refresh the alert list in the page header. Empty uses DD_ALERT_REFRESH.",
                null=True,
                verbose_name="Refresh alerts",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="disable_alert_counter",
            field=models.BooleanField(
                blank=True,
                default=None,
                help_text="Hide the unread alert count. Empty uses DD_DISABLE_ALERT_COUNTER.",
                null=True,
                verbose_name="Disable alert counter",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="max_alerts_per_user",
            field=models.IntegerField(
                blank=True,
                default=None,
                help_text="Alerts kept for each user; -1 keeps all of them. Empty uses DD_MAX_ALERTS_PER_USER.",
                null=True,
                validators=[django.core.validators.MinValueValidator(-1)],
                verbose_name="Maximum alerts per user",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="notification_scan_added_max_findings",
            field=models.IntegerField(
                blank=True,
                default=None,
                help_text="Findings a scan-added notification lists. Empty uses DD_NOTIFICATION_SCAN_ADDED_MAX_FINDINGS.",
                null=True,
                validators=[django.core.validators.MinValueValidator(0)],
                verbose_name="Findings listed in a scan notification",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="notifications_system_level_trump",
            field=models.JSONField(
                blank=True,
                default=None,
                help_text="Notification events whose system setting wins over each person's own. Empty uses DD_NOTIFICATIONS_SYSTEM_LEVEL_TRUMP.",
                null=True,
                validators=[dojo.system_settings.behaviour.validate_notifications_system_level_trump],
                verbose_name="System notifications that override personal ones",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="sla_notify_pre_breach",
            field=models.IntegerField(
                blank=True,
                default=None,
                help_text="Empty uses DD_SLA_NOTIFY_PRE_BREACH.",
                null=True,
                validators=[django.core.validators.MinValueValidator(0)],
                verbose_name="Days before an SLA breach to notify",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="sla_notify_post_breach",
            field=models.IntegerField(
                blank=True,
                default=None,
                help_text="Empty uses DD_SLA_NOTIFY_POST_BREACH.",
                null=True,
                validators=[django.core.validators.MinValueValidator(0)],
                verbose_name="Days after an SLA breach to keep notifying",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="hashcode_fields_per_scanner",
            field=models.JSONField(
                blank=True,
                default=None,
                help_text="Entries that replace or add to the deployment's map of scan type to hash code fields. Stored hash codes are not recomputed. Empty uses DD_HASHCODE_FIELDS_PER_SCANNER.",
                null=True,
                validators=[dojo.system_settings.behaviour.validate_hashcode_fields_per_scanner],
                verbose_name="Hash code fields per scanner",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="deduplication_algorithm_per_parser",
            field=models.JSONField(
                blank=True,
                default=None,
                help_text="Entries that replace or add to the deployment's map of scan type to deduplication algorithm. Empty uses DD_DEDUPLICATION_ALGORITHM_PER_PARSER.",
                null=True,
                validators=[dojo.system_settings.behaviour.validate_deduplication_algorithm_per_parser],
                verbose_name="Deduplication algorithm per parser",
            ),
        ),
        migrations.AddField(
            model_name="system_settings",
            name="default_language_code",
            field=models.CharField(
                blank=True,
                default=None,
                help_text="The language for people who have not chosen one. Empty uses DD_LANGUAGE_CODE.",
                max_length=16,
                null=True,
                validators=[dojo.system_settings.behaviour.validate_language_code],
                verbose_name="Default language",
            ),
        ),
    ]
