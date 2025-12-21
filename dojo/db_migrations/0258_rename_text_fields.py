# Generated migration to rename vulnerability_ids_field to vulnerability_ids_text and add endpoints_text

import pgtrigger.compiler
import pgtrigger.migrations
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0257_remove_vulnerability_id_template_model"),
    ]

    operations = [
        # Remove existing triggers that reference the old field name
        pgtrigger.migrations.RemoveTrigger(
            model_name="finding_template",
            name="insert_insert",
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name="finding_template",
            name="update_update",
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name="finding_template",
            name="delete_delete",
        ),
        # Rename fields
        migrations.RenameField(
            model_name="finding_template",
            old_name="vulnerability_ids_field",
            new_name="vulnerability_ids_text",
        ),
        migrations.AddField(
            model_name="finding_template",
            name="endpoints_text",
            field=models.TextField(blank=True, help_text="Endpoint URLs (one per line)", null=True),
        ),
        migrations.RenameField(
            model_name="finding_templateevent",
            old_name="vulnerability_ids_field",
            new_name="vulnerability_ids_text",
        ),
        migrations.AddField(
            model_name="finding_templateevent",
            name="endpoints_text",
            field=models.TextField(blank=True, help_text="Endpoint URLs (one per line)", null=True),
        ),
        # Re-add triggers with updated field names
        pgtrigger.migrations.AddTrigger(
            model_name="finding_template",
            trigger=pgtrigger.compiler.Trigger(
                name="insert_insert",
                sql=pgtrigger.compiler.UpsertTriggerSql(
                    func='INSERT INTO "dojo_finding_templateevent" ("component_name", "component_version", "cve", "cvssv3", "cvssv3_score", "cvssv4", "cvssv4_score", "cwe", "description", "effort_for_fixing", "fix_available", "fix_version", "id", "impact", "last_used", "mitigation", "notes", "numerical_severity", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "planned_remediation_version", "refs", "severity", "severity_justification", "steps_to_reproduce", "title", "vulnerability_ids_text", "endpoints_text") VALUES (NEW."component_name", NEW."component_version", NEW."cve", NEW."cvssv3", NEW."cvssv3_score", NEW."cvssv4", NEW."cvssv4_score", NEW."cwe", NEW."description", NEW."effort_for_fixing", NEW."fix_available", NEW."fix_version", NEW."id", NEW."impact", NEW."last_used", NEW."mitigation", NEW."notes", NEW."numerical_severity", _pgh_attach_context(), NOW(), \'insert\', NEW."id", NEW."planned_remediation_version", NEW."refs", NEW."severity", NEW."severity_justification", NEW."steps_to_reproduce", NEW."title", NEW."vulnerability_ids_text", NEW."endpoints_text"); RETURN NULL;',
                    hash="911a9b7b9a9e2d29ceec9f932e957822029ded91",
                    operation="INSERT",
                    pgid="pgtrigger_insert_insert_59092",
                    table="dojo_finding_template",
                    when="AFTER",
                ),
            ),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name="finding_template",
            trigger=pgtrigger.compiler.Trigger(
                name="update_update",
                sql=pgtrigger.compiler.UpsertTriggerSql(
                    condition="WHEN (OLD.* IS DISTINCT FROM NEW.*)",
                    func='INSERT INTO "dojo_finding_templateevent" ("component_name", "component_version", "cve", "cvssv3", "cvssv3_score", "cvssv4", "cvssv4_score", "cwe", "description", "effort_for_fixing", "fix_available", "fix_version", "id", "impact", "last_used", "mitigation", "notes", "numerical_severity", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "planned_remediation_version", "refs", "severity", "severity_justification", "steps_to_reproduce", "title", "vulnerability_ids_text", "endpoints_text") VALUES (NEW."component_name", NEW."component_version", NEW."cve", NEW."cvssv3", NEW."cvssv3_score", NEW."cvssv4", NEW."cvssv4_score", NEW."cwe", NEW."description", NEW."effort_for_fixing", NEW."fix_available", NEW."fix_version", NEW."id", NEW."impact", NEW."last_used", NEW."mitigation", NEW."notes", NEW."numerical_severity", _pgh_attach_context(), NOW(), \'update\', NEW."id", NEW."planned_remediation_version", NEW."refs", NEW."severity", NEW."severity_justification", NEW."steps_to_reproduce", NEW."title", NEW."vulnerability_ids_text", NEW."endpoints_text"); RETURN NULL;',
                    hash="b34e1e22297587c21cc5f3433502a771d0e87183",
                    operation="UPDATE",
                    pgid="pgtrigger_update_update_43036",
                    table="dojo_finding_template",
                    when="AFTER",
                ),
            ),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name="finding_template",
            trigger=pgtrigger.compiler.Trigger(
                name="delete_delete",
                sql=pgtrigger.compiler.UpsertTriggerSql(
                    func='INSERT INTO "dojo_finding_templateevent" ("component_name", "component_version", "cve", "cvssv3", "cvssv3_score", "cvssv4", "cvssv4_score", "cwe", "description", "effort_for_fixing", "fix_available", "fix_version", "id", "impact", "last_used", "mitigation", "notes", "numerical_severity", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "planned_remediation_version", "refs", "severity", "severity_justification", "steps_to_reproduce", "title", "vulnerability_ids_text", "endpoints_text") VALUES (OLD."component_name", OLD."component_version", OLD."cve", OLD."cvssv3", OLD."cvssv3_score", OLD."cvssv4", OLD."cvssv4_score", OLD."cwe", OLD."description", OLD."effort_for_fixing", OLD."fix_available", OLD."fix_version", OLD."id", OLD."impact", OLD."last_used", OLD."mitigation", OLD."notes", OLD."numerical_severity", _pgh_attach_context(), NOW(), \'delete\', OLD."id", OLD."planned_remediation_version", OLD."refs", OLD."severity", OLD."severity_justification", OLD."steps_to_reproduce", OLD."title", OLD."vulnerability_ids_text", OLD."endpoints_text"); RETURN NULL;',
                    hash="ad10ba8807613033b3a86b8f2ce2d9d0742829d6",
                    operation="DELETE",
                    pgid="pgtrigger_delete_delete_3f3a6",
                    table="dojo_finding_template",
                    when="AFTER",
                ),
            ),
        ),
    ]
