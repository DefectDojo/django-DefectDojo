import logging

from django.db import migrations, models
import django.db.models.deletion
import pgtrigger.compiler
import pgtrigger.migrations

logger = logging.getLogger(__name__)


def migrate_tool_configs_to_cicd_infrastructure(apps, schema_editor):
    """
    For each Tool_Configuration referenced by an engagement's build_server,
    source_code_management_server, or orchestration_engine FK, create a
    CICDInfrastructure record and point the new engagement FK to it.
    """
    Engagement = apps.get_model("dojo", "Engagement")
    CICDInfrastructure = apps.get_model("dojo", "CICDInfrastructure")

    field_mappings = [
        ("source_code_management_server", "cicd_scm_server", "scm_server"),
        ("build_server", "cicd_build_server", "build_server"),
        ("orchestration_engine", "cicd_orchestration_engine", "orchestration"),
    ]

    for old_field, new_field, infra_type in field_mappings:
        engagements_with_old_fk = Engagement.objects.filter(
            **{f"{old_field}__isnull": False},
        ).select_related(old_field)

        for engagement in engagements_with_old_fk:
            tc = getattr(engagement, old_field)
            if tc is None:
                continue

            cicd_infra, created = CICDInfrastructure.objects.get_or_create(
                name=tc.name,
                infrastructure_type=infra_type,
                defaults={
                    "description": tc.description or "",
                    "url": tc.url or "",
                },
            )
            if created:
                logger.info(
                    "Created CICDInfrastructure '%s' (type=%s) from Tool_Configuration '%s'",
                    cicd_infra.name, infra_type, tc.name,
                )

            setattr(engagement, new_field, cicd_infra)
            engagement.save(update_fields=[new_field])


class Migration(migrations.Migration):

    dependencies = [
        ("dojo", "0268_release_authorization_to_pro"),
    ]

    operations = [
        # Step 1: Create CICDInfrastructure model
        migrations.CreateModel(
            name="CICDInfrastructure",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=200)),
                ("description", models.CharField(blank=True, default="", max_length=2000)),
                ("url", models.URLField(blank=True, default="", help_text="Public URL of the tool (e.g., https://jenkins.company.com)", max_length=2000)),
                ("infrastructure_type", models.CharField(choices=[("scm_server", "SCM Server"), ("build_server", "Build Server"), ("orchestration", "Orchestration Engine")], max_length=30)),
            ],
            options={
                "ordering": ["name"],
                "unique_together": {("name", "infrastructure_type")},
            },
        ),
        # Step 2: Add new FK fields to Engagement (before removing old ones)
        migrations.AddField(
            model_name="engagement",
            name="cicd_scm_server",
            field=models.ForeignKey(
                blank=True, null=True,
                help_text="Source code management server used for this CI/CD engagement",
                limit_choices_to={"infrastructure_type": "scm_server"},
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="engagements_as_scm_server",
                to="dojo.cicdinfrastructure",
                verbose_name="SCM Server",
            ),
        ),
        migrations.AddField(
            model_name="engagement",
            name="cicd_build_server",
            field=models.ForeignKey(
                blank=True, null=True,
                help_text="Build server used for this CI/CD engagement",
                limit_choices_to={"infrastructure_type": "build_server"},
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="engagements_as_build_server",
                to="dojo.cicdinfrastructure",
                verbose_name="Build Server",
            ),
        ),
        migrations.AddField(
            model_name="engagement",
            name="cicd_orchestration_engine",
            field=models.ForeignKey(
                blank=True, null=True,
                help_text="Orchestration engine used for this CI/CD engagement",
                limit_choices_to={"infrastructure_type": "orchestration"},
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="engagements_as_orchestration",
                to="dojo.cicdinfrastructure",
                verbose_name="Orchestration Engine",
            ),
        ),
        # Step 3: Migrate data from Tool_Configuration to CICDInfrastructure
        migrations.RunPython(
            migrate_tool_configs_to_cicd_infrastructure,
            reverse_code=migrations.RunPython.noop,
        ),
        # Step 4: Remove old pgtrigger triggers (they reference old column names)
        pgtrigger.migrations.RemoveTrigger(
            model_name='engagement',
            name='insert_insert',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='engagement',
            name='update_update',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='engagement',
            name='delete_delete',
        ),
        # Step 5: Remove old FK fields from Engagement
        migrations.RemoveField(
            model_name="engagement",
            name="source_code_management_server",
        ),
        migrations.RemoveField(
            model_name="engagement",
            name="build_server",
        ),
        migrations.RemoveField(
            model_name="engagement",
            name="orchestration_engine",
        ),
        # Step 6: Update pghistory event table FK fields to point to CICDInfrastructure
        migrations.RenameField(
            model_name="engagementevent",
            old_name="source_code_management_server",
            new_name="cicd_scm_server",
        ),
        migrations.RenameField(
            model_name="engagementevent",
            old_name="build_server",
            new_name="cicd_build_server",
        ),
        migrations.RenameField(
            model_name="engagementevent",
            old_name="orchestration_engine",
            new_name="cicd_orchestration_engine",
        ),
        migrations.AlterField(
            model_name='engagementevent',
            name='cicd_scm_server',
            field=models.ForeignKey(blank=True, db_constraint=False, db_index=False, help_text='Source code management server used for this CI/CD engagement', limit_choices_to={'infrastructure_type': 'scm_server'}, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='+', related_query_name='+', to='dojo.cicdinfrastructure', verbose_name='SCM Server'),
        ),
        migrations.AlterField(
            model_name='engagementevent',
            name='cicd_build_server',
            field=models.ForeignKey(blank=True, db_constraint=False, db_index=False, help_text='Build server used for this CI/CD engagement', limit_choices_to={'infrastructure_type': 'build_server'}, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='+', related_query_name='+', to='dojo.cicdinfrastructure', verbose_name='Build Server'),
        ),
        migrations.AlterField(
            model_name='engagementevent',
            name='cicd_orchestration_engine',
            field=models.ForeignKey(blank=True, db_constraint=False, db_index=False, help_text='Orchestration engine used for this CI/CD engagement', limit_choices_to={'infrastructure_type': 'orchestration'}, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='+', related_query_name='+', to='dojo.cicdinfrastructure', verbose_name='Orchestration Engine'),
        ),
        # Step 7: Re-create pgtrigger triggers with new column names
        pgtrigger.migrations.AddTrigger(
            model_name='engagement',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "dojo_engagementevent" ("active", "api_test", "branch_tag", "build_id", "check_list", "cicd_build_server_id", "cicd_orchestration_engine_id", "cicd_scm_server_id", "commit_hash", "created", "deduplication_on_engagement", "description", "done_testing", "engagement_type", "first_contacted", "id", "lead_id", "name", "pen_test", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "preset_id", "product_id", "progress", "reason", "report_type_id", "requester_id", "source_code_management_uri", "status", "target_end", "target_start", "test_strategy", "threat_model", "tmodel_path", "tracker", "updated", "version") VALUES (NEW."active", NEW."api_test", NEW."branch_tag", NEW."build_id", NEW."check_list", NEW."cicd_build_server_id", NEW."cicd_orchestration_engine_id", NEW."cicd_scm_server_id", NEW."commit_hash", NEW."created", NEW."deduplication_on_engagement", NEW."description", NEW."done_testing", NEW."engagement_type", NEW."first_contacted", NEW."id", NEW."lead_id", NEW."name", NEW."pen_test", _pgh_attach_context(), NOW(), \'insert\', NEW."id", NEW."preset_id", NEW."product_id", NEW."progress", NEW."reason", NEW."report_type_id", NEW."requester_id", NEW."source_code_management_uri", NEW."status", NEW."target_end", NEW."target_start", NEW."test_strategy", NEW."threat_model", NEW."tmodel_path", NEW."tracker", NEW."updated", NEW."version"); RETURN NULL;', hash='a217ec77b975020749afc350ee463c5867cfea27', operation='INSERT', pgid='pgtrigger_insert_insert_125f1', table='dojo_engagement', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='engagement',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD."active" IS DISTINCT FROM (NEW."active") OR OLD."api_test" IS DISTINCT FROM (NEW."api_test") OR OLD."branch_tag" IS DISTINCT FROM (NEW."branch_tag") OR OLD."build_id" IS DISTINCT FROM (NEW."build_id") OR OLD."check_list" IS DISTINCT FROM (NEW."check_list") OR OLD."cicd_build_server_id" IS DISTINCT FROM (NEW."cicd_build_server_id") OR OLD."cicd_orchestration_engine_id" IS DISTINCT FROM (NEW."cicd_orchestration_engine_id") OR OLD."cicd_scm_server_id" IS DISTINCT FROM (NEW."cicd_scm_server_id") OR OLD."commit_hash" IS DISTINCT FROM (NEW."commit_hash") OR OLD."deduplication_on_engagement" IS DISTINCT FROM (NEW."deduplication_on_engagement") OR OLD."description" IS DISTINCT FROM (NEW."description") OR OLD."done_testing" IS DISTINCT FROM (NEW."done_testing") OR OLD."engagement_type" IS DISTINCT FROM (NEW."engagement_type") OR OLD."first_contacted" IS DISTINCT FROM (NEW."first_contacted") OR OLD."id" IS DISTINCT FROM (NEW."id") OR OLD."lead_id" IS DISTINCT FROM (NEW."lead_id") OR OLD."name" IS DISTINCT FROM (NEW."name") OR OLD."pen_test" IS DISTINCT FROM (NEW."pen_test") OR OLD."preset_id" IS DISTINCT FROM (NEW."preset_id") OR OLD."product_id" IS DISTINCT FROM (NEW."product_id") OR OLD."progress" IS DISTINCT FROM (NEW."progress") OR OLD."reason" IS DISTINCT FROM (NEW."reason") OR OLD."report_type_id" IS DISTINCT FROM (NEW."report_type_id") OR OLD."requester_id" IS DISTINCT FROM (NEW."requester_id") OR OLD."source_code_management_uri" IS DISTINCT FROM (NEW."source_code_management_uri") OR OLD."status" IS DISTINCT FROM (NEW."status") OR OLD."target_end" IS DISTINCT FROM (NEW."target_end") OR OLD."target_start" IS DISTINCT FROM (NEW."target_start") OR OLD."test_strategy" IS DISTINCT FROM (NEW."test_strategy") OR OLD."threat_model" IS DISTINCT FROM (NEW."threat_model") OR OLD."tmodel_path" IS DISTINCT FROM (NEW."tmodel_path") OR OLD."tracker" IS DISTINCT FROM (NEW."tracker") OR OLD."version" IS DISTINCT FROM (NEW."version"))', func='INSERT INTO "dojo_engagementevent" ("active", "api_test", "branch_tag", "build_id", "check_list", "cicd_build_server_id", "cicd_orchestration_engine_id", "cicd_scm_server_id", "commit_hash", "created", "deduplication_on_engagement", "description", "done_testing", "engagement_type", "first_contacted", "id", "lead_id", "name", "pen_test", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "preset_id", "product_id", "progress", "reason", "report_type_id", "requester_id", "source_code_management_uri", "status", "target_end", "target_start", "test_strategy", "threat_model", "tmodel_path", "tracker", "updated", "version") VALUES (NEW."active", NEW."api_test", NEW."branch_tag", NEW."build_id", NEW."check_list", NEW."cicd_build_server_id", NEW."cicd_orchestration_engine_id", NEW."cicd_scm_server_id", NEW."commit_hash", NEW."created", NEW."deduplication_on_engagement", NEW."description", NEW."done_testing", NEW."engagement_type", NEW."first_contacted", NEW."id", NEW."lead_id", NEW."name", NEW."pen_test", _pgh_attach_context(), NOW(), \'update\', NEW."id", NEW."preset_id", NEW."product_id", NEW."progress", NEW."reason", NEW."report_type_id", NEW."requester_id", NEW."source_code_management_uri", NEW."status", NEW."target_end", NEW."target_start", NEW."test_strategy", NEW."threat_model", NEW."tmodel_path", NEW."tracker", NEW."updated", NEW."version"); RETURN NULL;', hash='6a9569fa21d5d7ad16eb018bc4e6236e8401bced', operation='UPDATE', pgid='pgtrigger_update_update_65136', table='dojo_engagement', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='engagement',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "dojo_engagementevent" ("active", "api_test", "branch_tag", "build_id", "check_list", "cicd_build_server_id", "cicd_orchestration_engine_id", "cicd_scm_server_id", "commit_hash", "created", "deduplication_on_engagement", "description", "done_testing", "engagement_type", "first_contacted", "id", "lead_id", "name", "pen_test", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "preset_id", "product_id", "progress", "reason", "report_type_id", "requester_id", "source_code_management_uri", "status", "target_end", "target_start", "test_strategy", "threat_model", "tmodel_path", "tracker", "updated", "version") VALUES (OLD."active", OLD."api_test", OLD."branch_tag", OLD."build_id", OLD."check_list", OLD."cicd_build_server_id", OLD."cicd_orchestration_engine_id", OLD."cicd_scm_server_id", OLD."commit_hash", OLD."created", OLD."deduplication_on_engagement", OLD."description", OLD."done_testing", OLD."engagement_type", OLD."first_contacted", OLD."id", OLD."lead_id", OLD."name", OLD."pen_test", _pgh_attach_context(), NOW(), \'delete\', OLD."id", OLD."preset_id", OLD."product_id", OLD."progress", OLD."reason", OLD."report_type_id", OLD."requester_id", OLD."source_code_management_uri", OLD."status", OLD."target_end", OLD."target_start", OLD."test_strategy", OLD."threat_model", OLD."tmodel_path", OLD."tracker", OLD."updated", OLD."version"); RETURN NULL;', hash='de64abfdac94fadfbe7a8cd33212b1dc26ad9600', operation='DELETE', pgid='pgtrigger_delete_delete_9f4df', table='dojo_engagement', when='AFTER')),
        ),
    ]
