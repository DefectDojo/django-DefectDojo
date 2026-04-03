import logging

from django.db import migrations, models
import django.db.models.deletion

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
        ("build_server", "cicd_build_server", "build_server"),
        ("source_code_management_server", "cicd_scm_server", "scm_server"),
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
        ("dojo", "0263_language_type_unique_language"),
    ]

    operations = [
        # Step 1: Create CICDInfrastructure model
        migrations.CreateModel(
            name="CICDInfrastructure",
            fields=[
                ("id", models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=200)),
                ("description", models.CharField(blank=True, max_length=2000, null=True)),
                ("url", models.URLField(blank=True, help_text="Public URL of the tool (e.g., https://jenkins.company.com)", max_length=2000, null=True)),
                ("infrastructure_type", models.CharField(choices=[("build_server", "Build Server"), ("scm_server", "SCM Server"), ("orchestration", "Orchestration Engine")], max_length=30)),
            ],
            options={
                "ordering": ["name"],
            },
        ),
        # Step 2: Add new FK fields to Engagement (before removing old ones)
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
        # Step 4: Remove old FK fields from Engagement
        migrations.RemoveField(
            model_name="engagement",
            name="build_server",
        ),
        migrations.RemoveField(
            model_name="engagement",
            name="source_code_management_server",
        ),
        migrations.RemoveField(
            model_name="engagement",
            name="orchestration_engine",
        ),
    ]
