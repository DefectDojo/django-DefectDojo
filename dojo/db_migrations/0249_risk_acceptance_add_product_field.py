# Generated migration - Step 1: Add product field to Risk_Acceptance

from django.db import migrations, models
import django.db.models.deletion
import pgtrigger


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0248_alter_general_survey_expiration'),
    ]

    operations = [
        # Add product field (nullable initially so we can populate it)
        migrations.AddField(
            model_name='risk_acceptance',
            name='product',
            field=models.ForeignKey(editable=False, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='risk_acceptances', to='dojo.product'),
        ),
        migrations.AddField(
            model_name='risk_acceptanceevent',
            name='product',
            field=models.ForeignKey(db_constraint=False, db_index=False, editable=False, on_delete=django.db.models.deletion.DO_NOTHING, related_name='+', related_query_name='+', to='dojo.product'),
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='risk_acceptance',
            name='insert_insert',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='risk_acceptance',
            name='update_update',
        ),
        pgtrigger.migrations.RemoveTrigger(
            model_name='risk_acceptance',
            name='delete_delete',
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='risk_acceptance',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "dojo_risk_acceptanceevent" ("accepted_by", "created", "decision", "decision_details", "expiration_date", "expiration_date_handled", "expiration_date_warned", "id", "name", "owner_id", "path", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "product_id", "reactivate_expired", "recommendation", "recommendation_details", "restart_sla_expired", "updated") VALUES (NEW."accepted_by", NEW."created", NEW."decision", NEW."decision_details", NEW."expiration_date", NEW."expiration_date_handled", NEW."expiration_date_warned", NEW."id", NEW."name", NEW."owner_id", NEW."path", _pgh_attach_context(), NOW(), \'insert\', NEW."id", NEW."product_id", NEW."reactivate_expired", NEW."recommendation", NEW."recommendation_details", NEW."restart_sla_expired", NEW."updated"); RETURN NULL;', hash='83d5189fd3362f9e91757621240964180e09bf95', operation='INSERT', pgid='pgtrigger_insert_insert_d29bd', table='dojo_risk_acceptance', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='risk_acceptance',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD."accepted_by" IS DISTINCT FROM (NEW."accepted_by") OR OLD."decision" IS DISTINCT FROM (NEW."decision") OR OLD."decision_details" IS DISTINCT FROM (NEW."decision_details") OR OLD."expiration_date" IS DISTINCT FROM (NEW."expiration_date") OR OLD."expiration_date_handled" IS DISTINCT FROM (NEW."expiration_date_handled") OR OLD."expiration_date_warned" IS DISTINCT FROM (NEW."expiration_date_warned") OR OLD."id" IS DISTINCT FROM (NEW."id") OR OLD."name" IS DISTINCT FROM (NEW."name") OR OLD."owner_id" IS DISTINCT FROM (NEW."owner_id") OR OLD."path" IS DISTINCT FROM (NEW."path") OR OLD."product_id" IS DISTINCT FROM (NEW."product_id") OR OLD."reactivate_expired" IS DISTINCT FROM (NEW."reactivate_expired") OR OLD."recommendation" IS DISTINCT FROM (NEW."recommendation") OR OLD."recommendation_details" IS DISTINCT FROM (NEW."recommendation_details") OR OLD."restart_sla_expired" IS DISTINCT FROM (NEW."restart_sla_expired"))', func='INSERT INTO "dojo_risk_acceptanceevent" ("accepted_by", "created", "decision", "decision_details", "expiration_date", "expiration_date_handled", "expiration_date_warned", "id", "name", "owner_id", "path", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "product_id", "reactivate_expired", "recommendation", "recommendation_details", "restart_sla_expired", "updated") VALUES (NEW."accepted_by", NEW."created", NEW."decision", NEW."decision_details", NEW."expiration_date", NEW."expiration_date_handled", NEW."expiration_date_warned", NEW."id", NEW."name", NEW."owner_id", NEW."path", _pgh_attach_context(), NOW(), \'update\', NEW."id", NEW."product_id", NEW."reactivate_expired", NEW."recommendation", NEW."recommendation_details", NEW."restart_sla_expired", NEW."updated"); RETURN NULL;', hash='6e5515509e5c952f582b91b5ac3aa7f5bed0f727', operation='UPDATE', pgid='pgtrigger_update_update_55e64', table='dojo_risk_acceptance', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='risk_acceptance',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "dojo_risk_acceptanceevent" ("accepted_by", "created", "decision", "decision_details", "expiration_date", "expiration_date_handled", "expiration_date_warned", "id", "name", "owner_id", "path", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "product_id", "reactivate_expired", "recommendation", "recommendation_details", "restart_sla_expired", "updated") VALUES (OLD."accepted_by", OLD."created", OLD."decision", OLD."decision_details", OLD."expiration_date", OLD."expiration_date_handled", OLD."expiration_date_warned", OLD."id", OLD."name", OLD."owner_id", OLD."path", _pgh_attach_context(), NOW(), \'delete\', OLD."id", OLD."product_id", OLD."reactivate_expired", OLD."recommendation", OLD."recommendation_details", OLD."restart_sla_expired", OLD."updated"); RETURN NULL;', hash='68cfbb774b18823b974228d517729985c0087130', operation='DELETE', pgid='pgtrigger_delete_delete_7d103', table='dojo_risk_acceptance', when='AFTER')),
        ),
    ]
