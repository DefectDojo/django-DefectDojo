# Convert Product.platform / lifecycle / origin from CharField(choices) to ForeignKey
# to the editable dojo.product_attributes lookup tables, preserving existing data.
#
# The naive AlterField that makemigrations produces would try to cast the stored
# strings ("web service", "production", ...) straight to integer ids and lose the data.
# Instead each field is converted in place: add the new *_id column, backfill it from the
# option table by matching on ``value``, then drop the old string column. Any value not
# already seeded (a stray written directly to the DB / via import) gets an option row
# created for it first, so no asset or audit-history row loses its value.
#
# Product is pghistory-tracked, so its row triggers are dropped before the data work and
# recreated (against the new *_id columns) afterwards, and the mirrored productevent
# columns are converted the same way.
import django.db.models.deletion
import pgtrigger.compiler
import pgtrigger.migrations
from django.db import migrations, models

# (value, label, font-awesome icon base name, display_order) seeded from the old choice tuples /
# display tags. ``value`` is the machine string the Product fields used to store and still expose.
PLATFORMS = [
    ("web service", "API", "plug", 10),
    ("desktop", "Desktop", "desktop", 20),
    ("iot", "Internet of Things", "shuffle", 30),
    ("mobile", "Mobile", "mobile", 40),
    ("web", "Web", "rectangle-list", 50),
]
LIFECYCLES = [
    ("construction", "Construction", "compass", 10),
    ("production", "Production", "ship", 20),
    ("retirement", "Retirement", "moon", 30),
]
ORIGINS = [
    ("third party library", "Third Party Library", "book", 10),
    ("purchased", "Purchased", "money-bill", 20),
    ("contractor", "Contractor Developed", "suitcase", 30),
    ("internal", "Internally Developed", "home", 40),
    ("open source", "Open Source", "code", 50),
    ("outsourced", "Outsourced", "globe", 60),
]


def seed_options(apps, schema_editor):
    Product_Platform = apps.get_model("dojo", "Product_Platform")
    Product_Lifecycle = apps.get_model("dojo", "Product_Lifecycle")
    Product_Origin = apps.get_model("dojo", "Product_Origin")
    for model, rows in (
        (Product_Platform, PLATFORMS),
        (Product_Lifecycle, LIFECYCLES),
        (Product_Origin, ORIGINS),
    ):
        for value, label, icon, order in rows:
            model.objects.get_or_create(
                value=value,
                defaults={"name": label, "icon": icon, "display_order": order},
            )


def _seed_strays_sql(option_table, source_column):
    return f"""
        INSERT INTO {option_table} (value, name, icon, display_order)
        SELECT DISTINCT s.v, INITCAP(s.v), '', 100
        FROM (
            SELECT {source_column} AS v FROM dojo_product
                WHERE {source_column} IS NOT NULL AND {source_column} <> ''
            UNION
            SELECT {source_column} AS v FROM dojo_productevent
                WHERE {source_column} IS NOT NULL AND {source_column} <> ''
        ) s
        WHERE NOT EXISTS (SELECT 1 FROM {option_table} o WHERE o.value = s.v);
    """


SEED_STRAYS = (
    _seed_strays_sql("dojo_product_platform", "platform")
    + _seed_strays_sql("dojo_product_lifecycle", "lifecycle")
    + _seed_strays_sql("dojo_product_origin", "origin")
)


def _convert_product_fk_sql(column, option_table, constraint, index):
    # dojo_product carries DEFERRABLE INITIALLY DEFERRED foreign keys, so the UPDATE
    # queues deferred constraint checks ("pending trigger events") that would block the
    # following ALTER TABLE. SET CONSTRAINTS ALL IMMEDIATE forces them to run now and
    # clears the queue (it also stops later UPDATEs in this transaction from deferring).
    return f"""
        ALTER TABLE dojo_product ADD COLUMN {column}_id integer NULL;
        UPDATE dojo_product p SET {column}_id = o.id
            FROM {option_table} o WHERE o.value = p.{column};
        SET CONSTRAINTS ALL IMMEDIATE;
        ALTER TABLE dojo_product DROP COLUMN {column};
        ALTER TABLE dojo_product ADD CONSTRAINT {constraint}
            FOREIGN KEY ({column}_id) REFERENCES {option_table} (id)
            DEFERRABLE INITIALLY DEFERRED;
        CREATE INDEX {index} ON dojo_product ({column}_id);
    """


def _revert_product_fk_sql(column, option_table, constraint, index):
    return f"""
        ALTER TABLE dojo_product ADD COLUMN {column} varchar(50) NULL;
        UPDATE dojo_product p SET {column} = o.value
            FROM {option_table} o WHERE o.id = p.{column}_id;
        ALTER TABLE dojo_product DROP CONSTRAINT {constraint};
        DROP INDEX {index};
        ALTER TABLE dojo_product DROP COLUMN {column}_id;
    """


def _convert_event_fk_sql(column, option_table):
    # The pghistory event table carries no FK constraint or index (db_constraint=False,
    # db_index=False), so only the column type is converted.
    return f"""
        ALTER TABLE dojo_productevent ADD COLUMN {column}_id integer NULL;
        UPDATE dojo_productevent e SET {column}_id = o.id
            FROM {option_table} o WHERE o.value = e.{column};
        SET CONSTRAINTS ALL IMMEDIATE;
        ALTER TABLE dojo_productevent DROP COLUMN {column};
    """


def _revert_event_fk_sql(column, option_table):
    return f"""
        ALTER TABLE dojo_productevent ADD COLUMN {column} varchar(50) NULL;
        UPDATE dojo_productevent e SET {column} = o.value
            FROM {option_table} o WHERE o.id = e.{column}_id;
        ALTER TABLE dojo_productevent DROP COLUMN {column}_id;
    """


def _product_fk(name, target):
    return migrations.AlterField(
        model_name="product",
        name=name,
        field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.RESTRICT,
                                related_name="products", to=target),
    )


def _event_fk(name, target):
    return migrations.AlterField(
        model_name="productevent",
        name=name,
        field=models.ForeignKey(blank=True, db_constraint=False, db_index=False, null=True,
                                on_delete=django.db.models.deletion.DO_NOTHING, related_name="+",
                                related_query_name="+", to=target),
    )


class Migration(migrations.Migration):

    dependencies = [
        ('dojo', '0296_drop_unused_finding_indexes'),
    ]

    operations = [
        migrations.CreateModel(
            name='Product_Lifecycle',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(help_text='Stable machine value used by the API, imports and automation rules. Immutable once created.', max_length=50, unique=True)),
                ('name', models.CharField(help_text='Label shown in dropdowns and on the asset.', max_length=200)),
                ('icon', models.CharField(blank=True, default='', help_text='Optional Font Awesome icon class (classic UI only).', max_length=100)),
                ('display_order', models.IntegerField(default=0, help_text='Optional ordering for the dropdown (lower first).')),
            ],
            options={
                'ordering': ['display_order', 'name'],
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Product_Origin',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(help_text='Stable machine value used by the API, imports and automation rules. Immutable once created.', max_length=50, unique=True)),
                ('name', models.CharField(help_text='Label shown in dropdowns and on the asset.', max_length=200)),
                ('icon', models.CharField(blank=True, default='', help_text='Optional Font Awesome icon class (classic UI only).', max_length=100)),
                ('display_order', models.IntegerField(default=0, help_text='Optional ordering for the dropdown (lower first).')),
            ],
            options={
                'ordering': ['display_order', 'name'],
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Product_Platform',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('value', models.CharField(help_text='Stable machine value used by the API, imports and automation rules. Immutable once created.', max_length=50, unique=True)),
                ('name', models.CharField(help_text='Label shown in dropdowns and on the asset.', max_length=200)),
                ('icon', models.CharField(blank=True, default='', help_text='Optional Font Awesome icon class (classic UI only).', max_length=100)),
                ('display_order', models.IntegerField(default=0, help_text='Optional ordering for the dropdown (lower first).')),
            ],
            options={
                'ordering': ['display_order', 'name'],
                'abstract': False,
            },
        ),
        migrations.RunPython(seed_options, migrations.RunPython.noop),

        pgtrigger.migrations.RemoveTrigger(model_name='product', name='insert_insert'),
        pgtrigger.migrations.RemoveTrigger(model_name='product', name='update_update'),
        pgtrigger.migrations.RemoveTrigger(model_name='product', name='delete_delete'),

        # Create option rows for any values not already seeded, so the backfills below
        # map every existing value.
        migrations.RunSQL(SEED_STRAYS, reverse_sql=migrations.RunSQL.noop),

        # Product: string -> FK, data preserved.
        migrations.SeparateDatabaseAndState(
            state_operations=[_product_fk("platform", "dojo.product_platform")],
            database_operations=[migrations.RunSQL(
                _convert_product_fk_sql("platform", "dojo_product_platform",
                                        "dojo_product_platform_id_fk", "dojo_product_platform_id_idx"),
                reverse_sql=_revert_product_fk_sql("platform", "dojo_product_platform",
                                                   "dojo_product_platform_id_fk", "dojo_product_platform_id_idx"),
            )],
        ),
        migrations.SeparateDatabaseAndState(
            state_operations=[_product_fk("lifecycle", "dojo.product_lifecycle")],
            database_operations=[migrations.RunSQL(
                _convert_product_fk_sql("lifecycle", "dojo_product_lifecycle",
                                        "dojo_product_lifecycle_id_fk", "dojo_product_lifecycle_id_idx"),
                reverse_sql=_revert_product_fk_sql("lifecycle", "dojo_product_lifecycle",
                                                   "dojo_product_lifecycle_id_fk", "dojo_product_lifecycle_id_idx"),
            )],
        ),
        migrations.SeparateDatabaseAndState(
            state_operations=[_product_fk("origin", "dojo.product_origin")],
            database_operations=[migrations.RunSQL(
                _convert_product_fk_sql("origin", "dojo_product_origin",
                                        "dojo_product_origin_id_fk", "dojo_product_origin_id_idx"),
                reverse_sql=_revert_product_fk_sql("origin", "dojo_product_origin",
                                                   "dojo_product_origin_id_fk", "dojo_product_origin_id_idx"),
            )],
        ),

        # productevent (pghistory mirror): string -> FK id, historical data preserved.
        migrations.SeparateDatabaseAndState(
            state_operations=[_event_fk("platform", "dojo.product_platform")],
            database_operations=[migrations.RunSQL(
                _convert_event_fk_sql("platform", "dojo_product_platform"),
                reverse_sql=_revert_event_fk_sql("platform", "dojo_product_platform"),
            )],
        ),
        migrations.SeparateDatabaseAndState(
            state_operations=[_event_fk("lifecycle", "dojo.product_lifecycle")],
            database_operations=[migrations.RunSQL(
                _convert_event_fk_sql("lifecycle", "dojo_product_lifecycle"),
                reverse_sql=_revert_event_fk_sql("lifecycle", "dojo_product_lifecycle"),
            )],
        ),
        migrations.SeparateDatabaseAndState(
            state_operations=[_event_fk("origin", "dojo.product_origin")],
            database_operations=[migrations.RunSQL(
                _convert_event_fk_sql("origin", "dojo_product_origin"),
                reverse_sql=_revert_event_fk_sql("origin", "dojo_product_origin"),
            )],
        ),

        pgtrigger.migrations.AddTrigger(
            model_name='product',
            trigger=pgtrigger.compiler.Trigger(name='insert_insert', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "dojo_productevent" ("async_updating", "business_criticality", "created", "description", "disable_sla_breach_notifications", "enable_full_risk_acceptance", "enable_product_tag_inheritance", "enable_simple_risk_acceptance", "external_audience", "id", "internet_accessible", "lifecycle_id", "name", "origin_id", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "platform_id", "prod_numeric_grade", "prod_type_id", "product_manager_id", "revenue", "sla_configuration_id", "team_manager_id", "technical_contact_id", "tid", "updated", "user_records") VALUES (NEW."async_updating", NEW."business_criticality", NEW."created", NEW."description", NEW."disable_sla_breach_notifications", NEW."enable_full_risk_acceptance", NEW."enable_product_tag_inheritance", NEW."enable_simple_risk_acceptance", NEW."external_audience", NEW."id", NEW."internet_accessible", NEW."lifecycle_id", NEW."name", NEW."origin_id", _pgh_attach_context(), NOW(), \'insert\', NEW."id", NEW."platform_id", NEW."prod_numeric_grade", NEW."prod_type_id", NEW."product_manager_id", NEW."revenue", NEW."sla_configuration_id", NEW."team_manager_id", NEW."technical_contact_id", NEW."tid", NEW."updated", NEW."user_records"); RETURN NULL;', hash='56d7d4e2ec7a3c855444408a7cd6be18e2e9ab02', operation='INSERT', pgid='pgtrigger_insert_insert_d5d32', table='dojo_product', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='product',
            trigger=pgtrigger.compiler.Trigger(name='update_update', sql=pgtrigger.compiler.UpsertTriggerSql(condition='WHEN (OLD."async_updating" IS DISTINCT FROM (NEW."async_updating") OR OLD."business_criticality" IS DISTINCT FROM (NEW."business_criticality") OR OLD."description" IS DISTINCT FROM (NEW."description") OR OLD."disable_sla_breach_notifications" IS DISTINCT FROM (NEW."disable_sla_breach_notifications") OR OLD."enable_full_risk_acceptance" IS DISTINCT FROM (NEW."enable_full_risk_acceptance") OR OLD."enable_product_tag_inheritance" IS DISTINCT FROM (NEW."enable_product_tag_inheritance") OR OLD."enable_simple_risk_acceptance" IS DISTINCT FROM (NEW."enable_simple_risk_acceptance") OR OLD."external_audience" IS DISTINCT FROM (NEW."external_audience") OR OLD."id" IS DISTINCT FROM (NEW."id") OR OLD."internet_accessible" IS DISTINCT FROM (NEW."internet_accessible") OR OLD."lifecycle_id" IS DISTINCT FROM (NEW."lifecycle_id") OR OLD."name" IS DISTINCT FROM (NEW."name") OR OLD."origin_id" IS DISTINCT FROM (NEW."origin_id") OR OLD."platform_id" IS DISTINCT FROM (NEW."platform_id") OR OLD."prod_numeric_grade" IS DISTINCT FROM (NEW."prod_numeric_grade") OR OLD."prod_type_id" IS DISTINCT FROM (NEW."prod_type_id") OR OLD."product_manager_id" IS DISTINCT FROM (NEW."product_manager_id") OR OLD."revenue" IS DISTINCT FROM (NEW."revenue") OR OLD."sla_configuration_id" IS DISTINCT FROM (NEW."sla_configuration_id") OR OLD."team_manager_id" IS DISTINCT FROM (NEW."team_manager_id") OR OLD."technical_contact_id" IS DISTINCT FROM (NEW."technical_contact_id") OR OLD."tid" IS DISTINCT FROM (NEW."tid") OR OLD."user_records" IS DISTINCT FROM (NEW."user_records"))', func='INSERT INTO "dojo_productevent" ("async_updating", "business_criticality", "created", "description", "disable_sla_breach_notifications", "enable_full_risk_acceptance", "enable_product_tag_inheritance", "enable_simple_risk_acceptance", "external_audience", "id", "internet_accessible", "lifecycle_id", "name", "origin_id", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "platform_id", "prod_numeric_grade", "prod_type_id", "product_manager_id", "revenue", "sla_configuration_id", "team_manager_id", "technical_contact_id", "tid", "updated", "user_records") VALUES (NEW."async_updating", NEW."business_criticality", NEW."created", NEW."description", NEW."disable_sla_breach_notifications", NEW."enable_full_risk_acceptance", NEW."enable_product_tag_inheritance", NEW."enable_simple_risk_acceptance", NEW."external_audience", NEW."id", NEW."internet_accessible", NEW."lifecycle_id", NEW."name", NEW."origin_id", _pgh_attach_context(), NOW(), \'update\', NEW."id", NEW."platform_id", NEW."prod_numeric_grade", NEW."prod_type_id", NEW."product_manager_id", NEW."revenue", NEW."sla_configuration_id", NEW."team_manager_id", NEW."technical_contact_id", NEW."tid", NEW."updated", NEW."user_records"); RETURN NULL;', hash='49923bd314b57154a13024be447d70ff62dda123', operation='UPDATE', pgid='pgtrigger_update_update_e7040', table='dojo_product', when='AFTER')),
        ),
        pgtrigger.migrations.AddTrigger(
            model_name='product',
            trigger=pgtrigger.compiler.Trigger(name='delete_delete', sql=pgtrigger.compiler.UpsertTriggerSql(func='INSERT INTO "dojo_productevent" ("async_updating", "business_criticality", "created", "description", "disable_sla_breach_notifications", "enable_full_risk_acceptance", "enable_product_tag_inheritance", "enable_simple_risk_acceptance", "external_audience", "id", "internet_accessible", "lifecycle_id", "name", "origin_id", "pgh_context_id", "pgh_created_at", "pgh_label", "pgh_obj_id", "platform_id", "prod_numeric_grade", "prod_type_id", "product_manager_id", "revenue", "sla_configuration_id", "team_manager_id", "technical_contact_id", "tid", "updated", "user_records") VALUES (OLD."async_updating", OLD."business_criticality", OLD."created", OLD."description", OLD."disable_sla_breach_notifications", OLD."enable_full_risk_acceptance", OLD."enable_product_tag_inheritance", OLD."enable_simple_risk_acceptance", OLD."external_audience", OLD."id", OLD."internet_accessible", OLD."lifecycle_id", OLD."name", OLD."origin_id", _pgh_attach_context(), NOW(), \'delete\', OLD."id", OLD."platform_id", OLD."prod_numeric_grade", OLD."prod_type_id", OLD."product_manager_id", OLD."revenue", OLD."sla_configuration_id", OLD."team_manager_id", OLD."technical_contact_id", OLD."tid", OLD."updated", OLD."user_records"); RETURN NULL;', hash='fb5075dda22c29fcfbf16c799b636b5dbf993777', operation='DELETE', pgid='pgtrigger_delete_delete_064dd', table='dojo_product', when='AFTER')),
        ),
    ]
