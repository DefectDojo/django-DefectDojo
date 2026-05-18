"""
Release the authorization layer from dojo to pro.

Pairs with ``pro.0052_pro_authorization_takeover`` (``run_before``): Pro
adopts the seven RBAC tables and ``Dojo_Group`` into ``pro`` state via
state-only ``CreateModel`` operations, adds the relocated
``default_group`` / ``default_group_role`` / ``default_group_email_pattern``
columns onto ``pro_enhanced_system_settings``, and copies the existing
default-group values out of ``dojo_system_settings``. Ordering ensures
Pro adopts the tables and copies the values *before* this migration
flips them to ``managed=False`` and drops the source columns.

Five concerns folded into a single migration:

1. **Re-introduce the legacy ``authorized_users`` M2M** on Product /
   Product_Type. OS-only deployments authorize against this M2M (plus
   ``is_superuser`` / ``is_staff``); Pro deployments keep using RBAC.

2. **Backfill ``authorized_users`` from RBAC** (``RunPython``). Translates
   ``Product_Member`` / ``Product_Type_Member`` rows, ``Product_Group`` /
   ``Product_Type_Group`` (flattened through ``Dojo_Group_Member``), and
   ``Global_Role`` (Owner → ``is_superuser``, elevated → ``is_staff``)
   into legacy memberships and user-flag values. Idempotent — guarded on
   the presence of ``dojo_role`` so fresh installs are a no-op. The RBAC
   tables themselves are NOT modified or dropped — they remain
   bit-for-bit so Pro can adopt them unchanged.

3. **Drop the legacy M2M accessors on Product / Product_Type.** ``members``
   and ``authorization_groups`` were post-RBAC convenience accessors layered
   on top of the through-tables (``Product_Member`` / ``Product_Type_Member``
   and ``Product_Group`` / ``Product_Type_Group``). The through-tables are
   owned by Pro and remain the source of truth; the accessors duplicated
   their data and made it ambiguous which path was canonical.

4. **Flip the eight authorization shells to ``managed=False``** — the
   seven RBAC models plus ``Dojo_Group``. Pro's ``CreateModel`` in
   ``pro.0052`` is the ``managed=True`` canonical owner; both states
   share the same ``db_table`` so no DDL conflicts. The dojo-side classes
   stay as ``managed=False`` shells in ``dojo/authorization/models.py`` so
   OS code that imports them keeps resolving and historical pro
   migrations whose state references ``dojo.dojo_group`` /
   ``dojo.role`` / etc. (e.g. ``pro.0001_plugiun_consolidation``
   ``EnhancedDojoGroup.group`` and ``pro.0034_pghistory_for_permissions_models``
   proxy bases) keep resolving when the executor reloads project state.

5. **Drop the relocated default-group columns** from
   ``dojo_system_settings``. OS code base must not reference Pro app
   models, so ``default_group`` (FK to ``Dojo_Group``),
   ``default_group_role`` (FK to ``Role``), and
   ``default_group_email_pattern`` relocate onto
   ``pro.EnhancedSystemSettings``. Pro's matching migration copies the
   values across before this migration drops the source columns.

The first four concerns are pure state-only operations or RBAC-table
reads (no DDL on the eight shared tables); the new ``authorized_users``
M2M and the dropped ``default_group`` columns issue real DDL.
"""

from django.db import migrations, models


def backfill_authorized_users(apps, schema_editor):
    """Translate RBAC rows into the legacy ``authorized_users`` M2M.

    Forward-only data migration. The RBAC tables themselves are NOT
    modified — they remain available verbatim so a Pro install can pick
    them up unchanged via ``pro.0052_pro_authorization_takeover``.

    Mapping:
      Product_Member.user (any role)        -> Product.authorized_users
      Product_Type_Member.user (any role)   -> Product_Type.authorized_users
      Product_Group.group + Dojo_Group_Member.user
                                            -> Product.authorized_users (flattened)
      Product_Type_Group.group + Dojo_Group_Member.user
                                            -> Product_Type.authorized_users (flattened)
      Global_Role(Owner) for user           -> User.is_superuser = True
      Global_Role(Owner) via group          -> all group members.is_superuser = True
      Global_Role(Writer|Maintainer|API_Importer) for user
                                            -> User.is_staff = True
      Global_Role(Writer|Maintainer|API_Importer) via group
                                            -> all group members.is_staff = True
      Global_Role(Reader)                   -> no global elevation
                                              (relies on per-product membership)
    """
    connection = schema_editor.connection
    if "dojo_role" not in connection.introspection.table_names():
        # Fresh install: no RBAC tables. Nothing to do.
        return

    try:
        Product = apps.get_model("dojo", "Product")
        Product_Type = apps.get_model("dojo", "Product_Type")
        Dojo_User = apps.get_model("dojo", "Dojo_User")
        Product_Member = apps.get_model("dojo", "Product_Member")
        Product_Type_Member = apps.get_model("dojo", "Product_Type_Member")
        Product_Group = apps.get_model("dojo", "Product_Group")
        Product_Type_Group = apps.get_model("dojo", "Product_Type_Group")
        Dojo_Group_Member = apps.get_model("dojo", "Dojo_Group_Member")
        Global_Role = apps.get_model("dojo", "Global_Role")
    except LookupError:
        # Models already released from the dojo app state. Nothing to do.
        return

    # 1. Direct per-product / per-product-type memberships.
    for product_id, user_id in Product_Member.objects.values_list("product_id", "user_id"):
        Product.authorized_users.through.objects.get_or_create(
            product_id=product_id,
            dojo_user_id=user_id,
        )
    for product_type_id, user_id in Product_Type_Member.objects.values_list("product_type_id", "user_id"):
        Product_Type.authorized_users.through.objects.get_or_create(
            product_type_id=product_type_id,
            dojo_user_id=user_id,
        )

    # 2. Group memberships: flatten Dojo_Group_Member.user into authorized_users.
    for product_id, group_id in Product_Group.objects.values_list("product_id", "group_id"):
        member_user_ids = Dojo_Group_Member.objects.filter(group_id=group_id).values_list("user_id", flat=True)
        for user_id in member_user_ids:
            Product.authorized_users.through.objects.get_or_create(
                product_id=product_id,
                dojo_user_id=user_id,
            )
    for product_type_id, group_id in Product_Type_Group.objects.values_list("product_type_id", "group_id"):
        member_user_ids = Dojo_Group_Member.objects.filter(group_id=group_id).values_list("user_id", flat=True)
        for user_id in member_user_ids:
            Product_Type.authorized_users.through.objects.get_or_create(
                product_type_id=product_type_id,
                dojo_user_id=user_id,
            )

    # 3. Global_Role -> is_superuser / is_staff flags.
    owner_user_ids = list(
        Global_Role.objects.filter(role__name="Owner", user__isnull=False).values_list("user_id", flat=True),
    )
    owner_group_ids = list(
        Global_Role.objects.filter(role__name="Owner", group__isnull=False).values_list("group_id", flat=True),
    )
    owner_user_ids.extend(
        Dojo_Group_Member.objects.filter(group_id__in=owner_group_ids).values_list("user_id", flat=True),
    )
    if owner_user_ids:
        Dojo_User.objects.filter(id__in=owner_user_ids).update(is_superuser=True)

    elevated_user_ids = list(
        Global_Role.objects.filter(
            role__name__in=("Writer", "Maintainer", "API_Importer"),
            user__isnull=False,
        ).values_list("user_id", flat=True),
    )
    elevated_group_ids = list(
        Global_Role.objects.filter(
            role__name__in=("Writer", "Maintainer", "API_Importer"),
            group__isnull=False,
        ).values_list("group_id", flat=True),
    )
    elevated_user_ids.extend(
        Dojo_Group_Member.objects.filter(group_id__in=elevated_group_ids).values_list("user_id", flat=True),
    )
    if elevated_user_ids:
        Dojo_User.objects.filter(id__in=elevated_user_ids).update(is_staff=True)


def reverse_noop(apps, schema_editor):  # noqa: ARG001
    # Reverse is a no-op. Backfilled authorized_users membership and
    # is_superuser / is_staff flags are preserved if this migration is
    # rolled back; reverse cannot reliably distinguish migrated entries
    # from manually-added ones, and the source RBAC tables are still
    # intact for a forward re-run anyway.
    return


class Migration(migrations.Migration):
    dependencies = [
        ("dojo", "0267_usercontactinfo_ui_use_tailwind"),
    ]

    operations = [
        # Re-introduce the legacy ``authorized_users`` M2M and backfill it
        # from the RBAC tables.
        migrations.AddField(
            model_name="product",
            name="authorized_users",
            field=models.ManyToManyField(blank=True, related_name="authorized_products", to="dojo.dojo_user"),
        ),
        migrations.AddField(
            model_name="product_type",
            name="authorized_users",
            field=models.ManyToManyField(blank=True, related_name="authorized_product_types", to="dojo.dojo_user"),
        ),
        migrations.RunPython(backfill_authorized_users, reverse_noop),
        migrations.SeparateDatabaseAndState(
            state_operations=[
                # Drop the redundant post-RBAC M2M accessors. The
                # through-tables (Product_Member / Product_Group, etc.) are
                # owned by Pro and are the canonical source of truth.
                migrations.RemoveField(model_name="product_type", name="members"),
                migrations.RemoveField(model_name="product_type", name="authorization_groups"),
                migrations.RemoveField(model_name="product", name="members"),
                migrations.RemoveField(model_name="product", name="authorization_groups"),
                # Flip dojo's eight authorization shells to managed=False.
                # The class definitions stay in dojo/authorization/models.py
                # so historical pro migration bases referencing them keep
                # resolving when Django reloads project state.
                migrations.AlterModelOptions(name="dojo_group", options={"managed": False}),
                migrations.AlterModelOptions(name="dojo_group_member", options={"managed": False}),
                migrations.AlterModelOptions(name="global_role", options={"managed": False}),
                migrations.AlterModelOptions(name="product_group", options={"managed": False}),
                migrations.AlterModelOptions(name="product_member", options={"managed": False}),
                migrations.AlterModelOptions(name="product_type_group", options={"managed": False}),
                migrations.AlterModelOptions(name="product_type_member", options={"managed": False}),
                migrations.AlterModelOptions(name="role", options={"managed": False, "ordering": ("name",)}),
                # Pin the db_table for each shell so subsequent state
                # operations don't auto-generate a new table name.
                migrations.AlterModelTable(name="dojo_group", table="dojo_dojo_group"),
                migrations.AlterModelTable(name="dojo_group_member", table="dojo_dojo_group_member"),
                migrations.AlterModelTable(name="global_role", table="dojo_global_role"),
                migrations.AlterModelTable(name="product_group", table="dojo_product_group"),
                migrations.AlterModelTable(name="product_member", table="dojo_product_member"),
                migrations.AlterModelTable(name="product_type_group", table="dojo_product_type_group"),
                migrations.AlterModelTable(name="product_type_member", table="dojo_product_type_member"),
                migrations.AlterModelTable(name="role", table="dojo_role"),
            ],
            database_operations=[],
        ),
        # Drop the relocated default-group columns from System_Settings now
        # that ``pro.0052`` has copied them onto ``EnhancedSystemSettings``.
        migrations.RemoveField(
            model_name="system_settings",
            name="default_group",
        ),
        migrations.RemoveField(
            model_name="system_settings",
            name="default_group_role",
        ),
        migrations.RemoveField(
            model_name="system_settings",
            name="default_group_email_pattern",
        ),
    ]
