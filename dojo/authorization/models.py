"""
Legacy backward-compat shells for the seven RBAC model classes.

The canonical owner of these tables is now ``pro.authorization.models``.
After the paired ``SeparateDatabaseAndState`` migrations land
(``dojo.0268_release_rbac_state`` + ``pro.000X_adopt_rbac_tables``),
Pro's state owns the seven RBAC tables and OS's app state no longer
references them.

The class definitions remain here as ``managed=False`` shells purely so
the existing OS code that imports / isinstance-checks ``dojo.authorization
.models.X`` keeps compiling. Track B step #13 simplifies the callers and
deletes these shells entirely; until that lands, the shells let OS-only
deployments stay functional with the legacy authorization model.
"""

from django.contrib.auth.models import Group
from django.db import models
from django.utils.translation import gettext_lazy as _


class Dojo_Group(models.Model):

    """
    ``managed=False`` shell for the canonical ``Dojo_Group`` model, owned by
    ``pro.groups.models``. Mirrors the seven RBAC shells below: the state
    entry stays so historical pro migrations whose state references
    ``dojo.dojo_group`` (e.g. ``pro.0001`` ``EnhancedDojoGroup.group`` and
    ``pro.0034`` proxy ``bases=("dojo.dojo_group",)``) keep resolving when
    Django reloads project state. Pro's ``CreateModel(Dojo_Group)`` in
    ``pro.0053_adopt_dojo_group`` is the ``managed=True`` canonical owner;
    both states share ``db_table="dojo_dojo_group"`` so no DDL conflicts.
    Reverse accessors are suppressed with ``related_name="+"`` so they
    don't clash with ``pro.Dojo_Group``'s own accessors.
    """

    AZURE = "AzureAD"
    REMOTE = "Remote"
    SOCIAL_CHOICES = (
        (AZURE, _("AzureAD")),
        (REMOTE, _("Remote")),
    )
    name = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=4000, null=True, blank=True)
    users = models.ManyToManyField(
        "dojo.Dojo_User",
        through="dojo.Dojo_Group_Member",
        related_name="+",
        blank=True,
    )
    auth_group = models.ForeignKey(Group, null=True, blank=True, on_delete=models.CASCADE, related_name="+")
    social_provider = models.CharField(
        max_length=10,
        choices=SOCIAL_CHOICES,
        blank=True,
        null=True,
        help_text=_("Group imported from a social provider."),
        verbose_name=_("Social Authentication Provider"),
    )

    class Meta:
        app_label = "dojo"
        db_table = "dojo_dojo_group"
        managed = False

    def __str__(self):
        return self.name


class Role(models.Model):
    name = models.CharField(max_length=255, unique=True)
    is_owner = models.BooleanField(default=False)

    class Meta:
        app_label = "dojo"
        db_table = "dojo_role"
        managed = False
        ordering = ("name",)

    def __str__(self):
        return self.name


class Dojo_Group_Member(models.Model):
    group = models.ForeignKey("dojo.Dojo_Group", on_delete=models.CASCADE, related_name="+")
    user = models.ForeignKey("dojo.Dojo_User", on_delete=models.CASCADE, related_name="+")
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        related_name="+",
        help_text=_("This role determines the permissions of the user to manage the group."),
        verbose_name=_("Group role"),
    )

    class Meta:
        app_label = "dojo"
        db_table = "dojo_dojo_group_member"
        managed = False


class Global_Role(models.Model):
    user = models.OneToOneField("dojo.Dojo_User", null=True, blank=True, on_delete=models.CASCADE, related_name="+")
    group = models.OneToOneField("dojo.Dojo_Group", null=True, blank=True, on_delete=models.CASCADE, related_name="+")
    role = models.ForeignKey(
        Role,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="+",
        help_text=_("The global role will be applied to all product types and products."),
        verbose_name=_("Global role"),
    )

    class Meta:
        app_label = "dojo"
        db_table = "dojo_global_role"
        managed = False


class Product_Member(models.Model):
    product = models.ForeignKey("dojo.Product", on_delete=models.CASCADE, related_name="+")
    user = models.ForeignKey("dojo.Dojo_User", on_delete=models.CASCADE, related_name="+")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="+")

    class Meta:
        app_label = "dojo"
        db_table = "dojo_product_member"
        managed = False


class Product_Group(models.Model):
    product = models.ForeignKey("dojo.Product", on_delete=models.CASCADE, related_name="+")
    group = models.ForeignKey("dojo.Dojo_Group", on_delete=models.CASCADE, related_name="+")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="+")

    class Meta:
        app_label = "dojo"
        db_table = "dojo_product_group"
        managed = False


class Product_Type_Member(models.Model):
    product_type = models.ForeignKey("dojo.Product_Type", on_delete=models.CASCADE, related_name="+")
    user = models.ForeignKey("dojo.Dojo_User", on_delete=models.CASCADE, related_name="+")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="+")

    class Meta:
        app_label = "dojo"
        db_table = "dojo_product_type_member"
        managed = False


class Product_Type_Group(models.Model):
    product_type = models.ForeignKey("dojo.Product_Type", on_delete=models.CASCADE, related_name="+")
    group = models.ForeignKey("dojo.Dojo_Group", on_delete=models.CASCADE, related_name="+")
    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name="+")

    class Meta:
        app_label = "dojo"
        db_table = "dojo_product_type_group"
        managed = False
