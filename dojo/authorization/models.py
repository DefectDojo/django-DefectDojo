from django.db import models
from django.utils.translation import gettext_lazy as _


class Role(models.Model):
    name = models.CharField(max_length=255, unique=True)
    is_owner = models.BooleanField(default=False)

    class Meta:
        app_label = "dojo"
        ordering = ("name",)

    def __str__(self):
        return self.name


class Dojo_Group_Member(models.Model):
    group = models.ForeignKey("dojo.Dojo_Group", on_delete=models.CASCADE)
    user = models.ForeignKey("dojo.Dojo_User", on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, help_text=_("This role determines the permissions of the user to manage the group."), verbose_name=_("Group role"))

    class Meta:
        app_label = "dojo"


class Global_Role(models.Model):
    user = models.OneToOneField("dojo.Dojo_User", null=True, blank=True, on_delete=models.CASCADE)
    group = models.OneToOneField("dojo.Dojo_Group", null=True, blank=True, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, null=True, blank=True, help_text=_("The global role will be applied to all product types and products."), verbose_name=_("Global role"))

    class Meta:
        app_label = "dojo"


class Product_Member(models.Model):
    product = models.ForeignKey("dojo.Product", on_delete=models.CASCADE)
    user = models.ForeignKey("dojo.Dojo_User", on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Meta:
        app_label = "dojo"


class Product_Group(models.Model):
    product = models.ForeignKey("dojo.Product", on_delete=models.CASCADE)
    group = models.ForeignKey("dojo.Dojo_Group", on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Meta:
        app_label = "dojo"


class Product_Type_Member(models.Model):
    product_type = models.ForeignKey("dojo.Product_Type", on_delete=models.CASCADE)
    user = models.ForeignKey("dojo.Dojo_User", on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Meta:
        app_label = "dojo"


class Product_Type_Group(models.Model):
    product_type = models.ForeignKey("dojo.Product_Type", on_delete=models.CASCADE)
    group = models.ForeignKey("dojo.Dojo_Group", on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)

    class Meta:
        app_label = "dojo"
