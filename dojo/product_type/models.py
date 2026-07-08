from django.db import models
from django.urls import reverse
from django.utils.functional import cached_property

from dojo.base_models.base import BaseModel


class Product_Type(BaseModel):

    """
    Product types represent the top level model, these can be business unit divisions, different offices or locations, development teams, or any other logical way of distinguishing "types" of products.
    `
       Examples:
         * IAM Team
         * Internal / 3rd Party
         * Main company / Acquisition
         * San Francisco / New York offices
    """

    name = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=4000, null=True, blank=True)
    critical_product = models.BooleanField(default=False)
    key_product = models.BooleanField(default=False)
    authorized_users = models.ManyToManyField("dojo.Dojo_User", related_name="authorized_product_types", blank=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("product_type", args=[str(self.id)])

    def get_breadcrumbs(self):
        return [{"title": str(self),
               "url": reverse("edit_product_type", args=(self.id,))}]

    @cached_property
    def critical_present(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        c_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity="Critical")
        if c_findings.count() > 0:
            return True
        return None

    @cached_property
    def high_present(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        c_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity="High")
        if c_findings.count() > 0:
            return True
        return None

    @cached_property
    def calc_health(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        h_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity="High")
        c_findings = Finding.objects.filter(
            test__engagement__product__prod_type=self, severity="Critical")
        health = 100
        if c_findings.count() > 0:
            health = 40
            health -= ((c_findings.count() - 1) * 5)
        if h_findings.count() > 0:
            if health == 100:
                health = 60
            health -= ((h_findings.count() - 1) * 2)
        if health < 5:
            return 5
        return health

    # only used by bulk risk acceptance api
    @property
    def unaccepted_open_findings(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        return Finding.objects.filter(risk_accepted=False, active=True, duplicate=False, test__engagement__product__prod_type=self)
