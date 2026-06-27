from decimal import Decimal

from django.core.validators import MinValueValidator
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.translation import gettext as _
from tagulous.models import TagField

from dojo.base_models.base import BaseModel


class Product_Line(models.Model):
    name = models.CharField(max_length=300)
    description = models.CharField(max_length=2000)

    def __str__(self):
        return self.name


class Product(BaseModel):
    WEB_PLATFORM = "web"
    IOT = "iot"
    DESKTOP_PLATFORM = "desktop"
    MOBILE_PLATFORM = "mobile"
    WEB_SERVICE_PLATFORM = "web service"
    PLATFORM_CHOICES = (
        (WEB_SERVICE_PLATFORM, _("API")),
        (DESKTOP_PLATFORM, _("Desktop")),
        (IOT, _("Internet of Things")),
        (MOBILE_PLATFORM, _("Mobile")),
        (WEB_PLATFORM, _("Web")),
    )

    CONSTRUCTION = "construction"
    PRODUCTION = "production"
    RETIREMENT = "retirement"
    LIFECYCLE_CHOICES = (
        (CONSTRUCTION, _("Construction")),
        (PRODUCTION, _("Production")),
        (RETIREMENT, _("Retirement")),
    )

    THIRD_PARTY_LIBRARY_ORIGIN = "third party library"
    PURCHASED_ORIGIN = "purchased"
    CONTRACTOR_ORIGIN = "contractor"
    INTERNALLY_DEVELOPED_ORIGIN = "internal"
    OPEN_SOURCE_ORIGIN = "open source"
    OUTSOURCED_ORIGIN = "outsourced"
    ORIGIN_CHOICES = (
        (THIRD_PARTY_LIBRARY_ORIGIN, _("Third Party Library")),
        (PURCHASED_ORIGIN, _("Purchased")),
        (CONTRACTOR_ORIGIN, _("Contractor Developed")),
        (INTERNALLY_DEVELOPED_ORIGIN, _("Internally Developed")),
        (OPEN_SOURCE_ORIGIN, _("Open Source")),
        (OUTSOURCED_ORIGIN, _("Outsourced")),
    )

    VERY_HIGH_CRITICALITY = "very high"
    HIGH_CRITICALITY = "high"
    MEDIUM_CRITICALITY = "medium"
    LOW_CRITICALITY = "low"
    VERY_LOW_CRITICALITY = "very low"
    NONE_CRITICALITY = "none"
    BUSINESS_CRITICALITY_CHOICES = (
        (VERY_HIGH_CRITICALITY, _("Very High")),
        (HIGH_CRITICALITY, _("High")),
        (MEDIUM_CRITICALITY, _("Medium")),
        (LOW_CRITICALITY, _("Low")),
        (VERY_LOW_CRITICALITY, _("Very Low")),
        (NONE_CRITICALITY, _("None")),
    )

    name = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=4000)

    product_manager = models.ForeignKey("dojo.Dojo_User", null=True, blank=True,
                                        related_name="product_manager", on_delete=models.RESTRICT)
    technical_contact = models.ForeignKey("dojo.Dojo_User", null=True, blank=True,
                                          related_name="technical_contact", on_delete=models.RESTRICT)
    team_manager = models.ForeignKey("dojo.Dojo_User", null=True, blank=True,
                                     related_name="team_manager", on_delete=models.RESTRICT)

    prod_type = models.ForeignKey("dojo.Product_Type", related_name="prod_type",
                                  null=False, blank=False, on_delete=models.CASCADE)
    sla_configuration = models.ForeignKey("dojo.SLA_Configuration",
                                          related_name="sla_config",
                                          null=False,
                                          blank=False,
                                          default=1,
                                          on_delete=models.RESTRICT)
    tid = models.IntegerField(default=0, editable=False)
    authorized_users = models.ManyToManyField("dojo.Dojo_User", related_name="authorized_products", blank=True)
    prod_numeric_grade = models.IntegerField(null=True, blank=True)

    # Metadata
    business_criticality = models.CharField(max_length=9, choices=BUSINESS_CRITICALITY_CHOICES, blank=True, null=True)
    platform = models.CharField(max_length=11, choices=PLATFORM_CHOICES, blank=True, null=True)
    lifecycle = models.CharField(max_length=12, choices=LIFECYCLE_CHOICES, blank=True, null=True)
    origin = models.CharField(max_length=19, choices=ORIGIN_CHOICES, blank=True, null=True)
    user_records = models.PositiveIntegerField(blank=True, null=True, help_text=_("Estimate the number of user records within the application."))
    revenue = models.DecimalField(max_digits=15, decimal_places=2, blank=True, null=True, validators=[MinValueValidator(Decimal("0.00"))], help_text=_("Estimate the application's revenue."))
    external_audience = models.BooleanField(default=False, help_text=_("Specify if the application is used by people outside the organization."))
    internet_accessible = models.BooleanField(default=False, help_text=_("Specify if the application is accessible from the public internet."))
    regulations = models.ManyToManyField("dojo.Regulation", blank=True)

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this product. Choose from the list or add new tags. Press Enter key to add."))
    enable_product_tag_inheritance = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Enable Product Tag Inheritance"),
        help_text=_("Enables product tag inheritance. Any tags added on a product will automatically be added to all Engagements, Tests, and Findings"))
    enable_simple_risk_acceptance = models.BooleanField(default=False, help_text=_("Allows simple risk acceptance by checking/unchecking a checkbox."))
    enable_full_risk_acceptance = models.BooleanField(default=True, help_text=_("Allows full risk acceptance using a risk acceptance form, expiration date, uploaded proof, etc."))

    disable_sla_breach_notifications = models.BooleanField(
        default=False,
        blank=False,
        verbose_name=_("Disable SLA breach notifications"),
        help_text=_("Disable SLA breach notifications if configured in the global settings"))
    async_updating = models.BooleanField(default=False,
                                            help_text=_("Findings under this Product or SLA configuration are asynchronously being updated"))

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        # get the product's sla config before saving (if this is an existing product)
        initial_sla_config = None
        if self.pk is not None:
            initial_sla_config = getattr(Product.objects.get(pk=self.pk), "sla_configuration", None)
            # if initial sla config exists and async finding update is already running, revert sla config before saving
            if initial_sla_config and self.async_updating:
                self.sla_configuration = initial_sla_config

        super().save(*args, **kwargs)

        # if the initial sla config exists and async finding update is not running
        if initial_sla_config is not None and not self.async_updating:
            # get the new sla config from the saved product
            new_sla_config = getattr(self, "sla_configuration", None)
            # if the sla config has changed, update finding sla expiration dates within this product
            if new_sla_config and (initial_sla_config != new_sla_config):
                # set the async updating flag to true for this product
                self.async_updating = True
                super().save(*args, **kwargs)
                # set the async updating flag to true for the sla config assigned to this product
                sla_config = getattr(self, "sla_configuration", None)
                if sla_config:
                    from dojo.models import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
                        SLA_Configuration,
                    )
                    sla_config.async_updating = True
                    super(SLA_Configuration, sla_config).save()
                # launch the async task to update all finding sla expiration dates
                from dojo.sla_config.helpers import async_update_sla_expiration_dates_sla_config_sync  # noqa: I001, PLC0415 circular import
                from dojo.celery_dispatch import dojo_dispatch_task  # noqa: PLC0415 circular import

                dojo_dispatch_task(
                    async_update_sla_expiration_dates_sla_config_sync,
                    sla_config.id,
                    [self.id],
                )
                # The async task refetches and resets async_updating on its own copies.
                # Mirror that on this in-memory product and the in-memory sla_config so a
                # subsequent save() on either does not trigger their lock-revert paths.
                self.async_updating = False
                if sla_config:
                    sla_config.async_updating = False

    def get_absolute_url(self):
        return reverse("view_product", args=[str(self.id)])

    @cached_property
    def findings_count(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        try:
            # if prefetched, it's already there
            return self.active_finding_count
        except AttributeError:
            # ideally it's always prefetched and we can remove this code in the future
            self.active_finding_count = Finding.objects.filter(active=True,
                                            test__engagement__product=self).count()
            return self.active_finding_count

    @cached_property
    def findings_active_verified_count(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        try:
            # if prefetched, it's already there
            return self.active_verified_finding_count
        except AttributeError:
            # ideally it's always prefetched and we can remove this code in the future
            self.active_verified_finding_count = Finding.objects.filter(active=True,
                                            verified=True,
                                            test__engagement__product=self).count()
            return self.active_verified_finding_count

    # TODO: Delete this after the move to Locations
    @cached_property
    def endpoint_host_count(self):
        # active_endpoints is (should be) prefetched
        endpoints = getattr(self, "active_endpoints", None)

        hosts = []
        for e in endpoints:
            if e.host in hosts:
                continue
            hosts.append(e.host)

        return len(hosts)

    # TODO: Delete this after the move to Locations
    @cached_property
    def endpoint_count(self):
        # active_endpoints is (should be) prefetched
        endpoints = getattr(self, "active_endpoints", None)
        if endpoints:
            return len(self.active_endpoints)
        return 0

    def open_findings(self, start_date=None, end_date=None):
        if start_date is None or end_date is None:
            return {}

        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        from dojo.utils import get_system_setting  # noqa: PLC0415 circular import
        findings = Finding.objects.filter(test__engagement__product=self,
                                        mitigated__isnull=True,
                                        false_p=False,
                                        duplicate=False,
                                        out_of_scope=False,
                                        date__range=[start_date,
                                                    end_date])

        if get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_metrics", True):
            findings = findings.filter(verified=True)

        critical = findings.filter(severity="Critical").count()
        high = findings.filter(severity="High").count()
        medium = findings.filter(severity="Medium").count()
        low = findings.filter(severity="Low").count()

        return {"Critical": critical,
                "High": high,
                "Medium": medium,
                "Low": low,
                "Total": (critical + high + medium + low)}

    def get_breadcrumbs(self):
        return [{"title": str(self),
               "url": reverse("view_product", args=(self.id,))}]

    @property
    def get_product_type(self):
        return self.prod_type if self.prod_type is not None else "unknown"

    # only used in APIv2 serializers.py, should be deprecated or at least prefetched
    def open_findings_list(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        findings = Finding.objects.filter(test__engagement__product=self, active=True).values_list("id", flat=True)
        return list(findings)

    @property
    def has_jira_configured(self):
        from dojo.jira import services as jira_services  # noqa: PLC0415 circular import
        return jira_services.has_configured(self)

    def violates_sla(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        findings = Finding.objects.filter(test__engagement__product=self,
                                          active=True,
                                          sla_expiration_date__lt=timezone.now().date())
        return findings.count() > 0


class Product_API_Scan_Configuration(models.Model):
    product = models.ForeignKey("dojo.Product", null=False, blank=False, on_delete=models.CASCADE)
    tool_configuration = models.ForeignKey("dojo.Tool_Configuration", null=False, blank=False, on_delete=models.CASCADE)
    service_key_1 = models.CharField(max_length=200, null=True, blank=True)
    service_key_2 = models.CharField(max_length=200, null=True, blank=True)
    service_key_3 = models.CharField(max_length=200, null=True, blank=True)

    def __str__(self):
        name = self.tool_configuration.name
        if self.service_key_1 or self.service_key_2 or self.service_key_3:
            name += f" ({self.details})"
        return name

    @property
    def details(self):
        details = ""
        if self.service_key_1:
            details += f"{self.service_key_1}"
        if self.service_key_2:
            details += f" | {self.service_key_2}"
        if self.service_key_3:
            details += f" | {self.service_key_3}"
        return details
