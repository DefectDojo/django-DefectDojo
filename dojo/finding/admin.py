from django.contrib import admin

from dojo.finding.models import (
    CWE,
    BurpRawRequestResponse,
    Finding,
    Finding_Group,
    Finding_Template,
)


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    # TODO: Delete this after the move to Locations
    # For efficiency with large databases, display many-to-many fields with raw
    # IDs rather than multi-select
    raw_id_fields = (
        "endpoints",
    )


@admin.register(Finding_Template)
class FindingTemplateAdmin(admin.ModelAdmin):

    """Admin support for the Finding_Template model."""


@admin.register(Finding_Group)
class FindingGroupAdmin(admin.ModelAdmin):

    """Admin support for the Finding_Group model."""


admin.site.register(CWE)
admin.site.register(BurpRawRequestResponse)
