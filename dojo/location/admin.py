from django.contrib import admin

from dojo.location.models import Location, LocationFindingReference, LocationProductReference


@admin.register(Location)
class LocationAdmin(admin.ModelAdmin):

    """Admin support for the Location model."""


@admin.register(LocationFindingReference)
class LocationFindingReferenceAdmin(admin.ModelAdmin):

    """Admin support for the LocationFindingReference model."""


@admin.register(LocationProductReference)
class LocationProductReferenceAdmin(admin.ModelAdmin):

    """Admin support for the LocationProductReference model."""
