from django.contrib import admin

from dojo.location.types.url.models import URL


@admin.register(URL)
class URLAdmin(admin.ModelAdmin):

    """Admin support for the URL model."""
