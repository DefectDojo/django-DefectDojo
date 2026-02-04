from django.contrib import admin

from dojo.url.models import URL


@admin.register(URL)
class URLAdmin(admin.ModelAdmin):

    """Admin support for the URL model."""
