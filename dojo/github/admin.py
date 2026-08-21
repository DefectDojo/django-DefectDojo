from django.contrib import admin

from dojo.github.models import (
    GITHUB_Clone,
    GITHUB_Conf,
    GITHUB_Details_Cache,
    GITHUB_Issue,
    GITHUB_PKey,
)

admin.site.register(GITHUB_Conf)
admin.site.register(GITHUB_Issue)
admin.site.register(GITHUB_Clone)
admin.site.register(GITHUB_Details_Cache)
admin.site.register(GITHUB_PKey)
