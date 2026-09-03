from django.contrib import admin

from dojo.endpoint.models import Endpoint, Endpoint_Params, Endpoint_Status

admin.site.register(Endpoint_Params)
admin.site.register(Endpoint_Status)
admin.site.register(Endpoint)
admin.site.register(Endpoint.tags.tag_model)
admin.site.register(Endpoint.inherited_tags.tag_model)
