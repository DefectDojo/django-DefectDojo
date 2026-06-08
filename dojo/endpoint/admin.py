import tagulous.admin
from django.contrib import admin

from dojo.endpoint.models import Endpoint, Endpoint_Params, Endpoint_Status

admin.site.register(Endpoint_Params)
admin.site.register(Endpoint_Status)
admin.site.register(Endpoint)
tagulous.admin.register(Endpoint.tags)
tagulous.admin.register(Endpoint.inherited_tags)
