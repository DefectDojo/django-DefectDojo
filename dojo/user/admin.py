from django.contrib import admin

from dojo.user.models import Contact, UserContactInfo

admin.site.register(UserContactInfo)
admin.site.register(Contact)
