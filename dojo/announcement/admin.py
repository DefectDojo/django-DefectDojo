from django.contrib import admin

from dojo.announcement.models import Announcement, UserAnnouncement

admin.site.register(Announcement)
admin.site.register(UserAnnouncement)
