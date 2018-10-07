from auditlog.models import LogEntry
from django.contrib import admin

admin.site.unregister(LogEntry)
