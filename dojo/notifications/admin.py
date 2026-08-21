from django.contrib import admin

from dojo.notifications.models import Alerts, Notification_Webhooks, Notifications


@admin.register(Notifications)
class NotificationsAdmin(admin.ModelAdmin):
    list_filter = ("user", "product")

    def get_list_display(self, request):
        list_fields = ["user", "product"]
        list_fields += [f.name for f in self.model._meta.fields if f.name not in list_fields]
        return list_fields


@admin.register(Notification_Webhooks)
class NotificationWebhooksAdmin(admin.ModelAdmin):
    pass


@admin.register(Alerts)
class AlertsAdmin(admin.ModelAdmin):
    pass
