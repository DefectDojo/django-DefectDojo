from django.urls import path
from dojo.api_v2.notifications.views import NotificationEmailApiView     


urlpatterns = [
    path("api/v2/notifications_email", NotificationEmailApiView.as_view(), name='notifications_email'),
]
