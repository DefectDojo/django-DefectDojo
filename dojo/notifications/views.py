import logging

from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import render
from django.http import HttpRequest
from django.utils.translation import gettext as _
from django.views import View
from django.core.exceptions import PermissionDenied

from dojo.models import Notifications
from dojo.utils import get_enabled_notifications_list
from dojo.utils import add_breadcrumb
from dojo.forms import NotificationsForm

logger = logging.getLogger(__name__)


class SystemNotificationsView(View):
    def get_notifications(self, request: HttpRequest):
        try:
            notifications = Notifications.objects.get(user=None, product__isnull=True, template=False)
        except Notifications.DoesNotExist:
            notifications = Notifications(user=None, template=False)

        return notifications

    def check_user_permissions(self, request: HttpRequest):
        if not request.user.is_superuser:
            raise PermissionDenied()

    def get_form(self, request: HttpRequest, notifications: Notifications):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "instance": notifications,
        }

        return NotificationsForm(*args, **kwargs)

    def get_enabled_notifications(self):
        return get_enabled_notifications_list()

    def get_initial_context(self, request: HttpRequest, notifications: Notifications, scope: str):
        return {
            'form': self.get_form(request, notifications),
            'scope': scope,
            'enabled_notifications': self.get_enabled_notifications(),
            'admin': request.user.is_superuser
        }

    def set_breadcrumbs(self, request: HttpRequest):
        add_breadcrumb(title=_("System notification settings"), top_level=False, request=request)
        return request

    def process_form(self, request: HttpRequest, context: dict):
        if context["form"].is_valid():
            context["form"].save()
            messages.add_message(
                request,
                messages.SUCCESS,
                _('Settings saved.'),
                extra_tags='alert-success') 
            return request, True
        return request, False

    def get_template(self):
        return "dojo/notifications.html"

    def get_scope(self):
        return "system"

    def get(self, request: HttpRequest):
        # Check permissions
        self.check_user_permissions(request)
        # Get the notifications object
        notifications = self.get_notifications(request)
        # Set up the initial context
        context = self.get_initial_context(request, notifications, self.get_scope())
        # Add any breadcrumbs
        request = self.set_breadcrumbs(request)
        # Render the page
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest):
        # Check permissions
        self.check_user_permissions(request)
        # Get the notifications object
        notifications = self.get_notifications(request)
        # Set up the initial context
        context = self.get_initial_context(request, notifications, self.get_scope())
        # Determine the validity of the form
        request, success = self.process_form(request, context)
        # Add any breadcrumbs
        request = self.set_breadcrumbs(request)
        # Render the page
        return render(request, self.get_template(), context)


class PersonalNotificationsView(SystemNotificationsView):
    def get_notifications(self, request: HttpRequest):
        try:
            notifications = Notifications.objects.get(user=request.user, product__isnull=True)
        except Notifications.DoesNotExist:
            notifications = Notifications(user=request.user)
        return notifications

    def check_user_permissions(self, request: HttpRequest):
        pass

    def get_scope(self):
        return "personal"

    def set_breadcrumbs(self, request: HttpRequest):
        add_breadcrumb(title=_("Personal notification settings"), top_level=False, request=request)
        return request


class TemplateNotificationsView(SystemNotificationsView):
    def get_notifications(self, request: HttpRequest):
        try:
            notifications = Notifications.objects.get(template=True)
        except Notifications.DoesNotExist:
            notifications = Notifications(user=None, template=True)
        return notifications

    def get_scope(self):
        return "template"

    def set_breadcrumbs(self, request: HttpRequest):
        add_breadcrumb(title=_("Template notification settings"), top_level=False, request=request)
        return request
