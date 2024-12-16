import logging

import requests
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpRequest, HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils.translation import gettext as _
from django.views import View

from dojo.forms import DeleteNotificationsWebhookForm, NotificationsForm, NotificationsWebhookForm
from dojo.models import Notification_Webhooks, Notifications
from dojo.notifications.helper import test_webhooks_notification
from dojo.utils import add_breadcrumb, get_enabled_notifications_list, get_system_setting

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
            raise PermissionDenied

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
            "form": self.get_form(request, notifications),
            "scope": scope,
            "enabled_notifications": self.get_enabled_notifications(),
            "admin": request.user.is_superuser,
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
                _("Settings saved."),
                extra_tags="alert-success")
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
        request, _success = self.process_form(request, context)
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


class NotificationWebhooksView(View):

    def check_webhooks_enabled(self):
        if not get_system_setting("enable_webhooks_notifications"):
            raise Http404

    def check_user_permissions(self, request: HttpRequest):
        if not request.user.is_superuser:
            raise PermissionDenied
        # TODO: finished access for other users
        # if not user_has_configuration_permission(request.user, self.permission):
        #     raise PermissionDenied()

    def set_breadcrumbs(self, request: HttpRequest):
        add_breadcrumb(title=self.breadcrumb, top_level=False, request=request)
        return request

    def get_form(
        self,
        request: HttpRequest,
        **kwargs: dict,
    ) -> NotificationsWebhookForm:
        if request.method == "POST":
            return NotificationsWebhookForm(request.POST, is_superuser=request.user.is_superuser, **kwargs)
        return NotificationsWebhookForm(is_superuser=request.user.is_superuser, **kwargs)

    def preprocess_request(self, request: HttpRequest):
        # Check Webhook notifications are enabled
        self.check_webhooks_enabled()
        # Check permissions
        self.check_user_permissions(request)


class ListNotificationWebhooksView(NotificationWebhooksView):
    template = "dojo/view_notification_webhooks.html"
    permission = "dojo.view_notification_webhooks"
    breadcrumb = "Notification Webhook List"

    def get_initial_context(self, request: HttpRequest, nwhs: Notification_Webhooks):
        return {
            "name": "Notification Webhook List",
            "metric": False,
            "user": request.user,
            "nwhs": nwhs,
        }

    def get_notification_webhooks(self, request: HttpRequest):
        return Notification_Webhooks.objects.all().order_by("name")
        # TODO: finished pagination
        # TODO: restrict based on user - not only superadmins have access and they see everything

    def get(self, request: HttpRequest):
        # Run common checks
        super().preprocess_request(request)
        # Get Notification Webhooks
        nwhs = self.get_notification_webhooks(request)
        # Set up the initial context
        context = self.get_initial_context(request, nwhs)
        # Add any breadcrumbs
        request = self.set_breadcrumbs(request)
        # Render the page
        return render(request, self.template, context)


class AddNotificationWebhooksView(NotificationWebhooksView):
    template = "dojo/add_notification_webhook.html"
    permission = "dojo.add_notification_webhooks"
    breadcrumb = "Add Notification Webhook"

    # TODO: Disable Owner if not superadmin

    def get_initial_context(self, request: HttpRequest):
        return {
            "name": "Add Notification Webhook",
            "user": request.user,
            "form": self.get_form(request),
        }

    def process_form(self, request: HttpRequest, context: dict):
        form = context["form"]
        if form.is_valid():
            try:
                test_webhooks_notification(form.instance)
            except requests.exceptions.RequestException as e:
                messages.add_message(
                    request,
                    messages.ERROR,
                    _("Test of endpoint was not successful: %(error)s") % {"error": str(e)},
                    extra_tags="alert-danger",
                )
                return request, False
            else:
                # User can put here what ever he want
                # we override it with our only valid defaults
                nwh = form.save(commit=False)
                nwh.status = Notification_Webhooks.Status.STATUS_ACTIVE
                nwh.first_error = None
                nwh.last_error = None
                nwh.note = None
                nwh.save()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    _("Notification Webhook added successfully."),
                    extra_tags="alert-success",
                )
                return request, True
        return request, False

    def get(self, request: HttpRequest):
        # Run common checks
        super().preprocess_request(request)
        # Set up the initial context
        context = self.get_initial_context(request)
        # Add any breadcrumbs
        request = self.set_breadcrumbs(request)
        # Render the page
        return render(request, self.template, context)

    def post(self, request: HttpRequest):
        # Run common checks
        super().preprocess_request(request)
        # Set up the initial context
        context = self.get_initial_context(request)
        # Determine the validity of the form
        request, success = self.process_form(request, context)
        if success:
            return HttpResponseRedirect(reverse("notification_webhooks"))
        # Add any breadcrumbs
        request = self.set_breadcrumbs(request)
        # Render the page
        return render(request, self.template, context)


class EditNotificationWebhooksView(NotificationWebhooksView):
    template = "dojo/edit_notification_webhook.html"
    permission = "dojo.change_notification_webhooks"
    # TODO: this could be better: @user_is_authorized(Finding, Permissions.Finding_Delete, 'fid')
    breadcrumb = "Edit Notification Webhook"

    def get_notification_webhook(self, nwhid: int):
        return get_object_or_404(Notification_Webhooks, id=nwhid)

    # TODO: Disable Owner if not superadmin

    def get_initial_context(self, request: HttpRequest, nwh: Notification_Webhooks):
        return {
            "name": "Edit Notification Webhook",
            "user": request.user,
            "form": self.get_form(request, instance=nwh),
            "nwh": nwh,
        }

    def process_form(self, request: HttpRequest, nwh: Notification_Webhooks, context: dict):
        form = context["form"]
        if "deactivate_webhook" in request.POST:  # TODO: add this to API as well
            nwh.status = Notification_Webhooks.Status.STATUS_INACTIVE_PERMANENT
            nwh.first_error = None
            nwh.last_error = None
            nwh.note = "Deactivate from UI"
            nwh.save()
            messages.add_message(
                                    request,
                                    messages.SUCCESS,
                                    _("Notification Webhook deactivated successfully."),
                                    extra_tags="alert-success",
                                )
            return request, True

        if form.is_valid():
            try:
                test_webhooks_notification(form.instance)
            except requests.exceptions.RequestException as e:
                messages.add_message(
                    request,
                    messages.ERROR,
                    _("Test of endpoint was not successful: %(error)s") % {"error": str(e)},
                    extra_tags="alert-danger")
                return request, False
            else:
                # correct definition reset defaults
                nwh = form.save(commit=False)
                nwh.status = Notification_Webhooks.Status.STATUS_ACTIVE
                nwh.first_error = None
                nwh.last_error = None
                nwh.note = None
                nwh.save()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    _("Notification Webhook updated successfully."),
                    extra_tags="alert-success",
                )
                return request, True
        return request, False

    def get(self, request: HttpRequest, nwhid: int):
        # Run common checks
        super().preprocess_request(request)
        nwh = self.get_notification_webhook(nwhid)
        # Set up the initial context
        context = self.get_initial_context(request, nwh)
        # Add any breadcrumbs
        request = self.set_breadcrumbs(request)
        # Render the page
        return render(request, self.template, context)

    def post(self, request: HttpRequest, nwhid: int):
        # Run common checks
        super().preprocess_request(request)
        nwh = self.get_notification_webhook(nwhid)
        # Set up the initial context
        context = self.get_initial_context(request, nwh)
        # Determine the validity of the form
        request, success = self.process_form(request, nwh, context)
        if success:
            return HttpResponseRedirect(reverse("notification_webhooks"))
        # Add any breadcrumbs
        request = self.set_breadcrumbs(request)
        # Render the page
        return render(request, self.template, context)


class DeleteNotificationWebhooksView(NotificationWebhooksView):
    template = "dojo/delete_notification_webhook.html"
    permission = "dojo.delete_notification_webhooks"
    # TODO: this could be better: @user_is_authorized(Finding, Permissions.Finding_Delete, 'fid')
    breadcrumb = "Edit Notification Webhook"

    def get_notification_webhook(self, nwhid: int):
        return get_object_or_404(Notification_Webhooks, id=nwhid)

    # TODO: Disable Owner if not superadmin

    def get_form(
        self,
        request: HttpRequest,
        **kwargs: dict,
    ) -> NotificationsWebhookForm:
        if request.method == "POST":
            return DeleteNotificationsWebhookForm(request.POST, **kwargs)
        return DeleteNotificationsWebhookForm(**kwargs)

    def get_initial_context(self, request: HttpRequest, nwh: Notification_Webhooks):
        return {
            "form": self.get_form(request, instance=nwh),
            "nwh": nwh,
        }

    def process_form(self, request: HttpRequest, nwh: Notification_Webhooks, context: dict):
        form = context["form"]
        if form.is_valid():
            nwh.delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                _("Notification Webhook deleted successfully."),
                extra_tags="alert-success",
            )
            return request, True
        return request, False

    def get(self, request: HttpRequest, nwhid: int):
        # Run common checks
        super().preprocess_request(request)
        nwh = self.get_notification_webhook(nwhid)
        # Set up the initial context
        context = self.get_initial_context(request, nwh)
        # Add any breadcrumbs
        request = self.set_breadcrumbs(request)
        # Render the page
        return render(request, self.template, context)

    def post(self, request: HttpRequest, nwhid: int):
        # Run common checks
        super().preprocess_request(request)
        nwh = self.get_notification_webhook(nwhid)
        # Set up the initial context
        context = self.get_initial_context(request, nwh)
        # Determine the validity of the form
        request, success = self.process_form(request, nwh, context)
        if success:
            return HttpResponseRedirect(reverse("notification_webhooks"))
        # Add any breadcrumbs
        request = self.set_breadcrumbs(request)
        # Render the page
        return render(request, self.template, context)
