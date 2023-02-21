import logging
import requests

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.shortcuts import render, get_object_or_404
from django.utils.translation import gettext as _
from django.views import View

from dojo.forms import NotificationsForm

from django.urls import reverse
from django.http import HttpResponseRedirect, Http404

from dojo.models import Notifications, Notification_Webhooks
from dojo.utils import get_enabled_notifications_list, add_breadcrumb, get_system_setting
from dojo.forms import NotificationsForm, NotificationsWebhookForm, DeleteNotificationsWebhookForm
from dojo.authorization.authorization_decorators import user_is_configuration_authorized
from dojo.notifications.helper import test_webhooks_notification
from dojo.models import Notifications
from dojo.utils import add_breadcrumb, get_enabled_notifications_list

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


@user_is_configuration_authorized('dojo.view_notification_webhooks')
def notification_webhooks(request):
    nwhs = Webhook_Endpoints.objects.all().order_by('name')
    # name_words = initial_queryset.values_list('name', flat=True)
    # ntl = NoteTypesFilter(request.GET, queryset=initial_queryset)
    # nwhs = get_page_items(request, initial_queryset.qs, 25)
    # TODO finished pagination
    # TODO restrict base on user
    add_breadcrumb(title="Notification Webhook List", top_level=True, request=request)
    return render(request, 'dojo/view_notification_webhooks.html', {
        'name': 'Notification Webhook List',
        'metric': False,
        'user': request.user,
        'nwhs': nwhs,
        # 'ntl': ntl,
        })


@user_is_configuration_authorized('dojo.add_notification_webhook')
def add_notification_webhook(request):
    form = NotificationsWebhookForm()
    if request.method == 'POST':
        form = NotificationsWebhookForm(request.POST)
        # TODO Allow edit owner on if superadmin
        # TODO do not allow to change status, first_error, last_error
        if form.is_valid():
            form.save()
            # TODO add check of connecticity
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Notification Webhook added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('notification_webhooks'))
    # TODO Disable Owner if not superadmin
    add_breadcrumb(title="Add Notication Webhook", top_level=False, request=request)
    return render(request, 'dojo/add_notification_webhook.html', {
        'name': 'Add Notification Webhook',
        'user': request.user,
        'form': form,
    })


@user_is_configuration_authorized('dojo.change_notification_webhook')
# TODO this could be better: @user_is_authorized(Finding, Permissions.Finding_Delete, 'fid')
def edit_notification_webhook(request, nwhid):
    nwh = get_object_or_404(Webhook_Endpoints, pk=nwhid)
    nwh_form = NotificationsWebhookForm(instance=nwh)
    if request.method == "POST": # TODO do we need this:? and request.POST.get('edit_note_type'):
        nwh_form = NotificationsWebhookForm(request.POST, instance=nwh)
        # TODO Allow edit owner on if superadmin
        # TODO do not allow to change status, first_error, last_error
        if nwh_form.is_valid():
            nwh = nwh_form.save()
            # TODO add check of connecticity
            messages.add_message(
                request,
                messages.SUCCESS,
                'Notification Webhook updated successfully.',
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("notification_webhooks"))
    # TODO Disable Owner if not superadmin
    add_breadcrumb(title="Edit Notication Webhook", top_level=False, request=request)
    return render(request, 'dojo/edit_notification_webhook.html', {
        'name': 'Edit Notication Webhook',
        'user': request.user,
        'form': nwh_form,
        'nwh': nwh})


@user_is_configuration_authorized('dojo.delete_notification_webhook')
def delete_notification_webhook(request, nwhid):
    nwh = get_object_or_404(Webhook_Endpoints, id=nwhid)
    form = DeleteNotificationsWebhookForm(instance=nwh)

    if request.method == 'POST':
        form = DeleteNotificationsWebhookForm(request.POST, instance=nwh)
        if form.is_valid():
            nwh.delete()
            messages.add_message(
                request,
                messages.SUCCESS,
                'Notification Webhook deleted successfully.',
                extra_tags='alert-success')
            return HttpResponseRedirect(reverse("notification_webhooks"))
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Unable to delete Notification Webhook, please try again.',
                extra_tags='alert-danger')

    return render(request, 'dojo/delete_notification_webhook.html',
                  {
                   'form': form,
                   'nwh': nwh,
                   })

