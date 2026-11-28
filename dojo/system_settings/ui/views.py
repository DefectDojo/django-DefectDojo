import logging

from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.utils.translation import gettext as _
from django.views import View

from dojo.system_settings.models import System_Settings
from dojo.system_settings.ui.forms import SystemSettingsForm
from dojo.utils import add_breadcrumb

logger = logging.getLogger(__name__)


class SystemSettingsView(View):
    def permission_check(
        self,
        request: HttpRequest,
    ) -> None:
        if not request.user.is_superuser:
            raise PermissionDenied

    def get_settings_object(self) -> System_Settings:
        return System_Settings.objects.get(no_cache=True)

    def get_context(
        self,
        request: HttpRequest,
    ) -> dict:
        system_settings_obj = self.get_settings_object()
        return {
            "system_settings_obj": system_settings_obj,
            "form": self.get_form(request, system_settings_obj),
        }

    def get_form(
        self,
        request: HttpRequest,
        system_settings: System_Settings,
    ) -> SystemSettingsForm:
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "instance": system_settings,
        }

        return SystemSettingsForm(*args, **kwargs)

    def validate_form(
        self,
        request: HttpRequest,
        context: dict,
    ) -> tuple[HttpRequest, bool]:
        if context["form"].is_valid():
            errors = System_Settings.cross_field_errors(context["form"].cleaned_data)
            if errors:
                # The first broken rule, as the page has always reported it.
                messages.add_message(
                    request,
                    messages.WARNING,
                    next(iter(errors.values())),
                    extra_tags="alert-warning")
            else:
                context["form"].save()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    _("Settings saved."),
                    extra_tags="alert-success")
            return request, True
        return request, False

    def get_template(self) -> str:
        return "dojo/system_settings.html"

    def get(
        self,
        request: HttpRequest,
    ) -> HttpResponse:
        # permission check
        self.permission_check(request)
        # Set up the initial context
        context = self.get_context(request)
        # Add some breadcrumbs
        add_breadcrumb(title="System settings", top_level=False, request=request)
        # Render the page
        return render(request, self.get_template(), context)

    def post(
        self,
        request: HttpRequest,
    ) -> HttpResponse:
        # permission check
        self.permission_check(request)
        # Set up the initial context
        context = self.get_context(request)
        request, _ = self.validate_form(request, context)
        # Add some breadcrumbs
        add_breadcrumb(title="System settings", top_level=False, request=request)
        # Render the page
        return render(request, self.get_template(), context)


class CeleryStatusView(View):
    def get(
        self,
        request: HttpRequest,
    ) -> HttpResponse:
        if not request.user.is_superuser:
            raise PermissionDenied
        add_breadcrumb(title="Celery status", top_level=False, request=request)
        return render(request, "dojo/celery_status.html")
