import logging

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views import View

from dojo.forms import SystemSettingsForm
from dojo.models import System_Settings
from dojo.utils import add_breadcrumb, get_celery_worker_status

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
        # Set the initial context
        context = {
            "system_settings_obj": system_settings_obj,
            "form": self.get_form(request, system_settings_obj),
        }
        # Check the status of celery
        self.get_celery_status(context)

        return context

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
            if (context["form"].cleaned_data["default_group"] is None and context["form"].cleaned_data["default_group_role"] is not None) or \
               (context["form"].cleaned_data["default_group"] is not None and context["form"].cleaned_data["default_group_role"] is None):
                messages.add_message(
                    request,
                    messages.WARNING,
                    "Settings cannot be saved: Default group and Default group role must either both be set or both be empty.",
                    extra_tags="alert-warning")
            elif context["form"].cleaned_data["minimum_password_length"] >= context["form"].cleaned_data["maximum_password_length"]:
                messages.add_message(
                    request,
                    messages.WARNING,
                    "Settings cannot be saved: Minimum required password length must be less than maximum required password length.",
                    extra_tags="alert-warning")
            elif context["form"].cleaned_data["enable_deduplication"] is True and context["form"].cleaned_data["false_positive_history"] is True:
                messages.add_message(
                    request,
                    messages.WARNING,
                    "Settings cannot be saved: Deduplicate findings and False positive history can not be set at the same time.",
                    extra_tags="alert-warning")
            elif context["form"].cleaned_data["retroactive_false_positive_history"] is True and context["form"].cleaned_data["false_positive_history"] is False:
                messages.add_message(
                    request,
                    messages.WARNING,
                    "Settings cannot be saved: Retroactive false positive history can not be set without False positive history.",
                    extra_tags="alert-warning")
            else:
                context["form"].save()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    "Settings saved.",
                    extra_tags="alert-success")
            return request, True
        return request, False

    def get_celery_status(
        self,
        context: dict,
    ) -> None:
        # Celery needs to be set with the setting: CELERY_RESULT_BACKEND = 'db+sqlite:///dojo.celeryresults.sqlite'
        if hasattr(settings, "CELERY_RESULT_BACKEND"):
            # Check the status of Celery by sending calling a celery task
            context["celery_bool"] = get_celery_worker_status()

            if context["celery_bool"]:
                context["celery_msg"] = "Celery is processing tasks."
                context["celery_status"] = "Running"
            else:
                context["celery_msg"] = "Celery does not appear to be up and running. Please ensure celery is running."
                context["celery_status"] = "Not Running"
        else:
            context["celery_bool"] = False
            context["celery_msg"] = "Celery needs to have the setting CELERY_RESULT_BACKEND = 'db+sqlite:///dojo.celeryresults.sqlite' set in settings.py."
            context["celery_status"] = "Unknown"

        return

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
        add_breadcrumb(title="Application settings", top_level=False, request=request)
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
        # Check the status of celery
        request, _ = self.validate_form(request, context)
        # Add some breadcrumbs
        add_breadcrumb(title="Application settings", top_level=False, request=request)
        # Render the page
        return render(request, self.get_template(), context)
