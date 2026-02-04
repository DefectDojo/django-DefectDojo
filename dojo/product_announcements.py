from django.conf import settings
from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _


class ProductAnnouncementManager:

    """Base class for centralized helper methods"""

    base_try_free = "Try today for free"
    base_contact_us = "email us at"
    base_email_address = "hello@defectdojo.com"
    ui_try_free = f'<b><a href="https://cloud.defectdojo.com/accounts/onboarding/plg_step_1" target="_blank">{base_try_free}</a></b>'
    ui_contact_us = f'{base_contact_us} <b><a href="mailto:{base_email_address}">{base_email_address}</a></b>'
    ui_outreach = f"{ui_try_free} or {ui_contact_us}."
    api_outreach = f"{base_try_free} or {base_contact_us} {base_email_address}"

    def __init__(
        self,
        *args: list,
        request: HttpRequest = None,
        response: HttpResponse = None,
        response_data: dict | None = None,
        **kwargs: dict,
    ):
        """Skip all this if the CREATE_CLOUD_BANNER is not set"""
        if not settings.CREATE_CLOUD_BANNER:
            return
        # Fill in the vars if the were supplied correctly
        if request is not None and isinstance(request, HttpRequest):
            self._add_django_message(
                request=request,
                message=mark_safe(f"{self.base_message} {self.ui_outreach}"),
            )
        elif response is not None and isinstance(response, HttpResponse):
            response.data = self._add_api_response_key(
                message=f"{self.base_message} {self.api_outreach}", data=response.data,
            )
        elif response_data is not None and isinstance(response_data, dict):
            response_data = self._add_api_response_key(
                message=f"{self.base_message} {self.api_outreach}", data=response_data,
            )
        else:
            msg = "At least one of request, response, or response_data must be supplied"
            raise ValueError(msg)

    def _add_django_message(self, request: HttpRequest, message: str):
        """Add a message to the UI"""
        messages.add_message(
            request=request,
            level=messages.INFO,
            message=_(message),
            extra_tags="alert-info",
        )

    def _add_api_response_key(self, message: str, data: dict) -> dict:
        """Update the response data in place"""
        if (feature_list := data.get("pro")) is not None and isinstance(
            feature_list,
            list,
        ):
            data["pro"] = [*feature_list, _(message)]
        else:
            data["pro"] = [_(message)]
        return data


class ErrorPageProductAnnouncement(ProductAnnouncementManager):
    def __init__(
        self,
        *args: list,
        request: HttpRequest = None,
        response: HttpResponse = None,
        response_data: dict | None = None,
        **kwargs: dict,
    ):
        self.base_message = "Pro comes with support."
        super().__init__(
            *args,
            request=request,
            response=response,
            response_data=response_data,
            **kwargs,
        )


class LargeScanSizeProductAnnouncement(ProductAnnouncementManager):
    def __init__(
        self,
        *args: list,
        request: HttpRequest = None,
        response: HttpResponse = None,
        response_data: dict | None = None,
        duration: float = 0.0,  # seconds
        **kwargs: dict,
    ):
        self.trigger_threshold = 60.0
        minute_duration = round(duration / 60.0)
        self.base_message = f"Your import took about {minute_duration} minute(s). Did you know Pro has async imports?"
        if duration > self.trigger_threshold:
            super().__init__(
                *args,
                request=request,
                response=response,
                response_data=response_data,
                **kwargs,
            )


class LongRunningRequestProductAnnouncement(ProductAnnouncementManager):
    def __init__(
        self,
        *args: list,
        request: HttpRequest = None,
        response: HttpResponse = None,
        response_data: dict | None = None,
        duration: float = 0.0,  # seconds
        **kwargs: dict,
    ):
        self.trigger_threshold = 15.0
        self.base_message = "Did you know, Pro has a new UI and is performance tested up to 22M findings?"
        if duration > self.trigger_threshold:
            super().__init__(
                *args,
                request=request,
                response=response,
                response_data=response_data,
                **kwargs,
            )


class ScanTypeProductAnnouncement(ProductAnnouncementManager):
    supported_scan_types = [
        "Snyk Scan",
        "Semgrep JSON Report",
        "Burp Enterprise Scan",
        "AWS Security Hub Scan",
        "Probely Scan",  # No OS support here
        "Checkmarx One Scan",
        "Tenable Scan",
        "SonarQube Scan",
        "Dependency Track Finding Packaging Format (FPF) Export",
        "Wiz Scan",
    ]

    def __init__(
        self,
        *args: list,
        request: HttpRequest = None,
        response: HttpResponse = None,
        response_data: dict | None = None,
        scan_type: str | None = None,
        **kwargs: dict,
    ):
        self.base_message = (
            f"Did you know, Pro has an automated no-code connector for {scan_type}?"
        )
        if scan_type in self.supported_scan_types:
            super().__init__(
                *args,
                request=request,
                response=response,
                response_data=response_data,
                **kwargs,
            )
