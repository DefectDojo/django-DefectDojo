import contextlib
import logging
from datetime import timedelta

import hyperlink
from django.conf import settings
from django.contrib import messages
from django.contrib.admin.utils import NestedObjects
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm
from django.contrib.auth.views import LoginView, PasswordResetConfirmView, PasswordResetView
from django.contrib.humanize.templatetags.humanize import naturaltime
from django.core import serializers
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.mail import get_connection
from django.core.mail.backends.smtp import EmailBackend
from django.db import DEFAULT_DB_ALIAS
from django.db.models import Q
from django.db.models.deletion import RestrictedError
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils.timezone import now
from django.utils.translation import gettext as _
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import PermissionDenied as RFPermissionDenied
from rest_framework.exceptions import ValidationError as RFValidationError

from dojo.authorization.authorization import user_is_superuser_or_global_owner
from dojo.decorators import dojo_ratelimit
from dojo.filters import UserFilter
from dojo.forms import (
    AddDojoUserForm,
    APIKeyForm,
    Authorize_User_For_ProductsForm,
    Authorize_User_For_ProductTypesForm,
    ChangePasswordForm,
    ConfigurationPermissionsForm,
    DeleteUserForm,
    DojoUserForm,
    EditDojoUserForm,
    UserContactInfoForm,
)
from dojo.labels import get_labels
from dojo.middleware import set_language_cookie
from dojo.models import Alerts, Dojo_User, Product, Product_Type, UserContactInfo
from dojo.user.authentication import reset_token_for_user
from dojo.utils import add_breadcrumb, get_page_items, get_setting, get_system_setting

logger = logging.getLogger(__name__)

labels = get_labels()


class DojoLoginView(LoginView):
    template_name = "dojo/login.html"
    authentication_form = AuthenticationForm

    def form_valid(self, form):
        last_login = None
        with contextlib.suppress(Exception):
            username = form.cleaned_data.get("username")
            user = Dojo_User.objects.get(username=username)
            last_login = user.last_login
        response = super().form_valid(form)
        name = self.request.user.first_name or self.request.user.username
        last_login = last_login or self.request.user.last_login
        messages.add_message(
            self.request,
            messages.SUCCESS,
            _("Hello %s! Your last login was %s (%s)") % (name, naturaltime(last_login), last_login.strftime("%Y-%m-%d %I:%M:%S %p")),
            extra_tags="alert-success")
        return response

# #  Django Rest Framework API v2


def api_v2_key(request):
    # This check should not be necessary because url should not be in 'urlpatterns' but we never know
    if not settings.API_TOKENS_ENABLED:
        raise PermissionDenied
    api_key = ""
    form = APIKeyForm(instance=request.user)
    if request.method == "POST":  # new key requested
        form = APIKeyForm(request.POST, instance=request.user)
        if form.is_valid() and form.cleaned_data["id"] == request.user.id:
            try:
                reset_token_for_user(acting_user=request.user, target_user=request.user, allow_self_reset=True)
            except (RFPermissionDenied, RFValidationError) as e:
                messages.add_message(request,
                                    messages.ERROR,
                                    _("API Key generation failed: %s") % str(e),
                                    extra_tags="alert-danger")
            else:
                messages.add_message(request,
                                    messages.SUCCESS,
                                    _("API Key generated successfully."),
                                    extra_tags="alert-success")
        else:
            raise PermissionDenied
    else:
        try:
            api_key = Token.objects.get(user=request.user)
        except Token.DoesNotExist:
            api_key = Token.objects.create(user=request.user)
    add_breadcrumb(title=_("API Key"), top_level=True, request=request)

    return render(request, "dojo/api_v2_key.html",
                  {"name": _("API v2 Key"),
                   "metric": False,
                   "user": request.user,
                   "key": api_key,
                   "form": form,
                   })


# #  user specific
@dojo_ratelimit(key="post:username")
@dojo_ratelimit(key="post:password")
def login_view(request):
    return DojoLoginView.as_view(template_name="dojo/login.html", authentication_form=AuthenticationForm)(request)


def logout_view(request):
    logout(request)
    messages.add_message(request,
                     messages.SUCCESS,
                     _("You have logged out successfully."),
                     extra_tags="alert-success")

    return HttpResponseRedirect(reverse("login"))


@user_passes_test(lambda u: u.is_active)
def alerts(request):
    alerts = Alerts.objects.filter(user_id=request.user).order_by("-id")

    if request.method == "POST":
        removed_alerts = request.POST.getlist("alert_select")
        alerts.filter(id__in=removed_alerts).delete()
        alerts = alerts.filter(~Q(id__in=removed_alerts))

    paged_alerts = get_page_items(request, alerts, 25)
    alert_title = "Alerts"
    if request.user.get_full_name():
        alert_title += " for " + request.user.get_full_name()

    add_breadcrumb(title=alert_title, top_level=True, request=request)
    return render(request,
                  "notifications/alerts.html",
                  {"alerts": paged_alerts})


def delete_alerts(request):
    alerts = Alerts.objects.filter(user_id=request.user).order_by("-id")

    if request.method == "POST":
        alerts.filter().delete()
        messages.add_message(
            request,
            messages.SUCCESS,
            _("Alerts removed."),
            extra_tags="alert-success")
        return HttpResponseRedirect("alerts")

    return render(request, "notifications/delete_alerts.html", {
        "alerts": alerts,
        "delete_preview": get_setting("DELETE_PREVIEW"),
    })


@login_required
def alerts_json(request, limit=None):
    limit = request.GET.get("limit")
    if limit:
        alerts = serializers.serialize("json", Alerts.objects.filter(user_id=request.user)[:int(limit)])
    else:
        alerts = serializers.serialize("json", Alerts.objects.filter(user_id=request.user))
    return HttpResponse(alerts, content_type="application/json")


def alertcount(request):
    if not settings.DISABLE_ALERT_COUNTER:
        count = Alerts.objects.filter(user_id=request.user).count()
        return JsonResponse({"count": count})
    return JsonResponse({"count": 0})


def alertcount_text(request):
    """Return alert count as plain text for htmx polling."""
    count = Alerts.objects.filter(user_id=request.user).count() if not settings.DISABLE_ALERT_COUNTER else 0
    return HttpResponse(str(count), content_type="text/plain")


@login_required
def alerts_partial(request):
    """Return alert dropdown HTML partial for htmx."""
    limit = request.GET.get("limit")
    if limit:
        alerts = Alerts.objects.filter(user_id=request.user)[:int(limit)]
    else:
        alerts = Alerts.objects.filter(user_id=request.user)
    return render(request, "dojo/partials/alerts_dropdown.html", {"alerts": alerts})


def view_profile(request):
    user = get_object_or_404(Dojo_User, pk=request.user.id)
    form = DojoUserForm(instance=user)

    user_contact = user.usercontactinfo if hasattr(user, "usercontactinfo") else None
    contact_form = UserContactInfoForm(user=user) if user_contact is None else UserContactInfoForm(instance=user_contact, user=user)

    if request.method == "POST":
        form = DojoUserForm(request.POST, instance=user)
        contact_form = UserContactInfoForm(request.POST, instance=user_contact, user=user)
        if form.is_valid() and contact_form.is_valid():
            form.save()
            contact = contact_form.save(commit=False)
            contact.user = user
            contact.save()

            messages.add_message(request,
                                 messages.SUCCESS,
                                 _("Profile updated successfully."),
                                 extra_tags="alert-success")
            # Redirect so the response renders against a fresh request — this
            # ensures UIPreferenceLoader and the UI-toggle banner read the
            # just-saved usercontactinfo (e.g. ui_use_tailwind) instead of any
            # state cached on the POST request. Also prevents form
            # resubmission on refresh.
            response = HttpResponseRedirect(reverse("view_profile"))
            # Reflect a language change immediately on this device by refreshing
            # the cookie LocaleMiddleware reads; other devices pick the preference
            # up from UserContactInfo on their next browser session.
            return set_language_cookie(response, contact.language)
    add_breadcrumb(title=_("User Profile - %(user_full_name)s") % {"user_full_name": user.get_full_name()}, top_level=True, request=request)
    return render(request, "dojo/profile.html", {
        "user": user,
        "form": form,
        "contact_form": contact_form})


def change_password(request):
    user = get_object_or_404(Dojo_User, pk=request.user.id)
    form = ChangePasswordForm(user=user)

    if request.method == "POST":
        form = ChangePasswordForm(request.POST, user=user)
        if form.is_valid():
            new_password = form.cleaned_data["new_password"]

            user.set_password(new_password)
            user.disable_force_password_reset()
            user.save()
            # Case: user is logged in and changes their password via the profile UI.
            # We stamp password_last_reset here so this flow is tracked independently from
            # the "forgot password" reset flow (handled in DojoPasswordResetConfirmView).
            uci, _created = UserContactInfo.objects.get_or_create(user=user)
            uci.password_last_reset = now()
            uci.save(update_fields=["password_last_reset"])

            messages.add_message(request,
                                    messages.SUCCESS,
                                    _("Your password has been changed."),
                                    extra_tags="alert-success")
            return HttpResponseRedirect(reverse("view_profile"))

    add_breadcrumb(title=_("Change Password"), top_level=False, request=request)
    return render(request, "dojo/change_pwd.html", {"form": form})


def user(request):
    page_name = _("All Users")
    users = Dojo_User.objects.all() \
        .select_related("usercontactinfo") \
        .order_by("username", "last_name", "first_name")
    users = UserFilter(request.GET, queryset=users)
    paged_users = get_page_items(request, users.qs, 25)
    add_breadcrumb(title=page_name, top_level=True, request=request)
    return render(request, "dojo/users.html", {
        "users": paged_users,
        "filtered": users,
        "name": page_name,
    })


def add_user(request):
    page_name = _("Add User")
    form = AddDojoUserForm()
    contact_form = UserContactInfoForm()
    user = None

    if request.method == "POST":
        form = AddDojoUserForm(request.POST)
        contact_form = UserContactInfoForm(request.POST)
        if form.is_valid() and contact_form.is_valid():
            if not request.user.is_superuser and form.cleaned_data["is_superuser"]:
                messages.add_message(request,
                                    messages.ERROR,
                                    _("Only superusers are allowed to add superusers. User was not saved."),
                                    extra_tags="alert-danger")
            elif not request.user.is_superuser and form.cleaned_data["is_staff"]:
                messages.add_message(request,
                                    messages.ERROR,
                                    _("Only superusers are allowed to grant staff status. User was not saved."),
                                    extra_tags="alert-danger")
            else:
                user = form.save(commit=False)
                password = request.POST["password"]
                if password:
                    user.set_password(password)
                else:
                    user.set_unusable_password()
                user.active = True
                user.save()
                contact = contact_form.save(commit=False)
                contact.user = user
                contact.save()
                messages.add_message(request,
                                    messages.SUCCESS,
                                    _("User added successfully."),
                                    extra_tags="alert-success")
                return HttpResponseRedirect(reverse("view_user", args=(user.id,)))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 _("User was not added successfully."),
                                 extra_tags="alert-danger")
    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, "dojo/add_user.html", {
        "name": page_name,
        "form": form,
        "contact_form": contact_form,
        "to_add": True})


def view_user(request, uid):
    user = get_object_or_404(Dojo_User, id=uid)
    # Legacy access lists: Product / Product_Type the user is on
    # via authorized_users (with cascade Product_Type → Product).
    accessible_product_types = Product_Type.objects.filter(
        authorized_users=user,
    ).order_by("name")
    accessible_products = Product.objects.filter(
        Q(authorized_users=user) | Q(prod_type__authorized_users=user),
    ).distinct().order_by("name")
    configuration_permission_form = ConfigurationPermissionsForm(user=user)

    add_breadcrumb(title=_("View User"), top_level=False, request=request)
    return render(request, "dojo/view_user.html", {
        "user": user,
        "accessible_product_types": accessible_product_types,
        "accessible_products": accessible_products,
        "configuration_permission_form": configuration_permission_form})


def edit_user(request, uid):
    page_name = _("Edit User")
    user = get_object_or_404(Dojo_User, id=uid)
    form = EditDojoUserForm(instance=user)

    user_contact = user.usercontactinfo if hasattr(user, "usercontactinfo") else None
    contact_form = UserContactInfoForm(user=user) if user_contact is None else UserContactInfoForm(instance=user_contact, user=user)

    if request.method == "POST":
        form = EditDojoUserForm(request.POST, instance=user)
        if user_contact is None:
            contact_form = UserContactInfoForm(request.POST, user=user)
        else:
            contact_form = UserContactInfoForm(request.POST, instance=user_contact, user=user)

        if form.is_valid() and contact_form.is_valid():
            if not request.user.is_superuser and form.cleaned_data["is_superuser"]:
                messages.add_message(request,
                                    messages.ERROR,
                                    _("Only superusers are allowed to edit superusers. User was not saved."),
                                    extra_tags="alert-danger")
            elif not request.user.is_superuser and form.cleaned_data["is_staff"] != user.is_staff:
                messages.add_message(request,
                                    messages.ERROR,
                                    _("Only superusers are allowed to change staff status. User was not saved."),
                                    extra_tags="alert-danger")
            else:
                form.save()
                contact = contact_form.save(commit=False)
                contact.user = user
                contact.save()

                # Handle API token reset if checkbox is checked
                # Only allow superusers or global owners to reset tokens
                token_reset_success = False
                if user_is_superuser_or_global_owner(request.user):
                    reset_token = contact_form.cleaned_data.get("reset_api_token", False)
                    if reset_token:
                        try:
                            reset_token_for_user(acting_user=request.user, target_user=user)
                            token_reset_success = True
                            messages.add_message(request,
                                                messages.SUCCESS,
                                                _("API token reset successfully."),
                                                extra_tags="alert-success")
                        except (RFPermissionDenied, RFValidationError) as e:
                            # If permission denied or validation error, log but don't fail the user save
                            messages.add_message(request,
                                                messages.WARNING,
                                                _("User saved successfully, but API token reset failed: %s") % str(e),
                                                extra_tags="alert-warning")

                messages.add_message(request,
                                    messages.SUCCESS,
                                    _("User saved successfully."),
                                    extra_tags="alert-success")

                # Re-instantiate forms to uncheck the checkbox after successful save
                if token_reset_success:
                    # Reload contact from database to get updated token_last_reset timestamp
                    contact.refresh_from_db()
                    contact_form = UserContactInfoForm(instance=contact, user=user)
        else:
            messages.add_message(request,
                                messages.ERROR,
                                _("User was not saved successfully."),
                                extra_tags="alert-danger")
    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, "dojo/add_user.html", {
        "name": page_name,
        "form": form,
        "contact_form": contact_form,
        "to_edit": user})


def delete_user(request, uid):
    user = get_object_or_404(Dojo_User, id=uid)
    form = DeleteUserForm(instance=user)

    if user.id == request.user.id:
        messages.add_message(request,
                             messages.ERROR,
                             _("You may not delete yourself."),
                             extra_tags="alert-danger")
        return HttpResponseRedirect(reverse("edit_user", args=(user.id,)))

    if request.method == "POST":
        if "id" in request.POST and str(user.id) == request.POST["id"]:
            form = DeleteUserForm(request.POST, instance=user)
            if form.is_valid():
                if not request.user.is_superuser and user.is_superuser:
                    messages.add_message(request,
                                        messages.ERROR,
                                        _("Only superusers are allowed to delete superusers. User was not removed."),
                                        extra_tags="alert-danger")
                else:
                    try:
                        user.delete()
                        messages.add_message(request,
                                            messages.SUCCESS,
                                            _("User and relationships removed."),
                                            extra_tags="alert-success")
                    except RestrictedError as err:
                        messages.add_message(request,
                                            messages.WARNING,
                                            _("User cannot be deleted: %(error)s") % {"error": err},
                                            extra_tags="alert-warning")
                    return HttpResponseRedirect(reverse("users"))

    rels = ["Previewing the relationships has been disabled.", ""]
    display_preview = get_setting("DELETE_PREVIEW")
    if display_preview:
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([user])
        rels = collector.nested()

    add_breadcrumb(title=_("Delete User"), top_level=False, request=request)
    return render(request, "dojo/delete_user.html",
                  {"to_delete": user,
                   "form": form,
                   "rels": rels,
                   })


@user_passes_test(lambda u: u.is_staff)
def authorize_user_for_products(request, uid):
    """OS legacy: add this user to one or more products' authorized_users."""
    page_name = _("Authorize User for Products")
    user = get_object_or_404(Dojo_User, id=uid)
    form = Authorize_User_For_ProductsForm(user=user)
    if request.method == "POST":
        form = Authorize_User_For_ProductsForm(request.POST, user=user)
        if form.is_valid():
            products = form.cleaned_data["products"]
            for product in products:
                product.authorized_users.add(user)
            messages.add_message(
                request, messages.SUCCESS,
                _("Authorized %(username)s for %(count)d product(s).") % {
                    "username": user.username, "count": len(products),
                },
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_user", args=(uid,)))
    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, "dojo/authorize_user_for_products.html", {
        "name": page_name, "user": user, "form": form,
    })


@user_passes_test(lambda u: u.is_staff)
def authorize_user_for_product_types(request, uid):
    """OS legacy: add this user to one or more product_types' authorized_users."""
    page_name = _("Authorize User for Product Types")
    user = get_object_or_404(Dojo_User, id=uid)
    form = Authorize_User_For_ProductTypesForm(user=user)
    if request.method == "POST":
        form = Authorize_User_For_ProductTypesForm(request.POST, user=user)
        if form.is_valid():
            product_types = form.cleaned_data["product_types"]
            for pt in product_types:
                pt.authorized_users.add(user)
            messages.add_message(
                request, messages.SUCCESS,
                _("Authorized %(username)s for %(count)d product type(s).") % {
                    "username": user.username, "count": len(product_types),
                },
                extra_tags="alert-success",
            )
            return HttpResponseRedirect(reverse("view_user", args=(uid,)))
    add_breadcrumb(title=page_name, top_level=False, request=request)
    return render(request, "dojo/authorize_user_for_product_types.html", {
        "name": page_name, "user": user, "form": form,
    })


@user_passes_test(lambda u: u.is_staff)
def revoke_user_from_product(request, uid, pid):
    """OS legacy: remove user from a product's authorized_users."""
    if request.method != "POST":
        raise PermissionDenied
    user = get_object_or_404(Dojo_User, id=uid)
    product = get_object_or_404(Product, id=pid)
    product.authorized_users.remove(user)
    messages.add_message(
        request, messages.SUCCESS,
        _("Revoked %(username)s from %(product)s.") % {
            "username": user.username, "product": product.name,
        },
        extra_tags="alert-success",
    )
    return HttpResponseRedirect(reverse("view_user", args=(uid,)))


@user_passes_test(lambda u: u.is_staff)
def revoke_user_from_product_type(request, uid, ptid):
    """OS legacy: remove user from a product_type's authorized_users."""
    if request.method != "POST":
        raise PermissionDenied
    user = get_object_or_404(Dojo_User, id=uid)
    pt = get_object_or_404(Product_Type, id=ptid)
    pt.authorized_users.remove(user)
    messages.add_message(
        request, messages.SUCCESS,
        _("Revoked %(username)s from %(pt)s.") % {
            "username": user.username, "pt": pt.name,
        },
        extra_tags="alert-success",
    )
    return HttpResponseRedirect(reverse("view_user", args=(uid,)))


def edit_permissions(request, uid):
    user = get_object_or_404(Dojo_User, id=uid)
    if request.method == "POST":
        form = ConfigurationPermissionsForm(request.POST, user=user)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 _("Permissions updated."),
                                 extra_tags="alert-success")
    return HttpResponseRedirect(reverse("view_user", args=(uid,)))


class DojoForgotUsernameForm(PasswordResetForm):
    def send_mail(self, subject_template_name, email_template_name,
                  context, from_email, to_email, html_email_template_name=None):

        from_email = get_system_setting("email_from")

        url = hyperlink.parse(settings.SITE_URL)
        subject_template_name = "login/forgot_username_subject.html"
        email_template_name = "login/forgot_username.tpl"
        context["site_name"] = url.host
        context["protocol"] = url.scheme
        context["domain"] = settings.SITE_URL[len(f"{url.scheme}://"):]

        super().send_mail(subject_template_name, email_template_name, context, from_email, to_email, html_email_template_name)

    def clean(self):
        try:
            connection = get_connection()
            if isinstance(connection, EmailBackend):
                connection.open()
                connection.close()
        except Exception:
            msg = "SMTP server is not configured correctly..."
            raise ValidationError(msg)


class DojoPasswordResetForm(PasswordResetForm):
    def send_mail(self, subject_template_name, email_template_name,
                  context, from_email, to_email, html_email_template_name=None):

        from_email = get_system_setting("email_from")

        url = hyperlink.parse(settings.SITE_URL)
        email_template_name = "login/forgot_password.tpl"
        context["site_name"] = url.host
        context["protocol"] = url.scheme
        context["domain"] = settings.SITE_URL[len(f"{url.scheme}://"):]
        context["link_expiration_date"] = naturaltime(now() + timedelta(seconds=settings.PASSWORD_RESET_TIMEOUT))

        super().send_mail(subject_template_name, email_template_name, context, from_email, to_email, html_email_template_name)

    def clean(self):
        try:
            connection = get_connection()
            if isinstance(connection, EmailBackend):
                connection.open()
                connection.close()
        except Exception as e:
            logger.error("SMTP Server Connection Failure: %s", e)
            msg = "SMTP server is not configured correctly..."
            raise ValidationError(msg)


class DojoPasswordResetView(PasswordResetView):
    form_class = DojoPasswordResetForm


class DojoForgotUsernameView(PasswordResetView):
    form_class = DojoForgotUsernameForm


class DojoPasswordResetConfirmView(PasswordResetConfirmView):
    def form_valid(self, form):
        response = super().form_valid(form)
        # Flow: user resets password via the emailed "forgot password" link.
        # This uses PasswordResetConfirmView, so we stamp password_last_reset here
        # because this flow does not pass through change_password().
        user = form.user
        uci, _created = UserContactInfo.objects.get_or_create(user=user)
        uci.password_last_reset = now()
        uci.save(update_fields=["password_last_reset"])
        return response
