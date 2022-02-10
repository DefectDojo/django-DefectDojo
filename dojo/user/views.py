import logging
from crum import get_current_user
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import user_passes_test, login_required
from django.core import serializers
from django.core.exceptions import PermissionDenied
from django.db.models.deletion import RestrictedError
from django.urls import reverse
from django.conf import settings
from django.db.models import Q
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404
from django.contrib.admin.utils import NestedObjects
from django.contrib.auth.views import LoginView, PasswordResetView
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm
from django.utils.http import urlencode
from django.db import DEFAULT_DB_ALIAS
from rest_framework.authtoken.models import Token

from dojo.filters import UserFilter
from dojo.forms import DojoUserForm, ChangePasswordForm, AddDojoUserForm, EditDojoUserForm, DeleteUserForm, APIKeyForm, UserContactInfoForm, \
    Add_Product_Type_Member_UserForm, Add_Product_Member_UserForm, GlobalRoleForm, Add_Group_Member_UserForm, ConfigurationPermissionsForm
from dojo.models import Dojo_User, Alerts, Product_Member, Product_Type_Member, Dojo_Group_Member
from dojo.utils import get_page_items, add_breadcrumb, get_system_setting
from dojo.product.queries import get_authorized_product_members_for_user
from dojo.group.queries import get_authorized_group_members_for_user
from dojo.product_type.queries import get_authorized_product_type_members_for_user
from dojo.authorization.roles_permissions import Permissions
from dojo.decorators import dojo_ratelimit
from dojo.authorization.authorization_decorators import user_is_configuration_authorized

import hyperlink

logger = logging.getLogger(__name__)


# #  Django Rest Framework API v2

def api_v2_key(request):
    api_key = ''
    form = APIKeyForm(instance=request.user)
    if request.method == 'POST':  # new key requested
        form = APIKeyForm(request.POST, instance=request.user)
        if form.is_valid() and form.cleaned_data['id'] == request.user.id:
            try:
                api_key = Token.objects.get(user=request.user)
                api_key.delete()
                api_key = Token.objects.create(user=request.user)
            except Token.DoesNotExist:
                api_key = Token.objects.create(user=request.user)
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'API Key generated successfully.',
                                 extra_tags='alert-success')
        else:
            raise PermissionDenied
    else:
        try:
            api_key = Token.objects.get(user=request.user)
        except Token.DoesNotExist:
            api_key = Token.objects.create(user=request.user)
    add_breadcrumb(title="API Key", top_level=True, request=request)

    return render(request, 'dojo/api_v2_key.html',
                  {'name': 'API v2 Key',
                   'metric': False,
                   'user': request.user,
                   'key': api_key,
                   'form': form,
                   })

# #  user specific


@dojo_ratelimit(key='post:username')
@dojo_ratelimit(key='post:password')
def login_view(request):
    if not settings.SHOW_LOGIN_FORM and settings.SOCIAL_LOGIN_AUTO_REDIRECT and sum([
        settings.GOOGLE_OAUTH_ENABLED,
        settings.OKTA_OAUTH_ENABLED,
        settings.AZUREAD_TENANT_OAUTH2_ENABLED,
        settings.GITLAB_OAUTH2_ENABLED,
        settings.AUTH0_OAUTH2_ENABLED,
        settings.KEYCLOAK_OAUTH2_ENABLED,
        settings.SAML2_ENABLED
    ]) == 1 and not ('force_login_form' in request.GET):
        if settings.GOOGLE_OAUTH_ENABLED:
            social_auth = 'google-oauth2'
        elif settings.OKTA_OAUTH_ENABLED:
            social_auth = 'okta-oauth2'
        elif settings.AZUREAD_TENANT_OAUTH2_ENABLED:
            social_auth = 'azuread-tenant-oauth2'
        elif settings.GITLAB_OAUTH2_ENABLED:
            social_auth = 'gitlab'
        elif settings.KEYCLOAK_OAUTH2_ENABLED:
            social_auth = 'keycloak'
        elif settings.AUTH0_OAUTH2_ENABLED:
            social_auth = 'auth0'
        else:
            return HttpResponseRedirect('/saml2/login')
        return HttpResponseRedirect('{}?{}'.format(reverse('social:begin', args=[social_auth]),
                                                   urlencode({'next': request.GET.get('next')})))
    else:
        return LoginView.as_view(template_name='dojo/login.html', authentication_form=AuthenticationForm)(request)


def logout_view(request):
    logout(request)
    messages.add_message(request,
                         messages.SUCCESS,
                         'You have logged out successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse('login'))


@user_passes_test(lambda u: u.is_active)
def alerts(request):
    alerts = Alerts.objects.filter(user_id=request.user)

    if request.method == 'POST':
        removed_alerts = request.POST.getlist('alert_select')
        alerts.filter(id__in=removed_alerts).delete()
        alerts = alerts.filter(~Q(id__in=removed_alerts))

    paged_alerts = get_page_items(request, alerts, 25)
    alert_title = "Alerts"
    if request.user.get_full_name():
        alert_title += " for " + request.user.get_full_name()

    add_breadcrumb(title=alert_title, top_level=True, request=request)
    return render(request,
                  'dojo/alerts.html',
                  {'alerts': paged_alerts})


def delete_alerts(request):
    alerts = Alerts.objects.filter(user_id=request.user)

    if request.method == 'POST':
        removed_alerts = request.POST.getlist('alert_select')
        alerts.filter().delete()
        messages.add_message(request,
                                        messages.SUCCESS,
                                        'Alerts removed.',
                                        extra_tags='alert-success')
        return HttpResponseRedirect('alerts')

    return render(request,
                    'dojo/delete_alerts.html',
                    {'alerts': alerts})


@login_required
def alerts_json(request, limit=None):
    limit = request.GET.get('limit')
    if limit:
        alerts = serializers.serialize('json', Alerts.objects.filter(user_id=request.user)[:int(limit)])
    else:
        alerts = serializers.serialize('json', Alerts.objects.filter(user_id=request.user))
    return HttpResponse(alerts, content_type='application/json')


def alertcount(request):
    if not settings.DISABLE_ALERT_COUNTER:
        count = Alerts.objects.filter(user_id=request.user).count()
        return JsonResponse({'count': count})
    return JsonResponse({'count': 0})


def view_profile(request):
    user = get_object_or_404(Dojo_User, pk=request.user.id)
    form = DojoUserForm(instance=user)
    group_members = get_authorized_group_members_for_user(user)

    user_contact = user.usercontactinfo if hasattr(user, 'usercontactinfo') else None
    if user_contact is None:
        contact_form = UserContactInfoForm()
    else:
        contact_form = UserContactInfoForm(instance=user_contact)

    global_role = user.global_role if hasattr(user, 'global_role') else None
    if global_role is None:
        previous_global_role = None
        global_role_form = GlobalRoleForm()
    else:
        previous_global_role = global_role.role
        global_role_form = GlobalRoleForm(instance=global_role)

    if request.method == 'POST':
        form = DojoUserForm(request.POST, instance=user)
        contact_form = UserContactInfoForm(request.POST, instance=user_contact)
        global_role_form = GlobalRoleForm(request.POST, instance=global_role)
        if form.is_valid() and contact_form.is_valid() and global_role_form.is_valid():
            form.save()
            contact = contact_form.save(commit=False)
            contact.user = user
            contact.save()
            request_user = get_current_user()
            global_role = global_role_form.save(commit=False)
            if global_role.role != previous_global_role and not request_user.is_superuser:
                global_role.role = previous_global_role
                messages.add_message(request,
                                    messages.WARNING,
                                    'Only superusers are allowed to change their global role.',
                                    extra_tags='alert-warning')
            global_role.user = user
            global_role.save()

            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Profile updated successfully.',
                                 extra_tags='alert-success')
    add_breadcrumb(title="User Profile - " + user.get_full_name(), top_level=True, request=request)
    return render(request, 'dojo/profile.html', {
        'name': 'Engineer Profile',
        'metric': False,
        'user': user,
        'form': form,
        'contact_form': contact_form,
        'global_role_form': global_role_form,
        'group_members': group_members})


def change_password(request):
    user = get_object_or_404(Dojo_User, pk=request.user.id)
    form = ChangePasswordForm(user=user)

    if request.method == 'POST':
        form = ChangePasswordForm(request.POST, user=user)
        if form.is_valid():
            current_password = form.cleaned_data['current_password']
            new_password = form.cleaned_data['new_password']
            confirm_password = form.cleaned_data['confirm_password']

            user.set_password(new_password)
            Dojo_User.disable_force_password_reset(user)
            user.save()

            messages.add_message(request,
                                    messages.SUCCESS,
                                    'Your password has been changed.',
                                    extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_profile'))

    add_breadcrumb(title="Change Password", top_level=False, request=request)
    return render(request, 'dojo/change_pwd.html', {
        'name': 'ChangePassword',
        'form': form})


@user_is_configuration_authorized('auth.view_user', 'staff')
def user(request):
    users = Dojo_User.objects.all() \
        .select_related('usercontactinfo', 'global_role') \
        .order_by('username', 'last_name', 'first_name')
    users = UserFilter(request.GET, queryset=users)
    paged_users = get_page_items(request, users.qs, 25)
    add_breadcrumb(title="All Users", top_level=True, request=request)
    return render(request,
                  'dojo/users.html',
                  {"users": paged_users,
                   "filtered": users,
                   "name": "All Users",
                   })


@user_is_configuration_authorized('auth.add_user', 'superuser')
def add_user(request):
    form = AddDojoUserForm()
    contact_form = UserContactInfoForm()
    global_role_form = GlobalRoleForm()
    user = None

    if request.method == 'POST':
        form = AddDojoUserForm(request.POST)
        contact_form = UserContactInfoForm(request.POST)
        global_role_form = GlobalRoleForm(request.POST)
        if form.is_valid() and contact_form.is_valid() and global_role_form.is_valid():
            if not request.user.is_superuser and form.cleaned_data['is_superuser']:
                messages.add_message(request,
                                    messages.ERROR,
                                    'Only superusers are allowed to add superusers. User was not saved.',
                                    extra_tags='alert-danger')
            elif not request.user.is_superuser and global_role_form.cleaned_data['role']:
                messages.add_message(request,
                                    messages.ERROR,
                                    'Only superusers are allowed to add users with a global role. User was not saved.',
                                    extra_tags='alert-danger')
            else:
                user = form.save(commit=False)
                password = request.POST['password']
                if password:
                    user.set_password(password)
                else:
                    user.set_unusable_password()
                user.active = True
                user.save()
                contact = contact_form.save(commit=False)
                contact.user = user
                contact.save()
                global_role = global_role_form.save(commit=False)
                global_role.user = user
                global_role.save()
                messages.add_message(request,
                                    messages.SUCCESS,
                                    'User added successfully.',
                                    extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_user', args=(user.id,)))
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'User was not added successfully.',
                                 extra_tags='alert-danger')
    add_breadcrumb(title="Add User", top_level=False, request=request)
    return render(request, "dojo/add_user.html", {
        'name': 'Add User',
        'form': form,
        'contact_form': contact_form,
        'global_role_form': global_role_form,
        'to_add': True})


@user_is_configuration_authorized('auth.view_user', 'staff')
def view_user(request, uid):
    user = get_object_or_404(Dojo_User, id=uid)
    product_members = get_authorized_product_members_for_user(user, Permissions.Product_View)
    product_type_members = get_authorized_product_type_members_for_user(user, Permissions.Product_Type_View)
    group_members = get_authorized_group_members_for_user(user)
    configuration_permission_form = ConfigurationPermissionsForm(user=user)

    add_breadcrumb(title="View User", top_level=False, request=request)
    return render(request, 'dojo/view_user.html', {
        'user': user,
        'product_members': product_members,
        'product_type_members': product_type_members,
        'group_members': group_members,
        'configuration_permission_form': configuration_permission_form})


@user_is_configuration_authorized('auth.change_user', 'superuser')
def edit_user(request, uid):
    user = get_object_or_404(Dojo_User, id=uid)
    form = EditDojoUserForm(instance=user)

    user_contact = user.usercontactinfo if hasattr(user, 'usercontactinfo') else None
    if user_contact is None:
        contact_form = UserContactInfoForm()
    else:
        contact_form = UserContactInfoForm(instance=user_contact)

    global_role = user.global_role if hasattr(user, 'global_role') else None
    if global_role is None:
        global_role_form = GlobalRoleForm()
    else:
        global_role_form = GlobalRoleForm(instance=global_role)

    if request.method == 'POST':
        form = EditDojoUserForm(request.POST, instance=user)
        if user_contact is None:
            contact_form = UserContactInfoForm(request.POST)
        else:
            contact_form = UserContactInfoForm(request.POST, instance=user_contact)

        if global_role is None:
            global_role_form = GlobalRoleForm(request.POST)
        else:
            global_role_form = GlobalRoleForm(request.POST, instance=global_role)

        if form.is_valid() and contact_form.is_valid() and global_role_form.is_valid():
            if not request.user.is_superuser and form.cleaned_data['is_superuser']:
                messages.add_message(request,
                                    messages.ERROR,
                                    'Only superusers are allowed to edit superusers. User was not saved.',
                                    extra_tags='alert-danger')
            elif not request.user.is_superuser and global_role_form.cleaned_data['role']:
                messages.add_message(request,
                                    messages.ERROR,
                                    'Only superusers are allowed to edit users with a global role. User was not saved.',
                                    extra_tags='alert-danger')
            else:
                form.save()
                contact = contact_form.save(commit=False)
                contact.user = user
                contact.save()
                global_role = global_role_form.save(commit=False)
                global_role.user = user
                global_role.save()
                messages.add_message(request,
                                    messages.SUCCESS,
                                    'User saved successfully.',
                                    extra_tags='alert-success')
        else:
            messages.add_message(request,
                                messages.ERROR,
                                'User was not saved successfully.',
                                extra_tags='alert-danger')
    add_breadcrumb(title="Edit User", top_level=False, request=request)
    return render(request, "dojo/add_user.html", {
        'name': 'Edit User',
        'form': form,
        'contact_form': contact_form,
        'global_role_form': global_role_form,
        'to_edit': user})


@user_is_configuration_authorized('auth.delete_user', 'superuser')
def delete_user(request, uid):
    user = get_object_or_404(Dojo_User, id=uid)
    form = DeleteUserForm(instance=user)

    if user.id == request.user.id:
        messages.add_message(request,
                             messages.ERROR,
                             'You may not delete yourself.',
                             extra_tags='alert-danger')
        return HttpResponseRedirect(reverse('edit_user', args=(user.id,)))

    if request.method == 'POST':
        if 'id' in request.POST and str(user.id) == request.POST['id']:
            form = DeleteUserForm(request.POST, instance=user)
            if form.is_valid():
                if not request.user.is_superuser and user.is_superuser:
                    messages.add_message(request,
                                        messages.ERROR,
                                        'Only superusers are allowed to delete superusers. User was not removed.',
                                        extra_tags='alert-danger')
                elif not request.user.is_superuser and hasattr(user, 'global_role') and user.global_role.role:
                    messages.add_message(request,
                                        messages.ERROR,
                                        'Only superusers are allowed to delete users with a global role. User was not removed.',
                                        extra_tags='alert-danger')
                else:
                    try:
                        user.delete()
                        messages.add_message(request,
                                            messages.SUCCESS,
                                            'User and relationships removed.',
                                            extra_tags='alert-success')
                    except RestrictedError as err:
                        messages.add_message(request,
                                            messages.WARNING,
                                            'User cannot be deleted: {}'.format(err),
                                            extra_tags='alert-warning')
                    return HttpResponseRedirect(reverse('users'))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([user])
    rels = collector.nested()

    add_breadcrumb(title="Delete User", top_level=False, request=request)
    return render(request, 'dojo/delete_user.html',
                  {'to_delete': user,
                   'form': form,
                   'rels': rels,
                   })


@user_passes_test(lambda u: u.is_superuser)
def add_product_type_member(request, uid):
    user = get_object_or_404(Dojo_User, id=uid)
    memberform = Add_Product_Type_Member_UserForm(initial={'user': user.id})
    if request.method == 'POST':
        memberform = Add_Product_Type_Member_UserForm(request.POST, initial={'user': user.id})
        if memberform.is_valid():
            if 'product_types' in memberform.cleaned_data and len(memberform.cleaned_data['product_types']) > 0:
                for product_type in memberform.cleaned_data['product_types']:
                    existing_members = Product_Type_Member.objects.filter(product_type=product_type, user=user)
                    if existing_members.count() == 0:
                        product_type_member = Product_Type_Member()
                        product_type_member.product_type = product_type
                        product_type_member.user = user
                        product_type_member.role = memberform.cleaned_data['role']
                        product_type_member.save()
                messages.add_message(request,
                                    messages.SUCCESS,
                                    'Product type members added successfully.',
                                    extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_user', args=(uid, )))
    add_breadcrumb(title="Add Product Type Member", top_level=False, request=request)
    return render(request, 'dojo/new_product_type_member_user.html', {
        'user': user,
        'form': memberform,
    })


@user_passes_test(lambda u: u.is_superuser)
def add_product_member(request, uid):
    user = get_object_or_404(Dojo_User, id=uid)
    memberform = Add_Product_Member_UserForm(initial={'user': user.id})
    if request.method == 'POST':
        memberform = Add_Product_Member_UserForm(request.POST, initial={'user': user.id})
        if memberform.is_valid():
            if 'products' in memberform.cleaned_data and len(memberform.cleaned_data['products']) > 0:
                for product in memberform.cleaned_data['products']:
                    existing_members = Product_Member.objects.filter(product=product, user=user)
                    if existing_members.count() == 0:
                        product_member = Product_Member()
                        product_member.product = product
                        product_member.user = user
                        product_member.role = memberform.cleaned_data['role']
                        product_member.save()
            messages.add_message(request,
                                messages.SUCCESS,
                                'Product members added successfully.',
                                extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_user', args=(uid, )))
    add_breadcrumb(title="Add Product Member", top_level=False, request=request)
    return render(request, 'dojo/new_product_member_user.html', {
        'user': user,
        'form': memberform,
    })


@user_passes_test(lambda u: u.is_superuser)
def add_group_member(request, uid):
    user = get_object_or_404(Dojo_User, id=uid)
    memberform = Add_Group_Member_UserForm(initial={'user': user.id})

    if request.method == 'POST':
        memberform = Add_Group_Member_UserForm(request.POST, initial={'user': user.id})
        if memberform.is_valid():
            if 'groups' in memberform.cleaned_data and len(memberform.cleaned_data['groups']) > 0:
                for group in memberform.cleaned_data['groups']:
                    existing_groups = Dojo_Group_Member.objects.filter(user=user, group=group)
                    if existing_groups.count() == 0:
                        group_member = Dojo_Group_Member()
                        group_member.group = group
                        group_member.user = user
                        group_member.role = memberform.cleaned_data['role']
                        group_member.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Groups added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_user', args=(uid,)))

    add_breadcrumb(title="Add Group Member", top_level=False, request=request)
    return render(request, 'dojo/new_group_member_user.html', {
        'user': user,
        'form': memberform
    })


@user_is_configuration_authorized('auth.change_permission', 'superuser')
def edit_permissions(request, uid):
    user = get_object_or_404(Dojo_User, id=uid)
    if request.method == 'POST':
        form = ConfigurationPermissionsForm(request.POST, user=user)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Permissions updated.',
                                 extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_user', args=(uid,)))


class DojoPasswordResetForm(PasswordResetForm):
    def send_mail(self, subject_template_name, email_template_name,
                  context, from_email, to_email, html_email_template_name=None):

        from_email = get_system_setting('email_from')

        url = hyperlink.parse(settings.SITE_URL)
        context['site_name'] = url.host
        context['protocol'] = url.scheme
        context['domain'] = settings.SITE_URL[len(url.scheme + '://'):]

        super().send_mail(subject_template_name, email_template_name,
                          context, from_email, to_email, html_email_template_name)


class DojoPasswordResetView(PasswordResetView):
    form_class = DojoPasswordResetForm
