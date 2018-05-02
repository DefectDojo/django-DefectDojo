import logging

from django.contrib import messages
from django.contrib.auth import authenticate, logout
from django.contrib.auth.decorators import user_passes_test
from django.core import serializers
from django.core.exceptions import PermissionDenied
from django.core.urlresolvers import reverse
from django.db.models import Q
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404
from rest_framework.authtoken.models import Token
from tastypie.models import ApiKey

from dojo.filters import UserFilter
from dojo.forms import DojoUserForm, AddDojoUserForm, DeleteUserForm, APIKeyForm, UserContactInfoForm
from dojo.models import Product, Dojo_User, UserContactInfo, Alerts
from dojo.utils import get_page_items, add_breadcrumb, get_system_setting

logger = logging.getLogger(__name__)


# #  tastypie api

def api_key(request):
    api_key = ''
    form = APIKeyForm(instance=request.user)
    if request.method == 'POST':  # new key requested
        form = APIKeyForm(request.POST, instance=request.user)
        if form.is_valid() and form.cleaned_data['id'] == request.user.id:
            try:
                api_key = ApiKey.objects.get(user=request.user)
                api_key.key = None
                api_key.save()
            except ApiKey.DoesNotExist:
                api_key = ApiKey.objects.create(user=request.user)
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'API Key generated successfully.',
                                 extra_tags='alert-success')
        else:
            raise PermissionDenied
    else:
        try:
            api_key = ApiKey.objects.get(user=request.user)
        except ApiKey.DoesNotExist:
            api_key = ApiKey.objects.create(user=request.user)

    add_breadcrumb(title="API Key", top_level=True, request=request)

    return render(request, 'dojo/api_key.html',
                  {'name': 'API Key',
                   'metric': False,
                   'user': request.user,
                   'key': api_key,
                   'form': form,
                   })


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

def logout_view(request):
    logout(request)
    messages.add_message(request,
                         messages.SUCCESS,
                         'You have logged out successfully.',
                         extra_tags='alert-success')
    return HttpResponseRedirect(reverse('login'))


# @user_passes_test(lambda u: u.is_staff)
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

def alerts_json(request, limit=None):
    limit = request.GET.get('limit')
    if limit:
        alerts = serializers.serialize('json', Alerts.objects.filter(user_id=request.user)[:limit])
    else:
        alerts = serializers.serialize('json', Alerts.objects.filter(user_id=request.user))
    return HttpResponse(alerts, content_type='application/json')


def alertcount(request):
    count = Alerts.objects.filter(user_id=request.user).count()
    return JsonResponse({'count':count})


def view_profile(request):
    user = get_object_or_404(Dojo_User, pk=request.user.id)
    try:
        user_contact = UserContactInfo.objects.get(user=user)
    except UserContactInfo.DoesNotExist:
        user_contact = None

    form = DojoUserForm(instance=user)
    if user_contact is None:
        contact_form = UserContactInfoForm()
    else:
        contact_form = UserContactInfoForm(instance=user_contact)
    if request.method == 'POST':
        form = DojoUserForm(request.POST, instance=user)
        contact_form = UserContactInfoForm(request.POST, instance=user_contact)
        if form.is_valid() and contact_form.is_valid():
            form.save()
            contact = contact_form.save(commit=False)
            contact.user = user
            contact.save()

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
        'contact_form': contact_form})


def change_password(request):
    if request.method == 'POST':
        current_pwd = request.POST['current_password']
        new_pwd = request.POST['new_password']
        user = authenticate(username=request.user.username,
                            password=current_pwd)
        if user is not None:
            if user.is_active:
                user.set_password(new_pwd)
                user.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Your password has been changed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_profile'))

        messages.add_message(request,
                             messages.ERROR,
                             'Your password has not been changed.',
                             extra_tags='alert-danger')
    add_breadcrumb(title="Change Password", top_level=False, request=request)
    return render(request, 'dojo/change_pwd.html',
                  {'error': ''})


@user_passes_test(lambda u: u.is_staff)
def user(request):
    users = Dojo_User.objects.all().order_by('username', 'last_name', 'first_name')
    users = UserFilter(request.GET, queryset=users)
    paged_users = get_page_items(request, users.qs, 25)
    add_breadcrumb(title="All Users", top_level=True, request=request)
    return render(request,
                  'dojo/users.html',
                  {"users": paged_users,
                   "filtered": users,
                   "name": "All Users",
                   })


@user_passes_test(lambda u: u.is_staff)
def add_user(request):
    form = AddDojoUserForm()
    if not request.user.is_superuser:
        form.fields['is_staff'].widget.attrs['disabled'] = True
        form.fields['is_superuser'].widget.attrs['disabled'] = True
        form.fields['is_active'].widget.attrs['disabled'] = True
    contact_form = UserContactInfoForm()
    user = None

    if request.method == 'POST':
        form = AddDojoUserForm(request.POST)
        contact_form = UserContactInfoForm(request.POST)
        if form.is_valid() and contact_form.is_valid():
            user = form.save(commit=False)
            user.set_unusable_password()
            user.active = True
            user.save()
            contact = contact_form.save(commit=False)
            contact.user = user
            contact.save()
            if 'authorized_products' in form.cleaned_data and len(form.cleaned_data['authorized_products']) > 0:
                for p in form.cleaned_data['authorized_products']:
                    p.authorized_users.add(user)
                    p.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'User added successfully, you may edit if necessary.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('edit_user', args=(user.id,)))
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
        'to_add': True})


@user_passes_test(lambda u: u.is_staff)
def edit_user(request, uid):
    user = get_object_or_404(Dojo_User, id=uid)
    authed_products = Product.objects.filter(authorized_users__in=[user])
    form = AddDojoUserForm(instance=user, initial={'authorized_products': authed_products})
    if not request.user.is_superuser:
        form.fields['is_staff'].widget.attrs['disabled'] = True
        form.fields['is_superuser'].widget.attrs['disabled'] = True
        form.fields['is_active'].widget.attrs['disabled'] = True
    try:
        user_contact = UserContactInfo.objects.get(user=user)
    except UserContactInfo.DoesNotExist:
        user_contact = None
    if user_contact is None:
        contact_form = UserContactInfoForm()
    else:
        contact_form = UserContactInfoForm(instance=user_contact)

    if request.method == 'POST':
        form = AddDojoUserForm(request.POST, instance=user, initial={'authorized_products': authed_products})
        if user_contact is None:
            contact_form = UserContactInfoForm(request.POST)
        else:
            contact_form = UserContactInfoForm(request.POST, instance=user_contact)

        if form.is_valid() and contact_form.is_valid():
            form.save()
            if 'authorized_products' in form.cleaned_data and len(form.cleaned_data['authorized_products']) > 0:
                for p in form.cleaned_data['authorized_products']:
                    p.authorized_users.add(user)
                    p.save()
            contact = contact_form.save(commit=False)
            contact.user = user
            contact.save()
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
        'to_edit': user})


@user_passes_test(lambda u: u.is_staff)
def delete_user(request, uid):
    user = get_object_or_404(Dojo_User, id=uid)
    form = DeleteUserForm(instance=user)

    from django.contrib.admin.utils import NestedObjects
    from django.db import DEFAULT_DB_ALIAS

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([user])
    rels = collector.nested()

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
                user.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'User and relationships removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('users'))
    add_breadcrumb(title="Delete User", top_level=False, request=request)
    return render(request, 'dojo/delete_user.html',
                  {'to_delete': user,
                   'form': form,
                   'rels': rels,
                   })
