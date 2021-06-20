import logging
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test, login_required
from django.urls import reverse
from django.http import HttpResponseRedirect, HttpResponse, JsonResponse
from django.shortcuts import render, get_object_or_404
from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_permission
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.filters import GroupFilter
from dojo.forms import DojoGroupForm, DeleteGroupForm, Add_Product_Group_GroupForm, Add_Product_Type_Group_GroupForm, \
                        Add_Group_MemberForm, Edit_Group_MemberForm, Delete_Group_MemberForm
from dojo.models import Dojo_Group, Product_Group, Product_Type_Group, Dojo_Group_User
from dojo.utils import get_page_items, add_breadcrumb, is_title_in_breadcrumbs
from dojo.group.queries import get_authorized_products_for_group, get_authorized_product_types_for_group, \
                                get_users_for_group

logger = logging.getLogger(__name__)


@user_passes_test(lambda u: u.is_staff)
def group(request):
    groups = Dojo_Group.objects.order_by('name')
    groups = GroupFilter(request.GET, queryset=groups)
    paged_groups = get_page_items(request, groups.qs, 25)
    add_breadcrumb(title="All Groups", top_level=True, request=request)
    return render(request,
                  'dojo/groups.html',
                  {'groups': paged_groups,
                   'filtered': groups,
                   'name': 'All Groups',
                   })


@user_is_authorized(Dojo_Group, Permissions.Group_View, 'gid')
def view_group(request, gid):
    group = get_object_or_404(Dojo_Group, id=gid)
    products = get_authorized_products_for_group(group)
    product_types = get_authorized_product_types_for_group(group)
    users = get_users_for_group(group)

    add_breadcrumb(title="View Group", top_level=False, request=request)
    return render(request, 'dojo/view_group.html', {
        'group': group,
        'products': products,
        'product_types': product_types,
        'users': users
    })


@user_is_authorized(Dojo_Group, Permissions.Group_Edit, 'gid')
def edit_group(request, gid):
    group = get_object_or_404(Dojo_Group, id=gid)
    form = DojoGroupForm(instance=group)

    if request.method == 'POST':
        form = DojoGroupForm(request.POST, instance=group)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Group saved successfully.',
                                 extra_tags='alert-success')
        else:
            messages.add_message(request,
                                 messages.ERROR,
                                 'Group was not saved successfully.',
                                 extra_tags='alert_danger')

    add_breadcrumb(title="Edit Group", top_level=False, request=request)
    return render(request, "dojo/add_group.html", {
        'form': form
    })


@user_is_authorized(Dojo_Group, Permissions.Group_Delete, 'gid')
def delete_group(request, gid):
    group = get_object_or_404(Dojo_Group, id=gid)
    form = DeleteGroupForm(instance=group)

    if request.method == 'POST':
        if 'id' in request.POST and str(group.id) == request.POST['id']:
            form = DeleteGroupForm(request.POST, instance=group)
            if form.is_valid():
                group.delete()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Group and relationships successfully removed.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('groups'))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([group])
    rels = collector.nested()
    add_breadcrumb(title="Delete Group", top_level=False, request=request)
    return render(request, 'dojo/delete_group.html',{
        'to_delete': group,
        'form': form,
        'rels': rels
    })


@user_passes_test(lambda u: u.is_superuser)
def add_group(request):
    form = DojoGroupForm
    group = None

    if request.method == 'POST':
        form = DojoGroupForm(request.POST)
        if form.is_valid():
            group = form.save(commit=False)
            group.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Group was added successfully, you may edit if necessary.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('edit_group', args=(group.id,)))
        else:
            messages.add_message(request, messages.ERROR,
                                 'Group was not added successfully.',
                                 extra_tags='alert-danger')

    add_breadcrumb(title="Add Group", top_level=False, request=request)
    return render(request, "dojo/add_group.html", {
        'form': form
    })


@user_is_authorized(Dojo_Group, Permissions.Group_Manage_Users, 'gid')
def add_group_member(request, gid):
    group = get_object_or_404(Dojo_Group, id=gid)
    groupform = Add_Group_MemberForm(initial={'dojo_group': group.id})

    if request.method == 'POST':
        groupform = Add_Group_MemberForm(request.POST, initial={'dojo_group': group.id})
        if groupform.is_valid():
            if groupform.cleaned_data['role'].is_owner and not user_has_permission(request.user, group, Permissions.Group_Add_Owner):
                messages.add_message(request,
                                     messages.WARNING,
                                     'You are not permitted to add users as owners.',
                                     extra_tags='alert-warning')
            else:
                if 'users' in groupform.cleaned_data and len(groupform.cleaned_data['users']) > 0:
                    for user in groupform.cleaned_data['users']:
                        existing_users = Dojo_Group_User.objects.filter(dojo_group=group, user=user)
                        if existing_users.count() == 0:
                            group_user = Dojo_Group_User()
                            group_user.dojo_group = group
                            group_user.user = user
                            group_user.role = groupform.cleaned_data['role']
                            group_user.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Group members added successfully.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_group', args=(gid, )))

    add_breadcrumb(title="Add Group Member", top_level=False, request=request)
    return render(request, 'dojo/new_group_member.html', {
        'group': group,
        'form': groupform
    })

@user_is_authorized(Dojo_Group_User, Permissions.Group_Manage_Users, 'mid')
def edit_group_member(request, mid):
    member = get_object_or_404(Dojo_Group_User, pk=mid)
    memberform = Edit_Group_MemberForm(instance=member)

    if request.method == 'POST':
        memberform = Edit_Group_MemberForm(request.POST, instance=member)
        if memberform.is_valid():
            if member.role.is_owner and not user_has_permission(request.user, member.dojo_group, Permissions.Group_Add_Owner):
                messages.add_message(request,
                                     messages.WARNING,
                                     'You are not permitted to make users owners.',
                                     extra_tags='alert-warning')
            else:
                memberform.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Group member updated successfully',
                                     extra_tags='alert-success')
                if is_title_in_breadcrumbs('View User'):
                    return HttpResponseRedirect(reverse('view_user', args=(member.user.id, )))
                else:
                    return HttpResponseRedirect(reverse('view_group', args=(member.dojo_group.id, )))

    add_breadcrumb(title="Edit a Group Member", top_level=False, request=request)
    return render(request, 'dojo/edit_group_member.html', {
        'memberid': mid,
        'form': memberform
    })


@user_is_authorized(Dojo_Group_User, Permissions.Group_User_Delete, 'mid')
def delete_group_member(request, mid):
    member = get_object_or_404(Dojo_Group_User, pk=mid)
    memberform = Delete_Group_MemberForm(instance=member)

    if request.method == 'POST':
        memberform = Delete_Group_MemberForm(request.POST, instance=member)
        member = memberform.instance
        user = member.user
        member.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             'Group member deleted successfully.',
                             extra_tags='alert-success')
        if is_title_in_breadcrumbs('View User'):
            return HttpResponseRedirect(reverse('view_user', args=(member.user.id, )))
        else:
            if user == request.user:
                return HttpResponseRedirect(reverse('view_user', args=(member.user.id, )))
            else:
                return HttpResponseRedirect(reverse('view_group', args=(member.dojo_group.id, )))

    add_breadcrumb("Delete a group member", top_level=False, request=request)
    return render(request, 'dojo/delete_group_member.html', {
        'memberid': mid,
        'form': memberform
    })


@user_passes_test(lambda u: u.is_superuser)
def add_product_group(request, gid):
    group = get_object_or_404(Dojo_Group, id=gid)
    group_form = Add_Product_Group_GroupForm(initial={'group': group.id})

    if request.method == 'POST':
        group_form = Add_Product_Group_GroupForm(request.POST, initial={'group': group.id})
        if group_form.is_valid():
            if 'products' in group_form.cleaned_data and len(group_form.cleaned_data['products']) > 0:
                for product in group_form.cleaned_data['products']:
                    existing_groups = Product_Group.objects.filter(product=product, group=group)
                    if existing_groups.count() == 0:
                        product_group = Product_Group()
                        product_group.product = product
                        product_group.group = group
                        product_group.role = group_form.cleaned_data['role']
                        product_group.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Product group added successfully.',
                                 extra_tags='alert-success')
            return HttpResponseRedirect(reverse('view_group', args=(gid, )))

    add_breadcrumb(title="Add Product Group", top_level=False, request=request)
    return render(request, 'dojo/new_product_group_group.html', {
        'group': group,
        'form': group_form
    })


@user_passes_test(lambda u: u.is_superuser)
def add_product_type_group(request, gid):
    group = get_object_or_404(Dojo_Group, id=gid)
    group_form = Add_Product_Type_Group_GroupForm(initial={'group': group.id})

    if request.method == 'POST':
        group_form = Add_Product_Type_Group_GroupForm(request.POST, initial={'group': group.id})
        if group_form.is_valid():
            if 'product_types' in group_form.cleaned_data and len(group_form.cleaned_data['product_types']) > 0:
                for product_type in group_form.cleaned_data['product_types']:
                    existing_groups = Product_Type_Group.objects.filter(product_type=product_type)
                    if existing_groups.count() == 0:
                        product_type_group = Product_Type_Group()
                        product_type_group.product_type = product_type
                        product_type_group.group = group
                        product_type_group.role = group_form.cleaned_data['role']
                        product_type_group.save()
                messages.add_message(request,
                                     messages.SUCCESS,
                                     'Product type groups added successfully.',
                                     extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_group', args=(gid, )))

    add_breadcrumb(title="Add Product Type Group", top_level=False, request=request)
    return render(request, 'dojo/new_product_type_group_group.html', {
        'group': group,
        'form': group_form,
    })
