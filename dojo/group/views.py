import logging
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import Group
from django.db.models.deletion import RestrictedError
from django.urls import reverse
from django.http import HttpResponseRedirect
from django.shortcuts import render, get_object_or_404
from django.contrib.admin.utils import NestedObjects
from django.db import DEFAULT_DB_ALIAS
from dojo.authorization.roles_permissions import Permissions
from dojo.authorization.authorization import user_has_permission
from dojo.authorization.authorization_decorators import user_is_authorized
from dojo.filters import GroupFilter
from dojo.forms import DojoGroupForm, DeleteGroupForm, Add_Product_Group_GroupForm, \
    Add_Product_Type_Group_GroupForm, Add_Group_MemberForm, Edit_Group_MemberForm, \
    Delete_Group_MemberForm, GlobalRoleForm, ConfigurationPermissionsForm
from dojo.models import Dojo_Group, Product_Group, Product_Type_Group, Dojo_Group_Member
from dojo.utils import get_page_items, add_breadcrumb, is_title_in_breadcrumbs
from dojo.group.queries import get_authorized_groups, get_product_groups_for_group, \
    get_product_type_groups_for_group, get_group_members_for_group
from dojo.authorization.authorization_decorators import user_is_configuration_authorized
from dojo.group.utils import get_auth_group_name

logger = logging.getLogger(__name__)


@user_is_configuration_authorized('auth.view_group', 'staff')
def group(request):
    groups = get_authorized_groups(Permissions.Group_View)
    groups = GroupFilter(request.GET, queryset=groups)
    paged_groups = get_page_items(request, groups.qs, 25)
    add_breadcrumb(title="All Groups", top_level=True, request=request)
    return render(request, 'dojo/groups.html', {
        'groups': paged_groups,
        'filtered': groups,
        'name': 'All Groups'
    })


# Users need to be authorized to view groups in general and only the groups they are a member of
# because with the group they can see user information that might be considered as confidential
@user_is_configuration_authorized('auth.view_group', 'staff')
@user_is_authorized(Dojo_Group, Permissions.Group_View, 'gid')
def view_group(request, gid):
    group = get_object_or_404(Dojo_Group, id=gid)
    products = get_product_groups_for_group(group)
    product_types = get_product_type_groups_for_group(group)
    group_members = get_group_members_for_group(group)

    # Create authorization group if it doesn't exist and add product members
    if not group.auth_group:
        auth_group = Group(name=get_auth_group_name(group))
        auth_group.save()
        group.auth_group = auth_group
        members = group.users.all()
        for member in members:
            auth_group.user_set.add(member)
        group.save()
    configuration_permission_form = ConfigurationPermissionsForm(group=group)

    add_breadcrumb(title="View Group", top_level=False, request=request)
    return render(request, 'dojo/view_group.html', {
        'group': group,
        'products': products,
        'product_types': product_types,
        'group_members': group_members,
        'configuration_permission_form': configuration_permission_form,
    })


@user_is_authorized(Dojo_Group, Permissions.Group_Edit, 'gid')
def edit_group(request, gid):
    group = get_object_or_404(Dojo_Group, id=gid)
    form = DojoGroupForm(instance=group)

    global_role = group.global_role if hasattr(group, 'global_role') else None
    if global_role is None:
        previous_global_role = None
        global_role_form = GlobalRoleForm()
    else:
        previous_global_role = global_role.role
        global_role_form = GlobalRoleForm(instance=global_role)

    if request.method == 'POST':
        form = DojoGroupForm(request.POST, instance=group)

        if global_role is None:
            global_role_form = GlobalRoleForm(request.POST)
        else:
            global_role_form = GlobalRoleForm(request.POST, instance=global_role)

        if form.is_valid() and global_role_form.is_valid():
            if global_role_form.cleaned_data['role'] != previous_global_role and not request.user.is_superuser:
                messages.add_message(request,
                                    messages.WARNING,
                                    'Only superusers are allowed to change the global role.',
                                    extra_tags='alert-warning')
            else:
                form.save()
                global_role = global_role_form.save(commit=False)
                global_role.group = group
                global_role.save()
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
        'form': form,
        'global_role_form': global_role_form,
    })


@user_is_authorized(Dojo_Group, Permissions.Group_Delete, 'gid')
def delete_group(request, gid):
    group = get_object_or_404(Dojo_Group, id=gid)
    form = DeleteGroupForm(instance=group)

    if request.method == 'POST':
        if 'id' in request.POST and str(group.id) == request.POST['id']:
            form = DeleteGroupForm(request.POST, instance=group)
            if form.is_valid():
                try:
                    group.delete()
                    messages.add_message(request,
                                        messages.SUCCESS,
                                        'Group and relationships successfully removed.',
                                        extra_tags='alert-success')
                except RestrictedError as err:
                    messages.add_message(request,
                                         messages.WARNING,
                                         'Group cannot be deleted: {}'.format(err),
                                         extra_tags='alert-warning')
                return HttpResponseRedirect(reverse('groups'))

    collector = NestedObjects(using=DEFAULT_DB_ALIAS)
    collector.collect([group])
    rels = collector.nested()
    add_breadcrumb(title="Delete Group", top_level=False, request=request)
    return render(request, 'dojo/delete_group.html', {
        'to_delete': group,
        'form': form,
        'rels': rels
    })


@user_is_configuration_authorized('auth.add_group', 'staff')
def add_group(request):
    form = DojoGroupForm
    global_role_form = GlobalRoleForm()
    group = None

    if request.method == 'POST':
        form = DojoGroupForm(request.POST)
        global_role_form = GlobalRoleForm(request.POST)
        if form.is_valid() and global_role_form.is_valid():
            if global_role_form.cleaned_data['role'] is not None and not request.user.is_superuser:
                messages.add_message(request, messages.ERROR,
                                    'Only superusers are allowed to set global role.',
                                    extra_tags='alert-warning')
            else:
                group = form.save()
                global_role = global_role_form.save(commit=False)
                global_role.group = group
                global_role.save()

                messages.add_message(request,
                                    messages.SUCCESS,
                                    'Group was added successfully.',
                                    extra_tags='alert-success')
                return HttpResponseRedirect(reverse('view_group', args=(group.id,)))
        else:
            messages.add_message(request, messages.ERROR,
                                'Group was not added successfully.',
                                extra_tags='alert-danger')

    add_breadcrumb(title="Add Group", top_level=False, request=request)
    return render(request, "dojo/add_group.html", {
        'form': form,
        'global_role_form': global_role_form,
    })


@user_is_authorized(Dojo_Group, Permissions.Group_Manage_Members, 'gid')
def add_group_member(request, gid):
    group = get_object_or_404(Dojo_Group, id=gid)
    groupform = Add_Group_MemberForm(initial={'group': group.id})

    if request.method == 'POST':
        groupform = Add_Group_MemberForm(request.POST, initial={'group': group.id})
        if groupform.is_valid():
            if groupform.cleaned_data['role'].is_owner and not user_has_permission(request.user, group, Permissions.Group_Add_Owner):
                messages.add_message(request,
                                     messages.WARNING,
                                     'You are not permitted to add users as owners.',
                                     extra_tags='alert-warning')
            else:
                if 'users' in groupform.cleaned_data and len(groupform.cleaned_data['users']) > 0:
                    for user in groupform.cleaned_data['users']:
                        existing_users = Dojo_Group_Member.objects.filter(group=group, user=user)
                        if existing_users.count() == 0:
                            group_member = Dojo_Group_Member()
                            group_member.group = group
                            group_member.user = user
                            group_member.role = groupform.cleaned_data['role']
                            group_member.save()
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


@user_is_authorized(Dojo_Group_Member, Permissions.Group_Manage_Members, 'mid')
def edit_group_member(request, mid):
    member = get_object_or_404(Dojo_Group_Member, pk=mid)
    memberform = Edit_Group_MemberForm(instance=member)

    if request.method == 'POST':
        memberform = Edit_Group_MemberForm(request.POST, instance=member)
        if memberform.is_valid():
            if not member.role.is_owner:
                owners = Dojo_Group_Member.objects.filter(group=member.group, role__is_owner=True).exclude(id=member.id).count()
                if owners < 1:
                    messages.add_message(request,
                                        messages.WARNING,
                                        'There must be at least one owner for group {}.'.format(member.group.name),
                                        extra_tags='alert-warning')
                    if is_title_in_breadcrumbs('View User'):
                        return HttpResponseRedirect(reverse('view_user', args=(member.user.id, )))
                    else:
                        return HttpResponseRedirect(reverse('view_group', args=(member.group.id, )))
            if member.role.is_owner and not user_has_permission(request.user, member.group, Permissions.Group_Add_Owner):
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
                    return HttpResponseRedirect(reverse('view_group', args=(member.group.id, )))

    add_breadcrumb(title="Edit a Group Member", top_level=False, request=request)
    return render(request, 'dojo/edit_group_member.html', {
        'memberid': mid,
        'form': memberform
    })


@user_is_authorized(Dojo_Group_Member, Permissions.Group_Member_Delete, 'mid')
def delete_group_member(request, mid):
    member = get_object_or_404(Dojo_Group_Member, pk=mid)
    memberform = Delete_Group_MemberForm(instance=member)

    if request.method == 'POST':
        memberform = Delete_Group_MemberForm(request.POST, instance=member)
        member = memberform.instance
        if member.role.is_owner:
            owners = Dojo_Group_Member.objects.filter(group=member.group, role__is_owner=True).count()
            if owners <= 1:
                messages.add_message(request,
                                    messages.WARNING,
                                        'There must be at least one owner for group {}.'.format(member.group.name),
                                    extra_tags='alert-warning')
                if is_title_in_breadcrumbs('View User'):
                    return HttpResponseRedirect(reverse('view_user', args=(member.user.id, )))
                else:
                    return HttpResponseRedirect(reverse('view_group', args=(member.group.id, )))

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
                return HttpResponseRedirect(reverse('groups'))
            else:
                return HttpResponseRedirect(reverse('view_group', args=(member.group.id, )))

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
                                 'Product groups added successfully.',
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
                    existing_groups = Product_Type_Group.objects.filter(product_type=product_type, group=group)
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


@user_is_configuration_authorized('auth.change_permission', 'superuser')
def edit_permissions(request, gid):
    group = get_object_or_404(Dojo_Group, id=gid)
    if request.method == 'POST':
        form = ConfigurationPermissionsForm(request.POST, group=group)
        if form.is_valid():
            form.save()
            messages.add_message(request,
                                 messages.SUCCESS,
                                 'Permissions updated.',
                                 extra_tags='alert-success')
    return HttpResponseRedirect(reverse('view_group', args=(gid,)))
