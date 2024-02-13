import logging
from django.views import View
from django.db.models.query import QuerySet
from django.contrib import messages
from django.contrib.auth.decorators import user_passes_test
from django.contrib.auth.models import Group
from django.db.models.deletion import RestrictedError
from django.urls import reverse
from django.http import HttpResponseRedirect, HttpRequest
from django.core.exceptions import PermissionDenied
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
from dojo.models import Dojo_Group, Product_Group, Product_Type_Group, Dojo_Group_Member, Global_Role
from dojo.utils import get_page_items, add_breadcrumb, is_title_in_breadcrumbs, redirect_to_return_url_or_else
from dojo.group.queries import get_authorized_groups, get_product_groups_for_group, \
    get_product_type_groups_for_group, get_group_members_for_group
from dojo.authorization.authorization_decorators import user_is_configuration_authorized
from dojo.authorization.authorization import user_has_configuration_permission, user_has_permission_or_403
from dojo.group.utils import get_auth_group_name

logger = logging.getLogger(__name__)


class ListGroups(View):
    def get_groups(self):
        return get_authorized_groups(Permissions.Group_View)

    def get_initial_context(self, request: HttpRequest, groups: QuerySet[Dojo_Group]):
        filtered_groups = GroupFilter(request.GET, queryset=groups)
        return {
            "name": "All Groups",
            "filtered": filtered_groups,
            "groups": get_page_items(request, filtered_groups.qs, 25),
        }

    def get_template(self):
        return "dojo/groups.html"

    def get(self, request: HttpRequest):
        # quick permission check
        if not user_has_configuration_permission(request.user, 'auth.view_group'):
            raise PermissionDenied
        # Fetch the groups
        groups = self.get_groups()
        # Set up the initial context
        context = self.get_initial_context(request, groups)
        # Add a breadcrumb
        add_breadcrumb(title="All Groups", top_level=True, request=request)
        # Render the page
        return render(request, self.get_template(), context)


class ViewGroup(View):
    def get_group(self, group_id: int):
        return get_object_or_404(Dojo_Group, id=group_id)

    def get_initial_context(self, group: Dojo_Group):
        return {
            "group": group,
            "products": get_product_groups_for_group(group),
            "product_types": get_product_type_groups_for_group(group),
            "group_members": get_group_members_for_group(group),
        }

    def set_configuration_permissions(self, group: Dojo_Group, context: dict):
        # Create authorization group if it doesn't exist and add product members
        if not group.auth_group:
            auth_group = Group(name=get_auth_group_name(group))
            auth_group.save()
            group.auth_group = auth_group
            members = group.users.all()
            for member in members:
                auth_group.user_set.add(member)
            group.save()
        # create the config permissions form
        context["configuration_permission_form"] = ConfigurationPermissionsForm(group=group)

        return context

    def get_template(self):
        return "dojo/view_group.html"

    def get(self, request: HttpRequest, group_id: int):
        # Fetch the group
        group = self.get_group(group_id)
        # quick permission check
        if not user_has_configuration_permission(request.user, 'auth.view_group'):
            raise PermissionDenied
        user_has_permission_or_403(request.user, group, Permissions.Group_View)
        # Set up the initial context
        context = self.get_initial_context(group)
        # Set up the config permissions
        context = self.set_configuration_permissions(group, context)
        # Add a breadcrumb
        add_breadcrumb(title="View Group", top_level=False, request=request)
        # Render the page
        return render(request, self.get_template(), context)


class EditGroup(View):
    def get_group(self, group_id: int):
        return get_object_or_404(Dojo_Group, id=group_id)

    def get_global_role(self, group: Dojo_Group):
        # Try to pull the global role from the group object
        return group.global_role if hasattr(group, 'global_role') else None

    def get_group_form(self, request: HttpRequest, group: Dojo_Group):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "instance": group,
        }

        return DojoGroupForm(*args, **kwargs)

    def get_global_role_form(self, request: HttpRequest, global_role: Global_Role):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {}
        # Add the global role to te kwargs if it is present
        if global_role:
            kwargs["instance"] = global_role

        return GlobalRoleForm(*args, **kwargs)

    def get_initial_context(self, request: HttpRequest, group: Dojo_Group, global_role: Global_Role):
        return {
            "form": self.get_group_form(request, group),
            "global_role_form": self.get_global_role_form(request, global_role),
            "previous_global_role": global_role.role if global_role else None,
        }

    def process_forms(self, request: HttpRequest, group: Dojo_Group, context: dict):
        # Validate the forms
        if context["form"].is_valid() and context["global_role_form"].is_valid():
            # Determine if the previous global roles was changed with proper authorization
            if context["global_role_form"].cleaned_data['role'] != context["previous_global_role"] and not request.user.is_superuser:
                messages.add_message(
                    request,
                    messages.WARNING,
                    'Only superusers are allowed to change the global role.',
                    extra_tags='alert-warning')
            else:
                context["form"].save()
                global_role = context["global_role_form"].save(commit=False)
                global_role.group = group
                global_role.save()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    'Group saved successfully.',
                    extra_tags='alert-success')

            return request, True
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Group was not saved successfully.',
                extra_tags='alert_danger')

        return request, False

    def get_template(self):
        return "dojo/add_group.html"

    def get(self, request: HttpRequest, group_id: int):
        # Fetch the group and global role
        group = self.get_group(group_id)
        global_role = self.get_global_role(group)
        # quick permission check
        user_has_permission_or_403(request.user, group, Permissions.Group_Edit)
        # Set up the initial context
        context = self.get_initial_context(request, group, global_role)
        # Add a breadcrumb
        add_breadcrumb(title="Edit Group", top_level=False, request=request)
        # Render the page
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, group_id: int):
        # Fetch the group and global role
        group = self.get_group(group_id)
        global_role = self.get_global_role(group)
        # quick permission check
        user_has_permission_or_403(request.user, group, Permissions.Group_Edit)
        # Set up the initial context
        context = self.get_initial_context(request, group, global_role)
        # Process the forms
        request, success = self.process_forms(request, group, context)
        # Handle the case of a successful form
        if success:
            return redirect_to_return_url_or_else(request, reverse("view_group", args=(group_id,)))
        # Add a breadcrumb
        add_breadcrumb(title="Edit Group", top_level=False, request=request)
        # Render the page
        return render(request, self.get_template(), context)


class DeleteGroup(View):
    def get_group(self, group_id: int):
        return get_object_or_404(Dojo_Group, id=group_id)

    def get_group_form(self, request: HttpRequest, group: Dojo_Group):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {
            "instance": group,
        }

        return DeleteGroupForm(*args, **kwargs)

    def get_initial_context(self, request: HttpRequest, group: Dojo_Group):
        # Add the related objects to the delete page
        collector = NestedObjects(using=DEFAULT_DB_ALIAS)
        collector.collect([group])
        return {
            "form": self.get_group_form(request, group),
            "to_delete": group,
            "rels": collector.nested()
        }

    def process_forms(self, request: HttpRequest, group: Dojo_Group, context: dict):
        # Validate the forms
        if context["form"].is_valid():
            try:
                group.delete()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    'Group and relationships successfully removed.',
                    extra_tags='alert-success')
            except RestrictedError as err:
                messages.add_message(
                    request,
                    messages.WARNING,
                    f'Group cannot be deleted: {err}',
                    extra_tags='alert-warning',
                )
                return request, False

            return request, True
        return request, False

    def get_template(self):
        return "dojo/delete_group.html"

    def get(self, request: HttpRequest, group_id: int):
        # Fetch the group and global role
        group = self.get_group(group_id)
        # quick permission check
        user_has_permission_or_403(request.user, group, Permissions.Group_Delete)
        # Set up the initial context
        context = self.get_initial_context(request, group)
        # Add a breadcrumb
        add_breadcrumb(title="Delete Group", top_level=False, request=request)
        # Render the page
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest, group_id: int):
        # Fetch the group and global role
        group = self.get_group(group_id)
        # quick permission check
        user_has_permission_or_403(request.user, group, Permissions.Group_Delete)
        # Set up the initial context
        context = self.get_initial_context(request, group)
        # Process the forms
        request, success = self.process_forms(request, group, context)
        # Handle the case of a successful form
        if success:
            return redirect_to_return_url_or_else(request, reverse("groups"))
        # Add a breadcrumb
        add_breadcrumb(title="Delete Group", top_level=False, request=request)
        # Render the page
        return render(request, self.get_template(), context)


class AddGroup(View):
    def get_group_form(self, request: HttpRequest):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {}

        return DojoGroupForm(*args, **kwargs)

    def get_global_role_form(self, request: HttpRequest):
        # Set up the args for the form
        args = [request.POST] if request.method == "POST" else []
        # Set the initial form args
        kwargs = {}

        return GlobalRoleForm(*args, **kwargs)

    def get_initial_context(self, request: HttpRequest):
        return {
            "form": self.get_group_form(request),
            "global_role_form": self.get_global_role_form(request),
        }

    def process_forms(self, request: HttpRequest, context: dict):
        group = None
        # Validate the forms
        if context["form"].is_valid() and context["global_role_form"].is_valid():
            if context["global_role_form"].cleaned_data['role'] is not None and not request.user.is_superuser:
                messages.add_message(
                    request,
                    messages.ERROR,
                    'Only superusers are allowed to set global role.',
                    extra_tags='alert-warning')
            else:
                group = context["form"].save()
                global_role = context["global_role_form"].save(commit=False)
                global_role.group = group
                global_role.save()
                messages.add_message(
                    request,
                    messages.SUCCESS,
                    'Group was added successfully.',
                    extra_tags='alert-success')
                return request, group, True
        else:
            messages.add_message(
                request,
                messages.ERROR,
                'Group was not added successfully.',
                extra_tags='alert-danger')

        return request, group, False

    def get_template(self):
        return "dojo/add_group.html"

    def get(self, request: HttpRequest):
        # quick permission check
        if not user_has_configuration_permission(request.user, 'auth.add_group'):
            raise PermissionDenied
        # Set up the initial context
        context = self.get_initial_context(request)
        # Add a breadcrumb
        add_breadcrumb(title="Add Group", top_level=False, request=request)
        # Render the page
        return render(request, self.get_template(), context)

    def post(self, request: HttpRequest):
        # quick permission check
        if not user_has_configuration_permission(request.user, 'auth.add_group'):
            raise PermissionDenied
        # Set up the initial context
        context = self.get_initial_context(request)
        # Process the forms
        request, group, success = self.process_forms(request, context)
        # Handle the case of a successful form
        if success:
            return redirect_to_return_url_or_else(request, reverse("view_group", args=(group.id,)))
        # Add a breadcrumb
        add_breadcrumb(title="Add Group", top_level=False, request=request)
        # Render the page
        return render(request, self.get_template(), context)


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


@user_is_configuration_authorized('auth.change_permission')
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
