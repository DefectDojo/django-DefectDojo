from crum import get_current_user
from django.contrib.auth.models import Group
from dojo.models import Dojo_Group_Member, Role


def get_auth_group_name(group, attempt):
    if attempt > 999:
        raise Exception(f'Cannot find name for authorization group for Dojo_Group {group.name}, aborted after 999 attempts.')
    if attempt == 0:
        auth_group_name = group.name
    else:
        auth_group_name = group.name + '_' + str(attempt)

    try:
        auth_group = Group.objects.get(name=auth_group_name)
        return get_auth_group_name(group, attempt + 1)
    except Group.DoesNotExist:
        return auth_group_name


def group_post_create(group):
    # Add the current user as the owner of the group
    member = Dojo_Group_Member()
    member.user = get_current_user()
    member.group = group
    member.role = Role.objects.get(is_owner=True)
    member.save()
    # Create authentication group
    auth_group = Group(name=get_auth_group_name(group, 0))
    auth_group.save()
    group.auth_group = auth_group
    group.save()
    # Add user to authentication group as well
    auth_group.user_set.add(get_current_user())


def group_post_delete(group):
    # Authorization group doesn't get deleted automatically
    if group.auth_group:
        group.auth_group.delete()


def group_member_post_create(group_member):
    # Add user to authentication group as well
    if group_member.group.auth_group:
        group_member.group.auth_group.user_set.add(group_member.user)


def group_member_post_delete(group_member):
    # Remove user from the authentication group as well
    if group_member.group.auth_group:
        group_member.group.auth_group.user_set.remove(group_member.user)
