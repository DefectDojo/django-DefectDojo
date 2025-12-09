from crum import get_current_user
from django.conf import settings
from django.contrib.auth.models import Group
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from dojo.models import Dojo_Group, Dojo_Group_Member, Role


def get_auth_group_name(group, attempt=0):
    if attempt > 999:
        msg = f"Cannot find name for authorization group for Dojo_Group {group.name}, aborted after 999 attempts."
        raise Exception(msg)
    auth_group_name = group.name if attempt == 0 else group.name + "_" + str(attempt)

    try:
        # Attempt to fetch an existing group before moving forward with the real operation
        _ = Group.objects.get(name=auth_group_name)
        return get_auth_group_name(group, attempt + 1)
    except Group.DoesNotExist:
        return auth_group_name


@receiver(post_save, sender=Dojo_Group)
def group_post_save_handler(sender, **kwargs):
    created = kwargs.pop("created")
    group = kwargs.pop("instance")
    if created:
        # Create authentication group
        auth_group = Group(name=get_auth_group_name(group))
        auth_group.save()
        group.auth_group = auth_group
        group.save()
        user = get_current_user()
        if user and not settings.AZUREAD_TENANT_OAUTH2_GET_GROUPS:
            # Add the current user as the owner of the group
            member = Dojo_Group_Member()
            member.user = user
            member.group = group
            member.role = Role.objects.get(is_owner=True)
            member.save()
            # Add user to authentication group as well
            auth_group.user_set.add(user)


@receiver(post_delete, sender=Dojo_Group)
def group_post_delete_handler(sender, **kwargs):
    group = kwargs.pop("instance")
    # Authorization group doesn't get deleted automatically
    if group.auth_group:
        group.auth_group.delete()


@receiver(post_save, sender=Dojo_Group_Member)
def group_member_post_save_handler(sender, **kwargs):
    created = kwargs.pop("created")
    group_member = kwargs.pop("instance")
    if created:
        # Add user to authentication group as well
        if group_member.group.auth_group:
            group_member.group.auth_group.user_set.add(group_member.user)


@receiver(post_delete, sender=Dojo_Group_Member)
def group_member_post_delete_handler(sender, **kwargs):
    group_member = kwargs.pop("instance")
    # Remove user from the authentication group as well
    if group_member.group.auth_group:
        group_member.group.auth_group.user_set.remove(group_member.user)
