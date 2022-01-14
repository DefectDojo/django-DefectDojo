import logging
import sys
from django.conf import settings
from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission

from dojo.models import Dojo_Group, Dojo_Group_Member, Dojo_User, Global_Role, Role


logger = logging.getLogger(__name__)


class Command(BaseCommand):
    """
    This management command creates a group for staff users with all configuration
    permissions staff users had in previous releases and global owner role if
    AUTHORIZATION_STAFF_OVERRIDE is set to True.
    """
    help = 'Usage: manage.py migrate_staff_users'

    def handle(self, *args, **options):

        # If group already exists, then the migration has been running before
        group_name = 'Staff users'
        groups = Dojo_Group.objects.filter(name=group_name).count()
        if groups > 0:
            sys.exit(f'Group {group_name} already exists, migration aborted')

        # The superuser with the lowest id will be set as the owner of the group
        users = Dojo_User.objects.filter(is_superuser=True).order_by('id')
        if len(users) == 0:
            sys.exit('No superuser found, migration aborted')
        user = users[0]

        group = Dojo_Group(name=group_name, description='Migrated staff users')
        group.save()

        owner_role = Role.objects.get(is_owner=True)

        owner = Dojo_Group_Member(
            user=user,
            group=group,
            role=owner_role,
        )
        owner.save()

        # All staff users are made to members of the group
        reader_role = Role.objects.get(name='Reader')
        staff_users = Dojo_User.objects.filter(is_staff=True)
        for staff_user in staff_users:
            if staff_user != owner.user:
                member = Dojo_Group_Member(
                    user=staff_user,
                    group=group,
                    role=reader_role,
                )
                member.save()

        # If AUTHORIZATION_STAFF_OVERRIDE is True, then the group is made a global owner
        if settings.AUTHORIZATION_STAFF_OVERRIDE:
            global_role = Global_Role(group=group, role=owner_role)
            global_role.save()

        permissions_list = Permission.objects.all()
        permissions = {}
        for permission in permissions_list:
            permissions[permission.codename] = permission

        # Set the same configuration permissions, staff users had in previous releases
        auth_group = group.auth_group
        if not auth_group:
            sys.exit('Group has no auth_group, migration aborted')

        auth_group.permissions.add(permissions['view_group'])
        auth_group.permissions.add(permissions['add_group'])
        auth_group.permissions.add(permissions['view_development_environment'])
        auth_group.permissions.add(permissions['add_development_environment'])
        auth_group.permissions.add(permissions['change_development_environment'])
        auth_group.permissions.add(permissions['delete_development_environment'])
        auth_group.permissions.add(permissions['view_finding_template'])
        auth_group.permissions.add(permissions['add_finding_template'])
        auth_group.permissions.add(permissions['change_finding_template'])
        auth_group.permissions.add(permissions['delete_finding_template'])
        auth_group.permissions.add(permissions['view_engagement_survey'])
        auth_group.permissions.add(permissions['add_engagement_survey'])
        auth_group.permissions.add(permissions['change_engagement_survey'])
        auth_group.permissions.add(permissions['delete_engagement_survey'])
        auth_group.permissions.add(permissions['view_question'])
        auth_group.permissions.add(permissions['add_question'])
        auth_group.permissions.add(permissions['change_question'])
        auth_group.permissions.add(permissions['delete_question'])
        auth_group.permissions.add(permissions['view_test_type'])
        auth_group.permissions.add(permissions['add_test_type'])
        auth_group.permissions.add(permissions['change_test_type'])
        auth_group.permissions.add(permissions['delete_test_type'])
        auth_group.permissions.add(permissions['view_user'])
        auth_group.permissions.add(permissions['add_product_type'])

        logger.info(f'Migrated {len(staff_users)} staff users')
