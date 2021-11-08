from django.contrib.auth.models import Group


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
