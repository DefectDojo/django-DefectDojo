from dojo.utils import get_system_setting


class Permission_Helper:
    def __init__(self, *args, **kwargs):
        self.name = kwargs.pop('name')
        self.app = kwargs.pop('app')
        self.view = kwargs.pop('view', False)
        self.add = kwargs.pop('add', False)
        self.change = kwargs.pop('change', False)
        self.delete = kwargs.pop('delete', False)

    def display_name(self):
        if self.name == 'bannerconf':
            return 'Login Banner'
        elif self.name == 'cred user':
            return 'Credentials'
        elif self.name == 'github conf':
            return 'GitHub Configurations'
        elif self.name == 'engagement survey':
            return 'Questionnaires'
        elif self.name == 'permission':
            return 'Configuration Permissions'
        else:
            return self.name.title() + 's'

    def view_codename(self):
        if self.view:
            return f'view_{self.name.replace(" ", "_")}'
        else:
            return None

    def add_codename(self):
        if self.add:
            return f'add_{self.name.replace(" ", "_")}'
        else:
            return None

    def change_codename(self):
        if self.change:
            return f'change_{self.name.replace(" ", "_")}'
        else:
            return None

    def delete_codename(self):
        if self.delete:
            return f'delete_{self.name.replace(" ", "_")}'
        else:
            return None

    def codenames(self):
        codenames = []
        if self.view:
            codenames.append(self.view_codename())
        if self.add:
            codenames.append(self.add_codename())
        if self.change:
            codenames.append(self.change_codename())
        if self.delete:
            codenames.append(self.delete_codename())
        return codenames


def get_configuration_permissions_fields():

    if get_system_setting('enable_github'):
        github_permissions = [
            Permission_Helper(name='github conf', app='dojo', view=True, add=True, delete=True),
        ]
    else:
        github_permissions = []

    if get_system_setting('enable_google_sheets'):
        google_sheet_permissions = [
            Permission_Helper(name='google sheet', app='dojo', change=True),
        ]
    else:
        google_sheet_permissions = []

    if get_system_setting('enable_jira'):
        jira_permissions = [
            Permission_Helper(name='jira instance', app='dojo', view=True, add=True, change=True, delete=True),
        ]
    else:
        jira_permissions = []

    if get_system_setting('enable_questionnaires'):
        questionnaire_permissions = [
            Permission_Helper(name='engagement survey', app='dojo', view=True, add=True, change=True, delete=True),
            Permission_Helper(name='question', app='dojo', view=True, add=True, change=True),
        ]
    else:
        questionnaire_permissions = []

    if get_system_setting('enable_rules_framework'):
        rules_permissions = [
            Permission_Helper(name='rule', app='auth', view=True, add=True, change=True, delete=True),
        ]
    else:
        rules_permissions = []

    permission_fields = [
        Permission_Helper(name='cred user', app='dojo', view=True, add=True, change=True, delete=True),
        Permission_Helper(name='development environment', app='dojo', add=True, change=True, delete=True),
        Permission_Helper(name='finding template', app='dojo', view=True, add=True, change=True, delete=True)] + \
        github_permissions + \
        google_sheet_permissions + [
        Permission_Helper(name='group', app='auth', view=True, add=True)] + \
        jira_permissions + [
        Permission_Helper(name='language type', app='dojo', view=True, add=True, change=True, delete=True),
        Permission_Helper(name='bannerconf', app='dojo', change=True),
        Permission_Helper(name='note type', app='dojo', view=True, add=True, change=True, delete=True),
        Permission_Helper(name='product type', app='dojo', add=True)] + \
        questionnaire_permissions + [
        Permission_Helper(name='regulation', app='dojo', add=True, change=True, delete=True)] + \
        rules_permissions + [
        Permission_Helper(name='test type', app='dojo', add=True, change=True),
        Permission_Helper(name='tool configuration', app='dojo', view=True, add=True, change=True, delete=True),
        Permission_Helper(name='tool type', app='dojo', view=True, add=True, change=True, delete=True),
        Permission_Helper(name='user', app='auth', view=True, add=True, change=True, delete=True),
    ]

    return permission_fields


def get_configuration_permissions_codenames():
    codenames = []

    for permission_field in get_configuration_permissions_fields():
        codenames.extend(permission_field.codenames())

    return codenames
