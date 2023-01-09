from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.validators import RegexValidator
from django.db import models
from django.utils.translation import gettext as _


User = get_user_model()


# proxy class for convenience and UI
class Dojo_User(User):
    class Meta:
        proxy = True
        ordering = ['first_name']

    def get_full_name(self):
        return Dojo_User.generate_full_name(self)

    def __str__(self):
        return self.get_full_name()

    @staticmethod
    def wants_block_execution(user):
        # this return False if there is no user, i.e. in celery processes, unittests, etc.
        return hasattr(user, 'usercontactinfo') and user.usercontactinfo.block_execution

    @staticmethod
    def force_password_reset(user):
        return hasattr(user, 'usercontactinfo') and user.usercontactinfo.force_password_reset

    def disable_force_password_reset(user):
        if hasattr(user, 'usercontactinfo'):
            user.usercontactinfo.force_password_reset = False
            user.usercontactinfo.save()

    def enable_force_password_reset(user):
        if hasattr(user, 'usercontactinfo'):
            user.usercontactinfo.force_password_reset = True
            user.usercontactinfo.save()

    @staticmethod
    def generate_full_name(user):
        """
        Returns the first_name plus the last_name, with a space in between.
        """
        full_name = '%s %s (%s)' % (user.first_name,
                                    user.last_name,
                                    user.username)
        return full_name.strip()


class UserContactInfo(models.Model):
    user = models.OneToOneField(Dojo_User, on_delete=models.CASCADE)
    title = models.CharField(blank=True, null=True, max_length=150)
    phone_regex = RegexValidator(regex=r'^\+?1?\d{9,15}$',
                                 message=_("Phone number must be entered in the format: '+999999999'. "
                                         "Up to 15 digits allowed."))
    phone_number = models.CharField(validators=[phone_regex], blank=True,
                                    max_length=15,
                                    help_text=_("Phone number must be entered in the format: '+999999999'. "
                                              "Up to 15 digits allowed."))
    cell_number = models.CharField(validators=[phone_regex], blank=True,
                                   max_length=15,
                                   help_text=_("Phone number must be entered in the format: '+999999999'. "
                                             "Up to 15 digits allowed."))
    twitter_username = models.CharField(blank=True, null=True, max_length=150)
    github_username = models.CharField(blank=True, null=True, max_length=150)
    slack_username = models.CharField(blank=True, null=True, max_length=150, help_text=_("Email address associated with your slack account"), verbose_name=_('Slack Email Address'))
    slack_user_id = models.CharField(blank=True, null=True, max_length=25)
    block_execution = models.BooleanField(default=False, help_text=_("Instead of async deduping a finding the findings will be deduped synchronously and will 'block' the user until completion."))
    force_password_reset = models.BooleanField(default=False, help_text=_('Forces this user to reset their password on next login.'))


class Dojo_Group(models.Model):
    AZURE = 'AzureAD'
    SOCIAL_CHOICES = (
        (AZURE, _('AzureAD')),
    )
    name = models.CharField(max_length=255, unique=True)
    description = models.CharField(max_length=4000, null=True, blank=True)
    users = models.ManyToManyField(Dojo_User, through='Dojo_Group_Member', related_name='users', blank=True)
    auth_group = models.ForeignKey(Group, null=True, blank=True, on_delete=models.CASCADE)
    social_provider = models.CharField(max_length=10, choices=SOCIAL_CHOICES, blank=True, null=True, help_text='Group imported from a social provider.', verbose_name='Social Authentication Provider')

    def __str__(self):
        return self.name


class Role(models.Model):
    name = models.CharField(max_length=255, unique=True)
    is_owner = models.BooleanField(default=False)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ('name',)


class Dojo_Group_Member(models.Model):
    group = models.ForeignKey(Dojo_Group, on_delete=models.CASCADE)
    user = models.ForeignKey(Dojo_User, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, help_text=_("This role determines the permissions of the user to manage the group."), verbose_name=_('Group role'))


class Global_Role(models.Model):
    user = models.OneToOneField(Dojo_User, null=True, blank=True, on_delete=models.CASCADE)
    group = models.OneToOneField(Dojo_Group, null=True, blank=True, on_delete=models.CASCADE)
    role = models.ForeignKey(Role, on_delete=models.CASCADE, null=True, blank=True, help_text=_("The global role will be applied to all product types and products."), verbose_name=_('Global role'))


class Contact(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    team = models.CharField(max_length=100)
    is_admin = models.BooleanField(default=False)
    is_globally_read_only = models.BooleanField(default=False)
    updated = models.DateTimeField(auto_now=True)
