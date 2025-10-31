import logging
import re
from functools import cached_property

from django.conf import settings
from djangosaml2.backends import Saml2Backend as _Saml2Backend

from dojo.authorization.roles_permissions import Roles
from dojo.models import Dojo_Group, Dojo_Group_Member, Role

logger = logging.getLogger(__name__)


class Saml2Backend(_Saml2Backend):

    """Subclass to handle adding SAML2 groups as DefectDojo/Django groups to a user"""

    @cached_property
    def group_re(self):
        if settings.SAML2_ENABLED and settings.SAML2_GROUPS_ATTRIBUTE:
            if settings.SAML2_GROUPS_FILTER:
                return re.compile(settings.SAML2_GROUPS_FILTER)
            return re.compile(r".*")
        return None

    def _update_user(
        self,
        user,
        attributes: dict,
        attribute_mapping: dict,
        force_save=False,  # noqa: FBT002 - caannot add `*`, need to keep same signature as parent class
    ):
        """
        Method overriden to handle groups after user object is saved.
        Ideally we would only override "public" methods: in this case, get_or_create_user() would be the one but it doesn't save the NEW user
        We could override that AND save_user() (each to handle new or existing users) but the latter does not receive the attributes which include the groups...

        Similar to AzureAD, this creates the matching SAML groups if they do not already exist.
        """
        user = super()._update_user(user, attributes, attribute_mapping, force_save=force_save)
        if self.group_re is None:
            return user

        self._process_user_groups(user, attributes)
        return user

    def _process_user_groups(self, user, attributes):
        # list of all existing "SAML2-mapped" groups - regexp excluded so the ones no longer matching regexp are removed
        all_saml_groups = {group.name: group for group in Dojo_Group.objects.filter(social_provider=Dojo_Group.SAML)}

        # list of groups user MUST have
        needs_groups = set()
        if attributes[settings.SAML2_GROUPS_ATTRIBUTE]:
            needs_groups.update(
                group_name
                for group_name in attributes[settings.SAML2_GROUPS_ATTRIBUTE]
                if self.group_re.match(group_name)
            )

        # list of groups user ALREADY has
        has_groups = {
            dgm.group.name: dgm
            for dgm in Dojo_Group_Member.objects.filter(user_id=user.id).select_related("group")
            if dgm.group.name in all_saml_groups
        }

        groups_to_remove = has_groups.keys() - needs_groups
        groups_to_add = needs_groups - has_groups.keys()

        if groups_to_remove:
            # bulk .delete() can be used as it emits post_delete signal
            deleted, _ = Dojo_Group_Member.objects.filter(user_id=user.id, group__name__in=groups_to_remove).delete()
            logger.info("User %s removed from SAML2 groups: %s", user, ", ".join(groups_to_remove))
            if deleted != len(groups_to_remove):
                logger.error("User %s had %d groups to be removed but %d were", user, len(groups_to_remove), deleted)

        if groups_to_add:
            # .bulk_create() cannot be used as it does NOT emit post_save signal
            reader_role = Role.objects.get(id=Roles.Reader)
            for group_name in groups_to_add:
                group = all_saml_groups.get(group_name)
                if group is None:
                    group = Dojo_Group.objects.create(name=group_name, social_provider=Dojo_Group.SAML)
                    logger.error("Group %s did not exist locally so it was created", group_name)

                Dojo_Group_Member.objects.create(group=group, user_id=user.pk, role=reader_role)
                logger.debug("User %s became member of SAML2 group: %s", user, group.name)
        return user
