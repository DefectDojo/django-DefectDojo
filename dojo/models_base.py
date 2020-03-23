"""
A set of classes and functions to be used by all models.
"""

import os
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.db.models import Model
from django.utils.deconstruct import deconstructible
from django.utils.decorators import classonlymethod
from django.utils.timezone import now
from django_flexquery import Manager, Q, QuerySet  # noqa: F401
from django_flexquery.contrib.user_based import UserBasedFlexQuery
import rules
from rules.contrib.models import RulesModelBase, RulesModelMixin


User = get_user_model()


def get_perm(perm_type, obj):
    """Returns the name of the permission with given type for a model.

    perm_type must be one of "add", "change", "delete" and "filter".
    obj can either be a model class, concrete model instance or string with model name.
    A ValueError is raised for invalid permission types, TypeError for invalid obj.
    """
    if perm_type not in ("add", "change", "delete", "filter"):
        raise ValueError("invalid permission type {!r}".format(perm_type))
    if isinstance(obj, Model) or isinstance(obj, type) and issubclass(obj, Model):
        model_name = obj._meta.model_name
    elif isinstance(obj, str):
        model_name = obj
    else:
        raise TypeError("{!r} is no model, model instance or model name".format(obj))
    return "dojo.{}_{}".format(perm_type, model_name)


class DojoModel(RulesModelMixin, Model, metaclass=RulesModelBase):
    """
    Abstract base class adding common functionality to be used for all models of Dojo.
    """

    @classmethod
    def get_perm(cls, perm_type):
        return get_perm(perm_type, cls)

    @staticmethod
    def preprocess_rules_permissions(perms):
        """Sets defaults for unspecified permissions.

        The base queryset already gets restricted for the current user, hence this
        just allows a user to write everything he has access to via its base queryset,
        aka everything he can read.

        - "add": rules.is_authenticated
        - "change": rules.is_authenticated
        - "delete": the same as "change"
        - "filter": rules.is_authenticated, since the base queryset already gets
          restricted for the particular user and you usually don't want to forbid
          filtering entirely unless a model should be totally hidden to some users.
        """
        perms.setdefault("add", rules.is_authenticated)
        perms.setdefault("delete", perms.setdefault("change", rules.is_authenticated))
        perms.setdefault("filter", rules.is_authenticated)

    class Meta:
        abstract = True


class DojoUserBasedFlexQuery(UserBasedFlexQuery):
    """
    Treats an anonymous user as if it was no user.
    """

    pass_anonymous_user = False


class DojoQuerySet(QuerySet):
    """
    Custom QuerySet implementation that's used to derive the default manager for
    all models of Dojo from.

    A UserBasedFlexQuery is attached as the for_user attribute, with the default
    implementation performing no filtering. Either overwrite for_user with a custom
    DojoUserBasedFlexQuery when subclassing or use the with_for_user() classmethod to
    create a new DojoQuerySet type with model-specific filtering on-the-fly.
    """

    def complement(self):
        """QuerySet of all objects of the model's default manager not in this QuerySet.

        A lazy sub-query is used for selecting the original QuerySet's primary keys.
        """
        return self.model._default_manager.exclude(pk__in=self)

    @DojoUserBasedFlexQuery.from_func
    def for_user(base, req_or_user):
        """The default implementation does no filtering."""
        return Q()

    @classonlymethod
    def manager_with_for_user(cls, flexquery_func):
        """Shortcut for building a for_user()-capable Manager on-the-fly.

        This helper creates a new sub-type of DojoQuerySet with a DojoUserBasedFlexQuery
        from the given function attached as its for_user attribute. Then, as_manager()
        is called on that new type and the Manager instance returned.
        """
        return type(cls)(
            cls.__name__,
            (cls,),
            {"for_user": DojoUserBasedFlexQuery.from_func(flexquery_func)},
        ).as_manager()


@deconstructible
class UniqueUploadNameProvider:
    """
    A callable to be passed as upload_to parameter to FileField.

    Uploaded files will get random names based on UUIDs inside the given directory;
    strftime-style formatting is supported within the directory path. If keep_basename
    is True, the original file name is prepended to the UUID. If keep_ext is disabled,
    the filename extension will be dropped.
    """

    def __init__(self, directory=None, keep_basename=False, keep_ext=True):
        self.directory = directory
        self.keep_basename = keep_basename
        self.keep_ext = keep_ext

    def __call__(self, model_instance, filename):
        base, ext = os.path.splitext(filename)
        filename = "%s_%s" % (base, uuid4()) if self.keep_basename else str(uuid4())
        if self.keep_ext:
            filename += ext
        if self.directory is None:
            return filename
        return os.path.join(now().strftime(self.directory), filename)
