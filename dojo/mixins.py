from django.views.generic import CreateView, DeleteView, DetailView, UpdateView
from django.views.generic.detail import SingleObjectMixin
from django_filters.views import FilterView
from rules.contrib.rest_framework import AutoPermissionViewSetMixin
from rules.contrib.views import AutoPermissionRequiredMixin
from titlecase import titlecase

from .utils import add_breadcrumb


class DojoPermissionAPIViewSetMixin(AutoPermissionViewSetMixin):
    """
    Filters the base queryset for the current user and enforces object-level
    permissions.

    This mixin has to be used with rest_framework.viewsets.ViewSet.
    """

    # No need to check view permission because the base queryset is restricted
    permission_type_map = {
        **AutoPermissionViewSetMixin.permission_type_map,
        "list": "filter",
        "retrieve": None,
    }

    def get_queryset(self):
        """Restrict the queryset based on the requesting user."""
        return super().get_queryset().for_user(self.request)


class DojoPermissionViewMixin(AutoPermissionRequiredMixin):
    """
    A mixin for class-based views that checks for the correct model permission.
    """

    permission_type_map = [
        (CreateView, "add"),
        (UpdateView, "change"),
        (DeleteView, "delete"),
        (DetailView, None),
        (FilterView, "filter"),
    ]

    # Raise a 403 instead of redirecting to the login page when permission is denied
    raise_exception = True

    def get_queryset(self):
        """Restricts the QuerySet the view acts upon for the requesting user."""
        return super().get_queryset().for_user(self.request)


class DojoBreadcrumbViewMixin:
    """
    A mixin for class-based views allowing to specify breadcrumb data.

    It can auto-generate titles and detect parent objects for the base view types
    that DojoPermissionViewMixin supports as well.
    """

    # Set to the desired values in your view implementation or overwrite the get_*
    # methods for dynamic values.
    # In the title string, you can use {} formatting with the following keys:
    # - obj: value of self.get_object(), only available in single object views
    # - verbose_name: the verbose name of the associated model
    # - verbose_name_plural: the pluralized verbose name of the associated model
    title = None
    # Whether to put the title in title case.
    titlecase = True

    def get_parent_object(self):
        """Returns the parent object for use in breadcrumbs."""
        if isinstance(self, (UpdateView, DeleteView)):
            return self.get_object()
        return None

    def get_title(self):
        """Returns self.title in title case, if set, otherwise tries auto-generation."""
        # Perform auto detection by view type, needed to build the formatting keys
        title = None
        obj = None
        if isinstance(self, FilterView):
            model = self.get_filterset_class()._meta.model
            title = "{verbose_name_plural}"
        elif isinstance(self, SingleObjectMixin):
            model = self.get_queryset().model
            if isinstance(self, CreateView):
                title = "Create new {verbose_name}"
            else:
                obj = self.get_object()
                if isinstance(self, UpdateView):
                    title = "Update {verbose_name} {obj}"
                elif isinstance(self, DeleteView):
                    title = "Delete {verbose_name} {obj}"
                elif isinstance(self, DetailView):
                    title = "{verbose_name} {obj}"

        title = title if self.title is None else self.title
        if title is not None:
            return title.format(
                obj=obj,
                verbose_name=model._meta.verbose_name,
                verbose_name_plural=model._meta.verbose_name_plural,
            )

    def get_context_data(self, **kwargs):
        """Adds breadcrumbs. The page title is also added as context["title"]."""
        context = super().get_context_data(**kwargs)
        title = self.get_title()
        if title is not None:
            if self.titlecase:
                title = titlecase(title)
            context.setdefault("title", title)
            add_breadcrumb(
                title=title, parent=self.get_parent_object(), request=self.request
            )
        return context


class DojoViewMixin(DojoBreadcrumbViewMixin, DojoPermissionViewMixin):
    """
    A combination of the following mixins, which usually are used together:
    - dojo.mixins.DojoBreadcrumbViewMixin
    - dojo.mixins.DojoPermissionViewMixin
    """


class SuccessRedirectBackViewMixin:
    """
    A mixin to be used with Django's Editing Mixins.

    It overwrites get_success_url() to return an URL submitted with the form or,
    if that's not available, the value of HTTP_REFERER.

    Include dojo/snippets/form/success_redirect_back.html in your form template
    when using this mixin.
    """

    def get_success_url(self):
        """Tries to get _success_url from submitted data, HTTP_REFERER as fallback."""
        if self.request.method in ("POST", "PUT"):
            data = self.request.POST
        else:
            data = self.request.GET
        return data.get("_success_url") or self.request.META.get("HTTP_REFERER") or "/"

    def get_context_data(self, *args, **kwargs):
        """Adds  success_url to the context."""
        context = super().get_context_data(*args, **kwargs)
        context["success_url"] = self.get_success_url()
        return context
