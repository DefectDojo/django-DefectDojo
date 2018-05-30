# see tastypie documentation at http://django-tastypie.readthedocs.org/en
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.urlresolvers import resolve, get_script_prefix
from tastypie import fields
from tastypie.fields import RelatedField
from tastypie.authentication import ApiKeyAuthentication
from tastypie.authorization import Authorization
from tastypie.authorization import DjangoAuthorization
from tastypie.constants import ALL, ALL_WITH_RELATIONS
from tastypie.exceptions import Unauthorized, ImmediateHttpResponse, NotFound
from tastypie.http import HttpCreated
from tastypie.resources import ModelResource, Resource
from tastypie.serializers import Serializer
from tastypie.validation import FormValidation, Validation
from django.urls.exceptions import Resolver404
from django.utils import timezone


from dojo.models import Product, Engagement, Test, Finding, \
    User, ScanSettings, IPScan, Scan, Stub_Finding, Risk_Acceptance, \
    Finding_Template, Test_Type, Development_Environment, \
    BurpRawRequestResponse, Endpoint, Notes, JIRA_PKey, JIRA_Conf, \
    JIRA_Issue, Tool_Product_Settings, Tool_Configuration, Tool_Type, \
    Languages, Language_Type, App_Analysis
from dojo.forms import ProductForm, EngForm2, TestForm, \
    ScanSettingsForm, FindingForm, StubFindingForm, FindingTemplateForm, \
    ImportScanForm, SEVERITY_CHOICES, JIRAForm, JIRA_PKeyForm, EditEndpointForm, \
    JIRA_IssueForm, ToolConfigForm, ToolProductSettingsForm, \
    ToolTypeForm, LanguagesTypeForm, Languages_TypeTypeForm, App_AnalysisTypeForm
from dojo.tools.factory import import_parser_factory
from datetime import datetime
from object.parser import import_object_eng

"""
    Setup logging for the api

logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] %(levelname)s [%(name)s:%(lineno)d] %(message)s',
    datefmt='%d/%b/%Y %H:%M:%S',
    filename=settings.DOJO_ROOT + '/../dojo.log',
)
logger = logging.getLogger(__name__)
"""


class ModelFormValidation(FormValidation):
    """
    Override tastypie's standard ``FormValidation`` since this does not care
    about URI to PK conversion for ``ToOneField`` or ``ToManyField``.
    """

    resource = ModelResource

    def __init__(self, **kwargs):
        if 'resource' not in kwargs:
            raise ImproperlyConfigured("You must provide a 'resource' to 'ModelFormValidation' classes.")

        self.resource = kwargs.pop('resource')

        super(ModelFormValidation, self).__init__(**kwargs)

    def _get_pk_from_resource_uri(self, resource_field, resource_uri):
        """ Return the pk of a resource URI """
        base_resource_uri = resource_field.to().get_resource_uri()
        if not resource_uri.startswith(base_resource_uri):
            raise Exception("Couldn't match resource_uri {0} with {1}".format(resource_uri, base_resource_uri))
        before, after = resource_uri.split(base_resource_uri)
        return after[:-1] if after.endswith('/') else after

    def form_args(self, bundle):
        rsc = self.resource()
        kwargs = super(ModelFormValidation, self).form_args(bundle)

        for name, rel_field in rsc.fields.items():
            data = kwargs['data']
            if not issubclass(rel_field.__class__, RelatedField):
                continue  # Not a resource field
            if name in data and data[name] is not None:
                resource_uri = (data[name] if rel_field.full is False
                                            else data[name]['resource_uri'])
                pk = self._get_pk_from_resource_uri(rel_field, resource_uri)
                kwargs['data'][name] = pk

        return kwargs


class BaseModelResource(ModelResource):
    @classmethod
    def get_fields(cls, fields=None, excludes=None):
        """
         Unfortunately we must override this method because tastypie ignores
         'blank' attribute on model fields.

         Here we invoke an insane workaround hack due to metaclass inheritance
         issues:
          http://stackoverflow.com/questions/12757468/invoking-super-in-classmethod-called-from-metaclass-new
        """
        this_class = next(
            c for c in cls.__mro__
            if c.__module__ == __name__ and c.__name__ == 'BaseModelResource')
        fields = super(this_class, cls).get_fields(fields=fields,
                                                   excludes=excludes)
        if not cls._meta.object_class:
            return fields
        for django_field in cls._meta.object_class._meta.fields:
            if django_field.blank is True:
                res_field = fields.get(django_field.name, None)
                if res_field:
                    res_field.blank = True
        return fields


class MultipartResource(object):
    def deserialize(self, request, data, format=None):
        if not format:
            format = request.Meta.get('CONTENT_TYPE', 'application/json')
        if format == 'application/x-www-form-urlencoded':
            return request.POST
        if format.startswith('multipart'):
            data = request.POST.copy()
            data.update(request.FILES)
            return data

        return super(MultipartResource, self).deserialize(request, data, format)

# Authentication class - this only allows for header auth, no url parms allowed
# like parent class.


class DojoApiKeyAuthentication(ApiKeyAuthentication):
    def extract_credentials(self, request):
        if (request.META.get('HTTP_AUTHORIZATION') and
                request.META['HTTP_AUTHORIZATION'].lower().startswith('apikey ')):
            (auth_type, data) = request.META['HTTP_AUTHORIZATION'].split()

            if auth_type.lower() != 'apikey':
                raise ValueError("Incorrect authorization header.")

            username, api_key = data.split(':', 1)
        else:
            raise ValueError("Incorrect authorization header.")

        return username, api_key


# Authorization class for Product
class UserProductsOnlyAuthorization(Authorization):
    def read_list(self, object_list, bundle):
        # This assumes a ``QuerySet`` from ``ModelResource``.
        if bundle.request.user.is_staff:
            return object_list
        return object_list.filter(authorized_users__in=[bundle.request.user])

    def read_detail(self, object_list, bundle):
        # Is the requested object owned by the user?
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.authorized_users)

    def create_list(self, object_list, bundle):
        # Assuming they're auto-assigned to ``user``.
        return object_list.filter(authorized_users__in=[bundle.request.user])

    def create_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.authorized_users)

    def update_list(self, object_list, bundle):
        allowed = []

        # Since they may not all be saved, iterate over them.
        for obj in object_list:
            if (bundle.request.user.is_staff or
                        bundle.request.user in bundle.obj.authorized_users):
                allowed.append(obj)

        return allowed

    def update_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.authorized_users)

    def delete_list(self, object_list, bundle):
        # Sorry user, no deletes for you!
        raise Unauthorized("Sorry, no deletes.")

    def delete_detail(self, object_list, bundle):
        raise Unauthorized("Sorry, no deletes.")


# Authorization class for Scan Settings
class UserScanSettingsAuthorization(Authorization):
    def read_list(self, object_list, bundle):
        # This assumes a ``QuerySet`` from ``ModelResource``.
        if bundle.request.user.is_staff:
            return object_list

        return object_list.filter(product__authorized_users__in=[
            bundle.request.user])

    def read_detail(self, object_list, bundle):
        # Is the requested object owned by the user?
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.product.authorized_users)

    def create_list(self, object_list, bundle):
        # Assuming they're auto-assigned to ``user``.
        if bundle.request.user.is_staff:
            return object_list
        else:
            return object_list.filter(
                product__authorized_users__in=[bundle.request.user])

    def create_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.product.authorized_users)

    def update_list(self, object_list, bundle):
        allowed = []

        # Since they may not all be saved, iterate over them.
        for obj in object_list:
            if (bundle.request.user.is_staff or
                        bundle.request.user in
                        bundle.obj.product.authorized_users):
                allowed.append(obj)

        return allowed

    def update_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.product.authorized_users)

    def delete_list(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.product.authorized_users)

    def delete_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in bundle.obj.product.authorized_users)


# Authorization class for Scan Settings
class UserScanAuthorization(Authorization):
    def read_list(self, object_list, bundle):
        # This assumes a ``QuerySet`` from ``ModelResource``.
        if bundle.request.user.is_staff:
            return object_list

        return object_list.filter(
            scan_settings__product__authorized_users__in=[
                bundle.request.user])

    def read_detail(self, object_list, bundle):
        # Is the requested object owned by the user?
        return (bundle.request.user.is_staff or
                bundle.request.user in
                bundle.obj.scan_settings.product.authorized_users)

    def create_list(self, object_list, bundle):
        # Assuming they're auto-assigned to ``user``.
        if bundle.request.user.is_staff:
            return object_list
        else:
            return object_list.filter(
                scan_settings__product__authorized_users__in=[
                    bundle.request.user])

    def create_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in
                bundle.obj.scan_settings.product.authorized_users)

    def update_list(self, object_list, bundle):
        allowed = []

        # Since they may not all be saved, iterate over them.
        for obj in object_list:
            if (bundle.request.user.is_staff or
                        bundle.request.user in
                        bundle.obj.scan_settings.product.authorized_users):
                allowed.append(obj)

        return allowed

    def update_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in
                bundle.obj.scan_settings.product.authorized_users)

    def delete_list(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in
                bundle.obj.scan_settings.product.authorized_users)

    def delete_detail(self, object_list, bundle):
        return (bundle.request.user.is_staff or
                bundle.request.user in
                bundle.obj.scan_settings.product.authorized_users)


"""
  Look up resource only, no update, store, delete
"""


class UserResource(BaseModelResource):
    class Meta:
        queryset = User.objects.all()
        resource_name = 'users'
        fields = ['id', 'username', 'first_name', 'last_name', 'last_login']

        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'username': ALL,
            'first_name': ALL,
            'last_name': ALL
        }
        authorization = DjangoAuthorization()
        authentication = DojoApiKeyAuthentication()
        serializer = Serializer(formats=['json'])


"""
    POST, PUT
    Expects *product name, *description, *prod_type [1-7]
"""


class ProductResource(BaseModelResource):
    class Meta:
        resource_name = 'products'
        # disabled delete. Should not be allowed without fine authorization.
        list_allowed_methods = ['get', 'post']  # only allow get for lists
        detail_allowed_methods = ['get', 'post', 'put']
        queryset = Product.objects.all().order_by('name')
        ordering = ['name', 'id', 'description', 'findings_count', 'created',
                    'product_type_id']
        excludes = ['tid', 'manager', 'prod_manager', 'tech_contact',
                    'updated']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'name': ALL,
            'prod_type': ALL,
            'created': ALL,
            'findings_count': ALL
        }
        authentication = DojoApiKeyAuthentication()
        authorization = UserProductsOnlyAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=ProductForm, resource=ProductResource)

    def dehydrate(self, bundle):
        # Append the tags in a comma delimited list with the tag element
        """
        tags = ""
        for tag in bundle.obj.tags:
            tags = tags + str(tag) + ","
        if len(tags) > 0:
            tags = tags[:-1]
        bundle.data['tags'] = tags
        """
        try:
            bundle.data['prod_type'] = bundle.obj.prod_type
        except:
            bundle.data['prod_type'] = 'unknown'
        bundle.data['findings_count'] = bundle.obj.findings_count
        return bundle

    def obj_create(self, bundle, request=None, **kwargs):
        bundle = super(ProductResource, self).obj_create(bundle)
        """
        tags = bundle.data['tags']
        bundle.obj.tags = tags
        """
        return bundle

    def obj_update(self, bundle, request=None, **kwargs):
        bundle = super(ProductResource, self).obj_update(bundle, request, **kwargs)
        """
        tags = bundle.data['tags']
        bundle.obj.tags = tags
        """
        return bundle


"""
    POST, PUT [/id/]
    Expects *product *target_start, *target_end, *status[In Progress, On Hold,
    Completed], threat_model, pen_test, api_test, check_list
"""


class EngagementResource(BaseModelResource):
    product = fields.ForeignKey(ProductResource, 'product',
                                full=False, null=False)
    lead = fields.ForeignKey(UserResource, 'lead',
                             full=False, null=True)

    class Meta:
        resource_name = 'engagements'
        list_allowed_methods = ['get', 'post']
        # disabled delete for /id/
        detail_allowed_methods = ['get', 'post', 'put']
        queryset = Engagement.objects.all()
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'active': ALL,
            'eng_type': ALL,
            'target_start': ALL,
            'target_end': ALL,
            'requester': ALL,
            'report_type': ALL,
            'updated': ALL,
            'threat_model': ALL,
            'api_test': ALL,
            'pen_test': ALL,
            'status': ALL,
            'product': ALL,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=EngForm2, resource=EngagementResource)

    def dehydrate(self, bundle):
        if bundle.obj.eng_type is not None:
            bundle.data['eng_type'] = bundle.obj.eng_type.name
        else:
            bundle.data['eng_type'] = None
        bundle.data['product_id'] = bundle.obj.product.id
        bundle.data['report_type'] = bundle.obj.report_type
        bundle.data['requester'] = bundle.obj.requester
        return bundle


"""
    /api/v1/app_analysis/
    GET [/id/], DELETE [/id/]
    Expects: no params or id
    Returns Tool_ConfigurationResource
    Relevant apply filter ?test_type=?, ?id=?

    POST, PUT, DLETE [/id/]
"""


class App_AnalysisResource(BaseModelResource):

    product = fields.ForeignKey(ProductResource, 'product',
                                full=False, null=False)

    user = fields.ForeignKey(UserResource, 'user', null=False)

    class Meta:
        resource_name = 'app_analysis'
        list_allowed_methods = ['get', 'post', 'put', 'delete']
        detail_allowed_methods = ['get', 'post', 'put', 'delete']
        queryset = App_Analysis.objects.all()
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'product': ALL_WITH_RELATIONS,
            'user': ALL,
            'confidence': ALL,
            'version': ALL,
            'icon': ALL,
            'website': ALL,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=App_AnalysisTypeForm, resource=App_AnalysisResource)


"""
    /api/v1/language_types/
    GET [/id/], DELETE [/id/]
    Expects: no params or id
    Returns Tool_ConfigurationResource
    Relevant apply filter ?test_type=?, ?id=?

    POST, PUT, DLETE [/id/]
"""


class LanguageTypeResource(BaseModelResource):

    class Meta:
        resource_name = 'language_types'
        list_allowed_methods = ['get', 'post', 'put', 'delete']
        detail_allowed_methods = ['get', 'post', 'put', 'delete']
        queryset = Language_Type.objects.all()
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'language': ALL,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=Languages_TypeTypeForm, resource=LanguageTypeResource)


"""
    /api/v1/languages/
    GET [/id/], DELETE [/id/]
    Expects: no params or id
    Returns Tool_ConfigurationResource
    Relevant apply filter ?test_type=?, ?id=?

    POST, PUT, DLETE [/id/]
"""


class LanguagesResource(BaseModelResource):

    product = fields.ForeignKey(ProductResource, 'product',
                                full=False, null=False)

    language_type = fields.ForeignKey(LanguageTypeResource, 'language', full=False, null=False)

    user = fields.ForeignKey(UserResource, 'user', null=False)

    class Meta:
        resource_name = 'languages'
        list_allowed_methods = ['get', 'post', 'put', 'delete']
        detail_allowed_methods = ['get', 'post', 'put', 'delete']
        queryset = Languages.objects.all()
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'files': ALL,
            'language_type': ALL_WITH_RELATIONS,
            'product': ALL_WITH_RELATIONS,
            'user': ALL,
            'blank': ALL,
            'comment': ALL,
            'code': ALL
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=LanguagesTypeForm, resource=LanguagesResource)


"""
    /api/v1/tool_configurations/
    GET [/id/], DELETE [/id/]
    Expects: no params or id
    Returns Tool_ConfigurationResource
    Relevant apply filter ?test_type=?, ?id=?

    POST, PUT, DLETE [/id/]
"""


class Tool_TypeResource(BaseModelResource):

    class Meta:
        resource_name = 'tool_types'
        list_allowed_methods = ['get', 'post', 'put', 'delete']
        detail_allowed_methods = ['get', 'post', 'put', 'delete']
        queryset = Tool_Type.objects.all()
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'name': ALL,
            'description': ALL,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=ToolTypeForm, resource=Tool_TypeResource)


"""
    /api/v1/tool_configurations/
    GET [/id/], DELETE [/id/]
    Expects: no params or id
    Returns Tool_ConfigurationResource
    Relevant apply filter ?test_type=?, ?id=?

    POST, PUT, DLETE [/id/]
"""


class Tool_ConfigurationResource(BaseModelResource):

    tool_type = fields.ForeignKey(Tool_TypeResource, 'tool_type', full=False, null=False)

    class Meta:
        resource_name = 'tool_configurations'
        list_allowed_methods = ['get', 'post', 'put', 'delete']
        detail_allowed_methods = ['get', 'post', 'put', 'delete']
        queryset = Tool_Configuration.objects.all()
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'name': ALL,
            'tool_type': ALL_WITH_RELATIONS,
            'name': ALL,
            'tool_project_id': ALL,
            'url': ALL,
            'authentication_type': ALL,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=ToolConfigForm, resource=Tool_ConfigurationResource)


"""
    /api/v1/tool_product_settings/
    GET [/id/], DELETE [/id/]
    Expects: no params or id
    Returns ToolProductSettingsResource
    Relevant apply filter ?test_type=?, ?id=?

    POST, PUT, DLETE [/id/]
"""


class ToolProductSettingsResource(BaseModelResource):

    product = fields.ForeignKey(ProductResource, 'product',
                                full=False, null=False)
    tool_configuration = fields.ForeignKey(Tool_ConfigurationResource, 'tool_configuration', full=False, null=False)

    class Meta:
        resource_name = 'tool_product_settings'
        list_allowed_methods = ['get', 'post', 'put', 'delete']
        detail_allowed_methods = ['get', 'post', 'put', 'delete']
        queryset = Tool_Product_Settings.objects.all()
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'name': ALL,
            'product': ALL_WITH_RELATIONS,
            'tool_configuration': ALL_WITH_RELATIONS,
            'name': ALL,
            'tool_project_id': ALL,
            'url': ALL,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=ToolProductSettingsForm, resource=ToolProductSettingsResource)


"""
    /api/v1/endpoints/
    GET [/id/], DELETE [/id/]
    Expects: no params or endpoint id
    Returns endpoint
    Relevant apply filter ?test_type=?, ?id=?

    POST, PUT, DLETE [/id/]
"""


class EndpointResource(BaseModelResource):

    product = fields.ForeignKey(ProductResource, 'product',
                                full=False, null=False)

    class Meta:
        resource_name = 'endpoints'
        list_allowed_methods = ['get', 'post', 'put', 'delete']
        detail_allowed_methods = ['get', 'post', 'put', 'delete']
        queryset = Endpoint.objects.all()
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'host': ALL,
            'product': ALL_WITH_RELATIONS,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=EditEndpointForm, resource=EndpointResource)


"""
    /api/v1/jira_configurations/
    GET [/id/], DELETE [/id/]
    Expects: no params or JIRA_PKey
    Returns jira configuration: ALL or by JIRA_PKey

    POST, PUT [/id/]
"""


class JIRA_IssueResource(BaseModelResource):

    class Meta:
        resource_name = 'jira_finding_mappings'
        list_allowed_methods = ['get', 'post', 'put', 'delete']
        detail_allowed_methods = ['get', 'post', 'put', 'delete']
        queryset = JIRA_Issue.objects.all()
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'jira_id': ALL,
            'jira_key': ALL,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=JIRA_IssueForm, resource=JIRA_IssueResource)


"""
    /api/v1/jira_configurations/
    GET [/id/], DELETE [/id/]
    Expects: no params or JIRA_PKey
    Returns jira configuration: ALL or by JIRA_PKey

    POST, PUT [/id/]
"""


class JIRA_ConfResource(BaseModelResource):

    class Meta:
        resource_name = 'jira_configurations'
        list_allowed_methods = ['get', 'post', 'put', 'delete']
        detail_allowed_methods = ['get', 'post', 'put', 'delete']
        queryset = JIRA_Conf.objects.all()
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'url': ALL
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=JIRAForm, resource=JIRA_ConfResource)


"""
    /api/v1/jira/
    GET [/id/], DELETE [/id/]
    Expects: no params or jira product key

    POST, PUT, DELETE [/id/]
"""


class JiraResource(BaseModelResource):
    product = fields.ForeignKey(ProductResource, 'product',
                                full=False, null=False)
    conf = fields.ForeignKey(JIRA_ConfResource, 'conf',
                                full=False, null=True)

    class Meta:
        resource_name = 'jira_product_configurations'
        list_allowed_methods = ['get', 'post', 'put', 'delete']
        detail_allowed_methods = ['get', 'post', 'put', 'delete']

        queryset = JIRA_PKey.objects.all()
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'conf': ALL,
            'product': ALL_WITH_RELATIONS,
            'component': ALL,
            'project_key': ALL,
            'push_all_issues': ALL,
            'enable_engagement_epic_mapping': ALL,
            'push_notes': ALL
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=JIRA_PKeyForm, resource=JiraResource)


"""
    /api/v1/tests/
    GET [/id/], DELETE [/id/]
    Expects: no params or engagement_id
    Returns test: ALL or by engagement_id
    Relevant apply filter ?test_type=?, ?id=?

    POST, PUT [/id/]
    Expects *test_type, *engagement, *target_start, *target_end,
    estimated_time, actual_time, percent_complete, notes
"""


class TestResource(BaseModelResource):
    engagement = fields.ForeignKey(EngagementResource, 'engagement',
                                   full=False, null=False)

    class Meta:
        resource_name = 'tests'
        list_allowed_methods = ['get', 'post']
        # disabled delete. Should not be allowed without fine authorization.
        detail_allowed_methods = ['get', 'post', 'put']
        queryset = Test.objects.all().order_by('target_end')
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'test_type': ALL,
            'target_start': ALL,
            'target_end': ALL,
            'notes': ALL,
            'percent_complete': ALL,
            'actual_time': ALL,
            'engagement': ALL,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=TestForm, resource=TestResource)

    def dehydrate(self, bundle):
        bundle.data['test_type'] = bundle.obj.test_type
        return bundle


class RiskAcceptanceResource(BaseModelResource):
    class Meta:
        resource_name = 'risk_acceptances'
        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        queryset = Risk_Acceptance.objects.all().order_by('created')


"""
    /api/v1/findings/
    GET [/id/], DELETE [/id/]
    Expects: no params or test_id
    Returns test: ALL or by test_id
    Relevant apply filter ?active=True, ?id=?, ?severity=?

    POST, PUT [/id/]
    Expects *title, *date, *severity, *description, *mitigation, *impact,
    *endpoint, *test, cwe, active, false_p, verified,
    mitigated, *reporter

"""


class FindingResource(BaseModelResource):
    reporter = fields.ForeignKey(UserResource, 'reporter', null=False)
    test = fields.ForeignKey(TestResource, 'test', null=False)
    # risk_acceptance = fields.ManyToManyField(RiskAcceptanceResource, 'risk_acceptance', full=True, null=True)
    product = fields.ForeignKey(ProductResource, 'test__engagement__product', full=False, null=False)
    engagement = fields.ForeignKey(EngagementResource, 'test__engagement', full=False, null=False)

    class Meta:
        resource_name = 'findings'
        queryset = Finding.objects.select_related("test")
        # deleting of findings is not allowed via API.
        # Admin interface can be used for this.
        list_allowed_methods = ['get', 'post']
        detail_allowed_methods = ['get', 'post', 'put']
        include_resource_uri = True

        filtering = {
            'id': ALL,
            'title': ALL,
            'date': ALL,
            'severity': ALL,
            'description': ALL,
            'mitigated': ALL,
            'endpoint': ALL,
            'test': ALL_WITH_RELATIONS,
            'active': ALL,
            'verified': ALL,
            'false_p': ALL,
            'reporter': ALL,
            'url': ALL,
            'out_of_scope': ALL,
            'duplicate': ALL,
            # 'risk_acceptance': ALL_WITH_RELATIONS,
            'engagement': ALL_WITH_RELATIONS,
            'product': ALL_WITH_RELATIONS
            # 'build_id': ALL
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=FindingForm, resource=FindingResource)

    def dehydrate(self, bundle):
        engagement = Engagement.objects.select_related('product'). \
            filter(test__finding__id=bundle.obj.id)
        bundle.data['engagement'] = "/api/v1/engagements/%s/" % engagement[0].id
        bundle.data['product'] = \
            "/api/v1/products/%s/" % engagement[0].product.id
        return bundle


"""
    /api/v1/finding_templates/
    GET [/id/], DELETE [/id/]
    Expects: no params or test_id
    Returns test: ALL or by test_id
    Relevant apply filter ?active=True, ?id=?, ?severity=?

    POST, PUT [/id/]
    Expects *title, *severity, *description, *mitigation, *impact,
    *endpoint, *test, cwe, active, false_p, verified,
    mitigated, *reporter

"""


class FindingTemplateResource(BaseModelResource):

    class Meta:
        resource_name = 'finding_templates'
        queryset = Finding_Template.objects.all()
        excludes = ['numerical_severity']
        # deleting of Finding_Template is not allowed via API.
        # Admin interface can be used for this.
        list_allowed_methods = ['get', 'post']
        detail_allowed_methods = ['get', 'post', 'put']
        include_resource_uri = True
        """
        title = models.TextField(max_length=1000)
    cwe = models.IntegerField(default=None, null=True, blank=True)
    severity = models.CharField(max_length=200, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    mitigation = models.TextField(null=True, blank=True)
    impact = models.TextField(null=True, blank=True)
    references = models.TextField(null=True, blank=True, db_column="refs")
    numerical_severity
    """
        filtering = {
            'id': ALL,
            'title': ALL,
            'cwe': ALL,
            'severity': ALL,
            'description': ALL,
            'mitigated': ALL,
        }
        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=FindingTemplateForm, resource=FindingTemplateResource)


class StubFindingResource(BaseModelResource):
    reporter = fields.ForeignKey(UserResource, 'reporter', null=False)
    test = fields.ForeignKey(TestResource, 'test', null=False)

    class Meta:
        resource_name = 'stub_findings'
        queryset = Stub_Finding.objects.select_related("test")
        # deleting of findings is not allowed via UI or API.
        # Admin interface can be used for this.
        list_allowed_methods = ['get', 'post']
        detail_allowed_methods = ['get', 'post', 'put']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'title': ALL,
            'date': ALL,
            'severity': ALL,
            'description': ALL,
        }

        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=StubFindingForm, resource=StubFindingResource)

    def dehydrate(self, bundle):
        engagement = Engagement.objects.select_related('product'). \
            filter(test__stub_finding__id=bundle.obj.id)
        bundle.data['engagement'] = "/api/v1/engagements/%s/" % engagement[0].id
        bundle.data['product'] = \
            "/api/v1/products/%s/" % engagement[0].product.id
        return bundle


'''
    /api/v1/scansettings/
    GET [/id/], DELETE [/id/]
    Expects: no params or product_id
    Returns test: ALL or by product_id

    POST, PUT [/id/]
    Expects *addresses, *user, *date, *frequency, *email, *product
'''


class ScanSettingsResource(BaseModelResource):
    user = fields.ForeignKey(UserResource, 'user', null=False)
    product = fields.ForeignKey(ProductResource, 'product', null=False)

    class Meta:
        resource_name = 'scan_settings'
        queryset = ScanSettings.objects.all()

        list_allowed_methods = ['get', 'post']
        detail_allowed_methods = ['get', 'put', 'post', 'delete']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'date': ALL,
            'user': ALL,
            'frequency': ALL,
            'product': ALL,
            'addresses': ALL
        }

        authentication = DojoApiKeyAuthentication()
        authorization = UserScanSettingsAuthorization()
        serializer = Serializer(formats=['json'])

        @property
        def validation(self):
            return ModelFormValidation(form_class=ScanSettingsForm, resource=ScanSettingsResource)


"""
    /api/v1/ipscans/
    Not exposed via API - but used as part of
    ScanResource return values
"""


class IPScanResource(BaseModelResource):
    class Meta:
        resource_name = 'ipscans'
        queryset = IPScan.objects.all()

        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'address': ALL,
            'services': ALL,
            'scan': ALL
        }

        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        serializer = Serializer(formats=['json'])


"""
    /api/v1/scans/
    GET [/id/], DELETE [/id/]
    Expects: no params
    Returns scans: ALL
    Relevant filters: ?scan_setting=?
"""


class ScanResource(BaseModelResource):
    scan_settings = fields.ForeignKey(ScanSettingsResource,
                                      'scan_settings',
                                      null=False)
    ipscans = fields.ToManyField(
        IPScanResource,
        attribute=lambda bundle: IPScan.objects.filter(
            scan__id=bundle.obj.id) if IPScan.objects.filter(
            scan__id=bundle.obj.id) != [] else [], full=True, null=True)

    class Meta:
        resource_name = 'scans'
        queryset = Scan.objects.all()

        list_allowed_methods = ['get']
        detail_allowed_methods = ['get']
        include_resource_uri = True
        filtering = {
            'id': ALL,
            'date': ALL,
            'scan_settings': ALL
        }

        authentication = DojoApiKeyAuthentication()
        authorization = UserScanAuthorization()
        serializer = Serializer(formats=['json'])


# Method used to get Private Key from uri, Used in the ImportScan and ReImportScan resources
def get_pk_from_uri(uri):
    prefix = get_script_prefix()
    chomped_uri = uri

    if prefix and chomped_uri.startswith(prefix):
        chomped_uri = chomped_uri[len(prefix) - 1:]

    try:
        view, args, kwargs = resolve(chomped_uri)
    except Resolver404:
        raise NotFound("The URL provided '%s' was not a link to a valid resource." % uri)

    return kwargs['pk']


"""
    /api/v1/importscan/
    POST
    Expects file, scan_date, scan_type, tags, active, engagement
"""


# Create an Object that will store all the information sent to the endpoint
class ImportScanObject(object):
    def __init__(self, initial=None):
        self.__dict__['_data'] = {}
        if initial:
            self.update(initial)

    def __getattr__(self, name):
        return self._data.get(name, None)

    def __setattr__(self, name, value):
        self.__dict__['_data'][name] = value

    def update(self, other):
        for k in other:
            self.__setattr__(k, other[k])

    def to_dict(self):
        return self._data


# The default form validation was buggy so I implemented a custom validation class
class ImportScanValidation(Validation):
    def is_valid(self, bundle, request=None):
        if not bundle.data:
            return {'__all__': 'You didn\'t seem to pass anything in.'}

        errors = {}

        # Make sure file is present
        if 'file' not in bundle.data:
            errors.setdefault('file', []).append('You must pass a file in to be imported')

        # Make sure scan_date matches required format
        if 'scan_date' in bundle.data:
            try:
                datetime.strptime(bundle.data['scan_date'], '%Y-%m-%d')
            except ValueError:
                errors.setdefault('scan_date', []).append("Incorrect scan_date format, should be YYYY-MM-DD")

        # Make sure scan_type and minimum_severity have valid options
        if 'engagement' not in bundle.data:
            errors.setdefault('engagement', []).append('engagement must be given')
        else:
            # verify the engagement is valid
            try:
                get_pk_from_uri(uri=bundle.data['engagement'])
            except NotFound:
                errors.setdefault('engagement', []).append('A valid engagement must be supplied. Ex. /api/v1/engagements/1/')
        scan_type_list = list(map(lambda x: x[0], ImportScanForm.SCAN_TYPE_CHOICES))
        if 'scan_type' in bundle.data:
            if bundle.data['scan_type'] not in scan_type_list:
                errors.setdefault('scan_type', []).append('scan_type must be one of the following: ' + ', '.join(scan_type_list))
        else:
            errors.setdefault('scan_type', []).append('A scan_type must be given so we know how to import the scan file.')
        severity_list = list(map(lambda x: x[0], SEVERITY_CHOICES))
        if 'minimum_severity' in bundle.data:
            if bundle.data['minimum_severity'] not in severity_list:
                errors.setdefault('minimum_severity', []).append('minimum_severity must be one of the following: ' + ', '.join(severity_list))

        # Make sure active and verified are booleans
        if 'active' in bundle.data:
            if bundle.data['active'] in ['false', 'False', '0']:
                bundle.data['active'] = False
            elif bundle.data['active'] in ['true', 'True', '1']:
                bundle.data['active'] = True

            if not isinstance(bundle.data['active'], bool):
                errors.setdefault('active', []).append('active must be a boolean')
        if 'verified' in bundle.data:
            if bundle.data['verified'] in ['false', 'False', '0']:
                bundle.data['verified'] = False
            elif bundle.data['verified'] in ['true', 'True', '1']:
                bundle.data['verified'] = True

            if not isinstance(bundle.data['verified'], bool):
                errors.setdefault('verified', []).append('verified must be a boolean')

        return errors


class BuildDetails(MultipartResource, Resource):
    file = fields.FileField(attribute='file')
    engagement = fields.CharField(attribute='engagement')

    class Meta:
        resource_name = 'build_details'
        fields = ['engagement', 'file']
        list_allowed_methods = ['post']
        detail_allowed_methods = []
        include_resource_uri = True

        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        object_class = ImportScanObject

    def hydrate(self, bundle):
        bundle.obj.__setattr__('engagement_obj',
                               Engagement.objects.get(id=get_pk_from_uri(bundle.data['engagement'])))

        return bundle

    def obj_create(self, bundle, **kwargs):
        bundle.obj = ImportScanObject(initial=kwargs)
        self.is_valid(bundle)
        if bundle.errors:
            raise ImmediateHttpResponse(response=self.error_response(bundle.request, bundle.errors))

        bundle = self.full_hydrate(bundle)

        import_object_eng(bundle.request, bundle.obj.__getattr__('engagement_obj'), bundle.data['file'])


class ImportScanResource(MultipartResource, Resource):
    scan_date = fields.DateTimeField(attribute='scan_date')
    minimum_severity = fields.CharField(attribute='minimum_severity')
    active = fields.BooleanField(attribute='active')
    verified = fields.BooleanField(attribute='verified')
    scan_type = fields.CharField(attribute='scan_type')
    tags = fields.CharField(attribute='tags')
    file = fields.FileField(attribute='file')
    engagement = fields.CharField(attribute='engagement')
    lead = fields.CharField(attribute='lead')

    class Meta:
        resource_name = 'importscan'
        fields = ['scan_date', 'minimum_severity', 'active', 'verified', 'scan_type', 'tags', 'file', 'lead']
        list_allowed_methods = ['post']
        detail_allowed_methods = []
        include_resource_uri = True

        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        validation = ImportScanValidation()
        object_class = ImportScanObject

    def hydrate(self, bundle):
        if 'scan_date' not in bundle.data:
            bundle.data['scan_date'] = datetime.now().strftime("%Y/%m/%d")
        if 'minimum_severity' not in bundle.data:
            bundle.data['minimum_severity'] = "Info"
        if 'active' not in bundle.data:
            bundle.data['active'] = True
        if 'verified' not in bundle.data:
            bundle.data['verified'] = True
        if 'tags' not in bundle.data:
            bundle.data['tags'] = ""

        if 'lead' in bundle.data:
            bundle.obj.__setattr__('user_obj',
                                   User.objects.get(id=get_pk_from_uri(bundle.data['lead'])))

        bundle.obj.__setattr__('engagement_obj',
                               Engagement.objects.get(id=get_pk_from_uri(bundle.data['engagement'])))

        return bundle

    def detail_uri_kwargs(self, bundle_or_obj):
        kwargs = {}
        return kwargs

    def obj_create(self, bundle, **kwargs):
        bundle.obj = ImportScanObject(initial=kwargs)
        self.is_valid(bundle)
        if bundle.errors:
            raise ImmediateHttpResponse(response=self.error_response(bundle.request, bundle.errors))

        bundle = self.full_hydrate(bundle)

        # We now have all the options we need and will just replicate the process in views.py
        tt, t_created = Test_Type.objects.get_or_create(name=bundle.data['scan_type'])
        # will save in development environment
        environment, env_created = Development_Environment.objects.get_or_create(name="Development")

        scan_date = datetime.strptime(bundle.data['scan_date'], '%Y-%m-%d')

        t = Test(engagement=bundle.obj.__getattr__('engagement_obj'), lead=bundle.obj.__getattr__('user_obj'), test_type=tt, target_start=scan_date,
                 target_end=scan_date, environment=environment, percent_complete=100)

        try:
            t.full_clean()
        except ValidationError:
            print "Error Validating Test Object"
            print ValidationError

        t.save()
        t.tags = bundle.data['tags']

        try:
            parser = import_parser_factory(bundle.data['file'], t)
        except ValueError:
            raise NotFound("Parser ValueError")

        try:
            for item in parser.items:
                sev = item.severity
                if sev == 'Information' or sev == 'Informational':
                    sev = 'Info'

                item.severity = sev

                if Finding.SEVERITIES[sev] > Finding.SEVERITIES[bundle.data['minimum_severity']]:
                    continue

                item.test = t
                item.date = t.target_start
                item.reporter = bundle.request.user
                item.last_reviewed = timezone.now()
                item.last_reviewed_by = bundle.request.user
                item.active = bundle.data['active']
                item.verified = bundle.data['verified']
                item.save(dedupe_option=False)

                if hasattr(item, 'unsaved_req_resp') and len(item.unsaved_req_resp) > 0:
                    for req_resp in item.unsaved_req_resp:
                        burp_rr = BurpRawRequestResponse(finding=item,
                                                         burpRequestBase64=req_resp["req"],
                                                         burpResponseBase64=req_resp["resp"],
                                                         )
                        burp_rr.clean()
                        burp_rr.save()

                if item.unsaved_request is not None and item.unsaved_response is not None:
                    burp_rr = BurpRawRequestResponse(finding=item,
                                                     burpRequestBase64=item.unsaved_request,
                                                     burpResponseBase64=item.unsaved_response,
                                                     )
                    burp_rr.clean()
                    burp_rr.save()

                for endpoint in item.unsaved_endpoints:
                    ep, created = Endpoint.objects.get_or_create(protocol=endpoint.protocol,
                                                                 host=endpoint.host,
                                                                 path=endpoint.path,
                                                                 query=endpoint.query,
                                                                 fragment=endpoint.fragment,
                                                                 product=t.engagement.product)

                    item.endpoints.add(ep)
                item.save()

                if item.unsaved_tags is not None:
                    item.tags = item.unsaved_tags

        except SyntaxError:
            raise NotFound("Parser SyntaxError")

        # Everything executed fine. We successfully imported the scan.
        res = TestResource()
        uri = res.get_resource_uri(t)
        raise ImmediateHttpResponse(HttpCreated(location=uri))


# The default form validation was buggy so I implemented a custom validation class
class ReImportScanValidation(Validation):
    def is_valid(self, bundle, request=None):
        if not bundle.data:
            return {'__all__': 'You didn\'t seem to pass anything in.'}

        errors = {}

        # Make sure file is present
        if 'file' not in bundle.data:
            errors.setdefault('file', []).append('You must pass a file in to be imported')

        # Make sure scan_date matches required format
        if 'scan_date' in bundle.data:
            try:
                datetime.strptime(bundle.data['scan_date'], '%Y/%m/%d')
            except ValueError:
                errors.setdefault('scan_date', []).append("Incorrect scan_date format, should be YYYY/MM/DD")

        # Make sure scan_type and minimum_severity have valid options
        if 'test' not in bundle.data:
            errors.setdefault('test', []).append('test must be given')
        else:
            # verify the engagement is valid
            try:
                get_pk_from_uri(uri=bundle.data['test'])
            except NotFound:
                errors.setdefault('engagement', []).append('A valid engagement must be supplied. Ex. /api/v1/engagements/1/')
        scan_type_list = list(map(lambda x: x[0], ImportScanForm.SCAN_TYPE_CHOICES))
        if 'scan_type' in bundle.data:
            if bundle.data['scan_type'] not in scan_type_list:
                errors.setdefault('scan_type', []).append('scan_type must be one of the following: ' + ', '.join(scan_type_list))
        else:
            errors.setdefault('scan_type', []).append('A scan_type must be given so we know how to import the scan file.')
        severity_list = list(map(lambda x: x[0], SEVERITY_CHOICES))
        if 'minimum_severity' in bundle.data:
            if bundle.data['minimum_severity'] not in severity_list:
                errors.setdefault('minimum_severity', []).append('minimum_severity must be one of the following: ' + ', '.join(severity_list))

        # Make sure active and verified are booleans
        if 'active' in bundle.data:
            if bundle.data['active'] in ['false', 'False', '0']:
                bundle.data['active'] = False
            elif bundle.data['active'] in ['true', 'True', '1']:
                bundle.data['active'] = True

            if not isinstance(bundle.data['active'], bool):
                errors.setdefault('active', []).append('active must be a boolean')
        if 'verified' in bundle.data:
            if bundle.data['verified'] in ['false', 'False', '0']:
                bundle.data['verified'] = False
            elif bundle.data['verified'] in ['true', 'True', '1']:
                bundle.data['verified'] = True

            if not isinstance(bundle.data['verified'], bool):
                errors.setdefault('verified', []).append('verified must be a boolean')

        return errors


class ReImportScanResource(MultipartResource, Resource):
    scan_date = fields.DateTimeField(attribute='scan_date')
    minimum_severity = fields.CharField(attribute='minimum_severity')
    active = fields.BooleanField(attribute='active')
    verified = fields.BooleanField(attribute='verified')
    scan_type = fields.CharField(attribute='scan_type')
    tags = fields.CharField(attribute='tags')
    file = fields.FileField(attribute='file')
    test = fields.CharField(attribute='test')

    class Meta:
        resource_name = 'reimportscan'
        fields = ['scan_date', 'minimum_severity', 'active', 'verified', 'scan_type', 'tags', 'file']
        list_allowed_methods = ['post']
        detail_allowed_methods = []
        include_resource_uri = True

        authentication = DojoApiKeyAuthentication()
        authorization = DjangoAuthorization()
        validation = ReImportScanValidation()
        object_class = ImportScanObject

    def hydrate(self, bundle):
        if 'scan_date' not in bundle.data:
            bundle.data['scan_date'] = datetime.now().strftime("%Y/%m/%d")
        if 'minimum_severity' not in bundle.data:
            bundle.data['minimum_severity'] = "Info"
        if 'active' not in bundle.data:
            bundle.data['active'] = True
        if 'verified' not in bundle.data:
            bundle.data['verified'] = True
        if 'tags' not in bundle.data:
            bundle.data['tags'] = ""

        bundle.obj.__setattr__('test_obj',
                               Test.objects.get(id=get_pk_from_uri(bundle.data['test'])))

        return bundle

    def detail_uri_kwargs(self, bundle_or_obj):
        kwargs = {}
        return kwargs

    def obj_create(self, bundle, **kwargs):
        bundle.obj = ImportScanObject(initial=kwargs)
        self.is_valid(bundle)
        if bundle.errors:
            raise ImmediateHttpResponse(response=self.error_response(bundle.request, bundle.errors))
        bundle = self.full_hydrate(bundle)

        test = bundle.obj.__getattr__('test_obj')
        scan_type = bundle.obj.__getattr__('scan_type')
        min_sev = bundle.obj.__getattr__('minimum_severity')
        scan_date = bundle.obj.__getattr__('scan_date')
        verified = bundle.obj.__getattr__('verified')
        active = bundle.obj.__getattr__('active')

        try:
            parser = import_parser_factory(bundle.data['file'], test)
        except ValueError:
            raise NotFound("Parser ValueError")

        try:
            items = parser.items
            original_items = test.finding_set.all().values_list("id", flat=True)
            new_items = []
            mitigated_count = 0
            finding_count = 0
            finding_added_count = 0
            reactivated_count = 0
            for item in items:
                sev = item.severity
                if sev == 'Information' or sev == 'Informational':
                    sev = 'Info'

                if Finding.SEVERITIES[sev] > Finding.SEVERITIES[min_sev]:
                    continue

                if scan_type == 'Veracode Scan' or scan_type == 'Arachni Scan':
                    find = Finding.objects.filter(title=item.title,
                                                  test__id=test.id,
                                                  severity=sev,
                                                  numerical_severity=Finding.get_numerical_severity(sev),
                                                  description=item.description
                                                  )
                else:
                    find = Finding.objects.filter(title=item.title,
                                                  test__id=test.id,
                                                  severity=sev,
                                                  numerical_severity=Finding.get_numerical_severity(sev),
                                                  )

                if len(find) == 1:
                    find = find[0]
                    if find.mitigated:
                        # it was once fixed, but now back
                        find.mitigated = None
                        find.mitigated_by = None
                        find.active = True
                        find.verified = verified
                        find.save()
                        note = Notes(entry="Re-activated by %s re-upload." % scan_type,
                                     author=bundle.request.user)
                        note.save()
                        find.notes.add(note)
                        reactivated_count += 1
                    new_items.append(find.id)
                else:
                    item.test = test
                    item.date = test.target_start
                    item.reporter = bundle.request.user
                    item.last_reviewed = timezone.now()
                    item.last_reviewed_by = bundle.request.user
                    item.verified = verified
                    item.active = active
                    item.save()
                    finding_added_count += 1
                    new_items.append(item.id)
                    find = item

                    if hasattr(item, 'unsaved_req_resp') and len(item.unsaved_req_resp) > 0:
                        for req_resp in item.unsaved_req_resp:
                            burp_rr = BurpRawRequestResponse(finding=find,
                                                             burpRequestBase64=req_resp["req"],
                                                             burpResponseBase64=req_resp["resp"],
                                                             )
                            burp_rr.clean()
                            burp_rr.save()

                    if item.unsaved_request is not None and item.unsaved_response is not None:
                        burp_rr = BurpRawRequestResponse(finding=find,
                                                         burpRequestBase64=item.unsaved_request,
                                                         burpResponseBase64=item.unsaved_response,
                                                         )
                        burp_rr.clean()
                        burp_rr.save()
                if find:
                    finding_count += 1
                    for endpoint in item.unsaved_endpoints:
                        ep, created = Endpoint.objects.get_or_create(protocol=endpoint.protocol,
                                                                     host=endpoint.host,
                                                                     path=endpoint.path,
                                                                     query=endpoint.query,
                                                                     fragment=endpoint.fragment,
                                                                     product=test.engagement.product)
                        find.endpoints.add(ep)

                    if item.unsaved_tags is not None:
                        find.tags = item.unsaved_tags
            # calculate the difference
            to_mitigate = set(original_items) - set(new_items)
            for finding_id in to_mitigate:
                finding = Finding.objects.get(id=finding_id)
                finding.mitigated = datetime.combine(scan_date, timezone.now().time())
                finding.mitigated_by = bundle.request.user
                finding.active = False
                finding.save()
                note = Notes(entry="Mitigated by %s re-upload." % scan_type,
                             author=bundle.request.user)
                note.save()
                finding.notes.add(note)
                mitigated_count += 1

        except SyntaxError:
            raise NotFound("Parser SyntaxError")

        # Everything executed fine. We successfully imported the scan.
        raise ImmediateHttpResponse(HttpCreated(location=bundle.obj.__getattr__('test')))
