# see tastypie documentation at http://django-tastypie.readthedocs.org/en
from tastypie import fields
from tastypie.authentication import SessionAuthentication
from tastypie.constants import ALL
from tastypie.resources import ModelResource
from tastypie.serializers import Serializer
from tastypie.validation import CleanedDataFormValidation

from api import UserResource, TestResource
from dojo.api import UserProductsOnlyAuthorization
from dojo.forms import StubFindingForm
from dojo.models import Engagement, Stub_Finding


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

        authentication = SessionAuthentication()
        authorization = UserProductsOnlyAuthorization()
        serializer = Serializer(formats=['json'])
        validation = CleanedDataFormValidation(form_class=StubFindingForm)

    def dehydrate(self, bundle):
        engagement = Engagement.objects.select_related('product'). \
            filter(test__stub_finding__id=bundle.obj.id)
        bundle.data['engagement'] = "/api/v1/engagements/%s/" % engagement[0].id
        bundle.data['product'] = \
            "/api/v1/products/%s/" % engagement[0].product.id
        return bundle
