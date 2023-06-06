from drf_yasg import openapi, utils
from .prefetcher import _Prefetcher
from .utils import _get_prefetchable_fields
from ..schema import extra_schema
from ..schema.utils import LazySchemaRef


def get_prefetch_schema(methods, serializer):
    """ Swagger / OpenAPI v2 (drf-yasg) Return a composable swagger schema that contains in the query the fields that can be prefetch from the model
        supported by the serializer and in the reponse the structure of these fields in a new top-level attribute
        named prefetch.

        Returns:
            ComposableSchema: A swagger schema
    """
    prefetcher = _Prefetcher()
    fields = _get_prefetchable_fields(serializer())

    field_to_serializer = dict([(name, prefetcher._find_serializer(field_type)) for name, field_type in fields if prefetcher._find_serializer(field_type)])
    fields_to_refname = dict([(name, utils.get_serializer_ref_name(serializer())) for name, serializer in field_to_serializer.items()])
    fields_name = [name for name, field_type in fields if prefetcher._find_serializer(field_type)]

    # New openapi parameter corresponding to the prefetchable fields
    prefetch_params = [openapi.Parameter("prefetch", in_=openapi.IN_QUERY, required=False, type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING, enum=fields_name))]

    additional_props = dict([(name, openapi.Schema(type=openapi.TYPE_OBJECT, read_only=True, additional_properties=LazySchemaRef(fields_to_refname[name], True))) for name in fields_name])
    prefetch_response = {"200": {"prefetch": openapi.Schema(type=openapi.TYPE_OBJECT, properties=additional_props)}}

    schema = extra_schema.IdentitySchema()
    for method in methods:
        schema = schema.composeWith(extra_schema.ExtraParameters(method, prefetch_params))
        schema = schema.composeWith(extra_schema.ExtraResponseField(method, prefetch_response))

    return schema


def _get_path_to_GET_serializer_map(generator):
    path_to_GET_serializer = dict()
    for path, path_pattern, method, view in generator._get_paths_and_endpoints():
        # print(path, path_pattern, method, view)
        if method == 'GET':
            if hasattr(view, 'get_serializer_class'):
                path_to_GET_serializer[path] = view.get_serializer_class()

    return path_to_GET_serializer


def prefetch_postprocessing_hook(result, generator, request, public):
    """ OpenAPI v3 (drf-spectacular) Some endpoints are using the PrefetchListMixin and PrefetchRetrieveMixin.
    These have nothing to do with Django prefetch_related.
    The endpoints have an @extend_schema configured with an extra parameter 'prefetch'
    This parameter contains an array of relations to prefetch. These prefetched models
    will be returned in an additional property in the response.
    The below processor ensures the result schema matches this.
    """

    serializer_classes = _get_path_to_GET_serializer_map(generator)

    paths = result.get('paths', {})
    for path in paths:
        if 'get' in paths[path] and 'parameters' in paths[path]['get']:
            for parameter in paths[path]['get']['parameters']:
                if parameter['name'] == 'prefetch':
                    prefetcher = _Prefetcher()

                    fields = _get_prefetchable_fields(serializer_classes[path]())

                    field_names = [name for name, field_type in fields if prefetcher._find_serializer(field_type)]

                    parameter['schema']['type'] = 'array'
                    parameter['schema']['items'] = {
                        'type': "string",
                        'enum': field_names
                    }

                    field_to_serializer = dict([(name, prefetcher._find_serializer(field_type)) for name, field_type in fields if prefetcher._find_serializer(field_type)])
                    fields_to_refname = dict([(name, utils.get_serializer_ref_name(serializer()))
                        for name, serializer in field_to_serializer.items()])
                    properties = dict([(name, dict([("type", "object"), ("readOnly", True), ("additionalProperties", dict([("$ref", "#/components/schemas/" + fields_to_refname[name])]))]))
                        for name in field_names])
                    ref = paths[path]['get']['responses']['200']['content']['application/json']['schema']['$ref']
                    component_name = ref.split('/')[-1]
                    result['components']['schemas'][component_name]['properties']['prefetch'] = dict([("type", "object"), ("properties", properties)])

    return result
