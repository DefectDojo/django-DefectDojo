from drf_yasg2 import openapi, utils
from .prefetcher import _Prefetcher
from .utils import _get_prefetchable_fields
from ..schema.extra_schema import ExtraSchema
from ..schema.utils import LazySchemaRef


def prefetch_decorator(methods, serializer):
    """Decorator to generate swagger doc for a view set implementing prefetching.

    Args:
        methods (list[string]): list of the method for which prefetching is enabled. List must be a sublist of ["read", "list"].
        serializer (Serializer): the serializer associated to the model represented by the viewset

    Returns:
        func(class)->class: The decorator to apply
    """
    _supported_methods = ["read", "list"]

    def _decorator(cclass):
        prefetcher = _Prefetcher()
        fields = _get_prefetchable_fields(serializer())

        field_to_serializer = dict([(name, prefetcher._find_serializer(field)) for name, field in fields])
        fields_to_refname = dict([(name, utils.get_serializer_ref_name(serializer())) for name, serializer in field_to_serializer.items()])
        fields_name = [name for name, _ in fields]

        # New openapi parameter corresponding to the prefetchable fields
        prefetch_params = openapi.Parameter("prefetch", in_=openapi.IN_QUERY, required=False, type=openapi.TYPE_ARRAY, items=openapi.Items(type=openapi.TYPE_STRING, enum=fields_name))

        # New response field corresponding to the prefetch field
        additional_props = dict([(name, openapi.Schema(type=openapi.TYPE_OBJECT, read_only=True, additional_properties=LazySchemaRef(fields_to_refname[name], True))) for name in fields_name])
        prefetch_response = openapi.Schema(type=openapi.TYPE_OBJECT, properties=additional_props)

        # Create the object representing the information to add to the swagger doc
        extra_params = dict()
        for method in methods:
            if method in _supported_methods:
                extra_params[method] = {"parameters": prefetch_params, "responses": {"200": {"prefetch": prefetch_response}}}

        # Generate the swagger schema generator
        generator = ExtraSchema.create(extra_params)

        # Set the generator as the generator of the given class provided that one has not already been set
        assert not hasattr(cclass, "swagger_schema"), "swagger_schema applied twice to class"
        setattr(cclass, "swagger_schema", generator)
        return cclass

    return _decorator
