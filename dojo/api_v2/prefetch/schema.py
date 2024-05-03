from .prefetcher import _Prefetcher
from .utils import _get_prefetchable_fields


def _get_path_to_GET_serializer_map(generator):
    path_to_GET_serializer = dict()
    for (
        path,
        path_pattern,
        method,
        view,
    ) in generator._get_paths_and_endpoints():
        # print(path, path_pattern, method, view)
        if method == "GET":
            if hasattr(view, "get_serializer_class"):
                path_to_GET_serializer[path] = view.get_serializer_class()

    return path_to_GET_serializer


def get_serializer_ref_name(serializer):
    """Get serializer's ref_name
    inspired by https://github.com/axnsan12/drf-yasg/blob/78031f0c189585c30fccb5005a6899f2d34289a9/src/drf_yasg/utils.py#L416

    :param serializer: Serializer instance
    :return: Serializer's ``ref_name`` or ``None`` for inline serializer
    :rtype: str or None
    """
    serializer_meta = getattr(serializer, 'Meta', None)
    serializer_name = type(serializer).__name__
    if hasattr(serializer_meta, 'ref_name'):
        ref_name = serializer_meta.ref_name
    else:
        ref_name = serializer_name
        if ref_name.endswith('Serializer'):
            ref_name = ref_name[:-len('Serializer')]
    return ref_name


def prefetch_postprocessing_hook(result, generator, request, public):
    """OpenAPI v3 (drf-spectacular) Some endpoints are using the PrefetchListMixin and PrefetchRetrieveMixin.
    These have nothing to do with Django prefetch_related.
    The endpoints have an @extend_schema configured with an extra parameter 'prefetch'
    This parameter contains an array of relations to prefetch. These prefetched models
    will be returned in an additional property in the response.
    The below processor ensures the result schema matches this.
    """

    serializer_classes = _get_path_to_GET_serializer_map(generator)

    paths = result.get("paths", {})
    for path in paths:
        if "get" in paths[path] and "parameters" in paths[path]["get"]:
            for parameter in paths[path]["get"]["parameters"]:
                if parameter["name"] == "prefetch":
                    prefetcher = _Prefetcher()

                    fields = _get_prefetchable_fields(
                        serializer_classes[path]()
                    )

                    field_names = [
                        name
                        for name, field_type in fields
                        if prefetcher._find_serializer(field_type)
                    ]

                    parameter["schema"]["type"] = "array"
                    parameter["schema"]["items"] = {
                        "type": "string",
                        "enum": field_names,
                    }

                    field_to_serializer = {
                        name: prefetcher._find_serializer(field_type)
                        for name, field_type in fields
                        if prefetcher._find_serializer(field_type)
                    }

                    fields_to_refname = {
                        name: get_serializer_ref_name(serializer())
                        for name, serializer in field_to_serializer.items()
                    }

                    properties = {
                        name: {
                            "type": "object",
                            "readOnly": True,
                            "additionalProperties": {
                                "$ref": f"#/components/schemas/{fields_to_refname[name]}"
                            }
                        }
                        for name in field_names
                    }

                    ref = paths[path]["get"]["responses"]["200"]["content"][
                        "application/json"
                    ]["schema"]["$ref"]
                    component_name = ref.split("/")[-1]
                    result["components"]["schemas"][component_name][
                        "properties"
                    ]["prefetch"] = {
                        "type": "object",
                        "properties": properties,
                    }

    return result
