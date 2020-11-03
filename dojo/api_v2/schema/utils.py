from drf_yasg2.openapi import SchemaRef


class LazySchemaRef:
    """Utility class to support SchemaRef definition without knowing the resolver.
    The reference can be evaluated later in the context of a swagger generator
    """
    def __init__(self, schema_name, ignore_unresolved=False):
        # Bind curried version of the SchemaRef init
        self.schema_ref = lambda resolver: SchemaRef(resolver, schema_name, ignore_unresolved)

    def apply(self, resolver):
        """Resolve the LazySchemaRef with the given resolver

        Args:
            resolver (ReferenceResolver): resolver containing the schema refs

        Returns:
            SchemaRef: the corresponding SchemaRef
        """
        return self.schema_ref(resolver)


def try_apply(obj, resolver):
    """Helper method, try to resolve a LazySchemaRef

    Args:
        obj (object): A possible LazySchemaRef to resolve
        resolver (Resolver): an drf_yasg resolver

    Returns:
        object: the resolved LazySchemaRef or the original object if resolution couldn't take place
    """
    if type(obj) is LazySchemaRef:
        return obj.apply(resolver)
    else:
        return obj
