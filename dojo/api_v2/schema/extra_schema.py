from drf_yasg2.inspectors.view import SwaggerAutoSchema
from drf_yasg2.openapi import resolve_ref, Schema
from .utils import try_apply
import copy


class ExtraSchema(type):
    """Allow swagger schema expansion. It support additional query parameters
    and additional response fields.

    Returns:
        SwaggerAutoSchema: the new schema generator
    """
    class _Schema(SwaggerAutoSchema):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        def _evaluate_schema(self, schema):
            """Recursively evaluate the schema to unbox LazySchemaRef based on the underlying resolvers.

            Args:
                schema (object): the schema to evaluate

            Returns:
                object: the schema without LazySchemaRef
            """
            if type(schema) is not Schema:
                return try_apply(schema, self.components)

            if "properties" in schema:
                for prop_name, prop in schema["properties"].items():
                    schema["properties"][prop_name] = self._evaluate_schema(prop)
            if "additionalProperties" in schema:
                schema["additionalProperties"] = self._evaluate_schema(schema["additionalProperties"])

            return schema

        def _match_operation_id(self, operation):
            """Try to match the operationId with the operation description given to the generator.
            We use suffix matching as implemented by django.

            Args:
                operation (Operation): The operation to match

            Returns:
                string: the operation description or None if matching failed
            """
            operation_id = operation["operationId"]
            for name in self.operation_extra:
                if operation_id.endswith(name):
                    return self.operation_extra[name]

            return None

        def _augment_operation(self, operation):
            """Performs schema expansion by adding the new query parameters and response fields

            Args:
                operation (Operation): The operation to augment

            Returns:
                Operation: the augmented operation
            """
            extra = self._match_operation_id(operation)
            if extra is None:
                return operation

            extra_parameters = extra.get("parameters", None)
            if extra_parameters is not None:
                operation["parameters"].extend(extra_parameters if type(extra_parameters) is list else [extra_parameters])

            extra_responses = extra.get("responses", None)
            if extra_responses is not None:
                responses = operation["responses"]
                for code, params in extra_responses.items():
                    if code in responses:
                        original_schema = responses[code]["schema"]
                        # We resolve SchemaRef to be able to store the new response fields
                        schema = original_schema if type(original_schema) is Schema else resolve_ref(original_schema, self.components)
                        schema = copy.deepcopy(schema)

                        for name, param in params.items():
                            schema["properties"][name] = self._evaluate_schema(param)
                        responses[code]["schema"] = schema

            return operation

        def get_operation(self, operation_keys):
            """Override original SwaggerAutoSchema method to return the augmented schema

            Args:
                operation_keys (list[string]): Keys referrencing the operation

            Returns:
                Operation: The augmented operation
            """
            operation = super().get_operation(operation_keys)
            return self._augment_operation(operation)

    @staticmethod
    def create(operation_extra):
        """Ad-Hoc method to return a parametrized instance of the generator class.

        Args:
            operation_extra (dict()): The new parameters and response fields to add. The format must be
            {
                parameters: list[openapi.Parameter](params1, params2, ...),
                responses: {
                    code1: {
                        field1: openapi.Schema,
                        field2: openapi.Schema,
                        ...
                    },
                    code2: ...
                }
            }

        Returns:
            SwaggerAutoSchema: the swagger doc generator class
        """
        class _SchemaWrapper(ExtraSchema._Schema):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.operation_extra = operation_extra

        return _SchemaWrapper
