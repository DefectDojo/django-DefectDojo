from contextlib import suppress
import importlib
from django.conf import settings


class ParserTest:
    def __init__(self, *args: list, **kwargs: dict):
        parser_test_class = OpenSourceParserTest
        with suppress(ModuleNotFoundError):
            if (
                class_path := getattr(settings, "PARSER_TEST_CLASS_PATH", None)
            ) is not None:
                module_name, _separator, class_name = class_path.rpartition(".")
                module = importlib.import_module(module_name)
                parser_test_class = getattr(module, class_name)
        parser_test_class().apply(self, *args, **kwargs)


class OpenSourceParserTest:
    def apply(
        self,
        instance: ParserTest,
        name: str,
        parser_type: str,
        version: str,
        description: str = None,
        dynamic_tool: bool = None,
        static_tool: bool = None,
        *args: list,
        **kwargs: dict,
    ):
        instance.name = name
        instance.type = parser_type
        instance.version = version
        if description is not None:
            instance.description = description
        if dynamic_tool is not None:
            instance.dynamic_tool = dynamic_tool
        if static_tool is not None:
            instance.static_tool = static_tool
