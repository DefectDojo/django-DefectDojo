import logging

from .engines.base import BaseEngine
import importlib.util
import inspect
import json
import os

LOGGER = logging.getLogger(__name__)


def load_scanning_engine_parsers():
    def is_engine_parser(obj):
        return inspect.isclass(obj) and issubclass(obj, BaseEngine) and obj is not BaseEngine

    engines_dir = f"{os.path.dirname(__file__)}/engines"

    engine_parsers = {
        BaseEngine.SCANNING_ENGINE: BaseEngine(), }

    for file in os.listdir(engines_dir):
        if file in {'__init__.py', 'base.py'} or not file.endswith('.py'):
            continue
        module_name = file[:-3]
        file_path = os.path.join(engines_dir, file)
        spec = importlib.util.spec_from_file_location(module_name, file_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for _, ep in inspect.getmembers(mod, is_engine_parser):
            engine_parsers[ep.SCANNING_ENGINE] = ep()

    return engine_parsers


SCANNING_ENGINE_PARSERS = load_scanning_engine_parsers()


class AppCheckWebApplicationScannerParser(object):
    """
    AppCheck Web Application Security Scanner.
    """

    def get_scan_types(self):
        return ["AppCheck Web Application Scanner"]

    def get_label_for_scan_types(self, scan_type):
        return "AppCheck Web Application Scanner"

    def get_description_for_scan_types(self, scan_type):
        return "Parses scans from AppCheck Web Application Scanner"

    def get_scanning_engine_for_entry(self, item):
        return (item.get('meta') or {}).get('scanning_engine', {}).get('name', BaseEngine.SCANNING_ENGINE)

    def get_engine_parser(self, scanning_engine_name: str) -> BaseEngine:
        return SCANNING_ENGINE_PARSERS.get(scanning_engine_name, SCANNING_ENGINE_PARSERS[BaseEngine.SCANNING_ENGINE])

    def get_findings(self, file, test):
        data = json.load(file)

        findings = {}

        for item in data.get('items', []):
            scanning_engine = self.get_scanning_engine_for_entry(item)
            if parser := self.get_engine_parser(scanning_engine):
                finding, dupe_key = parser.parse_finding(item)
                if dupe_key not in findings:
                    findings[dupe_key] = finding
            else:
                LOGGER.warning(f"Skipping entry; could not find parser for scanning engine named: {scanning_engine}")

        return list(findings.values())
