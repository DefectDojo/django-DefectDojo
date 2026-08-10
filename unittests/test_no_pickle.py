"""
Guard tests preventing the reintroduction of pickle into the dojo app.

Pickle deserialization of attacker-controllable bytes is arbitrary code
execution. We removed all uses (form widgets, Celery serializer) and these
tests fail loudly if a future change adds them back.
"""

import re
from pathlib import Path

from django.conf import settings

import dojo
from unittests.dojo_test_case import DojoTestCase


class TestNoPickle(DojoTestCase):
    def test_no_pickle_imports_in_dojo(self):
        dojo_root = Path(dojo.__file__).resolve().parent
        offenders = []
        import_re = re.compile(r"^\s*(?:import\s+pickle|from\s+pickle\s+import)\b", re.MULTILINE)
        for path in dojo_root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            if import_re.search(text):
                offenders.append(str(path.relative_to(dojo_root.parent)))
        self.assertFalse(
            offenders,
            f"pickle is forbidden in dojo source. Offenders: {offenders}",
        )

    def test_celery_serializer_is_json_only(self):
        self.assertEqual(settings.CELERY_TASK_SERIALIZER, "json")
        self.assertEqual(settings.CELERY_ACCEPT_CONTENT, ["json"])
        self.assertEqual(settings.CELERY_RESULT_SERIALIZER, "json")
