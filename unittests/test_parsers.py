import ast
import os
from pathlib import Path

from django.test import tag as test_tag

from .dojo_test_case import DojoTestCase, get_unit_tests_path

basedir = get_unit_tests_path().parent

# Python randomises string hashing per process, so a set of strings iterates in a different order
# in every import worker. Whatever a parser builds by iterating a set therefore reshuffles on every
# import: text joined into description/file_path/references, the order of unsaved_locations, or
# which vulnerability id ends up being the primary one. Any of those that is a hash_code field
# gives the same unchanged report a different hash_code on every import, which breaks false
# positive history, risk acceptance copies and similar findings.
#
# Sort at the point the set is consumed. Where the order provably cannot escape, annotate the
# statement with this marker instead.
SET_ORDER_MARKER = "set-order-ok"

# Names of calls that turn a set into a sequence, freezing an arbitrary order into it
SET_TO_SEQUENCE_CALLS = {"list", "tuple"}


def _is_set_expression(node, set_names):
    """Whether this expression is (most likely) an unordered set."""
    if isinstance(node, ast.Set | ast.SetComp):
        return True
    if isinstance(node, ast.Name):
        return node.id in set_names
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name):
            return node.func.id in {"set", "frozenset"}
        if isinstance(node.func, ast.Attribute):
            # set.union(...), set.difference(...), ...
            return node.func.attr in {
                "difference", "intersection", "symmetric_difference", "union",
            } and _is_set_expression(node.func.value, set_names)
        return False
    if isinstance(node, ast.BinOp):
        # set algebra: a - b, a & b, a | b, a ^ b
        return isinstance(node.op, ast.Sub | ast.BitAnd | ast.BitOr | ast.BitXor) and (
            _is_set_expression(node.left, set_names) or _is_set_expression(node.right, set_names)
        )
    return False


def _set_variable_names(tree):
    """
    Names assigned a set anywhere in the module.

    Deliberately flow-insensitive (and therefore approximate): a name assigned a set once is
    treated as a set everywhere. Repeat until nothing new is found, so `b = set(); a = b` is
    resolved as well.
    """
    set_names = set()
    while True:
        before = len(set_names)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            else:
                continue
            if _is_set_expression(value, set_names):
                set_names.update(t.id for t in targets if isinstance(t, ast.Name))
        if len(set_names) == before:
            return set_names


def find_set_order_dependencies(source):
    """Return [(lineno, source line)] for every place where the iteration order of a set is used."""
    tree = ast.parse(source)
    set_names = _set_variable_names(tree)
    lines = source.splitlines()
    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.For) and _is_set_expression(node.iter, set_names):
            # for x in <set>: whatever the body accumulates inherits the set's order
            offenders = [node.iter]
        elif isinstance(node, ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp):
            offenders = [gen.iter for gen in node.generators if _is_set_expression(gen.iter, set_names)]
        elif isinstance(node, ast.Call) and node.args and (
            (isinstance(node.func, ast.Attribute) and node.func.attr == "join")
            or (isinstance(node.func, ast.Name) and node.func.id in SET_TO_SEQUENCE_CALLS)
        ):
            offenders = [node.args[0]] if _is_set_expression(node.args[0], set_names) else []
        else:
            continue
        for offender in offenders:
            line = lines[offender.lineno - 1]
            if SET_ORDER_MARKER not in line:
                findings.append((offender.lineno, line.strip()))
    return sorted(set(findings))


@test_tag("parser-supplement-tests")
class TestParsers(DojoTestCase):
    def test_file_existence(self):
        for parser_dir in os.scandir(Path(basedir) / "dojo" / "tools"):

            if parser_dir.is_file() or parser_dir.name == "__pycache__":
                continue  # this is not parser dir but some support file

            if parser_dir.name.startswith("api_"):
                doc_name = parser_dir.name[4:]
                category = "api"
            else:
                doc_name = parser_dir.name
                category = "file"

            if doc_name not in {
                "checkmarx_osa",  # it is documented in 'checkmarx'
                "wizcli_common_parsers",  # common class for other wizcli parsers
                "sysdig_common",  # common classes for sysdig parsers
            }:
                with self.subTest(parser=parser_dir.name, category="docs"):
                    doc_file = Path(basedir) / "docs" / "content" / "supported_tools" / "parsers" / category / f"{doc_name}.md"
                    self.assertTrue(
                        Path(doc_file).is_file(),
                        f"Documentation file '{doc_file}' is missing or using different name",
                                    )

                    content = Path(doc_file).read_text(encoding="utf-8")
                    self.assertRegex(content, "title:",
                                    f"Documentation file '{doc_file}' does not contain a title",
                                    )
                    self.assertRegex(content, "toc_hide: true",
                                    f"Documentation file '{doc_file}' does not contain toc_hide: true",
                                    )
                    if category == "file":
                        self.assertRegex(content, "### Sample Scan Data",
                                        f"Documentation file '{doc_file}' does not contain ### Sample Scan Data",
                                        )
                        self.assertRegex(content, "https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans",
                                        f"Documentation file '{doc_file}' does not contain https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans",
                                        )

            if parser_dir.name not in {
                "wizcli_common_parsers",  # common class for other wizcli parsers
                "sysdig_common",  # common classes for sysdig parsers
            }:
                with self.subTest(parser=parser_dir.name, category="parser"):
                    parser_test_file = Path(basedir) / "unittests" / "tools" / f"test_{parser_dir.name}_parser.py"
                    self.assertTrue(
                        Path(parser_test_file).is_file(),
                        f"Unittest of parser '{parser_test_file}' is missing or using different name",
                    )

            if parser_dir.name not in {
                "vcg",  # content of the sample report is string the directly in unittest
                "wizcli_common_parsers",  # common class for other wizcli parsers
                "sysdig_common",  # common classes for sysdig parsers
            }:
                with self.subTest(parser=parser_dir.name, category="testfiles"):
                    scan_dir = Path(basedir) / "unittests" / "scans" / parser_dir.name
                    self.assertTrue(
                        Path(scan_dir).is_dir(),
                        f"Test files for unittest of parser '{scan_dir}' are missing or using different name",
                    )

            if category == "api":
                if parser_dir.name not in {
                    "api_blackduck",  # TODO: tests should be implemented also for this parser
                    "api_vulners",  # TODO: tests should be implemented also for this parser
                }:
                    with self.subTest(parser=parser_dir.name, category="importer"):
                        importer_test_file = Path(basedir) / "unittests" / "tools" / f"test_{parser_dir.name}_importer.py"
                        self.assertTrue(
                            Path(importer_test_file).is_file(),
                            f"Unittest of importer '{importer_test_file}' is missing or using different name",
                        )
            for file in os.scandir(Path(basedir) / "dojo" / "tools" / parser_dir.name):
                if file.is_file() and file.name not in {"__pycache__", "__init__.py"}:
                    f_path = Path(basedir) / "dojo" / "tools" / parser_dir.name / file.name
                    read_true = False
                    with f_path.open(encoding="utf-8") as f:
                        i = 0
                        for line in f:
                            if read_true is True:
                                if ('"utf-8"' in str(line) or "'utf-8'" in str(line) or '"utf-8-sig"' in str(line) or "'utf-8-sig'" in str(line)) and i <= 4:
                                    read_true = False
                                    i = 0
                                elif i > 4:
                                    self.fail(f"In file '{f_path}' the test is failing because you don't have utf-8 after .read()")
                                    i = 0
                                    read_true = False
                                else:
                                    i += 1
                            if ".read()" in str(line):
                                read_true = True
                                i = 0

    def test_no_set_order_dependencies(self):
        """
        No parser may let the iteration order of a set decide what it produces.

        See SET_ORDER_MARKER above for why, and for how to annotate the rare case where the order
        provably cannot escape.
        """
        for parser_file in sorted((Path(basedir) / "dojo" / "tools").rglob("*.py")):
            source = parser_file.read_text(encoding="utf-8")
            findings = find_set_order_dependencies(source)
            if findings:
                with self.subTest(parser=str(parser_file.relative_to(Path(basedir) / "dojo" / "tools"))):
                    reported = "\n".join(f"  {parser_file}:{lineno}: {line}" for lineno, line in findings)
                    self.fail(
                        "the iteration order of a set is used here, which makes the parser output "
                        f"depend on PYTHONHASHSEED:\n{reported}\n"
                        "Sort where the set is consumed (sorted(...)), or annotate the line with "
                        f'"# {SET_ORDER_MARKER}: <why the order cannot escape>".',
                    )

    def test_set_order_checker(self):
        """The checker behind test_no_set_order_dependencies: it must catch the shapes that broke real parsers."""
        order_leaks = {
            # "".join(<set>), inline and through a variable (both were real bugs)
            "inline join": 'x = ", ".join(set(symbols))',
            "join via variable": 'names = set()\nnames.add(a)\nx = "; ".join(names)',
            # a set frozen into a sequence: the first element becomes the primary vulnerability id
            "list of a set": "ids = {vuln_id}\nvulnerability_ids = list(ids)",
            # locations built by iterating a set
            "comprehension": "locations = set()\nf.unsaved_locations = [url(u) for u in locations]",
            "for loop": "seen = set()\nfor s in seen:\n    description += s",
            "set algebra": "common = set(a) & set(b)\nfor key in common:\n    pass",
        }
        for name, source in order_leaks.items():
            with self.subTest(source=name):
                self.assertTrue(find_set_order_dependencies(source), f"{name} should be reported")

        ordered = {
            "sorted set": 'seen = set()\nx = ", ".join(sorted(seen))',
            "list": 'items = [1, 2]\nx = ", ".join(items)\nfor i in items:\n    pass',
            "dict (insertion ordered)": 'd = {}\nx = ", ".join(d)\nfor key in d:\n    pass',
            "membership test": 'keys = {"a", "b"}\nfound = "a" in keys',
            "annotated": f"seen = set()\nfor s in seen:  # {SET_ORDER_MARKER}: only counted\n    total += 1",
        }
        for name, source in ordered.items():
            with self.subTest(source=name):
                self.assertEqual([], find_set_order_dependencies(source), f"{name} should not be reported")

    def test_parser_existence(self):
        for docs in os.scandir(Path(basedir) / "docs" / "content" / "supported_tools" / "parsers" / "file"):
            if docs.name not in {
                "_index.md", "edgescan.md",
            }:
                with self.subTest(parser=docs.name.split(".md")[0], category="parser"):
                    parser = Path(basedir) / "dojo" / "tools" / f"{docs.name.split('.md')[0]}" / "parser.py"
                    self.assertTrue(
                        Path(parser).is_file(),
                        f"Parser '{parser}' is missing or using different name",
                                    )
