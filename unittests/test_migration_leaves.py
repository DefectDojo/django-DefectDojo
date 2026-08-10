"""
Tests for ``scripts/check_migration_leaves.py``, the migration-graph CI guard.

The script under test is deliberately Django-free so it can run as a bare
``python3`` step, so these tests import it by path and drive it with generated
fixture apps rather than going through the Django test machinery. Only the last
test touches the real ``dojo`` graph.
"""

import contextlib
import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_migration_leaves.py"

_spec = importlib.util.spec_from_file_location("check_migration_leaves", SCRIPT_PATH)
check_migration_leaves = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check_migration_leaves)

MIGRATION_TEMPLATE = """\
from django.db import migrations


class Migration(migrations.Migration):
{attributes}
    operations = []
"""


class MigrationGraphFixtureMixin(unittest.TestCase):

    """Builds throwaway ``<tmp>/<app_label>/db_migrations/`` trees to parse."""

    def setUp(self):
        super().setUp()
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def make_app(self, migrations_spec, app_label="dojo", dir_name="db_migrations"):
        """
        Write one migration module per entry and return the migrations dir.

        ``migrations_spec`` maps a migration name to the source of the class
        attributes it declares, e.g.
        ``{"0002_b": 'dependencies = [("dojo", "0001_a")]'}``.
        """
        migrations_dir = self.root / app_label / dir_name
        migrations_dir.mkdir(parents=True, exist_ok=True)
        (migrations_dir / "__init__.py").write_text("")
        for name, attributes in migrations_spec.items():
            body = "\n".join(f"    {line}" for line in attributes.splitlines()) + "\n" if attributes else ""
            (migrations_dir / f"{name}.py").write_text(MIGRATION_TEMPLATE.format(attributes=body))
        return migrations_dir


class TestLeafDetection(MigrationGraphFixtureMixin):
    def test_linear_chain_has_a_single_leaf(self):
        migrations_dir = self.make_app(
            {
                "0001_initial": "",
                "0002_second": 'dependencies = [("dojo", "0001_initial")]',
                "0003_third": 'dependencies = [("dojo", "0002_second")]',
            },
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.app_label, "dojo")
        self.assertEqual(graph.leaves, ("0003_third",))
        self.assertEqual(check_migration_leaves.describe_problems(graph), [])

    def test_two_changes_on_the_same_parent_report_both_leaves(self):
        """One of the two ways to fork the graph: concurrent PRs off one parent."""
        migrations_dir = self.make_app(
            {
                "0287_vulnerability_id_entity_tables": "",
                "0288_left": 'dependencies = [("dojo", "0287_vulnerability_id_entity_tables")]',
                "0288_right": 'dependencies = [("dojo", "0287_vulnerability_id_entity_tables")]',
            },
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.leaves, ("0288_left", "0288_right"))
        problems = check_migration_leaves.describe_problems(graph)
        self.assertEqual(len(problems), 1)
        # The offending node names must be in the message -- that is what makes
        # the CI failure actionable without checking anything out.
        self.assertIn("0288_left", problems[0])
        self.assertIn("0288_right", problems[0])
        self.assertIn("multiple leaf nodes", problems[0])

    def test_migration_written_against_a_stale_base_is_caught(self):
        """
        The other way to fork it, and the case the pull_request trigger exists for.

        A migration parented on what the author believed was the tip, while the
        base had already advanced several migrations past it. Reproduces the real
        instance from PR #15498, where 0281 was written on top of 0280 after
        0281-0288 had already landed on the base branch.
        """
        spec = {"0280_vulnerability_id_upper_index": ""}
        previous = "0280_vulnerability_id_upper_index"
        for name in (
            "0281_vulnerability_id_type",
            "0282_backfill_vulnerability_id_type",
            "0283_unique_finding_vulnerability_id",
            "0284_finding_cwe",
            "0285_backfill_finding_cwe",
            "0286_cicd_infrastructure",
            "0287_vulnerability_id_entity_tables",
            "0288_backfill_vulnerability_id_entities",
        ):
            spec[name] = f'dependencies = [("dojo", "{previous}")]'
            previous = name
        # The stale-base migration: numbered 0281, parented on 0280.
        spec["0281_fileupload_title_not_unique"] = 'dependencies = [("dojo", "0280_vulnerability_id_upper_index")]'

        graph = check_migration_leaves.build_app_graph(self.make_app(spec))

        self.assertEqual(
            graph.leaves,
            ("0281_fileupload_title_not_unique", "0288_backfill_vulnerability_id_entities"),
        )
        problems = check_migration_leaves.describe_problems(graph)
        self.assertEqual(len(problems), 1)
        # Each leaf is printed with its declared parent, which is what makes the
        # "written against a stale base" shape recognisable at a glance.
        self.assertIn("0281_fileupload_title_not_unique <- 0280_vulnerability_id_upper_index", problems[0])

    def test_re_parenting_the_later_migration_resolves_the_fork(self):
        """The fix applied to #15498: renumber onto the real tip."""
        migrations_dir = self.make_app(
            {
                "0287_vulnerability_id_entity_tables": "",
                "0288_backfill_vulnerability_id_entities": (
                    'dependencies = [("dojo", "0287_vulnerability_id_entity_tables")]'
                ),
                "0289_fileupload_title_not_unique": (
                    'dependencies = [("dojo", "0288_backfill_vulnerability_id_entities")]'
                ),
            },
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.leaves, ("0289_fileupload_title_not_unique",))
        self.assertEqual(check_migration_leaves.describe_problems(graph), [])

    def test_empty_merge_migration_resolves_the_fork(self):
        """The other accepted fix."""
        migrations_dir = self.make_app(
            {
                "0001_initial": "",
                "0002_left": 'dependencies = [("dojo", "0001_initial")]',
                "0003_right": 'dependencies = [("dojo", "0001_initial")]',
                "0004_merge": 'dependencies = [("dojo", "0002_left"), ("dojo", "0003_right")]',
            },
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.leaves, ("0004_merge",))
        self.assertEqual(check_migration_leaves.describe_problems(graph), [])

    def test_three_way_fork_lists_every_leaf(self):
        migrations_dir = self.make_app(
            {
                "0001_initial": "",
                "0002_a": 'dependencies = [("dojo", "0001_initial")]',
                "0002_b": 'dependencies = [("dojo", "0001_initial")]',
                "0002_c": 'dependencies = [("dojo", "0001_initial")]',
            },
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.leaves, ("0002_a", "0002_b", "0002_c"))


class TestGraphEdgeCases(MigrationGraphFixtureMixin):
    def test_cross_app_dependencies_are_ignored(self):
        """A dep on another app neither creates an edge nor counts as dangling."""
        migrations_dir = self.make_app(
            {
                "0001_initial": 'dependencies = [("auth", "0001_initial"), ("contenttypes", "0002_remove")]',
                "0002_second": 'dependencies = [("dojo", "0001_initial"), ("pghistory", "0007_auto")]',
            },
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.leaves, ("0002_second",))
        self.assertEqual(graph.dangling, ())

    def test_cross_app_sentinels_are_ignored(self):
        migrations_dir = self.make_app(
            {
                "0001_initial": 'dependencies = [("auth", "__first__")]',
                "0002_second": 'dependencies = [("dojo", "0001_initial"), ("auth", "__latest__")]',
            },
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.leaves, ("0002_second",))
        self.assertEqual(graph.dangling, ())

    def test_swappable_dependency_is_not_reported_as_unreadable(self):
        """It is always cross-app, and flagging it would bury the real message."""
        migrations_dir = self.make_app(
            {
                "0001_initial": (
                    "dependencies = [\n"
                    '        ("contenttypes", "0002_remove"),\n'
                    "        migrations.swappable_dependency(settings.AUTH_USER_MODEL),\n"
                    "    ]"
                ),
            },
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.migrations["0001_initial"].opaque, ())
        self.assertEqual(graph.leaves, ("0001_initial",))

    def test_run_before_creates_a_forward_edge(self):
        """``run_before`` points the opposite way to ``dependencies``."""
        migrations_dir = self.make_app(
            {
                "0001_initial": "",
                "0002_early": ('dependencies = [("dojo", "0001_initial")]\nrun_before = [("dojo", "0003_late")]'),
                "0003_late": 'dependencies = [("dojo", "0001_initial")]',
            },
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        # Without the run_before edge this would look like a two-leaf fork.
        self.assertEqual(graph.leaves, ("0003_late",))
        self.assertEqual(check_migration_leaves.describe_problems(graph), [])

    def test_squashed_migrations_leave_the_graph_and_references_rewire(self):
        migrations_dir = self.make_app(
            {
                "0001_initial": "",
                "0002_old_a": 'dependencies = [("dojo", "0001_initial")]',
                "0003_old_b": 'dependencies = [("dojo", "0002_old_a")]',
                "0003_squashed": (
                    'dependencies = [("dojo", "0001_initial")]\n'
                    'replaces = [("dojo", "0002_old_a"), ("dojo", "0003_old_b")]'
                ),
                "0004_after": 'dependencies = [("dojo", "0003_old_b")]',
            },
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.squashed_out, ("0002_old_a", "0003_old_b"))
        self.assertNotIn("0002_old_a", graph.migrations)
        # 0004's dep on the replaced 0003_old_b must land on the squash, not dangle.
        self.assertEqual(graph.dangling, ())
        self.assertEqual(graph.leaves, ("0004_after",))

    def test_dependency_on_a_missing_same_app_migration_is_reported(self):
        migrations_dir = self.make_app(
            {
                "0001_initial": "",
                "0002_second": 'dependencies = [("dojo", "0001_typo_never_existed")]',
            },
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.dangling, (("0002_second", "0001_typo_never_existed"),))
        problems = check_migration_leaves.describe_problems(graph)
        self.assertTrue(any("0001_typo_never_existed" in problem for problem in problems))

    def test_dynamically_built_dependencies_are_surfaced_not_silently_dropped(self):
        migrations_dir = self.make_app(
            {
                "0001_initial": "",
                "0002_second": "dependencies = DEPENDENCIES_FROM_A_CONSTANT",
            },
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.migrations["0002_second"].opaque, ("dependencies: DEPENDENCIES_FROM_A_CONSTANT",))
        # It reads as a second root, so the guard fails loudly rather than
        # quietly assuming the unparsed value was harmless.
        self.assertEqual(graph.leaves, ("0001_initial", "0002_second"))
        problems = check_migration_leaves.describe_problems(graph)
        self.assertTrue(any("DEPENDENCIES_FROM_A_CONSTANT" in problem for problem in problems))

    def test_attributes_outside_the_migration_class_are_ignored(self):
        """Only ``class Migration`` counts -- prose and helpers must not create edges."""
        migrations_dir = self.make_app(
            {"0001_initial": "", "0002_second": 'dependencies = [("dojo", "0001_initial")]'},
        )
        (migrations_dir / "0003_third.py").write_text(
            '"""A docstring that mentions dependencies and run_before."""\n'
            "\n"
            "from django.db import migrations\n"
            "\n"
            'dependencies = [("dojo", "0099_not_real")]\n'
            "\n"
            "\n"
            "class NotTheMigration:\n"
            '    dependencies = [("dojo", "0098_also_not_real")]\n'
            "\n"
            "\n"
            "class Migration(migrations.Migration):\n"
            '    dependencies = [("dojo", "0002_second")]\n'
            "\n"
            "    operations = []\n",
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.leaves, ("0003_third",))
        self.assertEqual(graph.dangling, ())

    def test_app_label_comes_from_the_parent_of_db_migrations(self):
        """This repo keeps migrations in ``dojo/db_migrations``, not ``dojo/migrations``."""
        migrations_dir = self.make_app(
            {"0001_initial": "", "0002_second": 'dependencies = [("dojo", "0001_initial")]'},
        )

        self.assertEqual(migrations_dir.name, "db_migrations")
        graph = check_migration_leaves.build_app_graph(migrations_dir)
        self.assertEqual(graph.app_label, "dojo")
        self.assertEqual(graph.leaves, ("0002_second",))

    def test_app_label_is_derived_per_directory(self):
        migrations_dir = self.make_app(
            {"0001_initial": "", "0002_second": 'dependencies = [("otherapp", "0001_initial")]'},
            app_label="otherapp",
        )
        graph = check_migration_leaves.build_app_graph(migrations_dir)

        self.assertEqual(graph.app_label, "otherapp")
        self.assertEqual(graph.leaves, ("0002_second",))


class TestCommandLineInterface(MigrationGraphFixtureMixin):
    def run_main(self, *argv):
        """Invoke ``main`` with its output captured; returns (exit_code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            exit_code = check_migration_leaves.main(list(argv))
        return exit_code, out.getvalue(), err.getvalue()

    def test_exits_zero_on_a_sound_graph(self):
        migrations_dir = self.make_app(
            {"0001_initial": "", "0002_second": 'dependencies = [("dojo", "0001_initial")]'},
        )
        exit_code, stdout, _ = self.run_main(str(migrations_dir))

        self.assertEqual(exit_code, 0)
        self.assertIn("single leaf 0002_second", stdout)

    def test_exits_non_zero_on_a_forked_graph(self):
        migrations_dir = self.make_app(
            {
                "0001_initial": "",
                "0002_a": 'dependencies = [("dojo", "0001_initial")]',
                "0002_b": 'dependencies = [("dojo", "0001_initial")]',
            },
        )
        exit_code, _, stderr = self.run_main(str(migrations_dir))

        self.assertEqual(exit_code, 1)
        # Failure detail belongs on stderr, and must name both offenders.
        self.assertIn("0002_a", stderr)
        self.assertIn("0002_b", stderr)

    def test_exits_non_zero_when_the_directory_is_missing(self):
        """A typo'd path must not read as a clean bill of health."""
        exit_code, _, _ = self.run_main(str(self.root / "nope"))

        self.assertEqual(exit_code, 1)

    def test_exits_non_zero_on_an_empty_migrations_directory(self):
        empty = self.root / "emptyapp" / "db_migrations"
        empty.mkdir(parents=True)
        (empty / "__init__.py").write_text("")
        exit_code, _, _ = self.run_main(str(empty))

        self.assertEqual(exit_code, 1)

    def test_defaults_to_the_dojo_app_when_given_no_arguments(self):
        """The bare invocation CI uses must resolve to dojo without a cwd assumption."""
        self.assertEqual(
            check_migration_leaves.DEFAULT_MIGRATION_DIRS,
            (Path(check_migration_leaves.__file__).resolve().parents[1] / "dojo" / "db_migrations",),
        )


class TestRealDojoGraph(unittest.TestCase):

    """The point of the whole exercise: this repo's own graph must be sound."""

    def test_dojo_migrations_have_exactly_one_leaf(self):
        graph = check_migration_leaves.build_app_graph(check_migration_leaves.DEFAULT_MIGRATION_DIRS[0])

        self.assertEqual(graph.app_label, "dojo")
        self.assertEqual(
            len(graph.leaves), 1,
            f"dojo has {len(graph.leaves)} migration leaves: {', '.join(graph.leaves)}",
        )
        self.assertEqual(check_migration_leaves.describe_problems(graph), [])
