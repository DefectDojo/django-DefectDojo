#!/usr/bin/env python3
"""
Fail when the Django migration graph has more than one leaf node in an app.

``migrate`` refuses to apply *anything* while a graph has two leaves::

    CommandError: Conflicting migrations detected; multiple leaf nodes in the
    migration graph: (0281_fileupload_title_not_unique,
    0288_backfill_vulnerability_id_entities in dojo).

Every fresh install and every CI database build off the branch is blocked until
someone re-parents one of them. There are two ways to arrive there, and the
workflow that calls this script watches for both:

* Two changes each add a migration on top of the same parent. Each is
  internally consistent, so both go green pre-merge; the fork exists only in
  their union, and nothing re-derives the graph after a merge.
* One change adds a migration on top of a parent that is no longer the tip,
  because the author's view of the base branch was stale. The branch alone
  looks fine — the fork appears in the merge with the base.

The failure is expensive out of proportion to the mistake: with no guard it
surfaces as every container-based job dying at boot, ~120 red checks whose logs
all have to be opened before one of them names the actual problem.

The script is deliberately standalone: ``ast`` only, no Django import, no
database, no settings module, no third-party package. That is what lets it run
as a plain ``python3`` step with nothing but a checkout, in under a second.

Usage::

    python3 scripts/check_migration_leaves.py           # checks dojo
    python3 scripts/check_migration_leaves.py DIR...    # checks DIRs
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from typing import TYPE_CHECKING, NamedTuple

if TYPE_CHECKING:
    from collections.abc import Sequence

# ``<repo>/scripts/`` -> ``<repo>/dojo/db_migrations``. ``dojo`` is the only
# Django app in this repo that ships migrations, and its migration modules live
# in ``db_migrations`` rather than the conventional ``migrations`` (see
# MIGRATION_MODULES in dojo/settings/settings.dist.py).
DEFAULT_MIGRATION_DIRS = (Path(__file__).resolve().parents[1] / "dojo" / "db_migrations",)

# Django resolves these against another app's graph, never this one's.
CROSS_APP_SENTINELS = frozenset({"__first__", "__latest__"})

# ``migrations.swappable_dependency(settings.AUTH_USER_MODEL)`` resolves to whichever
# app owns the user model — never ``dojo`` — so it cannot affect an intra-app leaf
# count. It is common enough that reporting it as unreadable would be pure noise.
KNOWN_CROSS_APP_CALLS = frozenset({"swappable_dependency"})


class Reference(NamedTuple):

    """An ``(app_label, migration_name)`` pair as written in a migration file."""

    app_label: str
    name: str


class ParsedMigration(NamedTuple):

    """The graph-relevant attributes of one migration module."""

    name: str
    path: Path
    dependencies: tuple[Reference, ...]
    run_before: tuple[Reference, ...]
    replaces: tuple[Reference, ...]
    # Entries we could not read as literal ``("app", "name")`` pairs — e.g.
    # ``migrations.swappable_dependency(settings.AUTH_USER_MODEL)``, which is
    # always cross-app and so never affects an intra-app leaf count. Reported
    # only when the check fails, as context for an otherwise puzzling verdict.
    opaque: tuple[str, ...]


class AppGraph(NamedTuple):

    """The intra-app migration graph derived from one migrations directory."""

    app_label: str
    directory: Path
    migrations: dict[str, ParsedMigration]
    children: dict[str, set[str]]
    leaves: tuple[str, ...]
    # ``("0281_x", "0280_missing")``: 0281 depends on a same-app migration that
    # is not on disk. Django raises NodeNotFoundError for this, and it would
    # also skew the leaf count here, so it is reported rather than ignored.
    dangling: tuple[tuple[str, str], ...]
    squashed_out: tuple[str, ...]


def _is_known_cross_app_call(node: ast.AST) -> bool:
    """True for calls that always resolve to some other app's graph."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
    return name in KNOWN_CROSS_APP_CALLS


def _literal_references(value: ast.AST) -> tuple[list[Reference], list[str]]:
    """
    Read a ``[("app", "name"), ...]`` literal into references.

    Returns the pairs it could read plus a source snippet for every entry it
    could not, so a dynamically built dependency never silently vanishes.
    """
    if not isinstance(value, (ast.List, ast.Tuple, ast.Set)):
        return [], [ast.unparse(value)]

    references: list[Reference] = []
    opaque: list[str] = []
    for element in value.elts:
        if (
            isinstance(element, (ast.Tuple, ast.List))
            and len(element.elts) == 2
            and all(isinstance(part, ast.Constant) and isinstance(part.value, str) for part in element.elts)
        ):
            app_label, name = (part.value for part in element.elts)
            references.append(Reference(app_label, name))
        elif not _is_known_cross_app_call(element):
            opaque.append(ast.unparse(element))
    return references, opaque


def parse_migration_file(path: Path) -> ParsedMigration:
    """
    Extract ``dependencies`` / ``run_before`` / ``replaces`` from one migration.

    Only assignments inside ``class Migration`` count, which is the only place
    Django reads them from. Anything not spelled as a literal pair of strings is
    recorded as opaque rather than guessed at.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    collected: dict[str, list[Reference]] = {"dependencies": [], "run_before": [], "replaces": []}
    opaque: list[str] = []

    for class_node in tree.body:
        if not isinstance(class_node, ast.ClassDef) or class_node.name != "Migration":
            continue
        for statement in class_node.body:
            if isinstance(statement, ast.Assign):
                targets = [t.id for t in statement.targets if isinstance(t, ast.Name)]
            elif isinstance(statement, ast.AnnAssign) and isinstance(statement.target, ast.Name):
                targets = [statement.target.id]
            else:
                continue
            for target in targets:
                if target not in collected or statement.value is None:
                    continue
                references, unreadable = _literal_references(statement.value)
                collected[target].extend(references)
                opaque.extend(f"{target}: {snippet}" for snippet in unreadable)

    return ParsedMigration(
        name=path.stem,
        path=path,
        dependencies=tuple(collected["dependencies"]),
        run_before=tuple(collected["run_before"]),
        replaces=tuple(collected["replaces"]),
        opaque=tuple(opaque),
    )


def _same_app(references: Sequence[Reference], app_label: str) -> list[str]:
    """Names from ``references`` that point at ``app_label`` itself."""
    return [ref.name for ref in references if ref.app_label == app_label and ref.name not in CROSS_APP_SENTINELS]


def build_app_graph(migrations_dir: Path, app_label: str | None = None) -> AppGraph:
    """
    Build the intra-app graph for one migrations directory.

    Cross-app edges are dropped on purpose: they cannot change how many leaves
    *this* app has, and following them would mean loading every other app.
    """
    if app_label is None:
        # ``.../dojo/db_migrations`` -> ``dojo``, matching how Django labels the app.
        app_label = migrations_dir.resolve().parent.name

    migrations: dict[str, ParsedMigration] = {}
    for path in sorted(migrations_dir.glob("*.py")):
        if path.name == "__init__.py":
            continue
        parsed = parse_migration_file(path)
        migrations[parsed.name] = parsed

    # A squashed migration takes the place of the ones it replaces, so the
    # replaced nodes leave the graph and references to them land on the squash.
    # This mirrors the fresh-install path, which is what the guard protects.
    replaced_by: dict[str, str] = {}
    for name, parsed in migrations.items():
        for superseded in _same_app(parsed.replaces, app_label):
            if superseded in migrations:
                replaced_by[superseded] = name
    for superseded in replaced_by:
        migrations.pop(superseded, None)

    def resolve(name: str) -> str:
        return replaced_by.get(name, name)

    children: dict[str, set[str]] = {name: set() for name in migrations}
    dangling: list[tuple[str, str]] = []

    for name, parsed in migrations.items():
        # ``dependencies`` points at parents: the parent gains this node as a child.
        for parent in map(resolve, _same_app(parsed.dependencies, app_label)):
            if parent in children:
                children[parent].add(name)
            elif parent != name:
                dangling.append((name, parent))
        # ``run_before`` points the other way: this node becomes the target's parent.
        for successor in map(resolve, _same_app(parsed.run_before, app_label)):
            if successor in children:
                children[name].add(successor)
            elif successor != name:
                dangling.append((name, successor))

    leaves = tuple(sorted(name for name, kids in children.items() if not kids))
    return AppGraph(
        app_label=app_label,
        directory=migrations_dir,
        migrations=migrations,
        children=children,
        leaves=leaves,
        dangling=tuple(sorted(set(dangling))),
        squashed_out=tuple(sorted(replaced_by)),
    )


def describe_problems(graph: AppGraph) -> list[str]:
    """Human-readable problems with ``graph``; empty when the graph is sound."""
    problems: list[str] = []

    if not graph.migrations:
        problems.append(f"{graph.directory}: no migrations found (wrong path?)")
        return problems

    if len(graph.leaves) > 1:
        joined = ", ".join(graph.leaves)
        lines = [
            (
                "Conflicting migrations detected; multiple leaf nodes in the migration graph: "
                f"({joined} in {graph.app_label})."
            ),
            "",
            "  `migrate` refuses to apply anything at all in this state, so every fresh",
            "  install and every CI database build off this branch is broken.",
            "",
            "  Either two changes added a migration on the same parent, or one was written",
            "  against a base branch that had already moved on. Fix it by re-parenting the",
            "  later migration onto the other leaf and renumbering it, or by adding an empty",
            "  merge migration that depends on both leaves.",
            "",
            "  Before renumbering, confirm what the base branch actually holds: a stale",
            "  remote-tracking ref is a common way to pick a number that is already taken.",
            "",
            "  Leaves and their declared parents:",
        ]
        for leaf in graph.leaves:
            parents = _same_app(graph.migrations[leaf].dependencies, graph.app_label) or ["(none — root)"]
            lines.append(f"    {leaf} <- {', '.join(parents)}")
        problems.append("\n".join(lines))

    for child, missing in graph.dangling:
        problems.append(
            f"{graph.app_label}.{child} depends on {graph.app_label}.{missing}, "
            f"which is not in {graph.directory} (Django raises NodeNotFoundError).",
        )

    if problems:
        opaque = [f"    {parsed.name}: {snippet}" for parsed in graph.migrations.values() for snippet in parsed.opaque]
        if opaque:
            problems.append(
                'Note: these entries were not literal ("app", "name") pairs and were skipped.\n'
                "They are normally cross-app (e.g. swappable_dependency) and harmless, but if a\n"
                "verdict above looks wrong, start here:\n" + "\n".join(sorted(opaque)),
            )

    return problems


def check_migration_dirs(directories: Sequence[Path]) -> list[str]:
    """Collect problems across every directory; empty means everything is sound."""
    problems: list[str] = []
    for directory in directories:
        if not directory.is_dir():
            problems.append(f"{directory}: not a directory")
            continue
        problems.extend(describe_problems(build_app_graph(directory)))
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument(
        "migrations_dirs",
        nargs="*",
        type=Path,
        help="migrations directories to check (default: the dojo app)",
    )
    args = parser.parse_args(argv)
    directories = tuple(args.migrations_dirs) or DEFAULT_MIGRATION_DIRS

    problems = check_migration_dirs(directories)
    if problems:
        print("Migration graph check FAILED\n", file=sys.stderr)
        for problem in problems:
            print(problem, file=sys.stderr)
            print(file=sys.stderr)
        return 1

    for directory in directories:
        graph = build_app_graph(directory)
        squashed = f", {len(graph.squashed_out)} squashed out" if graph.squashed_out else ""
        print(
            f"{graph.app_label}: {len(graph.migrations)} migrations{squashed}, single leaf {graph.leaves[0]}",
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
