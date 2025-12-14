#!/usr/bin/env python3
"""
Script to update performance test query counts.
I tried to implement this as management command, but it would become very slow on parsing the test output.

This script:
1. Runs all performance tests and captures actual query counts
2. Compares them with expected counts
3. Generates a report and optionally updates the test file
4. Provides a verification run

How to run:

    # Step 1: Run tests and generate report (uses TestDojoImporterPerformanceSmall by default)
    python3 scripts/update_performance_test_counts.py --report-only

    # Or specify a different test class:
    python3 scripts/update_performance_test_counts.py --test-class TestDojoImporterPerformanceSmall --report-only

    # Step 2: Review the report, then update the file
    python3 scripts/update_performance_test_counts.py --update

    # Step 3: Verify all tests pass
    python3 scripts/update_performance_test_counts.py --verify

The script defaults to TestDojoImporterPerformanceSmall if --test-class is not provided.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Path to the test file
TEST_FILE = Path(__file__).parent.parent / "unittests" / "test_importers_performance.py"


class TestCount:

    """Represents a test's expected and actual counts."""

    def __init__(self, test_name: str, step: str, metric: str):
        self.test_name = test_name
        self.step = step
        self.metric = metric
        self.expected = None
        self.actual = None
        self.difference = None

    def __repr__(self):
        return (
            f"TestCount({self.test_name}, {self.step}, {self.metric}, "
            f"expected={self.expected}, actual={self.actual})"
        )


def run_tests(test_class: str) -> str:
    """Run the performance tests and return the output."""
    print(f"Running tests for {test_class}...")
    cmd = [
        "./run-unittest.sh",
        "--test-case",
        f"unittests.test_importers_performance.{test_class}",
    ]
    result = subprocess.run(
        cmd, check=False, capture_output=True, text=True, cwd=Path(__file__).parent.parent,
    )
    return result.stdout + result.stderr


def parse_test_output(output: str) -> list[TestCount]:
    """Parse test output to extract actual vs expected counts."""
    counts = []

    # Pattern to match AssertionError with query counts
    # Format: AssertionError: 118 != 120 : 118 queries executed, 120 expected
    assertion_pattern = re.compile(
        r"AssertionError: (\d+) != (\d+) : (\d+) queries executed, (\d+) expected",
    )

    # Pattern to match test name and step
    # Format: (step='reimport2', metric='queries')
    step_pattern = re.compile(r"step='(\w+)', metric='(\w+)'")

    # Pattern to match test name
    # Format: FAIL: test_import_reimport_reimport_performance_async
    test_pattern = re.compile(r"FAIL: (test_\w+)")

    lines = output.split("\n")
    current_test = None
    current_step = None
    current_metric = None

    for line in lines:
        # Match test name
        test_match = test_pattern.search(line)
        if test_match:
            current_test = test_match.group(1)

        # Match step and metric
        step_match = step_pattern.search(line)
        if step_match:
            current_step = step_match.group(1)
            current_metric = step_match.group(2)

        # Match assertion error
        assertion_match = assertion_pattern.search(line)
        if assertion_match and current_test and current_step and current_metric:
            actual = int(assertion_match.group(1))
            expected = int(assertion_match.group(2))
            count = TestCount(current_test, current_step, current_metric)
            count.actual = actual
            count.expected = expected
            count.difference = expected - actual
            counts.append(count)

    return counts


def extract_expected_counts_from_file(test_class: str) -> dict[str, dict[str, int]]:
    """Extract expected counts from the test file."""
    if not TEST_FILE.exists():
        msg = f"Test file not found: {TEST_FILE}"
        raise FileNotFoundError(msg)

    content = TEST_FILE.read_text()

    # Pattern to match test method calls with expected counts
    # Format: self._import_reimport_performance(
    #             expected_num_queries1=340,
    #             expected_num_async_tasks1=7,
    #             expected_num_queries2=238,
    #             expected_num_async_tasks2=18,
    #             expected_num_queries3=120,
    #             expected_num_async_tasks3=17,
    #         )
    # More flexible pattern that handles whitespace variations
    pattern = re.compile(
        r"def (test_\w+)\([^)]*\):.*?"
        r"self\._import_reimport_performance\(\s*"
        r"expected_num_queries1\s*=\s*(\d+)\s*,\s*"
        r"expected_num_async_tasks1\s*=\s*(\d+)\s*,\s*"
        r"expected_num_queries2\s*=\s*(\d+)\s*,\s*"
        r"expected_num_async_tasks2\s*=\s*(\d+)\s*,\s*"
        r"expected_num_queries3\s*=\s*(\d+)\s*,\s*"
        r"expected_num_async_tasks3\s*=\s*(\d+)\s*,",
        re.DOTALL,
    )

    expected_counts = {}
    for match in pattern.finditer(content):
        test_name = match.group(1)
        expected_counts[test_name] = {
            "import1_queries": int(match.group(2)),
            "import1_async_tasks": int(match.group(3)),
            "reimport1_queries": int(match.group(4)),
            "reimport1_async_tasks": int(match.group(5)),
            "reimport2_queries": int(match.group(6)),
            "reimport2_async_tasks": int(match.group(7)),
        }

    return expected_counts


def generate_report(counts: list[TestCount], expected_counts: dict[str, dict[str, int]]):
    """Generate a report of differences."""
    if not counts:
        print("✅ All tests passed! No count differences found.")
        return

    print("\n" + "=" * 80)
    print("PERFORMANCE TEST COUNT DIFFERENCES REPORT")
    print("=" * 80 + "\n")

    # Group by test name
    by_test = {}
    for count in counts:
        if count.test_name not in by_test:
            by_test[count.test_name] = []
        by_test[count.test_name].append(count)

    for test_name, test_counts in sorted(by_test.items()):
        print(f"Test: {test_name}")
        print("-" * 80)
        for count in sorted(test_counts, key=lambda x: (x.step, x.metric)):
            print(
                f"  {count.step:12} {count.metric:15} "
                f"Expected: {count.expected:4} → Actual: {count.actual:4} "
                f"(Difference: {count.difference:+3})",
            )
        print()

    print("=" * 80)
    print("\nTo update the test file, run:")
    print(f"  python scripts/update_performance_test_counts.py --test-class {test_name.split('_')[0]} --update")
    print()


def update_test_file(counts: list[TestCount]):
    """Update the test file with new expected counts."""
    if not counts:
        print("No counts to update.")
        return

    content = TEST_FILE.read_text()

    # Create a mapping of test_name -> step_metric -> new_value
    updates = {}
    for count in counts:
        if count.test_name not in updates:
            updates[count.test_name] = {}
        step_metric = f"{count.step}_{count.metric}"
        updates[count.test_name][step_metric] = count.actual

    # Update each test method
    for test_name, test_updates in updates.items():
        # Find the test method and update expected_num_queries/async_tasks values
        # Map step_metric to parameter name
        param_map = {
            "import1_queries": "expected_num_queries1",
            "import1_async_tasks": "expected_num_async_tasks1",
            "reimport1_queries": "expected_num_queries2",
            "reimport1_async_tasks": "expected_num_async_tasks2",
            "reimport2_queries": "expected_num_queries3",
            "reimport2_async_tasks": "expected_num_async_tasks3",
        }

        for step_metric, new_value in test_updates.items():
            param_name = param_map.get(step_metric)
            if param_name:
                # Pattern to match: expected_num_queries3=120, (with flexible whitespace)
                pattern = re.compile(
                    rf"(def {re.escape(test_name)}\([^)]*\):.*?{re.escape(param_name)}\s*=\s*)(\d+)(\s*,)",
                    re.DOTALL,
                )

                def replace(match):
                    return f"{match.group(1)}{new_value}{match.group(3)}"  # noqa: B023

                content = pattern.sub(replace, content)

    # Write back to file
    TEST_FILE.write_text(content)
    print(f"✅ Updated {TEST_FILE}")
    print(f"   Updated {len(counts)} count(s) across {len(updates)} test(s)")


def verify_tests(test_class: str) -> bool:
    """Run tests to verify they all pass."""
    print(f"Verifying tests for {test_class}...")
    output = run_tests(test_class)
    counts = parse_test_output(output)

    if counts:
        print("❌ Some tests still have count mismatches:")
        for count in counts:
            print(f"  {count.test_name} - {count.step} {count.metric}: "
                  f"expected {count.expected}, got {count.actual}")
        return False
    else:  # noqa: RET505
        print("✅ All tests pass!")
        return True


def main():
    parser = argparse.ArgumentParser(
        description="Update performance test query counts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--test-class",
        required=False,
        default="TestDojoImporterPerformanceSmall",
        help="Test class name (e.g., TestDojoImporterPerformanceSmall). Defaults to TestDojoImporterPerformanceSmall if not provided.",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Only generate a report, don't update the file",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Update the test file with new counts",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run tests to verify they pass",
    )

    args = parser.parse_args()

    if args.report_only:
        # Step 1: Run tests and generate report
        output = run_tests(args.test_class)
        counts = parse_test_output(output)
        expected_counts = extract_expected_counts_from_file(args.test_class)
        generate_report(counts, expected_counts)

    elif args.update:
        # Step 2: Update the file
        output = run_tests(args.test_class)
        counts = parse_test_output(output)
        if counts:
            update_test_file(counts)
            print("\nNext step: Run --verify to ensure all tests pass")
        else:
            print("No differences found. All tests are already up to date.")

    elif args.verify:
        # Step 3: Verify
        success = verify_tests(args.test_class)
        sys.exit(0 if success else 1)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
