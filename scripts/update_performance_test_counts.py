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

    # Default: Update the test file (uses TestDojoImporterPerformanceSmall by default)
    python3 scripts/update_performance_test_counts.py

    # Or specify a different test class:
    python3 scripts/update_performance_test_counts.py --test-class TestDojoImporterPerformanceSmall

    # Step 1: Run tests and generate report only (without updating)
    python3 scripts/update_performance_test_counts.py --report-only

    # Step 2: Verify all tests pass
    python3 scripts/update_performance_test_counts.py --verify

The script defaults to TestDojoImporterPerformanceSmall if --test-class is not provided.
The script defaults to --update behavior if no action flag is provided.
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


def extract_test_methods(test_class: str) -> list[str]:
    """Extract all test method names from the test class."""
    if not TEST_FILE.exists():
        msg = f"Test file not found: {TEST_FILE}"
        raise FileNotFoundError(msg)

    content = TEST_FILE.read_text()

    # Find the test class definition
    class_pattern = re.compile(
        rf"class {re.escape(test_class)}.*?(?=class |\Z)",
        re.DOTALL,
    )
    class_match = class_pattern.search(content)
    if not class_match:
        return []

    class_content = class_match.group(0)

    # Find all test methods in this class
    test_method_pattern = re.compile(r"def (test_\w+)\(")
    return test_method_pattern.findall(class_content)


def run_test_method(test_class: str, test_method: str) -> tuple[str, int]:
    """Run a specific test method and return the output and return code."""
    print(f"Running {test_class}.{test_method}...")
    cmd = [
        "./run-unittest.sh",
        "--test-case",
        f"unittests.test_importers_performance.{test_class}.{test_method}",
    ]

    # Run with real-time output streaming
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=Path(__file__).parent.parent,
    )

    output_lines = []
    for line in process.stdout:
        print(line, end="")  # Print in real-time
        output_lines.append(line)

    process.wait()
    output = "".join(output_lines)

    return output, process.returncode


def run_tests(test_class: str) -> tuple[str, int]:
    """Run all tests in a test class and return the output and return code."""
    print(f"Running tests for {test_class}...")
    cmd = [
        "./run-unittest.sh",
        "--test-case",
        f"unittests.test_importers_performance.{test_class}",
    ]

    # Run with real-time output streaming
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        cwd=Path(__file__).parent.parent,
    )

    output_lines = []
    for line in process.stdout:
        print(line, end="")  # Print in real-time
        output_lines.append(line)

    process.wait()
    output = "".join(output_lines)

    return output, process.returncode


def check_test_execution_success(output: str, return_code: int) -> tuple[bool, str]:
    """Check if tests executed successfully or failed due to other reasons."""
    # Check for migration errors
    migration_error_patterns = [
        r"django\.db\.migrations\.exceptions\.",
        r"Migration.*failed",
        r"django\.core\.management\.base\.CommandError",
        r"OperationalError",
        r"ProgrammingError",
        r"relation.*does not exist",
        r"no such table",
    ]

    for pattern in migration_error_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            return False, f"Migration or database error detected: {pattern}"

    # Check if any tests actually ran
    test_run_patterns = [
        r"Ran \d+ test",
        r"OK",
        r"FAILED",
        r"FAIL:",
        r"test_\w+",
    ]

    tests_ran = any(re.search(pattern, output) for pattern in test_run_patterns)

    if not tests_ran and return_code != 0:
        return False, "Tests did not run successfully. Check the output above for errors."

    # Check for other critical errors
    critical_error_patterns = [
        r"ImportError",
        r"ModuleNotFoundError",
        r"SyntaxError",
        r"IndentationError",
    ]

    for pattern in critical_error_patterns:
        if re.search(pattern, output):
            return False, f"Critical error detected: {pattern}"

    return True, ""


def parse_test_output(output: str) -> list[TestCount]:
    """Parse test output to extract actual vs expected counts."""
    counts = []

    # Debug: Save a sample of the output to help diagnose parsing issues
    if "FAIL:" in output:
        # Extract failure sections for debugging
        fail_sections = []
        lines = output.split("\n")
        in_fail_section = False
        fail_section = []
        for line in lines:
            if "FAIL:" in line:
                if fail_section:
                    fail_sections.append("\n".join(fail_section))
                fail_section = [line]
                in_fail_section = True
            elif in_fail_section:
                fail_section.append(line)
                # Stop collecting after AssertionError line or after 5 more lines
                if "AssertionError:" in line or len(fail_section) > 6:
                    fail_sections.append("\n".join(fail_section))
                    fail_section = []
                    in_fail_section = False
        if fail_section:
            fail_sections.append("\n".join(fail_section))

        if fail_sections:
            print(f"\n🔍 Found {len(fail_sections)} failure section(s) in output")

    # The test output format is:
    # FAIL: test_name (step='import1', metric='queries')
    # AssertionError: 118 != 120 : 118 queries executed, 120 expected
    #
    # For async tasks we may see:
    # FAIL: test_name (step='import1', metric='async_tasks')
    # AssertionError: Expected 7 celery tasks, but 6 were created.

    # Parse failures by splitting into individual FAIL blocks, to avoid accidentally
    # associating an assertion from a different FAIL with the wrong metric.
    fail_header = re.compile(
        r"^FAIL:\s+(test_\w+)\s+\([^)]+\)\s+\(step=['\"](\w+)['\"],\s*metric=['\"](\w+)['\"]\)\s*$",
        re.MULTILINE,
    )

    headers = list(fail_header.finditer(output))
    for idx, match in enumerate(headers):
        test_name = match.group(1)
        step = match.group(2)
        metric = match.group(3)

        block_start = match.end()
        block_end = headers[idx + 1].start() if idx + 1 < len(headers) else len(output)
        block = output[block_start:block_end]

        actual: int | None = None
        expected: int | None = None

        if metric == "queries":
            m = re.search(
                r"AssertionError:\s+(\d+)\s+!=\s+(\d+)\s+:\s+\d+\s+queries\s+executed,\s+\d+\s+expected",
                block,
            )
            if m:
                actual = int(m.group(1))
                expected = int(m.group(2))
        elif metric == "async_tasks":
            # Celery task count assertions can be in a different format.
            m = re.search(r"AssertionError:\s+Expected\s+(\d+)\s+celery tasks?,\s+but\s+(\d+)\s+were created\.", block)
            if m:
                expected = int(m.group(1))
                actual = int(m.group(2))
            else:
                m = re.search(
                    r"AssertionError:\s+(\d+)\s+!=\s+(\d+)\s+:\s+\d+\s+async tasks?\s+executed,\s+\d+\s+expected",
                    block,
                )
                if m:
                    actual = int(m.group(1))
                    expected = int(m.group(2))

        if actual is None or expected is None:
            continue

        count = TestCount(test_name, step, metric)
        count.actual = actual
        count.expected = expected
        count.difference = expected - actual
        counts.append(count)

    if counts:
        print(f"\n📊 Parsed {len(counts)} count mismatch(es) from test output:")
        for count in counts:
            print(f"  {count.test_name} - {count.step} {count.metric}: {count.actual} != {count.expected}")
    elif "FAIL:" in output:
        print("\n⚠️  WARNING: Found FAIL in output but couldn't parse any count mismatches!")
        print("This might indicate a parsing issue. Check the output above.")

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

    def _extract_call_span(method_content: str, call_name: str) -> tuple[int, int] | None:
        """Return (start, end) indices of the first call to `call_name(...)` within method_content."""
        start = method_content.find(call_name)
        if start == -1:
            return None

        open_paren = method_content.find("(", start)
        if open_paren == -1:
            return None

        depth = 0
        for idx in range(open_paren, len(method_content)):
            ch = method_content[idx]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    return start, idx + 1
        return None

    # Create a mapping of test_name -> step_metric -> new_value
    updates = {}
    for count in counts:
        if count.test_name not in updates:
            updates[count.test_name] = {}
        step_metric = f"{count.step}_{count.metric}"
        updates[count.test_name][step_metric] = count.actual

    # Map step_metric to parameter name for different methods
    param_map_import_reimport = {
        "import1_queries": "expected_num_queries1",
        "import1_async_tasks": "expected_num_async_tasks1",
        "reimport1_queries": "expected_num_queries2",
        "reimport1_async_tasks": "expected_num_async_tasks2",
        "reimport2_queries": "expected_num_queries3",
        "reimport2_async_tasks": "expected_num_async_tasks3",
    }
    param_map_deduplication = {
        "first_import_queries": "expected_num_queries1",
        "first_import_async_tasks": "expected_num_async_tasks1",
        "second_import_queries": "expected_num_queries2",
        "second_import_async_tasks": "expected_num_async_tasks2",
    }

    # Update each test method
    for test_name, test_updates in updates.items():
        print(f"  Updating {test_name}...")
        # Find the test method boundaries
        test_method_pattern = re.compile(
            rf"(def {re.escape(test_name)}\([^)]*\):.*?)(?=def test_|\Z)",
            re.DOTALL,
        )
        test_match = test_method_pattern.search(content)
        if not test_match:
            print(f"⚠️  Warning: Could not find test method {test_name}")
            continue

        test_method_content = test_match.group(1)
        test_method_start = test_match.start()
        test_method_end = test_match.end()

        call_span = _extract_call_span(test_method_content, "self._import_reimport_performance")
        param_map = param_map_import_reimport
        if call_span is None:
            call_span = _extract_call_span(test_method_content, "self._deduplication_performance")
            if call_span is not None:
                param_map = param_map_deduplication
            else:
                print(
                    f"⚠️  Warning: Could not find _import_reimport_performance or _deduplication_performance call in {test_name}",
                )
                continue

        call_start, call_end = call_span
        original_call = test_method_content[call_start:call_end]
        updated_call = original_call

        updated_params = []
        for step_metric, param_name in param_map.items():
            if step_metric not in test_updates:
                continue
            new_value = test_updates[step_metric]
            m = re.search(rf"({re.escape(param_name)}\s*=\s*)(\d+)", updated_call)
            if not m:
                continue
            old_value = int(m.group(2))
            if old_value == new_value:
                continue
            updated_params.append(f"{param_name}: {old_value} → {new_value}")
            updated_call = re.sub(
                rf"({re.escape(param_name)}\s*=\s*)\d+",
                rf"\g<1>{new_value}",
                updated_call,
                count=1,
            )

        if updated_params:
            print(f"    Updated: {', '.join(updated_params)}")

        # Replace the method call within the test method content (in-place; do not reformat)
        updated_method_content = (
            test_method_content[:call_start]
            + updated_call
            + test_method_content[call_end:]
        )

        # Replace the entire test method in the original content
        content = content[:test_method_start] + updated_method_content + content[test_method_end:]

    # Write back to file
    TEST_FILE.write_text(content)
    print(f"✅ Updated {TEST_FILE}")
    print(f"   Updated {len(counts)} count(s) across {len(updates)} test(s)")


def verify_tests(test_class: str) -> bool:
    """Run tests to verify they all pass."""
    print(f"Verifying tests for {test_class}...")
    output, return_code = run_tests(test_class)

    success, error_msg = check_test_execution_success(output, return_code)
    if not success:
        print(f"\n❌ Test execution failed: {error_msg}")
        return False

    counts = parse_test_output(output)

    if counts:
        print("\n❌ Some tests still have count mismatches:")
        for count in counts:
            print(f"  {count.test_name} - {count.step} {count.metric}: "
                  f"expected {count.expected}, got {count.actual}")
        return False
    else:  # noqa: RET505
        print("\n✅ All tests pass!")
        return True


def verify_and_get_mismatches(test_class: str) -> tuple[bool, list[TestCount]]:
    """Run the full test class and return (success, parsed mismatches)."""
    print(f"Verifying tests for {test_class}...")
    output, return_code = run_tests(test_class)

    success, error_msg = check_test_execution_success(output, return_code)
    if not success:
        print(f"\n❌ Test execution failed: {error_msg}")
        return False, []

    counts = parse_test_output(output)
    if counts:
        print("\n❌ Some tests still have count mismatches:")
        for count in counts:
            print(
                f"  {count.test_name} - {count.step} {count.metric}: "
                f"expected {count.expected}, got {count.actual}",
            )
        return False, counts

    print("\n✅ All tests pass!")
    return True, []


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
        help="Update the test file with new counts (default behavior if no action flag is provided)",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Run tests to verify they pass",
    )

    args = parser.parse_args()

    if args.report_only:
        # Step 1: Run tests and generate report
        # Run each test method individually
        test_methods = extract_test_methods(args.test_class)
        if not test_methods:
            print(f"⚠️  No test methods found in {args.test_class}")
            sys.exit(1)

        print(f"\nFound {len(test_methods)} test method(s) in {args.test_class}")
        print("=" * 80)

        all_counts = []
        for test_method in test_methods:
            print(f"\n{'=' * 80}")
            output, return_code = run_test_method(args.test_class, test_method)
            success, error_msg = check_test_execution_success(output, return_code)
            if not success:
                print(f"\n⚠️  Test execution failed for {test_method}: {error_msg}")
                print("Skipping this test method...")
                continue

            counts = parse_test_output(output)
            if counts:
                all_counts.extend(counts)

        expected_counts = extract_expected_counts_from_file(args.test_class)
        generate_report(all_counts, expected_counts)

    elif args.verify:
        # Step 3: Verify
        success = verify_tests(args.test_class)
        sys.exit(0 if success else 1)

    else:
        # Default: Update the file (--update is the default behavior)
        # Run each test method individually
        test_methods = extract_test_methods(args.test_class)
        if not test_methods:
            print(f"⚠️  No test methods found in {args.test_class}")
            sys.exit(1)

        print(f"\nFound {len(test_methods)} test method(s) in {args.test_class}")
        print("=" * 80)

        all_counts = []
        for test_method in test_methods:
            print(f"\n{'=' * 80}")
            output, return_code = run_test_method(args.test_class, test_method)
            success, error_msg = check_test_execution_success(output, return_code)
            if not success:
                print(f"\n⚠️  Test execution failed for {test_method}: {error_msg}")
                print("Skipping this test method...")
                continue

            counts = parse_test_output(output)

            # Check if test actually passed
            test_passed = "OK" in output or ("Ran" in output and "FAILED" not in output and return_code == 0)

            if counts:
                all_counts.extend(counts)
                # Update immediately after each test
                update_test_file(counts)
                print(f"⚠️  {test_method}: Found {len(counts)} count mismatch(es) - updated file")
            elif test_passed:
                print(f"✅ {test_method}: Test passed, all counts match")
            elif return_code != 0:
                # Test might have failed for other reasons
                print(f"⚠️  {test_method}: Test failed (exit code {return_code}) but no count mismatches parsed")
                print("   This might indicate a parsing issue or a different type of failure")
                # Show a snippet of the output to help debug
                fail_lines = [line for line in output.split("\n") if "FAIL" in line or "Error" in line or "Exception" in line]
                if fail_lines:
                    print("   Relevant error lines:")
                    for line in fail_lines[:5]:
                        print(f"     {line}")

        if all_counts:
            print(f"\n{'=' * 80}")
            print(f"✅ Updated {len(all_counts)} count(s) across {len({c.test_name for c in all_counts})} test(s)")
            # Some performance counts can vary depending on test ordering / keepdb state.
            # Do a final full-suite pass and apply any remaining mismatches so the suite passes as run in CI.
            print("\nRunning a final verify pass for stability...")
            success, suite_mismatches = verify_and_get_mismatches(args.test_class)
            if not success and suite_mismatches:
                print("\nApplying remaining mismatches from full-suite run...")
                update_test_file(suite_mismatches)
                print("\nRe-running verify...")
                success, _ = verify_and_get_mismatches(args.test_class)
                sys.exit(0 if success else 1)
            sys.exit(0 if success else 1)
        else:
            print(f"\n{'=' * 80}")
            print("\n✅ No differences found. All tests are already up to date.")


if __name__ == "__main__":
    main()
