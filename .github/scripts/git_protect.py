import argparse
import logging
import re
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


def gitignore_to_regex(pattern) -> str:
    # Replace .gitignore-style patterns with regex equivalents
    pattern = pattern.replace("*", ".*")  # *      -> .*
    pattern = pattern.replace("?", ".")  # ?      -> .
    pattern = pattern.replace("[!", "[^")  # [!abc] -> [^abc]

    # If the pattern ends with '/', it matches directories
    if pattern.endswith("/"):
        pattern = f"{pattern}.*"

    return rf"^{pattern}"


def get_protected_files(file_name: str) -> list[str]:
    # Check to see if the .gitprotect file exists
    config_path = Path(file_name)
    if not config_path.exists():
        log.error(f"ERROR: Could not find .gitprotect at {config_path.absolute()}")
        exit(1)

    # Open the file and read in file paths
    with open(file_name, "r") as file:
        return [gitignore_to_regex(line.strip()) for line in file]


def get_changed_files(base_ref: str, head_ref: str) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            base_ref,
            head_ref,
        ],
        capture_output=True,
        text=True,
    )
    return result.stdout.splitlines()


def check_changes_against_protect_list(
    changed_files: list[str], protected_files: list[str]
):
    violations = set()

    # If any modified file is one in the protect list, add the files to the violations list
    for protected_file in protected_files:
        pattern = re.compile(protected_file)
        files_with_pattern = [f for f in changed_files if pattern.search(f)]
        violations.update(files_with_pattern)

    violations_list = "\n".join(violations)
    if violations:
        log.error(f"ERROR: The following files cannot be modified:\n{violations_list}")
        exit(1)


def main(args):
    changed_files = get_changed_files(args.base_ref, args.head_ref)
    protected_files = get_protected_files(".gitprotect")
    check_changes_against_protect_list(
        protected_files=protected_files, changed_files=changed_files
    )


if __name__ == "__main__":
    # base_ref head_ref
    parser = argparse.ArgumentParser(
        description="A utility function to check if protected files have been modified."
    )
    parser.add_argument(
        "base_ref", help="The git SHA for the most recent merged commit."
    )
    parser.add_argument("head_ref", help="The git SHA for the incoming commit")
    args = parser.parse_args()

    main(args)
