#!/usr/bin/env python3

import argparse
import json
import logging
import re
from collections.abc import Generator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from time import perf_counter
from typing import Any

DATETIME_FIELD_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})T"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d{1,6}))?Z$",
)
DATE_FIELD_PATTERN = re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2})$")
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ParsedUtcTimestamp:

    """
    UTC timestamp with preserved formatting metadata.

    >>> parsed = ParsedUtcTimestamp.parse("2024-01-02")
    >>> parsed is not None
    True
    >>> parsed.dt.isoformat()
    '2024-01-02T00:00:00+00:00'
    >>> parsed.value_type is DATE_FIELD_PATTERN
    True
    >>> parsed.fraction_len
    0

    >>> parsed = ParsedUtcTimestamp.parse("2024-01-02T03:04:05.12Z")
    >>> parsed is not None
    True
    >>> parsed.dt.isoformat()
    '2024-01-02T03:04:05.120000+00:00'
    >>> parsed.value_type is DATETIME_FIELD_PATTERN
    True
    >>> parsed.fraction_len
    2

    >>> ParsedUtcTimestamp.parse("2024-01-02T03:04:05.12Zx") is None
    True
    >>> ParsedUtcTimestamp.parse("2024-01-02T03:04:05Z") is not None
    True

    >>> dt = datetime.fromisoformat("2024-01-02T03:04:05.123456+00:00")
    >>> ParsedUtcTimestamp(dt, DATETIME_FIELD_PATTERN, 2).format()
    '2024-01-02T03:04:05.12Z'
    >>> ParsedUtcTimestamp(dt, DATE_FIELD_PATTERN, 0).format()
    '2024-01-02'
    """

    dt: datetime
    value_type: re.Pattern[str]
    fraction_len: int

    @classmethod
    def parse(cls, value: str) -> "ParsedUtcTimestamp | None":
        match = DATETIME_FIELD_PATTERN.match(value)
        if match:
            fraction = match.group("fraction") or ""
            padded_fraction = (fraction + "000000")[:6]
            timestamp = f"{match.group('date')}T{match.group('time')}.{padded_fraction}+00:00"
            parsed = datetime.fromisoformat(timestamp)
            return cls(parsed, DATETIME_FIELD_PATTERN, len(fraction))

        date_only_match = DATE_FIELD_PATTERN.match(value)
        if date_only_match:
            parsed = datetime.fromisoformat(f"{date_only_match.group('date')}T00:00:00+00:00")
            return cls(parsed, DATE_FIELD_PATTERN, 0)

        return None

    def format(self) -> str:
        value = self.dt.astimezone(UTC)
        if self.value_type is DATE_FIELD_PATTERN:
            return value.date().isoformat()

        base = value.strftime("%Y-%m-%dT%H:%M:%S")
        if self.fraction_len > 0:
            micro = f"{value.microsecond:06d}"[: self.fraction_len]
            return f"{base}.{micro}Z"
        return f"{base}Z"

    def shifted(self, delta: timedelta) -> "ParsedUtcTimestamp":
        return ParsedUtcTimestamp(self.dt + delta, self.value_type, self.fraction_len)


def iter_string_nodes(value: Any) -> Generator[tuple[dict[str, Any] | list[Any], str | int, str]]:
    """
    Yield mutable container references for every nested string value.

    >>> data = {"a": "x", "b": [1, {"c": "y"}]}
    >>> list(iter_string_nodes(data))
    [({'a': 'x', 'b': [1, {'c': 'y'}]}, 'a', 'x'), ({'c': 'y'}, 'c', 'y')]
    """
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, str):
                yield value, key, item
            else:
                yield from iter_string_nodes(item)
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            if isinstance(item, str):
                yield value, idx, item
            else:
                yield from iter_string_nodes(item)


def parse_target_latest_time(value: str) -> datetime:
    """
    Parse CLI `--latest-time` values.

    >>> parse_target_latest_time("2024-01-02").isoformat()
    '2024-01-02T00:00:00+00:00'
    >>> parse_target_latest_time("oops")
    Traceback (most recent call last):
    ...
    argparse.ArgumentTypeError: Invalid --latest-time. Expected YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS(.fraction)Z.
    """
    parsed = ParsedUtcTimestamp.parse(value)
    if not parsed:
        msg = "Invalid --latest-time. Expected YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS(.fraction)Z."
        raise argparse.ArgumentTypeError(msg)
    return parsed.dt


class FixtureUpdater:
    def __init__(self, fixture_path: Path, output_path: Path, target_latest_dt: datetime | None = None) -> None:
        self.fixture_path = fixture_path
        self.output_path = output_path
        self.target_latest_dt = target_latest_dt
        self.data: list[dict[str, Any]] = []
        self.found_dates: list[tuple[dict[str, Any] | list[Any], str | int, ParsedUtcTimestamp]] = []
        self.latest: ParsedUtcTimestamp | None = None
        self.delta: timedelta | None = None
        self.updated_count = 0
        self.elapsed_ms = 0

    def load_fixture(self) -> None:
        data = json.loads(self.fixture_path.read_text())
        if not isinstance(data, list):
            msg = "Fixture JSON must be an array at the top level."
            raise TypeError(msg)
        for idx, item in enumerate(data):
            if not isinstance(item, dict):
                msg = f"Fixture item at index {idx} is not an object."
                raise TypeError(msg)
            fields = item.get("fields")
            if not isinstance(fields, dict):
                msg = f'Fixture item at index {idx} is missing a valid "fields" object.'
                raise TypeError(msg)
        self.data = data

    def collect_dates(self) -> None:
        for obj in self.data:
            for container, key, item in iter_string_nodes(obj["fields"]):
                parsed = ParsedUtcTimestamp.parse(item)
                if parsed:
                    self.found_dates.append((container, key, parsed))

    def compute_shift(self) -> None:
        """
        Compute the delta between fixture latest timestamp and target timestamp.

        >>> updater = FixtureUpdater(Path("in.json"), Path("out.json"), parse_target_latest_time("2024-01-03"))
        >>> parsed = ParsedUtcTimestamp.parse("2024-01-01")
        >>> parsed is not None
        True
        >>> updater.found_dates = [({"x": "2024-01-01"}, "x", parsed)]
        >>> updater.compute_shift()
        >>> updater.delta == timedelta(days=2)
        True
        """
        _, _, self.latest = max(self.found_dates, key=lambda value: value[2].dt)
        target = self.target_latest_dt or datetime.now(UTC)
        self.delta = target - self.latest.dt

    def apply_shift(self) -> int:
        """
        Apply previously computed delta to all collected timestamp fields.

        >>> updater = FixtureUpdater(Path("in.json"), Path("out.json"))
        >>> parsed = ParsedUtcTimestamp.parse("2024-01-01T00:00:00Z")
        >>> parsed is not None
        True
        >>> container = {"x": "2024-01-01T00:00:00Z"}
        >>> updater.found_dates = [(container, "x", parsed)]
        >>> updater.delta = timedelta(days=1)
        >>> updater.apply_shift()
        1
        >>> container["x"]
        '2024-01-02T00:00:00Z'
        """
        if self.delta is None:
            msg = "Cannot apply shift before computing delta."
            raise RuntimeError(msg)
        for container, key, parsed in self.found_dates:
            container[key] = parsed.shifted(self.delta).format()
        return len(self.found_dates)

    def write_output(self) -> None:
        self.output_path.write_text(json.dumps(self.data, indent=2))

    def run(self) -> None:
        started_at = perf_counter()
        self.load_fixture()
        self.collect_dates()
        if not self.found_dates:
            self.elapsed_ms = int((perf_counter() - started_at) * 1000)
            return

        self.compute_shift()
        self.updated_count = self.apply_shift()
        self.write_output()
        self.elapsed_ms = int((perf_counter() - started_at) * 1000)

    def report(self) -> None:
        if self.latest is None or self.delta is None:
            logger.info("No matching UTC date strings found. No changes made.")
            logger.info("Completed in %dms!", self.elapsed_ms)
            return

        logger.info("Dates moved up by %.1f days", self.delta.total_seconds() / 86400)
        logger.info("Updated %d date value(s).", self.updated_count)
        logger.info(
            "Most recent original timestamp: %s",
            self.latest.format(),
        )
        logger.info(
            "New most recent timestamp:      %s",
            self.latest.shifted(self.delta).format(),
        )
        logger.info("Wrote updated fixture to:       %s", self.output_path)
        logger.info("Completed in %dms!", self.elapsed_ms)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    parser = argparse.ArgumentParser(
        description=(
            "Shift date values under each fixture object's 'fields' (supports "
            "YYYY-MM-DDTHH:MM:SS(.fraction)Z and YYYY-MM-DD) so the most recent "
            "detected value becomes the current UTC datetime."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("fixture_file", type=Path, help="Path to a Django fixture JSON file")
    parser.add_argument(
        "-o",
        "--output-file",
        default="output.json",
        type=Path,
        help="Path to output JSON file",
    )
    parser.add_argument(
        "--latest-time",
        type=parse_target_latest_time,
        help="Custom UTC target for the most recent fixture timestamp",
    )
    args = parser.parse_args()
    updater = FixtureUpdater(args.fixture_file, args.output_file, args.latest_time)
    updater.run()
    updater.report()


if __name__ == "__main__":
    main()
