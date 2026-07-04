from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from trace2policy.models import Event, Policy, TraceValidationError


def read_json_file(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_json_file(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise TraceValidationError(str(path), line_number, exc.msg) from exc
            if not isinstance(value, dict):
                raise TraceValidationError(str(path), line_number, "JSONL row must be an object")
            rows.append(value)
    return rows


def write_jsonl(path: Path, events: Iterable[Event]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for event in events:
            handle.write(event.model_dump_json(exclude_none=True))
            handle.write("\n")


def load_events(path: Path) -> list[Event]:
    events: list[Event] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
                events.append(Event.model_validate(value))
            except json.JSONDecodeError as exc:
                raise TraceValidationError(str(path), line_number, exc.msg) from exc
            except ValidationError as exc:
                raise TraceValidationError(str(path), line_number, str(exc)) from exc
    return events


def load_policy(path: Path) -> Policy:
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: policy YAML must be an object")
    return Policy.model_validate(data)


def write_policy(path: Path, policy: Policy) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        yaml.safe_dump(
            policy.model_dump(mode="json", exclude_none=True),
            handle,
            sort_keys=False,
            allow_unicode=False,
        )
