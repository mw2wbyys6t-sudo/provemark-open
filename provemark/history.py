"""Scan history: a local, append-only progress ledger shared by CLI and plugin.

Why this exists
---------------
A single ``scan`` answers "how bad is it now". Progress needs the fourth
dimension: time. This module stores one compact record per scan, on this
machine, for as many projects as you scan, and derives from them:

* the score / severity timeline of one project,
* every finding's lifecycle (first seen → fixed → reopened),
* a cross-project roll-up for the dashboard.

Storage is one JSON object per line under ``<cache>/provemark/history.jsonl``
(``PROVEMARK_HISTORY_FILE`` overrides the path). JSONL keeps appends cheap and
survives a truncated write. The file is bounded: old records rotate out by
count, per-project count and age, and a rewrite is atomic.

Privacy: records contain the project path, severity counts, and finding
*metadata* (rule id, severity, relative path, fingerprint). No file contents,
no secrets, no source text ever leaves a record.
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from . import cache

HISTORY_VERSION = 1
DEFAULT_MAX_TOTAL = 5000
DEFAULT_MAX_PER_ROOT = 400
DEFAULT_KEEP_DAYS = 400
DEFAULT_DEDUPE_SECONDS = 3600
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def default_history_path() -> Path:
    override = os.environ.get("PROVEMARK_HISTORY_FILE")
    if override:
        return Path(override).expanduser()
    return cache.default_cache_dir() / "history.jsonl"


# ------------------------------------------------------------------- timestamp
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


# ------------------------------------------------------------------- building
def record_from_scan(
    result: Any,
    *,
    source: str = "cli",
    mode: str = "online",
    now: datetime | None = None,
    limit: int = 800,
) -> dict[str, Any]:
    """Turn a ScanResult (or anything shaped like one) into a history record."""
    moment = now or utc_now()
    score = getattr(result, "score", None)
    counts = result.counts_by_severity() if hasattr(result, "counts_by_severity") else {}
    stats = getattr(result, "stats", None)
    findings = []
    ordered = result.sorted_findings() if hasattr(result, "sorted_findings") else list(getattr(result, "findings", []))
    for finding in ordered[:limit]:
        findings.append(
            {
                "f": str(getattr(finding, "fingerprint", "") or ""),
                "r": str(getattr(finding, "rule_id", "") or ""),
                "s": str(getattr(finding, "severity", "") or ""),
                "p": str(getattr(finding, "path", "") or "")[:180],
            }
        )
    return {
        "v": HISTORY_VERSION,
        "ts": iso(moment),
        "root": str(getattr(result, "root", "") or ""),
        "score": int(score.total) if score is not None else None,
        "grade": str(getattr(score, "grade", "") or "") if score is not None else "",
        "counts": {name: int(counts.get(name, 0)) for name in SEVERITY_ORDER},
        "files": int(getattr(stats, "files_scanned", 0) or 0),
        "packages": int(getattr(stats, "packages_total", 0) or 0),
        "reliable": bool(getattr(score, "reliable", True)) if score is not None else False,
        "network": bool(getattr(stats, "network_used", False))
        if stats is not None
        else mode == "online",
        "source": source,
        "duration_ms": int(round(float(getattr(stats, "duration_s", 0.0) or 0.0) * 1000)),
        "suppressed": len(getattr(result, "suppressed", []) or []),
        "findings": findings,
    }


def _fingerprint_set(record: dict[str, Any]) -> frozenset[str]:
    return frozenset(str(item.get("f", "")) for item in record.get("findings", []) if item.get("f"))


def is_duplicate(previous: dict[str, Any] | None, record: dict[str, Any], window_seconds: int) -> bool:
    """True when two consecutive scans say exactly the same thing, close in time."""
    if not previous:
        return False
    if previous.get("score") != record.get("score"):
        return False
    if previous.get("counts") != record.get("counts"):
        return False
    if _fingerprint_set(previous) != _fingerprint_set(record):
        return False
    before = parse_ts(previous.get("ts"))
    after = parse_ts(record.get("ts"))
    if before is None or after is None:
        return False
    return (after - before) <= timedelta(seconds=max(0, window_seconds))


# --------------------------------------------------------------------- storage
def load_history(path: Path | None = None) -> list[dict[str, Any]]:
    target = path or default_history_path()
    if not target.is_file():
        return []
    records: list[dict[str, Any]] = []
    try:
        with target.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue  # a torn line must not sink the whole ledger
                if isinstance(record, dict) and record.get("root") and record.get("ts"):
                    records.append(record)
    except OSError:
        return []
    records.sort(key=lambda item: str(item.get("ts", "")))
    return records


def _write_history(records: list[dict[str, Any]], path: Path) -> bool:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, delete=False, suffix=".tmp"
        ) as handle:
            for record in records:
                handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            temp_path = Path(handle.name)
        temp_path.replace(path)
        return True
    except OSError:
        return False


def append_record(
    record: dict[str, Any],
    *,
    path: Path | None = None,
    dedupe_seconds: int = DEFAULT_DEDUPE_SECONDS,
    max_total: int = DEFAULT_MAX_TOTAL,
    max_per_root: int = DEFAULT_MAX_PER_ROOT,
    keep_days: int = DEFAULT_KEEP_DAYS,
) -> dict[str, Any] | None:
    """Append one record; returns it, or None when it was a duplicate/no-op."""
    target = path or default_history_path()
    records = load_history(target)
    root = str(record.get("root", ""))
    same_root = [item for item in records if item.get("root") == root]
    previous = same_root[-1] if same_root else None
    if is_duplicate(previous, record, dedupe_seconds):
        return None
    records.append(record)
    kept = _rotate(records, max_total=max_total, max_per_root=max_per_root, keep_days=keep_days)
    _write_history(kept, target)
    return record


def _rotate(
    records: list[dict[str, Any]],
    *,
    max_total: int,
    max_per_root: int,
    keep_days: int,
) -> list[dict[str, Any]]:
    newest = parse_ts(records[-1].get("ts")) if records else None
    cutoff = (newest or utc_now()) - timedelta(days=max(1, keep_days))
    kept: list[dict[str, Any]] = []
    per_root: dict[str, int] = {}
    for record in reversed(records):
        moment = parse_ts(record.get("ts"))
        if moment is not None and moment < cutoff:
            break  # sorted newest-last, so everything older is past the cutoff
        root = str(record.get("root", ""))
        if per_root.get(root, 0) >= max_per_root:
            continue
        per_root[root] = per_root.get(root, 0) + 1
        kept.append(record)
        if len(kept) >= max_total:
            break
    kept.reverse()
    return kept


# ---------------------------------------------------------------- computation
def project_events(records: Iterable[dict[str, Any]], root: str) -> list[dict[str, Any]]:
    return sorted(
        (item for item in records if item.get("root") == root),
        key=lambda item: str(item.get("ts", "")),
    )


def known_roots(records: Iterable[dict[str, Any]]) -> list[str]:
    seen: dict[str, str] = {}
    for record in records:
        root = str(record.get("root", ""))
        if root:
            seen[root] = max(seen.get(root, ""), str(record.get("ts", "")))
    return sorted(seen, key=lambda root: seen[root], reverse=True)


def project_progress(events: list[dict[str, Any]], *, now: datetime | None = None, window_days: int = 7) -> dict[str, Any]:
    """Lifecycle + timeline for one project (events must be chronological)."""
    moment = now or utc_now()
    if not events:
        return {"root": "", "scans": 0, "series": [], "open": [], "empty": True}
    first = events[0]
    last = events[-1]
    root = str(last.get("root", ""))

    # Replay the ledger: every fingerprint gets first/last sighting and a fix time.
    lifecycle: dict[str, dict[str, Any]] = {}
    fix_events: list[dict[str, Any]] = []
    reopen_events: list[dict[str, Any]] = []
    series: list[dict[str, Any]] = []
    for record in events:
        ts = str(record.get("ts", ""))
        current = _fingerprint_set(record)
        for item in record.get("findings", []):
            fingerprint = str(item.get("f", ""))
            if not fingerprint:
                continue
            entry = lifecycle.setdefault(
                fingerprint,
                {
                    "fingerprint": fingerprint,
                    "rule": str(item.get("r", "")),
                    "severity": str(item.get("s", "")),
                    "path": str(item.get("p", "")),
                    "first_ts": ts,
                    "last_ts": ts,
                    "fixed_ts": "",
                    "reopened": False,
                },
            )
            entry["last_ts"] = ts
            entry["severity"] = str(item.get("s", "")) or entry["severity"]
            if entry["fixed_ts"]:
                # It came back after being fixed: that is a regression, not a fix.
                entry["reopened"] = True
                entry["fixed_ts"] = ""
                reopen_events.append({"fingerprint": fingerprint, "rule": entry["rule"], "ts": ts})
        for fingerprint, entry in lifecycle.items():
            if fingerprint in current or entry["fixed_ts"]:
                continue
            entry["fixed_ts"] = ts
            fix_events.append(
                {
                    "fingerprint": fingerprint,
                    "rule": entry["rule"],
                    "severity": entry["severity"],
                    "ts": ts,
                }
            )
        counts = record.get("counts", {}) or {}
        series.append(
            {
                "ts": ts,
                "score": record.get("score"),
                "grade": str(record.get("grade", "")),
                "counts": {name: int(counts.get(name, 0)) for name in SEVERITY_ORDER},
                "open": len(current),
                "files": int(record.get("files", 0) or 0),
            }
        )

    last_set = _fingerprint_set(last)
    open_entries = [lifecycle[fp] for fp in last_set if fp in lifecycle]
    open_entries.sort(key=lambda entry: (_severity_rank(entry["severity"]), entry["first_ts"]))
    still_fixed = [
        entry for fingerprint, entry in lifecycle.items() if entry["fixed_ts"] and fingerprint not in last_set
    ]
    reopened = [entry for entry in lifecycle.values() if entry.get("reopened")]

    window_start = moment - timedelta(days=max(1, window_days))
    fixed_recent = [item for item in fix_events if _after(item.get("ts"), window_start)]
    new_recent = [entry for entry in open_entries if _after(entry.get("first_ts"), window_start)]
    baseline_score = _as_int(first.get("score"))
    current_score = _as_int(last.get("score"))
    previous_event = events[-2] if len(events) > 1 else None
    return {
        "root": root,
        "scans": len(events),
        "first_ts": str(first.get("ts", "")),
        "last_ts": str(last.get("ts", "")),
        "current": _snapshot(last),
        "baseline": _snapshot(first),
        "previous": _snapshot(previous_event) if previous_event else None,
        "delta_score": (current_score - baseline_score)
        if current_score is not None and baseline_score is not None
        else None,
        "delta_counts": _delta_counts(first, last),
        "series": series,
        "open": open_entries,
        "open_count": len(open_entries),
        "fixed": still_fixed,
        "fixed_count": len(still_fixed),
        "reopened": reopened,
        "reopened_count": len(reopened),
        "fixed_recent": fixed_recent,
        "new_recent": new_recent,
        "subjects": len(lifecycle),
        "empty": False,
    }


def _snapshot(record: dict[str, Any] | None) -> dict[str, Any]:
    if not record:
        return {}
    counts = record.get("counts", {}) or {}
    return {
        "ts": str(record.get("ts", "")),
        "score": _as_int(record.get("score")),
        "grade": str(record.get("grade", "")),
        "counts": {name: int(counts.get(name, 0)) for name in SEVERITY_ORDER},
        "reliable": bool(record.get("reliable", True)),
        "files": int(record.get("files", 0) or 0),
        "packages": int(record.get("packages", 0) or 0),
        "source": str(record.get("source", "")),
    }


def _delta_counts(first: dict[str, Any], last: dict[str, Any]) -> dict[str, int]:
    a = first.get("counts", {}) or {}
    b = last.get("counts", {}) or {}
    return {name: int(b.get(name, 0)) - int(a.get(name, 0)) for name in SEVERITY_ORDER}


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _after(value: Any, moment: datetime) -> bool:
    parsed = parse_ts(value)
    return parsed is not None and parsed >= moment


def _severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def filter_recent(events: list[dict[str, Any]], days: int, *, now: datetime | None = None) -> list[dict[str, Any]]:
    """Keep events inside the window; never return an empty list for a live project."""
    if days <= 0 or not events:
        return events
    cutoff = (now or utc_now()) - timedelta(days=days)
    recent = [event for event in events if _after(event.get("ts"), cutoff)]
    return recent or events[-1:]


def build_report(
    records: list[dict[str, Any]],
    *,
    now: datetime | None = None,
    days: int | None = None,
    roots: Iterable[str] | None = None,
    window_days: int = 7,
    path: Path | None = None,
) -> dict[str, Any]:
    """Cross-project report: one entry per project plus aggregate totals."""
    moment = now or utc_now()
    wanted = list(roots) if roots is not None else known_roots(records)
    projects = []
    for root in wanted:
        events = project_events(records, root)
        if not events:
            continue
        if days:
            events = filter_recent(events, days, now=moment)
        projects.append(project_progress(events, now=moment, window_days=window_days))
    projects.sort(key=lambda project: str(project.get("last_ts", "")), reverse=True)
    totals = {
        "projects": len(projects),
        "scans": sum(int(project.get("scans", 0)) for project in projects),
        "open": sum(int(project.get("open_count", 0)) for project in projects),
        "fixed": sum(int(project.get("fixed_count", 0)) for project in projects),
        "reopened": sum(int(project.get("reopened_count", 0)) for project in projects),
        "by_severity": {
            name: sum(int((project.get("current", {}).get("counts", {}) or {}).get(name, 0)) for project in projects)
            for name in SEVERITY_ORDER
        },
        "fixed_recent": sum(len(project.get("fixed_recent", []) or []) for project in projects),
        "new_recent": sum(len(project.get("new_recent", []) or []) for project in projects),
    }
    return {
        "generated_at": iso(moment),
        "history_path": str(path or default_history_path()),
        "totals": totals,
        "projects": projects,
    }
