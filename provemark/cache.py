from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any


def default_cache_dir() -> Path:
    override = os.environ.get("PROVEMARK_CACHE_DIR") or os.environ.get("REPOSENTINEL_CACHE_DIR")
    if override:
        return Path(override).expanduser()
    base = os.environ.get("XDG_CACHE_HOME")
    root = Path(base).expanduser() if base else Path.home() / ".cache"
    return root / "provemark"


MAX_ENTRIES = 20000
KEEP_ENTRIES = 15000


class Cache:
    def __init__(self, directory: Path | None = None, enabled: bool = True) -> None:
        self.directory = directory or default_cache_dir()
        self.enabled = enabled
        self.path = self.directory / "cache.json"
        self._data: dict[str, dict[str, Any]] = {}
        self._dirty = False
        self._loaded = False

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.enabled or not self.path.is_file():
            return
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if isinstance(data, dict):
                self._data = data
        except (OSError, json.JSONDecodeError):
            self._data = {}

    def get(self, key: str, ttl: float) -> Any | None:
        if not self.enabled:
            return None
        self._load()
        entry = self._data.get(key)
        if not isinstance(entry, dict):
            return None
        if ttl >= 0 and time.time() - float(entry.get("ts", 0)) > ttl:
            return None
        return entry.get("value")

    def set(self, key: str, value: Any) -> None:
        if not self.enabled:
            return
        self._load()
        self._data[key] = {"ts": time.time(), "value": value}
        self._dirty = True

    def _prune(self) -> None:
        if len(self._data) <= MAX_ENTRIES:
            return
        ordered = sorted(
            self._data.items(), key=lambda item: float(item[1].get("ts", 0) or 0)
        )
        for key, _ in ordered[: len(self._data) - KEEP_ENTRIES]:
            self._data.pop(key, None)
        self._dirty = True

    def save(self) -> None:
        if not self.enabled or not self._dirty:
            return
        self._prune()
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=self.directory, delete=False, suffix=".tmp"
            ) as handle:
                json.dump(self._data, handle, ensure_ascii=False)
                temp_path = Path(handle.name)
            temp_path.replace(self.path)
        except OSError:
            return
        self._dirty = False
