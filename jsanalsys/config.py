"""
Configuration management for jsanalsys.
Loads settings from ~/.jsanalsys/config.json or environment variables.
"""
import json
import os
from pathlib import Path
from typing import Optional


CONFIG_DIR = Path.home() / ".jsanalsys"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULTS = {
    "db_path": str(CONFIG_DIR / "jsanalsys.db"),
    "proxy": None,
    "verify_ssl": True,
    "delay": 0.0,
    "max_retries": 3,
    "timeout": 30,
    "beautify": True,
    "chunk_discovery": True,
    "sourcemaps": True,
    "min_severity": "info",
    "brute_chunks": 0,
    "save_js": False,
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
}


class Config:
    """Singleton configuration loader."""

    def __init__(self):
        CONFIG_DIR.mkdir(exist_ok=True)
        self._data = dict(DEFAULTS)
        self._load_file()
        self._load_env()

    def _load_file(self):
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE) as f:
                    file_data = json.load(f)
                self._data.update(file_data)
            except Exception:
                pass

    def _load_env(self):
        env_map = {
            "JSANALSYS_PROXY": "proxy",
            "JSANALSYS_DB": "db_path",
            "JSANALSYS_DELAY": "delay",
            "JSANALSYS_TIMEOUT": "timeout",
            "JSANALSYS_MIN_SEVERITY": "min_severity",
            "JSANALSYS_VERIFY_SSL": "verify_ssl",
        }
        for env_key, cfg_key in env_map.items():
            val = os.environ.get(env_key)
            if val is not None:
                # Type coerce
                if cfg_key in ("delay", "timeout"):
                    try:
                        val = float(val)
                    except ValueError:
                        pass
                elif cfg_key == "verify_ssl":
                    val = val.lower() not in ("false", "0", "no")
                self._data[cfg_key] = val

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def set(self, key: str, value):
        self._data[key] = value

    def save(self):
        """Persist config to file."""
        CONFIG_DIR.mkdir(exist_ok=True)
        with open(CONFIG_FILE, "w") as f:
            json.dump(self._data, f, indent=2)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return self._data.get(name)

    def __repr__(self):
        return f"Config({self._data})"


# Global config instance
config = Config()
