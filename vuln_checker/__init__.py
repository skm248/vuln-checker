"""vuln-checker: CVE vulnerability scanner"""

import logging

# Version is read from package metadata (pyproject.toml) at runtime
try:
    from importlib.metadata import version
    __version__ = version("vuln-checker")
except Exception:
    # Fallback for development mode: read directly from pyproject.toml
    try:
        import tomli
        import os
        _pyproject_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "pyproject.toml")
        with open(_pyproject_path, "rb") as _f:
            _pyproject = tomli.load(_f)
            __version__ = _pyproject.get("project", {}).get("version", "unknown")
    except Exception:
        __version__ = "unknown"

__author__ = "Skm248"
__license__ = "MIT"

logger = logging.getLogger(__name__)
