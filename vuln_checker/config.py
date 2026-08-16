"""Configuration management"""
import os
from typing import Optional
import toml
import logging

logger = logging.getLogger(__name__)

class Config:
    """TOML-based configuration with defaults"""
    
    DEFAULT_FEED_DIR = "nvd_feeds"
    DEFAULT_START_YEAR = 2002
    DEFAULT_CACHE_FILE = "cve_cache.json"
    DEFAULT_INVENTORY_FILE = "server_inventory.json"
    DEFAULT_OUTPUT_DIR = "reports"
    DEFAULT_MAX_WORKERS = 5
    DEFAULT_LOG_FILE = "vuln-checker.log"
    
    DEFAULT_ALLOWED_LICENSES = [
        "MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Python-2.0",
        "LGPL-2.1-only", "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later",
        "Public-Domain", "CC0-1.0", "Unlicense", "Zlib"
    ]
    DEFAULT_DENIED_LICENSES = [
        "GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0-only", "AGPL-3.0-or-later",
        "SSPL", "Commons-Clause"
    ]
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file
        self.data = self._load_config()
    
    def _load_config(self) -> dict:
        """Load TOML config or use defaults"""
        config = {
            "feed_dir": self.DEFAULT_FEED_DIR,
            "start_year": self.DEFAULT_START_YEAR,
            "cache_file": self.DEFAULT_CACHE_FILE,
            "inventory_file": self.DEFAULT_INVENTORY_FILE,
            "output_dir": self.DEFAULT_OUTPUT_DIR,
            "max_workers": self.DEFAULT_MAX_WORKERS,
            "log_file": self.DEFAULT_LOG_FILE,
            "log_level": "INFO", 
            "excluded_cpes_file": "excluded_cpes.txt",
            "exclude_dirs": ["/proc", "/sys", "/dev", "/run", "/boot", "/var/log", "/var/cache", "/var/tmp", "/tmp", "/lost+found", "/media", "/mnt", "/srv", "/var/lib/docker", "/var/lib/containerd", "/var/lib/flatpak", "/var/lib/snapd", "/var/lib/rpm", "/var/lib/dpkg", "/var/lib/apt", "/usr/share/doc", "/usr/share/man"],
            "license_policy": {
                "enabled": False,
                "fail_on_violation": False,
                "allowed_licenses": self.DEFAULT_ALLOWED_LICENSES,
                "denied_licenses": self.DEFAULT_DENIED_LICENSES
            }
        }
        
        # Try to find config file: 1. Passed file, 2. CWD, 3. Package Dir
        active_config = self.config_file
        if not active_config or not os.path.exists(active_config):
            # Check CWD
            cwd_config = os.path.join(os.getcwd(), "config.toml")
            if os.path.exists(cwd_config):
                active_config = cwd_config
            else:
                # Check Package Data Dir
                pkg_config = os.path.join(os.path.dirname(__file__), "data", "config.toml")
                if os.path.exists(pkg_config):
                    active_config = pkg_config

        if active_config and os.path.exists(active_config):
            try:
                with open(active_config, 'r') as f:
                    toml_config = toml.load(f)
                    config.update(toml_config)
                    logger.info(f"✅ Loaded config from {active_config}")
            except Exception as e:
                logger.warning(f"⚠️ Failed to load config from {active_config}: {e}. Using defaults.")
        else:
            logger.info("ℹ️ No config.toml found. Using internal defaults.")
        
        return config
    
    def get(self, key: str, default=None):
        if key in self.data:
            return self.data[key]
        # Fallback: search in nested tables/sections
        for val in self.data.values():
            if isinstance(val, dict) and key in val:
                return val[key]
        return default
    
    def set(self, key: str, value):
        self.data[key] = value
    
    def save(self, output_file: str):
        try:
            with open(output_file, 'w') as f:
                toml.dump(self.data, f)
            logger.info(f"✅ Config saved to {output_file}")
        except Exception as e:
            logger.error(f"❌ Failed to save config: {e}")
