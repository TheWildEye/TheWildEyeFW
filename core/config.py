import os
import copy
import yaml

HERE = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

DEFAULT_CONFIG = {
    "general": {
        "timeout": 10,
        "max_threads": 20,
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "proxy": None,
        "max_retries": 2,
        "delay": 0.5,
    },
    "crawler": {
        "max_urls": 500,
        "max_depth": 3,
        "js_render": False,
        "extract_emails": True,
        "extract_links": True,
        "extract_js": True,
        "extract_forms": True,
        "extract_comments": True,
        "same_domain_only": True,
    },
    "dirhunter": {
        "extensions": ["php", "asp", "aspx", "jsp", "html", "txt", "xml", "json", "bak", "old", "zip", "tar.gz", "sql", "env", "conf"],
        "status_codes": [200, 301, 302, 403, 401, 500],
    },
    "js_reaper": {
        "extract_endpoints": True,
        "extract_secrets": True,
        "extract_routes": True,
        "fetch_sourcemaps": True,
        "max_js_files": 200,
    },

}

class Config:
    def __init__(self, path=None):
        self.data = copy.deepcopy(DEFAULT_CONFIG)
        if path is None:
            path = os.path.join(HERE, "config.yaml")
        if os.path.exists(path):
            with open(path, "r") as f:
                loaded = yaml.safe_load(f) or {}
            self._deep_merge(self.data, loaded)
        self._loaded_path = path

    def _deep_merge(self, base, override):
        for k, v in override.items():
            if isinstance(v, dict) and k in base and isinstance(base[k], dict):
                self._deep_merge(base[k], v)
            else:
                base[k] = v

    def get(self, *keys, default=None):
        val = self.data
        for k in keys:
            if isinstance(val, dict):
                val = val.get(k)
            else:
                return default
            if val is None:
                return default
        return val

    def set(self, key, value):
        self.data[key] = value

    def as_dict(self):
        return self.data

config = Config()
