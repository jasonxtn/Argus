import os
# config/settings.py

RESULTS_DIR = "results"

DEFAULT_TIMEOUT = 10

USER_AGENT = "Mozilla/5.0 (compatible; ArgusRecon/2.0)"

API_KEYS = {
    "VIRUSTOTAL_API_KEY": os.getenv("VIRUSTOTAL_API_KEY", ""),
    "SHODAN_API_KEY": os.getenv("SHODAN_API_KEY", ""),
    "GOOGLE_API_KEY": os.getenv("GOOGLE_API_KEY", ""),
    "CENSYS_API_ID": os.getenv("CENSYS_API_ID", ""),
    "CENSYS_API_SECRET": os.getenv("CENSYS_API_SECRET", ""),
    "SSL_LABS_API_KEY": os.getenv("SSL_LABS_API_KEY", ""),
    "HIBP_API_KEY": os.getenv("HIBP_API_KEY", ""),
}

EXPORT_SETTINGS = {
    "enable_txt_export": True,
    "enable_csv_export": False
}

LOG_SETTINGS = {
    "enable_logging": True,
    "log_file": "argus.log",
    "log_level": "INFO"
}

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept-Language": "en-US,en;q=0.9"
}

DEFAULT_THREADS = 1
DEFAULT_MAX_PAGES = 100
DEFAULT_WARN_MS = 3000
DEFAULT_FULL_CHAIN = 0
DEFAULT_QUIET = False
DEFAULT_COLOR = True
DEFAULT_WRAP_WIDTH = None

PROFILE_DEFAULTS = {
    "speed": {
        "max_pages": 50,
        "warn_ms": 1000,
        "full_chain": 0,
        "threads_min": 2
    },
    "deep": {
        "max_pages": 1000,
        "warn_ms": 5000,
        "full_chain": 1,
        "threads_min": 5
    },
    "safe": {
        "max_pages": 25,
        "warn_ms": 2000,
        "full_chain": 0,
        "threads_min": 1
    }
}

from multiprocessing import cpu_count
DEFAULT_THREAD_CAP = min(32, cpu_count() * 5)

# Pipeline settings
PIPELINE_ENABLED = True
CONTEXT_CHAINING = True
QUALITY_GATES_ENABLED = True
AUTO_EXPORT = None  # Set to "json" or "markdown" to auto-export reports
SESSION_DIR = "~/.argus/sessions"
