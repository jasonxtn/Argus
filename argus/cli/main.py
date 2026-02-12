import os, sys
from collections import deque
from cmd2 import Cmd
from rich.prompt import Prompt, Confirm
from argus.cli.commands import register_mixins
from argus.cli.status_bar import print_status_bar
from argus.cli.logo import logo
from argus.cli.helpers import (
    resolve_module_number,
    fuzzy_find_modules,
    suggest_option_name,
    numeric_or_warn,
    ALL_KNOWN_MODULE_OPTIONS,
    NUMERIC_OPTION_HINTS,
)
from argus.utils.util import check_api_configured
from argus.core.catalog_cache import (
    number_of_modules,
    VERSION,
    AUTHOR,
)

Base = Cmd

class _BareCLI(Base):
    prompt = "argus> "
    intro = ""

    def __init__(self):
        super().__init__()
        self.selected_module = None
        self.target = None
        self.threads = 1
        self.api_status = {
            "virustotal": check_api_configured("VIRUSTOTAL_API_KEY"),
            "shodan": check_api_configured("SHODAN_API_KEY"),
            "google": check_api_configured("GOOGLE_API_KEY"),
            "censys": check_api_configured("CENSYS_API_ID"),
            "censys_secret": check_api_configured("CENSYS_API_SECRET"),
            "ssl_labs": check_api_configured("SSL_LABS_API_KEY"),
            "hibp": check_api_configured("HIBP_API_KEY")
        }
        self.last_search_results = []
        self.module_options = {}
        self.global_option_overrides = {}
        self.recent_modules = deque(maxlen=10)
        self.favorite_modules = set()
        self.last_run_outputs = {}
        self.last_run_runtimes = []
        self.quiet_mode = False
        self.no_color = False
        self.wrap_width = None
        self._session = None  # Pipeline session (lazy-initialized)
        os.system("cls" if os.name == "nt" else "clear")
        logo(VERSION, number_of_modules, AUTHOR)
        print_status_bar(self)

    def _print_status_bar(self):
        print_status_bar(self)

    def _prompt_target_if_needed(self):
        if not self.target:
            self.target = Prompt.ask("Enter target domain or URL")

    def _resolve_by_any(self, ident: str):
        ident = ident.strip()
        r = resolve_module_number(ident) if ident.isdigit() else None
        if r:
            return next(t for t in fuzzy_find_modules("") if t["number"] == r)
        m = fuzzy_find_modules(ident)
        return m[0] if m else None

    def _record_recent(self, mid: str):
        try:
            self.recent_modules.remove(mid)
        except ValueError:
            pass
        self.recent_modules.append(mid)
        if list(self.recent_modules).count(mid) >= 5 and mid not in self.favorite_modules:
            if Confirm.ask(f"Add module {mid} to favorites?", default=False):
                self.favorite_modules.add(mid)

ArgusCLI = register_mixins(_BareCLI)

def main():
    ArgusCLI().cmdloop()
