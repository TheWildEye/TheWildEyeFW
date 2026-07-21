import os
import sys
import time
import threading
import importlib.util
from abc import ABC, abstractmethod

HERE = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

_module_registry = {}

class ReconModule(ABC):
    name = "base"
    description = "Base recon module"
    requires_target = True
    output_formats = ["txt", "json"]

    def __init__(self, config):
        self.config = config
        self.results = {}
        self.start_time = None
        self.end_time = None
        self.target = None
        self.report_writer = None

    @abstractmethod
    def run(self, target):
        pass

    def setup(self, target):
        self.target = target
        self.start_time = time.time()
        from core.reporter import ReportWriter
        self.report_writer = ReportWriter(self.name, target)
        return True

    def teardown(self):
        self.end_time = time.time()
        elapsed = self.end_time - self.start_time if self.start_time else 0
        self.results["elapsed_seconds"] = round(elapsed, 2)
        if self.report_writer:
            for section_name, section_data in self.results.items():
                if section_name != "elapsed_seconds":
                    self.report_writer.add_section(section_name, section_data)

    def save_report(self, partial=False):
        if not self.report_writer:
            return None
        if partial:
            self.results["partial"] = True
            self.report_writer.add_section("partial", True)
        saved = self.report_writer.save(self.output_formats)
        from core.utils import colored
        tag = "Partial report saved" if partial else "Report saved"
        print(f"\n  {colored(f'[+] {tag}:', 'green')}")
        for fmt, path in saved.items():
            print(f"    {fmt.upper()}: {colored(path, 'cyan')}")
        return saved

    def log(self, message, color=None):
        timestamp = time.strftime("%H:%M:%S")
        prefix = f"[{self.name}]"
        if color:
            from core.utils import colored
            print(f"{colored(timestamp, 'cyan')} {colored(prefix, 'green')} {message}")
        else:
            print(f"{timestamp} {prefix} {message}")

    def error(self, message):
        from core.utils import colored
        print(f"{colored('[ERROR]', 'red')} [{self.name}] {message}")


def register_module(cls):
    _module_registry[cls.name] = cls
    return cls


def get_module(name):
    return _module_registry.get(name)


def list_modules():
    return dict(_module_registry)


def autodiscover_modules():
    modules_dir = os.path.join(HERE, "modules")
    if not os.path.isdir(modules_dir):
        return
    sys.path.insert(0, HERE)
    for fname in sorted(os.listdir(modules_dir)):
        if fname.endswith(".py") and not fname.startswith("__"):
            modname = fname[:-3]
            try:
                importlib.import_module(f"modules.{modname}")
            except Exception as e:
                print(f"[-] Failed to load module {modname}: {e}")
