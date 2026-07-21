import os
import json
import csv
import time
import io

HERE = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

class ReportWriter:
    def __init__(self, module_name, target, output_dir=None):
        self.module_name = module_name
        self.target = target
        self.timestamp = time.strftime("%Y%m%d_%H%M%S")
        self.human_time = time.strftime("%Y-%m-%d %H:%M:%S")
        if output_dir:
            self.output_dir = output_dir
        else:
            self.output_dir = os.path.join(HERE, "reports")
        os.makedirs(self.output_dir, exist_ok=True)
        safe_target = target.replace("://", "_").replace(".", "_").replace("/", "_")[:60]
        self.base_name = f"{module_name}_{safe_target}_{self.timestamp}"
        self.data = {
            "module": module_name,
            "target": target,
            "timestamp": self.human_time,
            "results": {},
        }

    def add_section(self, name, content):
        self.data["results"][name] = content

    def to_txt(self):
        buf = io.StringIO()
        buf.write(f"{'='*60}\n")
        buf.write(f"TheWildEye - {self.module_name.upper()} Report\n")
        buf.write(f"Target: {self.target}\n")
        buf.write(f"Timestamp: {self.human_time}\n")
        buf.write(f"{'='*60}\n\n")
        self._write_section_txt(buf, self.data["results"], 0)
        return buf.getvalue()

    def _write_section_txt(self, buf, section, indent=0):
        prefix = "  " * indent
        if isinstance(section, dict):
            for key, value in section.items():
                if isinstance(value, (dict, list)):
                    buf.write(f"{prefix}[{key}]\n")
                    self._write_section_txt(buf, value, indent + 1)
                else:
                    buf.write(f"{prefix}{key}: {value}\n")
        elif isinstance(section, list):
            for item in section:
                if isinstance(item, (dict, list)):
                    self._write_section_txt(buf, item, indent)
                else:
                    buf.write(f"{prefix}- {item}\n")
        else:
            buf.write(f"{prefix}{section}\n")

    def to_json(self):
        return json.dumps(self.data, indent=2, default=str)

    def to_csv(self, flat_data):
        buf = io.StringIO()
        if not flat_data:
            return ""
        writer = csv.writer(buf)
        writer.writerow(list(flat_data[0].keys()))
        for row in flat_data:
            writer.writerow(list(row.values()))
        return buf.getvalue()

    def save_txt(self):
        path = os.path.join(self.output_dir, f"{self.base_name}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_txt())
        self._last_txt = path
        return path

    def save_json(self):
        path = os.path.join(self.output_dir, f"{self.base_name}.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write(self.to_json())
        self._last_json = path
        return path

    def save(self, formats=None):
        if formats is None:
            formats = ["txt"]
        saved = {}
        if "txt" in formats:
            saved["txt"] = self.save_txt()
        if "json" in formats:
            saved["json"] = self.save_json()
        self.saved = saved
        return saved

    def print_paths(self):
        paths = getattr(self, "saved", {})
        if not paths:
            return None
        from core.utils import colored
        print(f"\n{colored('[+] Report saved:', 'green')}")
        for fmt, path in paths.items():
            print(f"    {fmt.upper()}: {colored(path, 'cyan')}")
        return paths
