import json
import shutil
import subprocess
import urllib.request
import zipfile
from pathlib import Path
from typing import List, Optional

from copyleft_auditor.constants import LOKI_DEFAULT_VERSION, LOKI_ZIP_URL
from copyleft_auditor.models import LokiFinding


class LokiScanner:
    def __init__(self, workspace_dir: str):
        self.workspace_dir = Path(workspace_dir)
        self.loki_dir = self.workspace_dir / "loki"
        self.loki_exe = self.loki_dir / "loki.exe"
        self.loki_upgrader = self.loki_dir / "loki-upgrader.exe"
        self.is_available = False
        self._check_loki()

    def _check_loki(self):
        if self.loki_exe.exists():
            self.is_available = True
            return
        loki_path = shutil.which('loki.exe')
        if loki_path:
            self.loki_dir = Path(loki_path).parent
            self.loki_exe = Path(loki_path)
            self.is_available = True
            return
        self._download_loki()

    def _download_loki(self):
        try:
            print("Downloading Loki...")
            zip_path = self.workspace_dir / "loki.zip"
            urllib.request.urlretrieve(LOKI_ZIP_URL, zip_path)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(self.workspace_dir)
            extracted = self.workspace_dir / f"loki-{LOKI_DEFAULT_VERSION}"
            if extracted.exists():
                if self.loki_dir.exists():
                    shutil.rmtree(self.loki_dir)
                shutil.move(str(extracted), str(self.loki_dir))
            zip_path.unlink()
            if self.loki_exe.exists():
                self.is_available = True
                print("Loki downloaded successfully")
        except Exception as e:
            print(f"Loki download error: {e}")

    def update_signatures(self) -> bool:
        if not self.is_available:
            return False
        try:
            if self.loki_upgrader.exists():
                subprocess.run(
                    [str(self.loki_upgrader)],
                    capture_output=True, text=True, timeout=120,
                    cwd=str(self.loki_dir)
                )
                return True
            return False
        except Exception:
            return False

    def scan(self, target_path: str, progress_callback=None) -> List[LokiFinding]:
        if not self.is_available:
            return []
        findings = []
        report_path = self.workspace_dir / "loki_report.json"
        try:
            if progress_callback:
                progress_callback(95, "Scanning Loki (threat signatures)...")
            cmd = [
                str(self.loki_exe),
                "--folder", target_path,
                "--jsonl", str(report_path),
                "--no-tui",
                "--nolog",
                "--no-html"
            ]
            subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=300, cwd=str(self.loki_dir)
            )
            if report_path.exists():
                with open(report_path, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            if data.get('type') == 'hit':
                                level = data.get('level', 'unknown')
                                findings.append(LokiFinding(
                                    file=data.get('file', ''),
                                    rule=data.get('rule', ''),
                                    level=level,
                                    level_emoji='🔴' if level == 'high' else '🟡' if level == 'medium' else '🟢',
                                    description=data.get('description', '')
                                ))
                        except json.JSONDecodeError:
                            continue
                report_path.unlink()
            return findings
        except subprocess.TimeoutExpired:
            print("Loki scan timeout (>5 min)")
            return []
        except Exception:
            return []
