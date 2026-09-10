import os
import shutil
import subprocess
from typing import List, Optional, Tuple


class ArchiveExtractor:
    """Распаковка архивов с помощью 7za.exe (7-Zip)"""

    SUPPORTED_EXTENSIONS = {'.zip', '.7z', '.rar', '.tar', '.gz', '.bz2', '.xz', '.tgz', '.tbz2', '.txz'}

    def __init__(self):
        self.seven_zip_path = self._find_7zip()
        self.is_available = self.seven_zip_path is not None
        if self.is_available:
            print(f"7-Zip found: {self.seven_zip_path}")
        else:
            print("7-Zip not found. Install 7-Zip for archive extraction")

    def _find_7zip(self) -> Optional[str]:
        current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bin_paths = [
            os.path.join(current_dir, 'bin', '7za.exe'),
            os.path.join(current_dir, 'bin', '7z.exe'),
        ]
        for path in bin_paths:
            if os.path.exists(path):
                return path

        for name in ['7za.exe', '7z.exe']:
            path = shutil.which(name)
            if path:
                return path

        possible_paths = [
            r'C:\Program Files\7-Zip\7za.exe',
            r'C:\Program Files\7-Zip\7z.exe',
            r'C:\Program Files (x86)\7-Zip\7za.exe',
            r'C:\Program Files (x86)\7-Zip\7z.exe',
            r'C:\7-Zip\7za.exe',
            r'C:\7-Zip\7z.exe',
        ]
        for path in possible_paths:
            if os.path.exists(path):
                return path

        local_paths = [
            os.path.join(current_dir, '7za.exe'),
            os.path.join(current_dir, '7z.exe'),
        ]
        for path in local_paths:
            if os.path.exists(path):
                return path

        return None

    def extract(self, archive_path: str, extract_dir: str, progress_callback=None) -> Tuple[bool, List[str]]:
        if not self.is_available:
            return False, []
        if not os.path.exists(archive_path):
            return False, []

        ext = os.path.splitext(archive_path)[1].lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            _, ext2 = os.path.splitext(os.path.splitext(archive_path)[0])
            if ext2 + ext not in ['.tar.gz', '.tar.bz2', '.tar.xz']:
                return False, []

        try:
            os.makedirs(extract_dir, exist_ok=True)

            if progress_callback:
                progress_callback(15, f"Unpacking {os.path.basename(archive_path)}...")

            cmd = [
                self.seven_zip_path,
                'x',
                archive_path,
                f'-o{extract_dir}',
                '-y',
                '-aos',
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )

            if result.returncode == 0:
                extracted_files = []
                for root, _, files in os.walk(extract_dir):
                    for f in files:
                        extracted_files.append(os.path.join(root, f))
                print(f"Extracted {len(extracted_files)} files from {os.path.basename(archive_path)}")
                return True, extracted_files
            else:
                print(f"Extraction error {archive_path}: {result.stderr}")
                return False, []

        except subprocess.TimeoutExpired:
            print(f"Extraction timeout {archive_path} (>5 min)")
            return False, []
        except Exception as e:
            print(f"Extraction error {archive_path}: {e}")
            return False, []

    def find_archives(self, root_path: str) -> List[str]:
        archives = []
        for root, _, files in os.walk(root_path):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in self.SUPPORTED_EXTENSIONS:
                    archives.append(os.path.join(root, f))
                else:
                    _, ext2 = os.path.splitext(os.path.splitext(f)[0])
                    if ext2 + ext in ['.tar.gz', '.tar.bz2', '.tar.xz']:
                        archives.append(os.path.join(root, f))
        return archives
