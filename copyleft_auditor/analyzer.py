import ast
import base64
import os
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from copyleft_auditor.archive import ArchiveExtractor
from copyleft_auditor.loki import LokiScanner
from copyleft_auditor.models import FileAnalysis, LicenseInfo, LokiFinding, RepositoryReport


class CodeAnalyzer:
    OBSCURE_PATTERNS = [
        (r'_0x[a-fA-F0-9]{3,}', 'Обфусцированные переменные _0x...'),
        (r'eval\s*\(', 'Использование eval() — риск инъекции'),
        (r'Function\s*\(', 'Конструктор Function() — динамический код'),
        (r'atob\s*\(', 'Декодирование Base64'),
        (r'exec\s*\(', 'Использование exec() — выполнение команд'),
        (r'__import__\s*\(', 'Динамический импорт'),
        (r'system\s*\(', 'Вызов system()'),
        (r'popen\s*\(', 'popen() — выполнение команд'),
    ]

    LANGUAGE_MAP = {
        '.py': 'Python',
        '.js': 'JavaScript',
        '.ts': 'TypeScript',
        '.go': 'Go',
        '.rs': 'Rust',
        '.java': 'Java',
        '.cpp': 'C++',
        '.c': 'C',
        '.cs': 'C#',
        '.rb': 'Ruby',
        '.php': 'PHP',
        '.kt': 'Kotlin',
        '.swift': 'Swift',
    }

    MAX_FILE_SIZE = 5 * 1024 * 1024

    def __init__(self, repo_path: str, loki_scanner: Optional[LokiScanner] = None):
        self.repo_path = Path(repo_path)
        self.results: List[FileAnalysis] = []
        self.licenses: List[LicenseInfo] = []
        self.repo_name = self.repo_path.name
        self.scan_start = datetime.now()
        self.loki_scanner = loki_scanner
        self.loki_findings: List[LokiFinding] = []
        self.extractor = ArchiveExtractor()
        self.extracted_dirs: List[str] = []

    def _find_file_absolute(self, filepath: str) -> Optional[str]:
        repo_path = Path(self.repo_path)

        full_path = repo_path / filepath
        if full_path.exists():
            return str(full_path)

        for extracted_dir in self.extracted_dirs:
            extracted_path = Path(extracted_dir)
            test_path = extracted_path / filepath
            if test_path.exists():
                return str(test_path)

            if filepath.startswith('_extracted/'):
                clean_path = filepath.replace('_extracted/', '', 1)
                test_path = extracted_path / clean_path
                if test_path.exists():
                    return str(test_path)

        file_name = os.path.basename(filepath)
        for root, _, files in os.walk(repo_path):
            if file_name in files:
                return os.path.join(root, file_name)

        for extracted_dir in self.extracted_dirs:
            for root, _, files in os.walk(extracted_dir):
                if file_name in files:
                    return os.path.join(root, file_name)

        return None

    def _get_file_content_preview(self, filepath: str) -> str:
        try:
            abs_path = self._find_file_absolute(filepath)
            if abs_path and os.path.exists(abs_path):
                with open(abs_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                if len(content) > 2000:
                    content = content[:2000] + "\n\n... (обрезано)"
                return content
            return ""
        except Exception as e:
            return f"*Ошибка чтения: {e}*"

    def _analyze_licenses(self):
        patterns = ['LICENSE*', 'COPYING*', 'LICENCE*', 'LICENSE.txt', 'LICENSE.md', 'COPYRIGHT*']
        files = []
        for p in patterns:
            try:
                files.extend(self.repo_path.rglob(p))
            except PermissionError:
                continue

        for extracted_dir in self.extracted_dirs:
            extracted_path = Path(extracted_dir)
            for p in patterns:
                try:
                    files.extend(extracted_path.rglob(p))
                except PermissionError:
                    continue

        readme_files = list(self.repo_path.rglob('README.md')) + list(self.repo_path.rglob('README'))
        for rf in readme_files:
            try:
                text = rf.read_text(errors='ignore')
                if re.search(r'license|licence|copyright', text, re.IGNORECASE):
                    files.append(rf)
            except Exception:
                pass

        for f in files:
            try:
                text = None
                for encoding in ['utf-8', 'utf-8-sig', 'windows-1251', 'latin-1']:
                    try:
                        text = f.read_text(encoding=encoding, errors='ignore')
                        break
                    except Exception:
                        continue
                if text is None:
                    continue

                text_lower = re.sub(r'\s+', ' ', text.lower()).strip()
                name = 'Неизвестная'
                license_type = 'unknown'
                full_text = text[:5000]

                first_gpl_pos = text_lower.find('gnu general public license')
                first_agpl_pos = text_lower.find('gnu affero general public license')
                first_lgpl_pos = text_lower.find('gnu lesser general public license')
                first_library_pos = text_lower.find('gnu library general public license')

                has_gpl_family = (first_gpl_pos != -1 or first_agpl_pos != -1 or
                                  first_lgpl_pos != -1 or first_library_pos != -1)

                if has_gpl_family:
                    if first_agpl_pos != -1 and (first_gpl_pos == -1 or first_agpl_pos < first_gpl_pos):
                        if first_lgpl_pos == -1 or first_agpl_pos < first_lgpl_pos:
                            name = 'AGPL-3.0'
                            license_type = 'copyleft_strong'
                    elif first_gpl_pos != -1:
                        if first_lgpl_pos == -1 or first_gpl_pos < first_lgpl_pos:
                            if 'version 3' in text_lower or 'v3' in text_lower:
                                name = 'GPL-3.0'
                            elif 'version 2' in text_lower or 'v2' in text_lower:
                                name = 'GPL-2.0'
                            else:
                                name = 'GPL'
                            license_type = 'copyleft_strong'

                if name == 'Неизвестная' and (first_lgpl_pos != -1 or first_library_pos != -1):
                    if 'version 3' in text_lower:
                        name = 'LGPL-3.0'
                    elif 'version 2.1' in text_lower:
                        name = 'LGPL-2.1'
                    elif 'version 2' in text_lower:
                        name = 'LGPL-2.0'
                    else:
                        name = 'LGPL'
                    license_type = 'copyleft_weak'

                if name == 'Неизвестная' and re.search(r'bsd', text_lower) and re.search(r'redistribution', text_lower):
                    if '3-clause' in text_lower:
                        name = 'BSD-3-Clause'
                    elif '2-clause' in text_lower:
                        name = 'BSD-2-Clause'
                    else:
                        name = 'BSD'
                    license_type = 'permissive'

                if name == 'Неизвестная' and (
                    re.search(r'mit license', text_lower) or
                    (re.search(r'permission is hereby granted', text_lower) and not re.search(r'bsd', text_lower))
                ):
                    name = 'MIT'
                    license_type = 'permissive'

                if name == 'Неизвестная' and re.search(r'apache license', text_lower):
                    if 'version 2.0' in text_lower:
                        name = 'Apache-2.0'
                    else:
                        name = 'Apache'
                    license_type = 'permissive'

                if name == 'Неизвестная' and (
                    re.search(r'mozilla public license', text_lower) or re.search(r'mpl', text_lower)
                ):
                    name = 'MPL'
                    license_type = 'copyleft_weak'

                if name == 'Неизвестная' and (
                    re.search(r'eclipse public license', text_lower) or re.search(r'epl', text_lower)
                ):
                    name = 'EPL'
                    license_type = 'copyleft_weak'

                if name == 'Неизвестная' and (
                    re.search(r'common development and distribution license', text_lower) or
                    re.search(r'cddl', text_lower)
                ):
                    name = 'CDDL'
                    license_type = 'copyleft_weak'

                if name == 'Неизвестная' and re.search(r'isc license', text_lower):
                    name = 'ISC'
                    license_type = 'permissive'

                if name == 'Неизвестная' and re.search(r'unlicense', text_lower):
                    name = 'Unlicense'
                    license_type = 'public_domain'

                if name == 'Неизвестная' and (
                    re.search(r'public domain', text_lower) or re.search(r'dedicate.*public domain', text_lower)
                ):
                    name = 'Public Domain'
                    license_type = 'public_domain'

                if name == 'Неизвестная' and (
                    re.search(r'creative commons.*cc0', text_lower) or re.search(r'cc0', text_lower)
                ):
                    name = 'CC0-1.0'
                    license_type = 'public_domain'

                if name == 'Неизвестная' and re.search(r'wtfpl', text_lower):
                    name = 'WTFPL'
                    license_type = 'permissive'

                if name == 'Неизвестная':
                    if re.search(r'you must.*open.*source|you must.*disclose', text_lower):
                        license_type = 'copyleft_strong'
                        name = 'Неизвестная (copyleft)'
                    elif re.search(r'permission is hereby granted|without restriction|as is', text_lower):
                        license_type = 'permissive'
                        name = 'Неизвестная (перmissive)'
                    elif re.search(r'public domain|dedicate', text_lower):
                        license_type = 'public_domain'
                        name = 'Неизвестная (public domain)'

                cr = None
                cr_patterns = [
                    r'Copyright\s*\(c\)\s*(\d{4})?\s*([\w\s.,]+)',
                    r'Copyright\s+(\d{4})?\s*([\w\s.,]+)',
                    r'©\s*(\d{4})?\s*([\w\s.,]+)',
                ]
                for pattern in cr_patterns:
                    cr = re.search(pattern, text, re.IGNORECASE)
                    if cr:
                        break

                self.licenses.append(LicenseInfo(
                    name=name,
                    file_path=str(f.relative_to(self.repo_path)),
                    full_text=full_text,
                    has_copyright=bool(cr),
                    copyright_holder=cr.group(2).strip() if cr and len(cr.groups()) >= 2 else None,
                    copyright_year=cr.group(1) if cr and len(cr.groups()) >= 1 else None,
                    is_valid=bool(cr) if name != 'Неизвестная' else False,
                    license_type=license_type
                ))

                print(f"Лицензия: {name} ({license_type}) в {f.name}")

            except Exception as e:
                print(f"Ошибка чтения лицензии {f}: {e}")

    def _strip_comments(self, code: str, lang: str) -> str:
        if lang == 'Python':
            return re.sub(
                r'"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|#.*',
                lambda m: ' ' * len(m.group(0)), code
            )
        if lang in ('JavaScript', 'TypeScript'):
            return re.sub(
                r'`[\s\S]*?`|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|//.*|/\*[\s\S]*?\*/',
                lambda m: ' ' * len(m.group(0)), code
            )
        return re.sub(
            r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|#.*|//.*',
            lambda m: ' ' * len(m.group(0)), code
        )

    def _analyze_file(self, filepath: Path) -> Optional[FileAnalysis]:
        ext = filepath.suffix
        lang = self.LANGUAGE_MAP.get(ext, 'Unknown')
        try:
            code = filepath.read_text(errors='ignore')
        except Exception:
            return None

        issues = []
        suggestions = []
        score = 0.0
        has_eval = False
        has_exec = False
        encoded = 0
        license_violation = False

        renamed_vars = 0
        dead_code_blocks = 0
        nested_conditions = 0
        encoded_strings_detected = 0
        suspicious_patterns = []
        issue_lines = []

        code_lines = code.split('\n')

        def _line_no(pos: int) -> int:
            """Возвращает номер строки (1-based) по позиции в коде."""
            return code[:pos].count('\n') + 1

        def _add_line(line_no: int):
            if line_no not in issue_lines:
                issue_lines.append(line_no)

        if lang in ('JavaScript', 'TypeScript', 'Python'):
            for m in re.finditer(r'\b[a-zA-Z_][a-zA-Z0-9_]{0,2}\b', code):
                name = m.group(0)
                if len(name) <= 2 and name not in ('i', 'j', 'k', 'x', 'y', 'z', 'id', 'el', 'cb'):
                    renamed_vars += 1
                    _add_line(_line_no(m.start()))
            if renamed_vars > 0 and len(code_lines) > 0 and renamed_vars > len(code_lines) * 0.3:
                score += 0.15
                suspicious_patterns.append(f"Найдено {renamed_vars} переименованных переменных (короткие имена)")
            else:
                renamed_vars = 0

        dead_code_patterns = [
            r'if\s*\(false\)', r'if\s*\(0\)', r'if\s*\(null\)',
            r'//\s*dead code', r'//\s*todo.*remove', r'return\s*;\s*\n\s*[a-zA-Z]'
        ]
        for pattern in dead_code_patterns:
            for m in re.finditer(pattern, code, re.IGNORECASE):
                dead_code_blocks += 1
                _add_line(_line_no(m.start()))
        if dead_code_blocks > 0:
            score += 0.05 * min(dead_code_blocks, 3)
            suspicious_patterns.append(f"Найдено {dead_code_blocks} блоков мертвого кода")

        nested_conditions_pattern = r'(if\s*\([^\)]*\)\s*\{[^{]*if\s*\([^\)]*\)\s*\{[^{]*if\s*\()'
        for m in re.finditer(nested_conditions_pattern, code, re.DOTALL):
            nested_conditions += 1
            _add_line(_line_no(m.start()))
        if nested_conditions > 0:
            score += 0.05 * min(nested_conditions, 3)
            suspicious_patterns.append(f"Найдено {nested_conditions} глубоко вложенных условий — возможная обфускация логики")

        string_literals = re.finditer(r'["\']([^"\']{20,})["\']', code)
        for m in string_literals:
            s = m.group(1)
            line_no = _line_no(m.start())
            try:
                if len(base64.b64decode(s, validate=True)) > 10:
                    encoded_strings_detected += 1
                    score += 0.03
                    _add_line(line_no)
            except Exception:
                pass
            if re.fullmatch(r'[0-9a-fA-F]{20,}', s):
                encoded_strings_detected += 1
                score += 0.03
                _add_line(line_no)
        if encoded_strings_detected > 0:
            suspicious_patterns.append(f"Найдено {encoded_strings_detected} кодированных строк")

        for pattern, desc in self.OBSCURE_PATTERNS:
            for m in re.finditer(pattern, code, re.IGNORECASE):
                line_no = _line_no(m.start())
                issues.append(f"{desc} (найдено: 1)")
                score += 0.08
                suspicious_patterns.append(f"{desc} (строка {line_no})")
                _add_line(line_no)
                if 'eval' in desc.lower():
                    has_eval = True
                if 'exec' in desc.lower() or 'system' in desc.lower():
                    has_exec = True

        obfuscation_type = 'none'
        if renamed_vars > 10:
            obfuscation_type = 'rename'
        elif dead_code_blocks > 2:
            obfuscation_type = 'dead_code'
        elif nested_conditions > 3:
            obfuscation_type = 'nested'
        elif encoded_strings_detected > 2:
            obfuscation_type = 'encoded'
        elif len(suspicious_patterns) > 2:
            obfuscation_type = 'mixed'

        if lang == 'Python':
            try:
                tree = ast.parse(code)
                names = []
                for node in ast.walk(tree):
                    if isinstance(node, ast.Name):
                        names.append((node.id, node.lineno))
                if names:
                    short = [n for n, ln in names if len(n) <= 2 and n not in ['i', 'j', 'k', 'x', 'y', 'z']]
                    if len(short) / len(names) > 0.3:
                        issues.append(f"Много коротких имен ({len(short)/len(names):.0%})")
                        score += 0.15
                        for n, ln in names:
                            if len(n) <= 2 and n not in ['i', 'j', 'k', 'x', 'y', 'z']:
                                _add_line(ln)
            except Exception:
                pass

        if lang in ('JavaScript', 'TypeScript'):
            if len(code) > 1000 and '\n' not in code:
                issues.append("Минифицированный код (одна строка)")
                score += 0.15
                _add_line(1)

        if 'Copyright' not in code and 'license' not in code.lower():
            license_violation = True

        score = min(score, 1.0)

        if has_eval or has_exec:
            risk = 'RED'
        elif score > 0.6:
            risk = 'RED'
        elif score > 0.3:
            risk = 'YELLOW'
        else:
            risk = 'GREEN'

        if has_eval:
            suggestions.append("Заменить eval() на безопасную альтернативу")
        if has_exec:
            suggestions.append("Избегать exec()/system()")
        if license_violation:
            suggestions.append("Добавить уведомление об авторских правах")

        abs_path = self._find_file_absolute(str(filepath.relative_to(self.repo_path))) or ''

        return FileAnalysis(
            path=str(filepath.relative_to(self.repo_path)),
            language=lang,
            risk_level=risk,
            issues=issues[:5],
            obfuscation_score=score,
            has_eval=has_eval,
            has_exec=has_exec,
            encoded_strings=encoded,
            short_vars_ratio=0.0,
            license_violation=license_violation,
            suggestions=suggestions[:3],
            obfuscation_type=obfuscation_type,
            obfuscation_details=suspicious_patterns[:5],
            file_content_preview='',
            file_absolute_path=abs_path,
            issue_lines=sorted(set(issue_lines))
        )

    def scan(self, progress_callback=None) -> RepositoryReport:
        if progress_callback:
            progress_callback(10, "Проверка лицензий...")

        if self.extractor.is_available:
            archives = self.extractor.find_archives(str(self.repo_path))
            if archives:
                if progress_callback:
                    progress_callback(15, f"Найдено {len(archives)} архивов, распаковка...")

                extract_base = self.repo_path / "_extracted"
                extract_base.mkdir(exist_ok=True)

                for idx, archive in enumerate(archives):
                    if progress_callback:
                        progress_callback(
                            15 + int(10 * idx / len(archives)),
                            f"Распаковка {os.path.basename(archive)}..."
                        )

                    archive_name = os.path.splitext(os.path.basename(archive))[0]
                    extract_dir = extract_base / archive_name

                    success, files = self.extractor.extract(archive, str(extract_dir), progress_callback)
                    if success:
                        self.extracted_dirs.append(str(extract_dir))

        self._analyze_licenses()

        files_to_scan = []
        for ext in self.LANGUAGE_MAP:
            try:
                files_to_scan.extend(self.repo_path.rglob(f"*{ext}"))
            except PermissionError:
                continue

        for extracted_dir in self.extracted_dirs:
            extracted_path = Path(extracted_dir)
            for ext in self.LANGUAGE_MAP:
                try:
                    files_to_scan.extend(extracted_path.rglob(f"*{ext}"))
                except PermissionError:
                    continue

        exclude = {'node_modules', 'venv', 'env', '.git', '__pycache__', 'dist', 'build', 'target'}
        files_to_scan = [f for f in files_to_scan if not any(x in str(f).split(os.sep) for x in exclude)]
        files_to_scan = [f for f in files_to_scan if f.stat().st_size < self.MAX_FILE_SIZE]
        files_to_scan = [f for f in files_to_scan if f.name not in {'copyleft_auditor.py'}]

        total = len(files_to_scan)
        self.results = []

        for idx, f in enumerate(files_to_scan[:500]):
            if progress_callback:
                progress_callback(25 + int(70 * idx / max(total, 1)), f"Анализ {f.name}...")
            analysis = self._analyze_file(f)
            if analysis:
                self.results.append(analysis)

        if self.loki_scanner and self.loki_scanner.is_available:
            if progress_callback:
                progress_callback(92, "Обновление сигнатур Loki...")
            self.loki_scanner.update_signatures()
            self.loki_findings = self.loki_scanner.scan(str(self.repo_path), progress_callback)

        if progress_callback:
            progress_callback(95, "Генерация отчета...")

        return self._generate_report()

    def _generate_report(self) -> RepositoryReport:
        risk_counts = defaultdict(int)
        critical = []
        all_suggestions = []

        for a in self.results:
            risk_counts[a.risk_level] += 1
            if a.risk_level == 'RED':
                critical.append(f"{a.path}: {a.issues[0] if a.issues else 'Высокий риск'}")
            all_suggestions.extend(a.suggestions)

        if self.licenses:
            for l in self.licenses:
                if l.license_type == 'copyleft_strong':
                    critical.append(
                        f"Обнаружена лицензия {l.name} в {l.file_path} — СИЛЬНЫЙ КОПИЛЕФТ! Код должен быть открыт"
                    )
                elif l.license_type == 'copyleft_weak':
                    critical.append(
                        f"Обнаружена лицензия {l.name} в {l.file_path} — слабый копилефт, требует проверки"
                    )
                elif l.name in ('Неизвестная', 'Неизвестная (copyleft)', 'Неизвестная (перmissive)', 'Неизвестная (public domain)'):
                    critical.append(
                        f"Неизвестная лицензия в {l.file_path} — требуется юридическая проверка"
                    )

        loki_high = [f for f in self.loki_findings if f.level == 'high']
        if loki_high:
            for f in loki_high[:3]:
                critical.append(f"LOKI: {f.file} — {f.rule} (УРОВЕНЬ: {f.level.upper()})")
            if len(loki_high) > 3:
                critical.append(f"LOKI: и ещё {len(loki_high)-3} угроз высокого уровня")

        if not self.results and not self.licenses:
            overall = 'RED'
            summary = f"ПУСТОЙ РЕПОЗИТОРИЙ {self.repo_name}"
            critical.append("Нет файлов кода")
            critical.append("Нет LICENSE")
        elif not self.licenses and self.results:
            overall = 'RED'
            summary = f"КРИТИЧЕСКИЙ РИСК в {self.repo_name}. Код без лицензии!"
            critical.append("LICENSE ОТСУТСТВУЕТ")
        elif self.licenses and not any(l.has_copyright for l in self.licenses):
            overall = 'YELLOW'
            summary = f"Средний риск в {self.repo_name}. Нет авторских прав."
            critical.append("Нет явного уведомления об авторских правах")
        else:
            red = risk_counts.get('RED', 0)
            yellow = risk_counts.get('YELLOW', 0)
            green = risk_counts.get('GREEN', 0)

            has_strong = any(l.license_type == 'copyleft_strong' for l in self.licenses)
            if has_strong:
                red += 2
                critical.append("Обнаружена лицензия сильного копилефта (AGPL/GPL) — ВЫСОКИЙ ЮРИДИЧЕСКИЙ РИСК")

            has_weak = any(l.license_type == 'copyleft_weak' for l in self.licenses)
            if has_weak:
                yellow += 1
                critical.append("Обнаружена лицензия слабого копилефта — требует юридической проверки")

            has_unknown = any(
                l.name in ('Неизвестная', 'Неизвестная (copyleft)', 'Неизвестная (перmissive)', 'Неизвестная (public domain)')
                for l in self.licenses
            )
            if has_unknown:
                yellow += 1
                critical.append("Обнаружена неизвестная лицензия — требует юридической проверки")

            if loki_high:
                red += 1

            if red > 0:
                overall = 'RED'
            elif yellow > 3:
                overall = 'YELLOW'
            elif yellow > 0:
                overall = 'YELLOW'
            else:
                overall = 'GREEN'

            if overall == 'GREEN':
                summary = f"Репозиторий {self.repo_name} прошел проверку. {green} файлов чисты."
            elif overall == 'YELLOW':
                summary = f"Репозиторий {self.repo_name} требует внимания: {yellow} файлов со средним риском."
            else:
                summary = (
                    f"КРИТИЧЕСКИЙ РИСК в {self.repo_name}: "
                    f"{red} файлов с обфускацией или угрозами."
                )

        if not Path(self.repo_path).joinpath('README.md').exists():
            critical.append("README.md отсутствует")

        return RepositoryReport(
            repo_path=str(self.repo_path),
            scan_timestamp=self.scan_start.isoformat(),
            overall_risk=overall,
            files_analyzed=len(self.results),
            risk_summary=dict(risk_counts),
            licenses=self.licenses,
            file_analyses=self.results,
            critical_issues=critical[:10],
            recommendations=list(set(all_suggestions))[:5],
            executive_summary=summary,
            loki_findings=self.loki_findings,
            extracted_dirs=self.extracted_dirs
        )
