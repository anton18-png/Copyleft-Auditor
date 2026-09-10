import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from copyleft_auditor.constants import RISK_EMOJI, RISK_TEXT
from copyleft_auditor.models import RepositoryReport


class MarkdownGenerator:
    def __init__(self, report: RepositoryReport):
        self.report = report
        self.repo_name = os.path.basename(report.repo_path)
        self.extracted_dirs = getattr(report, 'extracted_dirs', [])

    def _find_file_path(self, filepath: str) -> Optional[Path]:
        repo_path = Path(self.report.repo_path)

        full_path = repo_path / filepath
        if full_path.exists():
            return full_path

        for extracted_dir in self.extracted_dirs:
            extracted_path = Path(extracted_dir)
            test_path = extracted_path / filepath
            if test_path.exists():
                return test_path

            if filepath.startswith('_extracted/'):
                clean_path = filepath.replace('_extracted/', '', 1)
                test_path = extracted_path / clean_path
                if test_path.exists():
                    return test_path

        file_name = os.path.basename(filepath)

        for root, _, files in os.walk(repo_path):
            if file_name in files:
                return Path(root) / file_name

        for extracted_dir in self.extracted_dirs:
            for root, _, files in os.walk(extracted_dir):
                if file_name in files:
                    return Path(root) / file_name

        return None

    def _render_file_code(self, filepath: str, issue_lines: list = None) -> str:
        try:
            full_path = self._find_file_path(filepath)

            if not full_path or not full_path.exists():
                return f"*Файл не найден: {filepath}*"

            ext = full_path.suffix.lower()
            lang_map = {
                '.py': 'python', '.js': 'javascript', '.ts': 'typescript',
                '.go': 'go', '.rs': 'rust', '.java': 'java', '.cpp': 'cpp',
                '.c': 'c', '.cs': 'csharp', '.rb': 'ruby', '.php': 'php',
                '.kt': 'kotlin', '.swift': 'swift', '.html': 'html',
                '.css': 'css', '.json': 'json', '.xml': 'xml',
            }
            lang = lang_map.get(ext, '')

            all_lines = full_path.read_text(encoding='utf-8', errors='ignore').split('\n')

            if not issue_lines:
                snippet = '\n'.join(all_lines[:50])
                if len(all_lines) > 50:
                    snippet += '\n... (обрезано)'
                return f"```{lang}\n{snippet}\n```"

            context = 3
            ranges = []
            for ln in sorted(set(issue_lines)):
                start = max(0, ln - 1 - context)
                end = min(len(all_lines), ln + context)
                if ranges and start <= ranges[-1][1]:
                    ranges[-1] = (ranges[-1][0], end)
                else:
                    ranges.append((start, end))

            blocks = []
            total_shown = 0
            for start, end in ranges:
                if total_shown >= 30:
                    blocks.append(f"... ({len(ranges) - len(blocks)} ещё фрагментов скрыто)")
                    break
                chunk = all_lines[start:end]
                total_shown += len(chunk)
                numbered = []
                for i, line in enumerate(chunk, start=start + 1):
                    numbered.append(f"{i:>5} | {line}")
                blocks.append('\n'.join(numbered))

            result = f"```{lang}\n" + '\n\n'.join(blocks) + "\n```"
            return result

        except Exception as e:
            return f"*Ошибка чтения: {e}*"

    def generate(self) -> str:
        lines = []
        lines.append(f"# Copyleft Auditor Pro — Отчет аудита кода\n")
        lines.append(f"**Репозиторий:** `{self.repo_name}`  \n")
        lines.append(f"**Путь:** `{self.report.repo_path}`  \n")
        lines.append(f"**Дата:** {self.report.scan_timestamp}  \n")
        lines.append(f"**Файлов проанализировано:** {self.report.files_analyzed}  \n")
        lines.append("")

        emoji = RISK_EMOJI.get(self.report.overall_risk, '⚪')
        text = RISK_TEXT.get(self.report.overall_risk, 'Неизвестно')
        lines.append(f"## {emoji} Общий уровень риска: **{text}**\n")
        lines.append(f"> {self.report.executive_summary}\n")
        lines.append("---\n")

        lines.append("## Краткая сводка\n")
        lines.append(f"**Оценка:** {emoji} {text}\n")
        lines.append(f"{self.report.executive_summary}\n")
        lines.append("")

        lines.append("### Основные показатели\n")
        lines.append("| Показатель | Значение | Статус |")
        lines.append("|------------|----------|--------|")
        lines.append(f"| Всего файлов | {self.report.files_analyzed} | |")
        lines.append(f"| Зеленых | {self.report.risk_summary.get('GREEN', 0)} | ОК |")
        lines.append(f"| Желтых | {self.report.risk_summary.get('YELLOW', 0)} | ВНИМ |")
        lines.append(f"| Красных | {self.report.risk_summary.get('RED', 0)} | КРИТ |")
        lines.append("")

        if self.report.loki_findings:
            lines.append("### Результаты Loki (угрозы)\n")
            lines.append("| Файл | Правило | Уровень | Описание |")
            lines.append("|------|---------|---------|----------|")
            for f in self.report.loki_findings[:10]:
                level_text = f.level.upper()
                lines.append(f"| `{f.file}` | {f.rule} | {level_text} | {f.description or '-'} |")
            lines.append("")
            if len(self.report.loki_findings) > 10:
                lines.append(f"_Показано 10 из {len(self.report.loki_findings)} сигнатур_\n")

        if self.report.critical_issues:
            lines.append("### Ключевые проблемы\n")
            for issue in self.report.critical_issues[:5]:
                lines.append(f"- {issue}")
            lines.append("")
        lines.append("---\n")

        lines.append("## Юридический индекс здоровья\n")
        score = self._calc_score()
        grade = self._get_grade(score)
        lines.append(f"**Оценка:** {score}/100  \n")
        lines.append(f"**Грейд:** {grade}  \n")
        lines.append("")

        lines.append("## Анализ лицензий\n")
        if not self.report.licenses:
            lines.append("**ЛИЦЕНЗИИ НЕ НАЙДЕНЫ**\n")
            lines.append("- Нельзя использовать в коммерческих продуктах")
            lines.append("- Риск судебных исков")
            lines.append("")
            lines.append("**Рекомендация:** СРОЧНО добавить файл LICENSE\n")
        else:
            for lic in self.report.licenses:
                lines.append(f"### {lic.name}\n")
                lines.append(f"- **Файл:** `{lic.file_path}`")
                lines.append(f"- **Тип:** {lic.license_type}")
                lines.append(f"- **Авторское право:** {'Да' if lic.has_copyright else 'Нет'}")
                if lic.copyright_holder:
                    lines.append(f"- **Правообладатель:** {lic.copyright_holder}")
                if lic.copyright_year:
                    lines.append(f"- **Год:** {lic.copyright_year}")
                lines.append(f"- **Статус:** {'Действительна' if lic.is_valid else 'Требует проверки'}")

                if lic.full_text:
                    text_preview = lic.full_text[:500]
                    if len(lic.full_text) > 500:
                        text_preview += "...\n\n_Полный текст сохранен в отчете_"
                    lines.append("\n**Текст лицензии:**\n")
                    lines.append("```")
                    lines.append(text_preview)
                    lines.append("```")
                lines.append("")

        problem_files = [f for f in self.report.file_analyses if f.issues or f.obfuscation_details]

        if problem_files:
            lines.append("## Проблемные файлы с кодом\n")
            for f in problem_files[:5]:
                risk_label = RISK_TEXT.get(f.risk_level, f.risk_level)
                lines.append(f"### {RISK_EMOJI.get(f.risk_level, '')} `{f.path}`\n")
                lines.append(f"- **Язык:** {f.language}")
                lines.append(f"- **Риск:** {risk_label}")
                lines.append(f"- **Оценка:** {f.obfuscation_score:.0%}")
                if f.obfuscation_details:
                    lines.append("**Детали обфускации:**")
                    for detail in f.obfuscation_details[:5]:
                        lines.append(f"- {detail}")
                if f.issues:
                    lines.append("**Проблемы:**")
                    for issue in f.issues:
                        lines.append(f"- {issue}")

                lines.append("\n**Релевантный код:**\n")
                code_block = self._render_file_code(f.path, f.issue_lines)
                lines.append(code_block)
                lines.append("")

        lines.append("---\n")
        lines.append("## Рекомендации\n")
        recs = self._get_recs()
        if recs:
            for i, r in enumerate(recs, 1):
                lines.append(f"{i}. {r}")
        else:
            lines.append("Все рекомендации выполнены")
        lines.append("")
        lines.append("---\n")
        lines.append(
            f"_Отчет сгенерирован Copyleft Auditor Pro v3.0 | "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M')}_\n"
        )
        return "\n".join(lines)

    def _calc_score(self) -> int:
        score = 100
        if not self.report.licenses:
            score -= 30
        red = self.report.risk_summary.get('RED', 0)
        yellow = self.report.risk_summary.get('YELLOW', 0)
        if red > 0:
            score -= 20 * min(red, 3)
        if yellow > 5:
            score -= 5 * min(yellow // 5, 4)
        if not Path(self.report.repo_path).joinpath('README.md').exists():
            score -= 10
        return max(0, min(100, score))

    def _get_grade(self, score: int) -> str:
        if score >= 80:
            return "A (Отлично)"
        elif score >= 60:
            return "B (Хорошо)"
        elif score >= 40:
            return "C (Удовлетворительно)"
        return "D (Критично)"

    def _get_recs(self) -> list:
        recs = set()
        for f in self.report.file_analyses:
            recs.update(f.suggestions)
        if not self.report.licenses:
            recs.add("Добавить файл LICENSE")
        if self.report.critical_issues:
            recs.add("Провести аудит критических файлов")
        if self.report.loki_findings:
            recs.add("Проверить сигнатуры Loki — возможные угрозы")
        return sorted(recs)
