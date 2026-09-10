import os
from typing import Optional

from copyleft_auditor.models import RepositoryReport


def check_dependencies():
    """Проверка и вывод информации о зависимостях."""
    status = {}

    try:
        import customtkinter
        status['customtkinter'] = True
    except ImportError:
        status['customtkinter'] = False

    try:
        import markdown
        status['markdown'] = True
    except ImportError:
        status['markdown'] = False

    return status


def generate_file_tree(report: RepositoryReport) -> str:
    """Генерирует текстовое дерево файлов с подсветкой рисков."""
    lines = []
    lines.append("=" * 60)
    lines.append("ДЕРЕВО ФАЙЛОВ С ПОДСВЕТКОЙ РИСКОВ")
    lines.append("=" * 60)
    lines.append("")
    lines.append("  [OK]  = низкий риск (зеленый)")
    lines.append("  [!]   = средний риск (желтый)")
    lines.append("  [!!]  = высокий риск (красный)")
    lines.append("")
    lines.append("  [ФАЙЛ] = обычный файл")
    lines.append("  [ПЕРЕИМ] = переименование переменных")
    lines.append("  [МЁРТВ] = мертвый код")
    lines.append("  [ВЛОЖЕН] = вложенные условия")
    lines.append("  [КОДИР] = кодированные строки")
    lines.append("  [СМЕШ] = смешанная обфускация")
    lines.append("")
    lines.append("-" * 60)
    lines.append("")

    tree = {}
    for f in report.file_analyses:
        parts = f.path.split(os.sep)
        current = tree
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = {
            'risk': f.risk_level,
            'score': f.obfuscation_score,
            'type': f.obfuscation_type
        }

    def render_tree(node, depth=0, prefix=""):
        items = []
        sorted_keys = sorted(node.keys())
        for idx, name in enumerate(sorted_keys):
            is_last = (idx == len(sorted_keys) - 1)
            connector = "└── " if is_last else "├── "
            indent = "    " if is_last else "│   "

            value = node[name]
            if isinstance(value, dict) and value and all(isinstance(v, dict) for v in value.values()):
                items.append(f"{prefix}{connector}[ПАПКА] {name}/")
                next_prefix = prefix + indent
                items.append(render_tree(value, depth + 1, next_prefix))
            elif isinstance(value, dict):
                risk_marker = '[OK]' if value['risk'] == 'GREEN' else '[!]' if value['risk'] == 'YELLOW' else '[!!]'
                type_icons = {
                    'rename': '[ПЕРЕИМ]', 'dead_code': '[МЁРТВ]', 'nested': '[ВЛОЖЕН]',
                    'encoded': '[КОДИР]', 'mixed': '[СМЕШ]', 'none': '[ФАЙЛ]'
                }
                score_str = f"({value['score']:.0%})"
                items.append(
                    f"{prefix}{connector}{risk_marker} {type_icons.get(value['type'], '[ФАЙЛ]')} {name} {score_str}"
                )
        return "\n".join(items)

    lines.append(render_tree(tree))
    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)
