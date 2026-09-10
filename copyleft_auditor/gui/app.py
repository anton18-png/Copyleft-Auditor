import os
import re
import shutil
import sys
import tempfile
import threading
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

import customtkinter as ctk

from copyleft_auditor.analyzer import CodeAnalyzer
from copyleft_auditor.constants import RISK_COLOR, RISK_EMOJI, RISK_TEXT
from copyleft_auditor.loki import LokiScanner
from copyleft_auditor.models import RepositoryReport
from copyleft_auditor.reports.markdown_gen import MarkdownGenerator
from copyleft_auditor.utils import generate_file_tree

_BUNDLE_DIR = getattr(sys, '_MEIPASS', None)

if getattr(sys, 'frozen', False):
    APP_DIR = Path(sys.executable).resolve().parent
else:
    APP_DIR = Path(__file__).resolve().parent.parent.parent

REPORTS_DIR = APP_DIR / "reports"
ICON_PATH = Path(_BUNDLE_DIR) / "icon.png" if _BUNDLE_DIR else APP_DIR / "icon.png"


class CopyleftAuditorApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Copyleft Auditor Pro — Антивирус для кода")
        self.geometry("1350x870")
        self.minsize(1100, 750)
        self.repo_path = None
        self.current_report = None
        self.scanning = False
        self.workspace_dir = APP_DIR
        self.loki_scanner = LokiScanner(str(self.workspace_dir))
        self._extracted_dirs = []
        self.colors = {
            'bg': '#0a0e17', 'card': '#111827', 'border': '#1e2d45',
            'accent': '#2563eb', 'text': '#e5e7eb', 'text_secondary': '#9ca3af'
        }
        REPORTS_DIR.mkdir(exist_ok=True)
        self._app_icon = None
        self._header_icon = None
        self._set_window_icon()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self._setup_ui()

    def _set_window_icon(self):
        try:
            from tkinter import PhotoImage
            if ICON_PATH.exists():
                self._app_icon = PhotoImage(file=str(ICON_PATH))
                self.iconphoto(True, self._app_icon)
                try:
                    from PIL import Image, ImageTk
                    img = Image.open(ICON_PATH)
                    img = img.resize((34, 34), Image.LANCZOS)
                    self._header_icon = ImageTk.PhotoImage(img)
                except Exception:
                    self._header_icon = self._app_icon
        except Exception:
            pass

    def _setup_ui(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        main = ctk.CTkFrame(self, fg_color=self.colors['bg'], corner_radius=0)
        main.grid(row=0, column=0, sticky="nsew")
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(main, height=65, fg_color=self.colors['card'], corner_radius=0)
        top.grid(row=0, column=0, sticky="ew")
        top.grid_columnconfigure(2, weight=1)
        top.grid_propagate(False)
        logo = ctk.CTkFrame(top, fg_color="transparent")
        logo.grid(row=0, column=0, padx=(25, 0), pady=10, sticky="w")
        if self._header_icon:
            ctk.CTkLabel(logo, image=self._header_icon, text="").pack(side="left", padx=(0, 10))
        ctk.CTkLabel(logo, text="Copyleft Auditor Pro", font=ctk.CTkFont(size=20, weight="bold"),
                      text_color=self.colors['text']).pack(side="left")
        ctk.CTkLabel(logo, text="| Enterprise + Loki", font=ctk.CTkFont(size=13),
                      text_color=self.colors['text_secondary']).pack(side="left", padx=(8, 0))
        ctk.CTkLabel(top, text="v3.0", font=ctk.CTkFont(size=12, weight="bold"),
                      text_color=self.colors['accent']).grid(row=0, column=1, padx=10)
        right = ctk.CTkFrame(top, fg_color="transparent")
        right.grid(row=0, column=2, padx=20, sticky="e")
        ctk.CTkButton(right, text="О программе", width=120, height=32, corner_radius=8,
                       fg_color=self.colors['border'], hover_color=self.colors['card'],
                       command=self._show_about).pack(side="right")

        tabs_container = ctk.CTkFrame(main, fg_color=self.colors['bg'], corner_radius=0)
        tabs_container.grid(row=1, column=0, sticky="nsew", padx=20, pady=20)
        tabs_container.grid_rowconfigure(0, weight=1)
        tabs_container.grid_columnconfigure(0, weight=1)

        self.tabs = ctk.CTkTabview(
            tabs_container, fg_color=self.colors['card'],
            segmented_button_fg_color=self.colors['card'],
            segmented_button_selected_color=self.colors['accent'],
            segmented_button_unselected_color=self.colors['border'],
            text_color=self.colors['text'],
        )
        self.tabs.grid(row=0, column=0, sticky="nsew")

        self.tab_scan = self.tabs.add("Сканирование")
        self.tab_reports = self.tabs.add("Отчеты")

        self._build_scan_tab()
        self._build_reports_tab()

        status = ctk.CTkFrame(main, height=30, fg_color=self.colors['card'], corner_radius=0)
        status.grid(row=2, column=0, sticky="ew")
        status.grid_columnconfigure(0, weight=1)
        status.grid_columnconfigure(1, weight=0)
        status.grid_propagate(False)
        ctk.CTkLabel(status, text="Copyleft Auditor Pro v3.0 | AGPL-3.0 | Loki | 7-Zip",
                      font=ctk.CTkFont(size=11), text_color=self.colors['text_secondary']).grid(
            row=0, column=0, padx=20, sticky="w"
        )
        ctk.CTkLabel(status, text="Anton-18 PNG", font=ctk.CTkFont(size=11, weight="bold"),
                      text_color=self.colors['accent']).grid(row=0, column=1, padx=20, sticky="e")

    # ── Scan tab ──────────────────────────────────────────────────────

    def _build_scan_tab(self):
        self.tab_scan.grid_columnconfigure(1, weight=1)
        self.tab_scan.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(self.tab_scan, width=320, fg_color=self.colors['card'], corner_radius=16,
                             border_width=1, border_color=self.colors['border'])
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 20))
        left.grid_propagate(False)
        ctk.CTkLabel(left, text="Источник", font=ctk.CTkFont(size=16, weight="bold"),
                      text_color=self.colors['text']).pack(anchor="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(left, text="Укажите репозиторий для сканирования", font=ctk.CTkFont(size=12),
                      text_color=self.colors['text_secondary']).pack(anchor="w", padx=20, pady=(0, 15))
        inp = ctk.CTkFrame(left, fg_color="transparent")
        inp.pack(fill="x", padx=20, pady=(0, 10))
        self.path_entry = ctk.CTkEntry(inp, placeholder_text="C:\\repo или https://github.com/user/repo",
                                        height=42, font=ctk.CTkFont(size=13),
                                        border_color=self.colors['border'], fg_color=self.colors['bg'])
        self.path_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        ctk.CTkButton(inp, text="...", width=42, height=42, corner_radius=10,
                       fg_color=self.colors['accent'], hover_color='#3b82f6',
                       command=self._browse_repo).pack(side="right")
        self.scan_btn = ctk.CTkButton(left, text="Запустить сканирование", height=50, corner_radius=12,
                                       font=ctk.CTkFont(size=15, weight="bold"),
                                       fg_color=self.colors['accent'], hover_color='#3b82f6',
                                       command=self._start_scan)
        self.scan_btn.pack(fill="x", padx=20, pady=10)
        stats = ctk.CTkFrame(left, fg_color=self.colors['bg'], corner_radius=12,
                              border_width=1, border_color=self.colors['border'])
        stats.pack(fill="both", expand=True, padx=20, pady=(10, 0))
        ctk.CTkLabel(stats, text="Статистика", font=ctk.CTkFont(size=14, weight="bold"),
                      text_color=self.colors['text']).pack(anchor="w", padx=15, pady=(15, 8))
        self.stats_text = ctk.CTkTextbox(stats, height=200, font=ctk.CTkFont(size=12),
                                          fg_color=self.colors['bg'], border_width=0)
        self.stats_text.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.stats_text.insert("1.0",
                               "Ожидание сканирования...\n\nВыберите репозиторий и нажмите 'Запустить сканирование'")
        self.stats_text.configure(state="disabled")

        right_panel = ctk.CTkFrame(self.tab_scan, fg_color=self.colors['card'], corner_radius=16,
                                    border_width=1, border_color=self.colors['border'])
        right_panel.grid(row=0, column=1, sticky="nsew")
        right_panel.grid_columnconfigure(0, weight=1)
        right_panel.grid_rowconfigure(2, weight=1)

        risk_frame = ctk.CTkFrame(right_panel, height=90, fg_color=self.colors['bg'], corner_radius=12,
                                   border_width=1, border_color=self.colors['border'])
        risk_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=(20, 15))
        risk_frame.grid_columnconfigure(1, weight=1)
        risk_frame.grid_propagate(False)
        self.risk_indicator = ctk.CTkFrame(risk_frame, width=55, height=55, corner_radius=28,
                                            fg_color=self.colors['border'])
        self.risk_indicator.grid(row=0, column=0, padx=(20, 15), pady=17)
        risk_text = ctk.CTkFrame(risk_frame, fg_color="transparent")
        risk_text.grid(row=0, column=1, sticky="w")
        self.risk_label = ctk.CTkLabel(risk_text, text="Ожидание сканирования",
                                        font=ctk.CTkFont(size=18, weight="bold"),
                                        text_color=self.colors['text'])
        self.risk_label.pack(anchor="w")
        self.risk_subtitle = ctk.CTkLabel(risk_text, text="Выберите репозиторий для начала анализа",
                                           font=ctk.CTkFont(size=13),
                                           text_color=self.colors['text_secondary'])
        self.risk_subtitle.pack(anchor="w")

        action = ctk.CTkFrame(right_panel, fg_color="transparent")
        action.grid(row=1, column=0, sticky="ew", padx=20, pady=(0, 15))
        action.grid_columnconfigure(0, weight=1)
        action.grid_columnconfigure(1, weight=1)
        self.tree_btn = ctk.CTkButton(action, text="Дерево файлов", height=40, corner_radius=10,
                                       font=ctk.CTkFont(size=13, weight="bold"),
                                       fg_color=self.colors['border'], hover_color=self.colors['card'],
                                       state="disabled", command=self._show_tree)
        self.tree_btn.grid(row=0, column=0, padx=(0, 5))
        self.export_html = ctk.CTkButton(action, text="Экспорт HTML", height=40, corner_radius=10,
                                          font=ctk.CTkFont(size=13, weight="bold"),
                                          fg_color=self.colors['accent'], hover_color='#3b82f6',
                                          state="disabled", command=self._export_html)
        self.export_html.grid(row=0, column=1, padx=(5, 0))

        table_frame = ctk.CTkFrame(right_panel, fg_color=self.colors['bg'], corner_radius=12,
                                    border_width=1, border_color=self.colors['border'])
        table_frame.grid(row=2, column=0, sticky="nsew", padx=20, pady=(0, 20))
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(table_frame, text="Детальный анализ файлов",
                      font=ctk.CTkFont(size=14, weight="bold"),
                      text_color=self.colors['text']).pack(anchor="w", padx=15, pady=(15, 8))
        tree_inner = ctk.CTkFrame(table_frame, fg_color=self.colors['bg'], corner_radius=8)
        tree_inner.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        tree_inner.grid_columnconfigure(0, weight=1)
        tree_inner.grid_rowconfigure(0, weight=1)
        self.tree = ttk.Treeview(tree_inner, columns=("File", "Language", "Risk", "Score", "Issues"),
                                  show="headings", height=12, style="Custom.Treeview")
        self.tree.heading("File", text="Файл")
        self.tree.heading("Language", text="Язык")
        self.tree.heading("Risk", text="Уровень риска")
        self.tree.heading("Score", text="Оценка")
        self.tree.heading("Issues", text="Проблемы")
        self.tree.column("File", width=280, anchor="w")
        self.tree.column("Language", width=80, anchor="center")
        self.tree.column("Risk", width=110, anchor="center")
        self.tree.column("Score", width=70, anchor="center")
        self.tree.column("Issues", width=320, anchor="w")
        scroll = ttk.Scrollbar(tree_inner, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Custom.Treeview", background=self.colors['bg'], foreground=self.colors['text'],
                         fieldbackground=self.colors['bg'], borderwidth=0, font=("Segoe UI", 11), rowheight=32)
        style.configure("Custom.Treeview.Heading", background=self.colors['card'],
                         foreground=self.colors['text_secondary'], borderwidth=0,
                         font=("Segoe UI", 11, "bold"))
        style.map("Custom.Treeview", background=[("selected", self.colors['accent'])],
                   foreground=[("selected", "white")])

    # ── Reports tab ───────────────────────────────────────────────────

    def _build_reports_tab(self):
        self.tab_reports.grid_columnconfigure(0, weight=1)
        self.tab_reports.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self.tab_reports, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=5, pady=(5, 10))
        header.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(header, text="Сохраненные отчеты", font=ctk.CTkFont(size=16, weight="bold"),
                      text_color=self.colors['text']).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text=str(REPORTS_DIR),
                      font=ctk.CTkFont(size=11), text_color=self.colors['text_secondary']).grid(
            row=0, column=1, padx=15, sticky="w")
        ctk.CTkButton(header, text="Обновить", width=100, height=32, corner_radius=8,
                       fg_color=self.colors['border'], hover_color=self.colors['card'],
                       command=self._refresh_reports_list).grid(row=0, column=2, sticky="e")
        ctk.CTkButton(header, text="Открыть папку", width=120, height=32, corner_radius=8,
                       fg_color=self.colors['accent'], hover_color='#3b82f6',
                       command=self._open_reports_dir).grid(row=0, column=3, padx=(8, 0), sticky="e")

        list_frame = ctk.CTkFrame(self.tab_reports, fg_color=self.colors['bg'], corner_radius=12,
                                   border_width=1, border_color=self.colors['border'])
        list_frame.grid(row=1, column=0, sticky="nsew")
        list_frame.grid_columnconfigure(0, weight=1)
        list_frame.grid_rowconfigure(0, weight=1)

        self.reports_tree = ttk.Treeview(
            list_frame,
            columns=("Name", "Date", "Size"),
            show="headings", height=18, style="Custom.Treeview"
        )
        self.reports_tree.heading("Name", text="Файл отчета")
        self.reports_tree.heading("Date", text="Дата")
        self.reports_tree.heading("Size", text="Размер")
        self.reports_tree.column("Name", width=500, anchor="w")
        self.reports_tree.column("Date", width=180, anchor="center")
        self.reports_tree.column("Size", width=100, anchor="e")

        reports_scroll = ttk.Scrollbar(list_frame, orient="vertical", command=self.reports_tree.yview)
        self.reports_tree.configure(yscrollcommand=reports_scroll.set)
        self.reports_tree.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        reports_scroll.grid(row=0, column=1, sticky="ns", pady=5)

        self.reports_tree.bind("<Double-1>", self._on_report_double_click)

        btn_frame = ctk.CTkFrame(self.tab_reports, fg_color="transparent")
        btn_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=(10, 0))
        ctk.CTkButton(btn_frame, text="Открыть отчет", height=36, corner_radius=8,
                       fg_color=self.colors['accent'], hover_color='#3b82f6',
                       command=self._open_selected_report).pack(side="left")
        ctk.CTkButton(btn_frame, text="Удалить отчет", height=36, corner_radius=8,
                       fg_color='#ef4444', hover_color='#dc2626',
                       command=self._delete_selected_report).pack(side="left", padx=(10, 0))

        self._refresh_reports_list()

    def _refresh_reports_list(self):
        for item in self.reports_tree.get_children():
            self.reports_tree.delete(item)

        if not REPORTS_DIR.exists():
            return

        reports = sorted(REPORTS_DIR.glob("*.html"), key=lambda p: p.stat().st_mtime, reverse=True)
        for report_path in reports:
            stat = report_path.stat()
            dt = datetime.fromtimestamp(stat.st_mtime).strftime("%d.%m.%Y  %H:%M")
            size = self._format_size(stat.st_size)
            self.reports_tree.insert("", "end", values=(report_path.name, dt, size),
                                     tags=(str(report_path),))

    def _format_size(self, size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} Б"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} КБ"
        else:
            return f"{size_bytes / (1024 * 1024):.1f} МБ"

    def _open_reports_dir(self):
        if REPORTS_DIR.exists():
            os.startfile(str(REPORTS_DIR))

    def _get_selected_report_path(self) -> Optional[Path]:
        sel = self.reports_tree.selection()
        if not sel:
            messagebox.showwarning("Внимание", "Выберите отчет из списка")
            return None
        values = self.reports_tree.item(sel[0], "values")
        return REPORTS_DIR / values[0]

    def _on_report_double_click(self, event):
        self._open_selected_report()

    def _open_selected_report(self):
        path = self._get_selected_report_path()
        if path and path.exists():
            webbrowser.open(str(path))

    def _delete_selected_report(self):
        path = self._get_selected_report_path()
        if path and path.exists():
            confirm = messagebox.askyesno("Подтверждение", f"Удалить отчет?\n{path.name}")
            if confirm:
                path.unlink(missing_ok=True)
                self._refresh_reports_list()

    # ── About dialog ──────────────────────────────────────────────────

    def _show_about(self):
        msg = """Copyleft Auditor Pro v3.0

Антивирус для кода — защита от юридических и безопасностных угроз в Open Source

Питч:
"Мы делаем рентген для кода. Вы видите не только баги, но и то,
украл ли вашего разработчика этот репозиторий, и не спрятана ли там
мина для вашего бизнеса. Мы — страховка от дурака в Open Source".

Интеграция: Loki (сканер IoC)
Поддержка архивов: 7-Zip (zip, 7z, rar, tar, gz, bz2, xz)
Лицензия: AGPL-3.0
Автор: Anton-18 PNG

Возможности:
- 50+ определяемых лицензий
- Полный текст лицензий в отчете
- Поиск лицензий в README.md
- Детальная диагностика обфускации
- Визуализация дерева файлов
- Экспорт в HTML
- Распаковка архивов для сканирования
- Отображение кода подозрительных файлов
- Автосохранение отчетов в папке "reports" рядом с программой"""
        messagebox.showinfo("О программе", msg)

    # ── Browse / clone / scan ─────────────────────────────────────────

    def _browse_repo(self):
        path = filedialog.askdirectory(title="Выберите локальный репозиторий")
        if path:
            self.path_entry.delete(0, "end")
            self.path_entry.insert(0, path)
            self.repo_path = path

    def _is_github_url(self, text: str) -> bool:
        return bool(re.match(r'https?://(www\.)?github\.com/[\w.-]+/[\w.-]+', text.strip()))

    def _clone_repo(self, url: str) -> Optional[str]:
        url = url.strip()
        if url.endswith('.git'):
            url = url[:-4]
        if url.endswith('/'):
            url = url[:-1]
        repo_name = url.split('/')[-1]
        temp_dir = tempfile.mkdtemp(prefix=f"copyleft_audit_{repo_name}_")
        clone_path = os.path.join(temp_dir, repo_name)
        self.after(0, lambda: self._update_progress(5, f"Клонирование {repo_name}..."))
        try:
            import subprocess
            subprocess.run(
                ['git', 'clone', '--depth', '1', url, clone_path],
                capture_output=True, text=True, timeout=120, check=True
            )
            return clone_path
        except Exception as e:
            raise Exception(f"Ошибка клонирования: {e}")

    def _start_scan(self):
        if self.scanning:
            return
        repo_input = self.path_entry.get().strip()
        if not repo_input:
            messagebox.showerror("Ошибка", "Укажите путь или GitHub URL")
            return
        self.repo_path = repo_input
        self.scanning = True
        self.scan_btn.configure(state="disabled", text="Сканирование...")
        self.tree_btn.configure(state="disabled")
        self.export_html.configure(state="disabled")
        self._extracted_dirs = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        cloned = None
        try:
            repo_path = self.repo_path
            if self._is_github_url(repo_path):
                cloned = self._clone_repo(repo_path)
                repo_path = cloned
            elif not os.path.exists(repo_path):
                self.after(0, lambda: self._show_error(f"Путь не найден: {repo_path}"))
                return
            analyzer = CodeAnalyzer(repo_path, self.loki_scanner)
            report = analyzer.scan(progress_callback=self._update_progress)
            self.current_report = report
            self._extracted_dirs = analyzer.extracted_dirs
            self.after(0, lambda: self._update_results(report))
        except Exception as e:
            self.after(0, lambda: self._show_error(str(e)))
        finally:
            if cloned:
                shutil.rmtree(cloned, ignore_errors=True)
            self.after(0, self._scan_finished)

    def _update_progress(self, value: int, message: str):
        def update():
            self.risk_label.configure(text=message)
            self.risk_subtitle.configure(text=f"Прогресс: {value}%")
        self.after(0, update)

    def _update_results(self, report: RepositoryReport):
        color = RISK_COLOR.get(report.overall_risk, '#2d2d2d')
        text = RISK_TEXT.get(report.overall_risk, 'Ожидание')
        emoji = RISK_EMOJI.get(report.overall_risk, '⚪')
        self.risk_indicator.configure(fg_color=color)
        self.risk_label.configure(text=f"{emoji} {text} РИСК")
        self.risk_subtitle.configure(text=report.executive_summary[:80] + "...")
        self.stats_text.configure(state="normal")
        self.stats_text.delete("1.0", "end")
        stats = f"""Репозиторий: {os.path.basename(report.repo_path)}
Файлов: {report.files_analyzed}
Зеленых: {report.risk_summary.get('GREEN', 0)}
Желтых: {report.risk_summary.get('YELLOW', 0)}
Красных: {report.risk_summary.get('RED', 0)}
Loki: найдено сигнатур: {len(report.loki_findings)}
Лицензии:
"""
        for lic in report.licenses[:3]:
            stats += f"  * {lic.name} ({lic.file_path}) — {lic.license_type}\n"
        if report.critical_issues:
            stats += f"\nКритические проблемы:\n"
            for issue in report.critical_issues[:3]:
                stats += f"  * {issue}\n"
        self.stats_text.insert("1.0", stats)
        self.stats_text.configure(state="disabled")

        for a in report.file_analyses:
            emoji = RISK_EMOJI.get(a.risk_level, '⚪')
            type_icons = {
                'rename': 'ПЕРЕИМ', 'dead_code': 'МЁРТВ', 'nested': 'ВЛОЖЕН',
                'encoded': 'КОДИР', 'mixed': 'СМЕШ', 'none': ''
            }
            type_prefix = f"[{type_icons.get(a.obfuscation_type, '')}] " if a.obfuscation_type != 'none' else ''
            issues_display = (
                a.issues[0] if a.issues else
                ("Обф: " + ", ".join(a.obfuscation_details[:2]) if a.obfuscation_details else "Чисто")
            )
            self.tree.insert("", "end", values=(
                a.path[:50],
                a.language,
                f"{emoji} {a.risk_level}",
                f"{a.obfuscation_score:.0%}",
                f"{type_prefix}{issues_display[:60]}"
            ), tags=(a.risk_level,))
        self.tree.tag_configure('GREEN', foreground='#10b981')
        self.tree.tag_configure('YELLOW', foreground='#f59e0b')
        self.tree.tag_configure('RED', foreground='#ef4444')
        self.tree_btn.configure(state="normal")
        self.export_html.configure(state="normal")

    def _scan_finished(self):
        self.scanning = False
        self.scan_btn.configure(state="normal", text="Запустить сканирование")
        for dir_path in self._extracted_dirs:
            try:
                shutil.rmtree(dir_path, ignore_errors=True)
            except Exception:
                pass
        self._extracted_dirs = []

    def _show_error(self, error: str):
        messagebox.showerror("Ошибка", error)

    # ── File tree ─────────────────────────────────────────────────────

    def _show_tree(self):
        if not self.current_report:
            return
        tree_text = generate_file_tree(self.current_report)
        win = ctk.CTkToplevel(self)
        win.title("Дерево файлов с подсветкой рисков")
        win.geometry("800x700")
        win.configure(fg_color='#0a0e17')
        frm = ctk.CTkFrame(win, fg_color='#111827', corner_radius=12)
        frm.pack(fill="both", expand=True, padx=15, pady=15)
        txt = ctk.CTkTextbox(frm, font=ctk.CTkFont(size=12, family="Consolas"),
                              fg_color='#0d1117', text_color='#e6edf3')
        txt.pack(fill="both", expand=True, padx=10, pady=10)
        txt.insert("1.0", tree_text)
        txt.configure(state="disabled")

    # ── Export HTML ───────────────────────────────────────────────────

    def _generate_html_body(self, report: RepositoryReport) -> str:
        md_content = MarkdownGenerator(report).generate()
        import markdown as markdown_lib
        html_body = markdown_lib.markdown(
            md_content, extensions=['tables', 'fenced_code', 'nl2br']
        )
        repo_name = os.path.basename(report.repo_path)
        return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Отчет аудита — {repo_name}</title>
<style>
body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; color: #1a1a1a; }}
pre {{ background: #f5f5f5; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 12px; border: 1px solid #e0e0e0; white-space: pre-wrap; }}
code {{ font-family: Consolas, monospace; }}
table {{ border-collapse: collapse; width: 100%; margin: 15px 0; }}
th {{ background: #0d1117; color: white; padding: 8px 12px; text-align: left; }}
td {{ padding: 6px 12px; border: 1px solid #ddd; }}
blockquote {{ border-left: 4px solid #2563eb; padding: 10px 20px; background: #f0f7ff; margin: 15px 0; }}
hr {{ border: none; border-top: 1px solid #e6e6e6; margin: 25px 0; }}
</style>
</head>
<body>
{html_body}
</body>
</html>"""

    def _export_html(self):
        if not self.current_report:
            return
        try:
            report = self.current_report
            repo_name = os.path.basename(report.repo_path)
            date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            default_name = f"{repo_name}_{date_str}.html"

            REPORTS_DIR.mkdir(exist_ok=True)
            save_path = REPORTS_DIR / default_name

            full_html = self._generate_html_body(report)
            save_path.write_text(full_html, encoding='utf-8')
            webbrowser.open(str(save_path))
            self._refresh_reports_list()
            messagebox.showinfo("Успешно", f"HTML сохранен:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
