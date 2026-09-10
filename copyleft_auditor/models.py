from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class LicenseInfo:
    name: str
    file_path: str
    full_text: str
    has_copyright: bool
    copyright_holder: Optional[str]
    copyright_year: Optional[str]
    is_valid: bool
    license_type: str = 'unknown'


@dataclass
class FileAnalysis:
    path: str
    language: str
    risk_level: str
    issues: List[str]
    obfuscation_score: float
    has_eval: bool
    has_exec: bool
    encoded_strings: int
    short_vars_ratio: float
    license_violation: bool
    suggestions: List[str]
    obfuscation_type: str = 'none'
    obfuscation_details: List[str] = field(default_factory=list)
    file_content_preview: str = ''
    file_absolute_path: str = ''
    issue_lines: List[int] = field(default_factory=list)


@dataclass
class LokiFinding:
    file: str
    rule: str
    level: str
    level_emoji: str
    description: str


@dataclass
class RepositoryReport:
    repo_path: str
    scan_timestamp: str
    overall_risk: str
    files_analyzed: int
    risk_summary: Dict[str, int]
    licenses: List[LicenseInfo]
    file_analyses: List[FileAnalysis]
    critical_issues: List[str]
    recommendations: List[str]
    executive_summary: str
    loki_findings: List[LokiFinding]
    extracted_dirs: List[str] = field(default_factory=list)
