# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['copyleft_auditor/__main__.py'],
    pathex=[],
    binaries=[
        ('bin/7za.exe', 'bin'),
    ],
    datas=[
        ('loki', 'loki'),
        ('icon.png', '.'),
    ],
    hiddenimports=[
        'customtkinter',
        'markdown',
        'copyleft_auditor',
        'copyleft_auditor.models',
        'copyleft_auditor.constants',
        'copyleft_auditor.archive',
        'copyleft_auditor.loki',
        'copyleft_auditor.analyzer',
        'copyleft_auditor.utils',
        'copyleft_auditor.reports',
        'copyleft_auditor.reports.markdown_gen',
        'copyleft_auditor.gui',
        'copyleft_auditor.gui.app',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyd = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyd,
    a.scripts,
    [],
    exclude_binaries=True,
    name='CopyleftAuditorPro',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='icon.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='CopyleftAuditorPro',
)
