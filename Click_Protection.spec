# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['Click_Protection.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('assets/CLICKPROLOGO.png', 'assets'),
        ('assets/CLICKPROLOGO.ico', 'assets'),
        ('data/config.ini', 'data'),
        ('data/blacklist.txt', 'data'),
        ('data/history.txt', 'data'),
        ('data/real_domains.txt', 'data'),
    ],
    hiddenimports=[
        'modules.logger',
        'modules.security',
        'modules.utils',
        'modules.rate_limiter',
        'modules.usom_checker',
        'modules.export',
        'modules.ip_reputation',
        'modules.certificate_transparency',
        'modules.advanced_cache',
        'modules.ml_scorer',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ClickProtection',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets/CLICKPROLOGO.ico'],
)

