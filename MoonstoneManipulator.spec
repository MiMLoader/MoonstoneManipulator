# -*- mode: python ; coding: utf-8 -*-

import os

# Define the path to the main script
script_path = os.path.join('src', 'MoonstoneManipulator.py')

a = Analysis(
    [script_path],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
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
    a.datas,
    [],
    name='MoonstoneManipulator',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    icon=[os.path.join('src', 'Assets', 'icon.png')],
)
