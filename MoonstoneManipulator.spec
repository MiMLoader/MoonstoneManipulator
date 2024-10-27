# -*- mode: python ; coding: utf-8 -*-

import sys
import os

# Determine the operating system
is_windows = sys.platform == "win32"
is_linux = sys.platform == "linux"

# Set the icon path and executable name based on the OS
icon_path = os.path.join('src', 'Assets', 'icon.png')
exe_name = 'MoonstoneManipulator.exe' if is_windows else 'MoonstoneManipulator'

# Path for the main script
script_path = os.path.join('src', 'MoonstoneManipulator.py')

# Use os.path.abspath to ensure the paths are absolute
script_path = os.path.abspath(script_path)
icon_path = os.path.abspath(icon_path)

a = Analysis(
    [script_path],
    pathex=[],
    binaries=[],
    datas=[(os.path.join('src', 'Assets'), 'Assets')],
    hiddenimports=['PIL._tkinter_finder'],
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
    console=not is_windows,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['src/Assets/icon.png'],
)
