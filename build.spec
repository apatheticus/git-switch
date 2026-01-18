# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification for Git-Switch Profile Manager.

This spec file configures PyInstaller to create a single-file Windows executable
for the Git-Switch application. The build includes:
- All Python dependencies bundled
- Assets (icons) embedded
- GPU-accelerated DearPyGui rendering support
- Windows-specific integrations (keyring, pywin32, pystray)

Build command:
    pyinstaller build.spec

Output:
    dist/Git-Switch.exe
"""

from PyInstaller.utils.hooks import collect_submodules, collect_data_files

# Block cipher for encrypting Python bytecode (None = no encryption)
block_cipher = None

# Collect all submodules for packages that have dynamic imports
hiddenimports = [
    # Windows keyring backend
    'keyring.backends.Windows',
    # GPG wrapper
    'gnupg',
    # DearPyGui internal modules
    'dearpygui.dearpygui',
    'dearpygui._dearpygui',
    # Paramiko for SSH operations
    'paramiko',
    'paramiko.ed25519key',
    'paramiko.ecdsakey',
    'paramiko.rsakey',
    'paramiko.dsskey',
    # Cryptography backends
    'cryptography.hazmat.primitives.ciphers.aead',
    'cryptography.hazmat.primitives.kdf.pbkdf2',
    'cryptography.hazmat.backends.openssl',
    # GitPython
    'git',
    'git.cmd',
    'git.config',
    'git.repo',
    # PIL/Pillow for tray icon
    'PIL',
    'PIL.Image',
    'PIL.ImageDraw',
    # pystray for system tray
    'pystray',
    'pystray._win32',
    # win10toast for notifications
    'win10toast',
    # pywin32 modules
    'win32api',
    'win32con',
    'win32gui',
    'win32event',
    'win32process',
    'pywintypes',
    'pythoncom',
    # Our application modules
    'src',
    'src.models',
    'src.models.profile',
    'src.models.repository',
    'src.models.settings',
    'src.models.exceptions',
    'src.models.serialization',
    'src.services',
    'src.services.protocols',
    'src.services.container',
    'src.services.git_service',
    'src.services.ssh_service',
    'src.services.gpg_service',
    'src.services.credential_service',
    'src.core',
    'src.core.protocols',
    'src.core.crypto',
    'src.core.session',
    'src.core.profile_manager',
    'src.core.repository_manager',
    'src.core.settings_manager',
    'src.core.validation',
    'src.core.import_export',
    'src.utils',
    'src.utils.paths',
    'src.utils.windows',
    'src.utils.notifications',
    'src.ui',
    'src.ui.theme',
    'src.ui.app',
    'src.ui.main_window',
    'src.ui.system_tray',
    'src.ui.views',
    'src.ui.views.profiles_view',
    'src.ui.views.repositories_view',
    'src.ui.views.settings_view',
    'src.ui.views.import_export_view',
    'src.ui.dialogs',
    'src.ui.dialogs.password_dialog',
    'src.ui.dialogs.profile_dialog',
    'src.ui.dialogs.confirm_dialog',
    'src.ui.components',
    'src.ui.components.profile_card',
    'src.ui.components.status_bar',
]

# Collect data files from packages that need them
datas = [
    # Application assets
    ('assets/icons', 'assets/icons'),
    ('assets/fonts', 'assets/fonts'),
]

# Try to collect DearPyGui data files (fonts, etc.)
try:
    datas += collect_data_files('dearpygui')
except Exception:
    pass

# Analysis phase - analyze the main script
a = Analysis(
    ['src/main.py'],
    pathex=['.'],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude unused modules to reduce size
        'tkinter',
        '_tkinter',
        'tcl',
        'tk',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'IPython',
        'pytest',
        'mypy',
        'black',
        'isort',
        'ruff',
        # Exclude test modules
        'tests',
        'test',
        'unittest',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# Create the Python archive
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher,
)

# Create the executable
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Git-Switch',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window (GUI application)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icons/app_icon.ico',
    uac_admin=False,  # No admin privileges required
    uac_uiaccess=False,
    version_file=None,  # Can add version info later if needed
)
