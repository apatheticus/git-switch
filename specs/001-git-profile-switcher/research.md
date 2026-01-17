# Research: Git-Switch Profile Manager

**Branch**: `001-git-profile-switcher` | **Date**: 2026-01-17

## Overview

This document captures research findings and technical decisions for the Git-Switch application. All items marked "NEEDS CLARIFICATION" in the Technical Context have been resolved below.

---

## 1. Encryption Implementation

### Decision: AES-256-GCM via `cryptography` library

**Rationale**: The `cryptography` library is the de facto standard for Python cryptographic operations. It provides:
- FIPS-validated cryptographic primitives
- AES-GCM authenticated encryption (prevents tampering)
- PBKDF2-HMAC-SHA256 key derivation built-in
- Well-maintained with regular security updates

**Alternatives Considered**:
| Alternative | Rejected Because |
|-------------|------------------|
| Fernet (cryptography) | Uses AES-128-CBC, constitution requires AES-256 |
| PyCryptodome | Less maintained, more complex API |
| nacl/libsodium | Overkill for file encryption use case |

**Implementation Pattern**:
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Key derivation (100,000 iterations per constitution)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,  # 256 bits
    salt=salt,
    iterations=100_000,
)
key = kdf.derive(password.encode())

# Encryption
aesgcm = AESGCM(key)
nonce = os.urandom(12)  # 96-bit nonce for GCM
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
```

**Security Considerations**:
- Generate unique 32-byte salt per installation (stored in config)
- Generate unique 12-byte nonce per encryption operation (prepend to ciphertext)
- Store verification hash: HMAC-SHA256 of known constant "GIT-SWITCH-VERIFY"
- Zero key material after use via `ctypes.memset`

---

## 2. SSH Agent Integration (Windows OpenSSH)

### Decision: Subprocess calls to native `ssh-add` command

**Rationale**: Constitution mandates Windows OpenSSH only (no Pageant, no third-party). The native `ssh-add.exe` provides:
- Standard interface to Windows ssh-agent service
- Supports passphrase-protected keys via stdin pipe
- No additional dependencies

**Alternatives Considered**:
| Alternative | Rejected Because |
|-------------|------------------|
| paramiko SSH agent | Implements its own agent protocol, not Windows native |
| Direct named pipe | Undocumented Windows implementation details |
| pywin32 service API | No direct ssh-agent API, would need to replicate ssh-add |

**Implementation Pattern**:
```python
import subprocess

def add_key_to_agent(private_key_path: str, passphrase: str | None = None) -> bool:
    """Add SSH key to Windows ssh-agent."""
    cmd = ["ssh-add", private_key_path]

    if passphrase:
        # Pipe passphrase to stdin for protected keys
        result = subprocess.run(
            cmd,
            input=passphrase + "\n",
            capture_output=True,
            text=True,
            timeout=30,
        )
    else:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    return result.returncode == 0

def clear_all_keys() -> bool:
    """Remove all keys from ssh-agent."""
    result = subprocess.run(["ssh-add", "-D"], capture_output=True, timeout=30)
    return result.returncode == 0

def list_keys() -> list[str]:
    """List loaded key fingerprints."""
    result = subprocess.run(["ssh-add", "-l"], capture_output=True, text=True, timeout=30)
    if result.returncode == 0:
        return result.stdout.strip().split("\n")
    return []
```

**Error Handling**:
- Check if ssh-agent service is running: `sc query ssh-agent`
- Offer to start service: `sc start ssh-agent` (may need admin)
- Graceful degradation: warn user but don't block application

**Key Storage**:
- SSH keys stored encrypted in `%APPDATA%/GitProfileSwitcher/keys/`
- Decrypt to temp file, add to agent, securely delete temp file
- Use `os.remove()` followed by file overwrite pattern for secure deletion

---

## 3. Windows Credential Manager Integration

### Decision: `keyring` library with Windows backend

**Rationale**: The `keyring` library provides a Pythonic interface to Windows Credential Manager with automatic backend detection.

**Implementation Pattern**:
```python
import keyring
from keyring.backends import Windows

# Ensure Windows backend
keyring.set_keyring(Windows.WinVaultKeyring())

def clear_git_credentials() -> list[str]:
    """Clear cached Git/GitHub credentials from Windows Credential Manager."""
    cleared = []

    # Common credential targets for Git
    targets = [
        "git:https://github.com",
        "git:https://github.com/",
        "LegacyGeneric:target=git:https://github.com",
    ]

    for target in targets:
        try:
            # keyring doesn't support direct deletion, use ctypes
            credential = keyring.get_credential(target, None)
            if credential:
                _delete_credential(target)
                cleared.append(target)
        except keyring.errors.KeyringError:
            pass

    return cleared

def _delete_credential(target: str) -> bool:
    """Delete credential using Windows API via ctypes."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.windll.advapi32
    CredDelete = advapi32.CredDeleteW
    CredDelete.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD]
    CredDelete.restype = wintypes.BOOL

    CRED_TYPE_GENERIC = 1
    return bool(CredDelete(target, CRED_TYPE_GENERIC, 0))
```

**Git Credential Manager Considerations**:
- Git Credential Manager (GCM) stores OAuth tokens
- Target format varies: `git:https://github.com` or with trailing slash
- May need to clear multiple entries to fully reset

---

## 4. GPG Integration

### Decision: `python-gnupg` library wrapping GPG CLI

**Rationale**: GPG operations require the GnuPG installation. The `python-gnupg` library provides a clean wrapper.

**Implementation Pattern**:
```python
import gnupg

def create_gpg_instance() -> gnupg.GPG | None:
    """Create GPG instance, return None if GPG not installed."""
    try:
        gpg = gnupg.GPG(gpgbinary="gpg")
        # Verify GPG is functional
        version = gpg.version
        return gpg
    except Exception:
        return None

def import_key(gpg: gnupg.GPG, private_key_data: bytes) -> str | None:
    """Import GPG private key, return key ID or None on failure."""
    result = gpg.import_keys(private_key_data)
    if result.count > 0:
        return result.fingerprints[0]
    return None

def verify_signing_capability(gpg: gnupg.GPG, key_id: str) -> bool:
    """Verify key can sign data."""
    test_data = b"test"
    signed = gpg.sign(test_data, keyid=key_id, detach=True)
    return bool(signed.data)
```

**Graceful Degradation**:
- GPG features disabled if GnuPG not installed
- Show informational message with download link
- Profile creation still works without GPG section

---

## 5. DearPyGui Best Practices

### Decision: DearPyGui 1.10+ with custom theming

**Rationale**: DearPyGui provides GPU-accelerated rendering via Dear ImGui, suitable for the high-tech aesthetic required.

**Theme Implementation**:
```python
import dearpygui.dearpygui as dpg

# Color constants (from mockup)
COLORS = {
    "bg_dark": (15, 23, 42),           # #0F172A - Dark background
    "bg_panel": (30, 41, 59),          # #1E293B - Panel background
    "bg_card": (51, 65, 85),           # #334155 - Card background
    "accent_cyan": (0, 212, 255),      # #00D4FF - Primary accent
    "accent_glow": (0, 255, 255, 80),  # #00FFFF with alpha - Glow effect
    "text_primary": (241, 245, 249),   # #F1F5F9 - Primary text
    "text_secondary": (148, 163, 184), # #94A3B8 - Secondary text
    "success": (34, 197, 94),          # #22C55E - Success indicator
    "warning": (234, 179, 8),          # #EAB308 - Warning indicator
    "error": (239, 68, 68),            # #EF4444 - Error indicator
}

def create_theme():
    with dpg.theme() as global_theme:
        with dpg.theme_component(dpg.mvAll):
            dpg.add_theme_color(dpg.mvThemeCol_WindowBg, COLORS["bg_dark"])
            dpg.add_theme_color(dpg.mvThemeCol_ChildBg, COLORS["bg_panel"])
            dpg.add_theme_color(dpg.mvThemeCol_Button, COLORS["bg_card"])
            dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, COLORS["accent_cyan"])
            dpg.add_theme_color(dpg.mvThemeCol_Text, COLORS["text_primary"])
            dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 4)
            dpg.add_theme_style(dpg.mvStyleVar_WindowPadding, 12, 12)
    return global_theme
```

**Performance Considerations**:
- Use `dpg.configure_item()` for updates instead of recreating widgets
- Batch UI updates in single frame where possible
- Use `dpg.mutex()` for thread-safe UI updates from background operations

---

## 6. Git Configuration Management

### Decision: GitPython for config parsing, subprocess for writes

**Rationale**: GitPython provides excellent config parsing but its write operations can be unreliable. Use subprocess for critical writes.

**Implementation Pattern**:
```python
import subprocess
from pathlib import Path

def update_global_config(username: str, email: str, gpg_key_id: str | None = None):
    """Update Git global configuration."""
    subprocess.run(["git", "config", "--global", "user.name", username], check=True)
    subprocess.run(["git", "config", "--global", "user.email", email], check=True)

    if gpg_key_id:
        subprocess.run(["git", "config", "--global", "commit.gpgsign", "true"], check=True)
        subprocess.run(["git", "config", "--global", "user.signingkey", gpg_key_id], check=True)
    else:
        subprocess.run(["git", "config", "--global", "--unset", "commit.gpgsign"], check=False)
        subprocess.run(["git", "config", "--global", "--unset", "user.signingkey"], check=False)

def update_local_config(repo_path: Path, username: str, email: str):
    """Update repository local configuration."""
    subprocess.run(
        ["git", "config", "--local", "user.name", username],
        cwd=repo_path,
        check=True,
    )
    subprocess.run(
        ["git", "config", "--local", "user.email", email],
        cwd=repo_path,
        check=True,
    )

def get_current_config() -> dict[str, str]:
    """Read current Git global configuration."""
    result = {}
    for key in ["user.name", "user.email", "user.signingkey", "commit.gpgsign"]:
        try:
            proc = subprocess.run(
                ["git", "config", "--global", "--get", key],
                capture_output=True,
                text=True,
                check=True,
            )
            result[key] = proc.stdout.strip()
        except subprocess.CalledProcessError:
            pass
    return result
```

---

## 7. System Tray Integration

### Decision: `pystray` library with PIL for icon generation

**Rationale**: `pystray` is the most mature cross-platform tray library for Python, with excellent Windows support.

**Implementation Pattern**:
```python
import pystray
from PIL import Image

def create_tray_icon(profiles: list, active_profile_id: str, callbacks: dict):
    """Create system tray icon with profile menu."""

    # Load icon image
    icon_image = Image.open("assets/icons/tray_icon.ico")

    # Build menu items
    menu_items = []
    for profile in profiles:
        is_active = profile.id == active_profile_id
        item = pystray.MenuItem(
            profile.name,
            lambda _, p=profile: callbacks["switch"](p.id),
            checked=lambda item, p=profile: p.id == active_profile_id,
        )
        menu_items.append(item)

    menu_items.extend([
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open Application", callbacks["open"]),
        pystray.MenuItem("Lock", callbacks["lock"]),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Exit", callbacks["exit"]),
    ])

    return pystray.Icon(
        "git-switch",
        icon_image,
        f"Git-Switch - {profiles[active_profile_id].name if active_profile_id else 'No profile'}",
        pystray.Menu(*menu_items),
    )
```

**Threading Considerations**:
- `pystray` runs in its own thread
- Use queue or callback mechanism to communicate with main UI thread
- Update menu by recreating icon when profiles change

---

## 8. Windows Notifications

### Decision: `win10toast` or `plyer` for toast notifications

**Rationale**: Windows 10/11 toast notifications provide non-intrusive feedback for profile switches.

**Implementation Pattern**:
```python
from win10toast import ToastNotifier

_notifier = ToastNotifier()

def show_notification(title: str, message: str, duration: int = 5):
    """Show Windows toast notification."""
    _notifier.show_toast(
        title,
        message,
        icon_path="assets/icons/app_icon.ico",
        duration=duration,
        threaded=True,
    )
```

**Alternative**: `plyer` library for broader platform support (future consideration).

---

## 9. PyInstaller Configuration

### Decision: Single-file bundle with UPX compression

**Implementation Notes**:
```python
# build.spec
block_cipher = None

a = Analysis(
    ['src/main.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('assets', 'assets'),
    ],
    hiddenimports=[
        'keyring.backends.Windows',
        'gnupg',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=['tkinter'],  # Not needed, save space
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='GitProfileSwitcher',
    debug=False,
    strip=False,
    upx=True,
    console=False,
    icon='assets/icons/app_icon.ico',
    uac_admin=False,
)
```

**Size Optimization**:
- Exclude tkinter (not used)
- UPX compression enabled
- Expected size: ~50-80MB single file

---

## 10. Secure Memory Handling

### Decision: ctypes memset + context managers

**Implementation Pattern**:
```python
import ctypes
from contextlib import contextmanager
from typing import Generator

def secure_zero(data: bytearray) -> None:
    """Securely zero a bytearray."""
    ctypes.memset(ctypes.addressof((ctypes.c_char * len(data)).from_buffer(data)), 0, len(data))

@contextmanager
def secure_key(key_bytes: bytes) -> Generator[bytearray, None, None]:
    """Context manager that zeros key material on exit."""
    key = bytearray(key_bytes)
    try:
        yield key
    finally:
        secure_zero(key)

# Usage
with secure_key(derived_key) as key:
    aesgcm = AESGCM(bytes(key))
    # ... use key ...
# Key is zeroed after this block
```

---

## Summary of Technology Decisions

| Area | Decision | Library/Tool |
|------|----------|--------------|
| Encryption | AES-256-GCM + PBKDF2 | `cryptography` |
| SSH Agent | Native Windows OpenSSH | subprocess + `ssh-add` |
| Credentials | Windows Credential Manager | `keyring` + ctypes |
| GPG | GnuPG wrapper | `python-gnupg` |
| GUI | GPU-accelerated dark theme | `dearpygui` |
| Git Config | Subprocess writes | subprocess + `git config` |
| System Tray | Platform tray integration | `pystray` |
| Notifications | Windows toast | `win10toast` |
| Packaging | Single-file portable | PyInstaller + UPX |
| Memory Safety | Secure zeroing | ctypes + context managers |

All NEEDS CLARIFICATION items from Technical Context have been resolved.
