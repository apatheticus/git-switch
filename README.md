# Git-Switch

> One-click Git profile switching for Windows

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Windows 10/11](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6.svg)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Overview

Git-Switch is a Windows desktop application that enables developers to seamlessly switch between multiple Git/GitHub user profiles. It eliminates the tedious manual process of reconfiguring Git identities, SSH keys, GPG signing keys, and cached credentials.

**The Problem:** Developers managing multiple Git accounts (personal, work, clients) must manually update `~/.gitconfig`, manage SSH keys in ssh-agent, clear credential caches, and configure GPG signing - every single time they switch contexts.

**The Solution:** Git-Switch stores your profiles securely with AES-256-GCM encryption and switches everything with one click.

## Features

### Profile Management

- Store multiple Git identities (username, email, organization)
- Securely store SSH private keys (encrypted at rest)
- Optional GPG signing key configuration per profile
- Profile validation before saving

### One-Click Switching

- **Global switch**: Updates `~/.gitconfig` for all Git operations
- **Local switch**: Updates only a specific repository's config
- Automatically manages SSH keys in Windows ssh-agent
- Clears Windows Credential Manager cache to prevent auth conflicts
- Configures GPG commit signing when enabled

### Security-First Design

- AES-256-GCM authenticated encryption for all sensitive data
- Master password protection with PBKDF2 key derivation (100,000 iterations)
- Auto-lock after configurable inactivity timeout
- Secure memory clearing to minimize secret exposure
- No plaintext secrets ever written to disk

### System Tray Integration

- Quick profile switching from the system tray menu
- Windows toast notifications on profile switch
- Runs in background when minimized
- Start with Windows option

### Import/Export

- Backup all profiles to an encrypted archive
- Restore profiles on a new machine
- Password-protected archives (separate from master password)

## Requirements

### System Requirements

- Windows 10 or Windows 11 (64-bit)
- GPU with OpenGL 3.3+ support (for DearPyGui GUI)

### Prerequisites

- **Git 2.x** - Must be installed and available in PATH
- **Windows OpenSSH** - Enable via Settings > Apps > Optional Features > OpenSSH Client
- **GnuPG 2.x** (optional) - Required only for GPG commit signing

## Installation

### Option 1: Portable Executable (Recommended)

1. Download `GitProfileSwitcher.exe` from the [Releases](https://github.com/apatheticus/git-switch/releases) page
2. Run the executable - no installation required
3. Data is stored in `%APPDATA%\GitProfileSwitcher\`

### Option 2: From Source

```bash
# Clone the repository
git clone https://github.com/apatheticus/git-switch.git
cd git-switch

# Create a virtual environment
python -m venv .venv
.venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python -m src.main
```

### Option 3: Build Portable Executable

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Build with PyInstaller
pyinstaller build.spec

# Output: dist/GitProfileSwitcher.exe
```

## Quick Start

1. **First Launch**: Create a master password when prompted
   - This password cannot be recovered - choose wisely and remember it
   - Used to encrypt all your stored profiles and keys

2. **Add a Profile**:
   - Click "New Profile"
   - Enter your Git username and email
   - Import your SSH private key (supports OpenSSH and PEM formats)
   - Optionally configure GPG signing
   - Click "Save"

3. **Switch Profiles**:
   - Select a profile from the list
   - Click "Apply Global" to switch for all Git operations
   - Or use the system tray for quick switching

4. **Verify**:

   ```bash
   git config --global user.name
   git config --global user.email
   ssh -T git@github.com
   ```

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| Language | Python 3.11+ | Core application |
| GUI | DearPyGui 1.10+ | GPU-accelerated interface |
| Encryption | cryptography 41+ | AES-256-GCM, PBKDF2 |
| SSH | Paramiko 3.3+ | Key parsing and validation |
| Git | GitPython 3.1+ | Git configuration management |
| GPG | python-gnupg 0.5+ | GPG key operations |
| Windows | pywin32 306+ | Windows API integration |
| System Tray | pystray 0.19+ | Tray icon and menu |
| Packaging | PyInstaller 6+ | Single-file executable |

## Project Structure

```text
src/
├── main.py              # Application entry point
├── models/              # Data models and exceptions
├── services/            # External system integrations (Git, SSH, GPG)
├── core/                # Business logic (encryption, profiles, sessions)
├── ui/                  # DearPyGui interface
│   ├── views/           # Main screens
│   ├── dialogs/         # Modal windows
│   └── components/      # Reusable UI elements
└── utils/               # Utility functions

tests/
├── unit/                # Unit tests
├── integration/         # Integration tests
├── security/            # Security-focused tests
└── e2e/                 # End-to-end tests
```

## Documentation

- [User Guide](docs/user-guide.md) - Complete usage instructions
- [Architecture](docs/architecture.md) - Technical design documentation
- [Contributing](CONTRIBUTING.md) - Development setup and guidelines
- [Security](SECURITY.md) - Security policy and features

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:

- Development environment setup
- Code style guidelines (black, ruff, mypy)
- Testing requirements
- Pull request process

## Security

Git-Switch is designed with security as a core principle. See [SECURITY.md](SECURITY.md) for:

- Vulnerability reporting process
- Encryption implementation details
- Security features and limitations
- Best practices for secure usage

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [DearPyGui](https://github.com/hoffstadt/DearPyGui) for the GPU-accelerated GUI framework
- [cryptography](https://cryptography.io/) for FIPS-validated cryptographic primitives
- [Paramiko](https://www.paramiko.org/) for SSH key handling
