# Quickstart: Git-Switch Development Setup

**Branch**: `001-git-profile-switcher` | **Date**: 2026-01-17

## Prerequisites

### Required Software

| Software | Version | Purpose | Installation |
|----------|---------|---------|--------------|
| Python | 3.11+ | Runtime | [python.org](https://www.python.org/downloads/) |
| Git | 2.x+ | Version control, config operations | [git-scm.com](https://git-scm.com/download/win) |
| Windows OpenSSH | Built-in | SSH agent integration | Windows Features |

### Optional Software

| Software | Version | Purpose | Installation |
|----------|---------|---------|--------------|
| GnuPG | 2.x+ | GPG signing features | [gnupg.org](https://gnupg.org/download/) |
| Visual Studio Code | Latest | Recommended IDE | [code.visualstudio.com](https://code.visualstudio.com/) |

### Windows OpenSSH Setup

1. Open Settings → Apps → Optional Features
2. Add "OpenSSH Client" if not already installed
3. Enable ssh-agent service:
   ```powershell
   # Run as Administrator
   Set-Service -Name ssh-agent -StartupType Automatic
   Start-Service ssh-agent
   Get-Service ssh-agent  # Verify: Status = Running
   ```

---

## Environment Setup

### 1. Clone Repository

```powershell
git clone <repository-url> git-switch
cd git-switch
```

### 2. Create Virtual Environment

```powershell
# Create virtual environment
python -m venv .venv

# Activate (PowerShell)
.\.venv\Scripts\Activate.ps1

# Or activate (Command Prompt)
.\.venv\Scripts\activate.bat
```

### 3. Install Dependencies

```powershell
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt
```

### 4. Verify Installation

```powershell
# Verify DearPyGui (requires GPU with OpenGL 3.3+)
python -c "import dearpygui.dearpygui as dpg; dpg.create_context(); print('DearPyGui OK')"

# Verify cryptography
python -c "from cryptography.hazmat.primitives.ciphers.aead import AESGCM; print('Cryptography OK')"

# Verify Git service
git --version

# Verify SSH agent
ssh-add -l  # May show "The agent has no identities" - that's OK
```

---

## Project Structure Overview

```
git-switch/
├── src/                    # Source code
│   ├── main.py             # Application entry point
│   ├── models/             # Data models (Profile, Repository, Settings)
│   ├── services/           # External integrations (Git, SSH, GPG, Credentials)
│   ├── core/               # Business logic (ProfileManager, Crypto, Session)
│   ├── ui/                 # DearPyGui presentation layer
│   └── utils/              # Cross-cutting utilities
├── tests/                  # Test suite
│   ├── unit/               # Unit tests (mocked dependencies)
│   ├── integration/        # Integration tests (real services)
│   ├── security/           # Security-focused tests
│   └── e2e/                # End-to-end workflow tests
├── assets/                 # Icons and fonts
├── specs/                  # Feature specifications
│   └── 001-git-profile-switcher/
│       ├── spec.md         # Feature specification
│       ├── plan.md         # Implementation plan
│       ├── research.md     # Technical research
│       ├── data-model.md   # Entity definitions
│       ├── contracts/      # Service interfaces
│       └── tasks.md        # Implementation tasks (generated)
├── .specify/               # Speckit configuration
├── pyproject.toml          # Project configuration
├── requirements.txt        # Production dependencies
├── requirements-dev.txt    # Development dependencies
└── build.spec              # PyInstaller configuration
```

---

## Development Workflow

### Running the Application

```powershell
# Run from source
python src/main.py

# Or with module syntax
python -m src.main
```

### Running Tests

```powershell
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test categories
pytest tests/unit/              # Unit tests only
pytest tests/integration/       # Integration tests only
pytest tests/security/          # Security tests only

# Run specific test file
pytest tests/unit/test_crypto.py

# Run with verbose output
pytest -v

# Run tests matching pattern
pytest -k "test_encrypt"
```

### Type Checking

```powershell
# Run mypy in strict mode (required by constitution)
mypy src/ --strict

# Check specific module
mypy src/core/crypto.py --strict
```

### Code Formatting

```powershell
# Format code with black
black src/ tests/

# Sort imports with isort
isort src/ tests/

# Lint with ruff
ruff check src/ tests/
```

### Building Executable

```powershell
# Build single-file executable
pyinstaller build.spec

# Output: dist/Git-Switch.exe
```

---

## Configuration Files

### pyproject.toml

```toml
[project]
name = "git-switch"
version = "0.1.0"
requires-python = ">=3.11"

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = "test_*.py"
python_functions = "test_*"
addopts = "-ra -q"

[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_configs = true

[tool.black]
line-length = 100
target-version = ["py311"]

[tool.isort]
profile = "black"
line_length = 100

[tool.ruff]
line-length = 100
target-version = "py311"
select = ["E", "F", "W", "I", "N", "UP", "B", "C4", "SIM"]
```

### requirements.txt

```txt
# GUI Framework
dearpygui>=1.10.0

# Cryptography
cryptography>=41.0.0

# SSH Operations
paramiko>=3.3.0

# Git Operations
GitPython>=3.1.40

# GPG Operations
python-gnupg>=0.5.2

# Windows Credential Manager
keyring>=24.3.0

# Windows Integration
pywin32>=306

# System Tray
pystray>=0.19.5
Pillow>=10.1.0

# Notifications
win10toast>=0.9
```

### requirements-dev.txt

```txt
-r requirements.txt

# Testing
pytest>=7.4.0
pytest-cov>=4.1.0
pytest-mock>=3.12.0

# Type Checking
mypy>=1.7.0
types-Pillow
types-pywin32

# Code Formatting
black>=23.12.0
isort>=5.13.0
ruff>=0.1.8

# Build
pyinstaller>=6.3.0
```

---

## Common Tasks

### Create a New Test File

```python
# tests/unit/test_<module>.py
"""Unit tests for <module>."""

import pytest
from unittest.mock import Mock, patch

from src.<layer>.<module> import <Class>


class TestClassName:
    """Tests for ClassName."""

    def test_method_scenario_expected_result(self) -> None:
        """Test that method returns expected result in scenario."""
        # Arrange
        ...

        # Act
        ...

        # Assert
        ...
```

### Add a New Service

1. Define Protocol in `src/services/protocols.py`
2. Create implementation in `src/services/<service>_service.py`
3. Add to ServiceContainer in `src/services/__init__.py`
4. Create tests in `tests/unit/test_<service>_service.py`

### Add a New Model

1. Define dataclass in `src/models/<entity>.py`
2. Add validation in `__post_init__`
3. Export from `src/models/__init__.py`
4. Create tests in `tests/unit/test_models.py`

---

## Troubleshooting

### DearPyGui Won't Start

**Error**: "Failed to create OpenGL context"

**Solution**: Update graphics drivers or ensure GPU supports OpenGL 3.3+

```powershell
# Check OpenGL version (via PowerShell)
# Install OpenGL Extension Viewer from Microsoft Store
```

### SSH Agent Not Running

**Error**: "Could not open a connection to your authentication agent"

**Solution**:
```powershell
# Check service status
Get-Service ssh-agent

# Start service (requires admin)
Start-Service ssh-agent

# Set to auto-start
Set-Service -Name ssh-agent -StartupType Automatic
```

### GPG Not Found

**Error**: "gpg: command not found"

**Solution**: Install GnuPG and add to PATH

```powershell
# After installing GnuPG, verify
gpg --version

# If not in PATH, add manually:
# C:\Program Files (x86)\GnuPG\bin
```

### Import Errors

**Error**: "ModuleNotFoundError: No module named 'src'"

**Solution**: Run from repository root or install in editable mode

```powershell
# Option 1: Run from repo root
cd git-switch
python src/main.py

# Option 2: Install editable
pip install -e .
```

---

## Next Steps

1. Read the [Feature Specification](./spec.md) for requirements
2. Review the [Data Model](./data-model.md) for entity definitions
3. Review the [Service Interfaces](./contracts/service-interfaces.md) for API contracts
4. Check [Constitution](../../.specify/memory/constitution.md) for coding standards
5. Run `/speckit.tasks` to generate implementation tasks

---

## Resources

- [DearPyGui Documentation](https://dearpygui.readthedocs.io/)
- [Python cryptography Documentation](https://cryptography.io/en/latest/)
- [paramiko Documentation](https://docs.paramiko.org/)
- [GitPython Documentation](https://gitpython.readthedocs.io/)
- [PyInstaller Documentation](https://pyinstaller.org/en/stable/)
