# Contributing to Git-Switch

Thank you for your interest in contributing to Git-Switch! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
- [Project Structure](#project-structure)
- [Code Style](#code-style)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Commit Conventions](#commit-conventions)

## Development Environment Setup

### Prerequisites

- **Python 3.11 or higher** - [Download](https://www.python.org/downloads/)
- **Git** - [Download](https://git-scm.com/)
- **Windows 10/11** - Required for Windows-specific features
- **Visual Studio Build Tools** - May be required for pywin32 compilation

### Setup Steps

```bash
# Clone the repository
git clone https://github.com/apatheticus/git-switch.git
cd git-switch

# Create a virtual environment
python -m venv .venv

# Activate the virtual environment
.venv\Scripts\activate

# Install development dependencies (includes production deps)
pip install -r requirements-dev.txt

# Verify installation
pytest --version
mypy --version
ruff --version
black --version
```

### IDE Configuration

#### VS Code (Recommended)

Create `.vscode/settings.json`:

```json
{
    "python.defaultInterpreterPath": ".venv/Scripts/python.exe",
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": ["tests"],
    "editor.formatOnSave": true,
    "editor.rulers": [100],
    "[python]": {
        "editor.defaultFormatter": "ms-python.black-formatter"
    }
}
```

Recommended extensions:

- Python (Microsoft)
- Black Formatter
- Ruff
- Mypy Type Checker

## Project Structure

```text
src/
├── main.py                 # Application entry point
├── models/                 # Data models (dataclasses)
│   ├── profile.py          # Profile, SSHKey, GPGKey
│   ├── repository.py       # Repository model
│   ├── settings.py         # Settings, MasterKeyConfig
│   ├── exceptions.py       # Exception hierarchy
│   └── serialization.py    # JSON serialization helpers
├── services/               # External system integrations
│   ├── protocols.py        # Service interfaces (Protocols)
│   ├── container.py        # Dependency injection container
│   ├── git_service.py      # Git configuration operations
│   ├── ssh_service.py      # SSH agent operations
│   ├── gpg_service.py      # GPG keyring operations
│   └── credential_service.py  # Windows Credential Manager
├── core/                   # Business logic layer
│   ├── protocols.py        # Core interfaces
│   ├── crypto.py           # AES-256-GCM encryption
│   ├── session.py          # Master password session
│   ├── profile_manager.py  # Profile CRUD and switching
│   ├── repository_manager.py  # Repository registration
│   ├── settings_manager.py # Application settings
│   ├── validation.py       # Credential validation
│   └── import_export.py    # Archive operations
├── ui/                     # DearPyGui presentation layer
│   ├── app.py              # Main application controller
│   ├── main_window.py      # Root layout
│   ├── system_tray.py      # System tray integration
│   ├── theme.py            # Colors and styling
│   ├── views/              # Main content views
│   ├── dialogs/            # Modal windows
│   └── components/         # Reusable UI widgets
└── utils/                  # Utility functions
    ├── paths.py            # Path resolution
    ├── windows.py          # Windows API utilities
    └── notifications.py    # Toast notifications

tests/
├── conftest.py             # Shared pytest fixtures
├── unit/                   # Unit tests (mocked dependencies)
├── integration/            # Integration tests (real services)
├── security/               # Security-focused tests
└── e2e/                    # End-to-end workflow tests
```

### Architecture Rules

1. **Layer Boundaries** (strictly enforced):
   - UI Layer → may only call Core Layer
   - Core Layer → may only call Services Layer and Models
   - Services Layer → may only call Models and external libraries
   - Models → no dependencies on other layers

2. **Dependency Injection**:
   - All services are injected via `ServiceContainer`
   - Use Protocol classes for interfaces
   - Never instantiate services directly in business logic

3. **Error Handling**:
   - Models: Raise `ValueError` on validation failure
   - Services: Raise specific `ServiceError` subclass
   - Core: Catch service errors, translate to user-friendly messages
   - UI: Display error dialogs, never expose technical details

## Code Style

### Formatting Tools

```bash
# Format code
black src tests
isort src tests

# Lint code
ruff check src tests

# Type check
mypy src

# Run all checks
black --check src tests && isort --check-only src tests && ruff check src tests && mypy src
```

### Configuration

All tool configurations are in `pyproject.toml`:

| Tool | Key Settings |
|------|--------------|
| black | `line-length = 100`, `target-version = ["py311"]` |
| isort | `profile = "black"`, `line_length = 100` |
| ruff | Extensive rule set, see `pyproject.toml` |
| mypy | `strict = true`, type stubs for dependencies |

### Docstring Format (Google Style)

```python
def switch_profile(
    self,
    profile_id: UUID,
    scope: str = "global",
) -> None:
    """Switch to a profile and apply its configuration.

    Applies the specified profile's Git identity, SSH key, and
    optional GPG signing configuration to either global or local
    Git config.

    Args:
        profile_id: UUID of the profile to switch to.
        scope: Either "global" for ~/.gitconfig or "local" for
            repository-specific .git/config.

    Raises:
        ProfileNotFoundError: If profile doesn't exist.
        SessionExpiredError: If session is locked.
        GitServiceError: If Git configuration update fails.
        SSHServiceError: If SSH agent operations fail.

    Example:
        >>> manager.switch_profile(profile.id, scope="global")
    """
```

### Security Coding Guidelines

1. **Never log sensitive data** - Use `[REDACTED]` placeholders for secrets
2. **Zero secrets after use** - Call `secure_zero()` from `core.crypto`
3. **Validate all inputs** - Especially in Models' `__post_init__`
4. **Use constant-time comparison** - `hmac.compare_digest()` for secrets
5. **Handle encryption errors gracefully** - Don't leak implementation details
6. **Sanitize subprocess inputs** - Prevent command injection

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=src --cov-report=html --cov-report=term-missing

# Run specific test categories
pytest -m unit           # Unit tests only
pytest -m integration    # Integration tests
pytest -m security       # Security tests
pytest -m e2e            # End-to-end tests
pytest -m "not slow"     # Skip slow tests

# Run specific test file
pytest tests/unit/test_crypto.py

# Run with verbose output
pytest -v
```

### Coverage Requirements

The project requires **80% minimum coverage** (enforced in CI):

| Layer | Target | Notes |
|-------|--------|-------|
| Models | 100% | Full coverage expected |
| Core | 95%+ | Critical business logic |
| Services | 85%+ | Some Windows-specific code excluded |
| UI | Excluded | DearPyGui makes UI testing impractical |

### Test Naming Conventions

```text
test_<method_name>_<scenario>_<expected_result>
```

Examples:

- `test_encrypt_valid_data_returns_ciphertext`
- `test_derive_key_empty_password_still_derives`
- `test_verify_password_wrong_password_returns_false`
- `test_switch_profile_locked_session_raises_expired`

### Test Categories

| Marker | Purpose | Example |
|--------|---------|---------|
| `@pytest.mark.unit` | Isolated tests with mocks | Testing encryption roundtrip |
| `@pytest.mark.integration` | Real service interactions | Profile switch workflow |
| `@pytest.mark.security` | Security verification | Plaintext leakage checks |
| `@pytest.mark.e2e` | Full user workflows | Create profile → switch → verify |
| `@pytest.mark.slow` | Tests > 5 seconds | Large data encryption |

### Writing Security Tests

Security tests go in `tests/security/`. Focus on:

```python
class TestEncryptionSecurity:
    """Security tests for encryption implementation."""

    def test_no_plaintext_in_encrypted_output(self) -> None:
        """Encrypted data should not contain plaintext fragments."""
        plaintext = b"SENSITIVE_DATA_12345"
        ciphertext = crypto.encrypt(plaintext, key)
        assert plaintext not in ciphertext

    def test_different_nonce_per_encryption(self) -> None:
        """Each encryption should use a unique nonce."""
        c1 = crypto.encrypt(b"data", key)
        c2 = crypto.encrypt(b"data", key)
        assert c1[:12] != c2[:12]  # First 12 bytes are nonce
```

## Pull Request Process

### Before Submitting

1. **Run all checks locally**:

   ```bash
   # Format and lint
   black src tests
   isort src tests
   ruff check src tests --fix

   # Type check
   mypy src

   # Run tests
   pytest

   # Verify coverage
   pytest --cov=src --cov-fail-under=80
   ```

2. **Update documentation** if behavior changes

3. **Add tests** for new functionality

4. **Update CHANGELOG** (if maintaining one)

### PR Requirements

- [ ] All CI checks pass (tests, linting, type checking)
- [ ] Code coverage maintained at 80%+
- [ ] Documentation updated (if applicable)
- [ ] Security implications considered
- [ ] No new warnings introduced

### Review Process

1. Open a PR against the `main` branch
2. Fill out the PR template
3. Request review from maintainers
4. Address review feedback
5. Squash merge when approved

### PR Template

```markdown
## Summary

[1-2 sentences describing the change]

## Changes

- [Bullet points of specific changes]

## Testing

- [ ] Unit tests added/updated
- [ ] Integration tests (if applicable)
- [ ] Manual testing performed on Windows

## Security Considerations

[Any security implications of this change, or "N/A"]

## Breaking Changes

[Any breaking changes, or "None"]
```

## Commit Conventions

### Format

```text
<type>(<scope>): <description>

[optional body]

[optional footer]
```

### Types

| Type | When to Use |
|------|-------------|
| `feat` | New feature for users |
| `fix` | Bug fix for users |
| `docs` | Documentation changes only |
| `style` | Formatting, no code change |
| `refactor` | Code restructuring, no behavior change |
| `test` | Adding or updating tests |
| `chore` | Build, tooling, dependencies |
| `security` | Security-related changes |
| `perf` | Performance improvements |

### Scopes

Common scopes: `profile`, `crypto`, `ssh`, `gpg`, `ui`, `tray`, `settings`, `import`, `export`

### Examples

```text
feat(profile): add GPG key validation on save

Validates GPG key format and signing capability before
saving to prevent configuration errors.

fix(ssh): handle passphrase-protected keys correctly

Previously, keys with passphrases would fail silently.
Now prompts user for passphrase via SSH_ASKPASS.

Fixes #42

docs(readme): add installation instructions for Windows

security(crypto): increase PBKDF2 iterations to 100k

Increases key derivation iterations from 50,000 to 100,000
to meet current security recommendations.

BREAKING CHANGE: Existing profiles must be re-encrypted.
```

## Getting Help

- **Questions**: Open a [Discussion](https://github.com/apatheticus/git-switch/discussions)
- **Bugs**: Open an [Issue](https://github.com/apatheticus/git-switch/issues)
- **Security**: See [SECURITY.md](SECURITY.md) for private disclosure

Thank you for contributing to Git-Switch!
