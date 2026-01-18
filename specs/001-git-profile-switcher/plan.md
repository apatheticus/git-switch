# Implementation Plan: Git-Switch Profile Manager

**Branch**: `001-git-profile-switcher` | **Date**: 2026-01-17 | **Spec**: [spec.md](./spec.md)
**Input**: Feature specification from `/specs/001-git-profile-switcher/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/commands/plan.md` for the execution workflow.

## Summary

Git-Switch is a Windows desktop application that enables developers to seamlessly switch between multiple Git/GitHub user profiles. The application manages Git configurations, SSH keys, GPG signing keys, and Windows Credential Manager entries through a modern, GPU-accelerated GUI built with DearPyGui. It provides encrypted profile storage with master password protection, one-click profile switching (global or per-repository), and system tray integration for quick access.

**Technical Approach**: Python 3.11+ desktop application using DearPyGui for GPU-accelerated UI, AES-256-GCM encryption via cryptography library, paramiko for SSH operations, GitPython for Git config management, and PyInstaller for single-file portable distribution.

## Technical Context

**Language/Version**: Python 3.11+
**Primary Dependencies**: DearPyGui (1.10+), cryptography (41+), paramiko (3.3+), GitPython (3.1+), python-gnupg (0.5+), keyring (24+), pywin32 (306+), pystray (0.19+)
**Storage**: File-based encrypted storage in `%APPDATA%/Git-Switch/` (profiles.dat, config.json, repositories.json)
**Testing**: pytest with pytest-mock for unit/integration tests
**Target Platform**: Windows 10/11 (64-bit) with OpenSSH, Git, optional GnuPG
**Project Type**: Single desktop application
**Performance Goals**: Profile switch < 5 seconds, application startup < 3 seconds, UI response < 100ms
**Constraints**: Single portable .exe, no admin privileges required, GPU with OpenGL 3.3+ for DearPyGui
**Scale/Scope**: Single-user desktop app, ~10 profiles typical, ~50 repositories max

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

### Security (Section I) - CRITICAL

| Requirement | Status | Implementation Notes |
|-------------|--------|---------------------|
| AES-256-GCM encryption with PBKDF2 (100k+ iterations) | ✅ PLANNED | Use `cryptography` library Fernet + custom PBKDF2 |
| Master password never stored (only verification hash) | ✅ PLANNED | Store HMAC-SHA256 of known constant |
| Secure memory handling (clear secrets after use) | ✅ PLANNED | Zero buffers, use context managers |
| Defense in depth (validate all inputs) | ✅ PLANNED | Validate at all layer boundaries |
| Audit logging (no plaintext secrets) | ✅ PLANNED | Log events with [REDACTED] for sensitive data |
| Fail secure (deny on error) | ✅ PLANNED | Lock application on cryptographic errors |

### Test-Driven Development (Section II)

| Requirement | Status | Implementation Notes |
|-------------|--------|---------------------|
| Red-Green-Refactor cycle | ✅ PLANNED | Tests written before implementation |
| Core layer 95% coverage | ✅ PLANNED | Encryption, profile management, validation |
| Services layer 85% coverage | ✅ PLANNED | Git, SSH, GPG, Credential services |
| Models 100% coverage | ✅ PLANNED | All dataclasses fully tested |
| Test naming convention | ✅ PLANNED | `test_<method>_<scenario>_<expected_result>` |
| Security test suite | ✅ PLANNED | Dedicated `tests/security/` directory |

### Code Maintainability (Section III)

| Requirement | Status | Implementation Notes |
|-------------|--------|---------------------|
| Single Responsibility Principle | ✅ PLANNED | Separate modules per concern |
| Layered Architecture (UI → Core → Services → Models) | ✅ PLANNED | Strict layer boundaries enforced |
| Dependency Injection | ✅ PLANNED | All services injected, no direct instantiation |
| Type Safety (mypy --strict) | ✅ PLANNED | Full type hints, strict mode CI check |
| Google-style docstrings | ✅ PLANNED | All public APIs documented |
| Protocol classes for services | ✅ PLANNED | Service interfaces as Protocols |

### GUI Design (Section IV)

| Requirement | Status | Implementation Notes |
|-------------|--------|---------------------|
| Dark theme with cyan/electric blue accents | ✅ PLANNED | Per mockup: #00D4FF, #00FFFF |
| GPU-accelerated rendering (DearPyGui) | ✅ PLANNED | OpenGL 3.3+ backend |
| Immediate feedback (<100ms) | ✅ PLANNED | Async operations with progress indicators |
| Keyboard navigation | ✅ PLANNED | Tab, Enter, Escape, Arrow keys |
| WCAG AA contrast (4.5:1 minimum) | ✅ PLANNED | Validated color choices |

### Windows Platform Integration (Section VI)

| Requirement | Status | Implementation Notes |
|-------------|--------|---------------------|
| Windows OpenSSH ssh-agent (no third-party) | ✅ PLANNED | Use native ssh-add/ssh-agent |
| Windows Credential Manager via keyring | ✅ PLANNED | `keyring` with Windows backend |
| Portable single .exe via PyInstaller | ✅ PLANNED | No installation, no admin required |
| System tray integration | ✅ PLANNED | `pystray` library |
| Graceful degradation (missing Git/GPG) | ✅ PLANNED | Show helpful errors, don't crash |

### Development Workflow (Section VII)

| Requirement | Status | Implementation Notes |
|-------------|--------|---------------------|
| Spec-driven development | ✅ FOLLOWING | /speckit workflow in progress |
| Atomic commits | ✅ PLANNED | One logical change per commit |
| Commit message format | ✅ PLANNED | `<type>(<scope>): <description>` |
| Human approval gates for security changes | ✅ ACKNOWLEDGED | Security PRs flagged for review |

**Gate Status**: ✅ PASS - All constitution requirements addressed in design

## Project Structure

### Documentation (this feature)

```text
specs/001-git-profile-switcher/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
│   └── service-interfaces.md  # Internal service contracts (Protocol classes)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

```text
src/
├── main.py                    # Application entry point
├── models/                    # Data models layer
│   ├── __init__.py
│   ├── profile.py             # Profile dataclass
│   ├── repository.py          # Repository registration dataclass
│   ├── settings.py            # Application settings dataclass
│   └── exceptions.py          # Custom exception hierarchy
├── services/                  # External system integrations
│   ├── __init__.py
│   ├── protocols.py           # Service interface protocols
│   ├── git_service.py         # Git config operations
│   ├── ssh_service.py         # SSH agent operations (Windows OpenSSH)
│   ├── gpg_service.py         # GPG keyring operations
│   └── credential_service.py  # Windows Credential Manager
├── core/                      # Business logic layer
│   ├── __init__.py
│   ├── crypto.py              # AES-256-GCM encryption, PBKDF2 key derivation
│   ├── profile_manager.py     # Profile CRUD, switching logic
│   ├── repository_manager.py  # Repository registration, local config
│   ├── validation.py          # Credential validation service
│   ├── session.py             # Master password session, auto-lock
│   └── import_export.py       # .gps archive handling
├── ui/                        # DearPyGui presentation layer
│   ├── __init__.py
│   ├── app.py                 # Main application controller
│   ├── theme.py               # Colors, fonts, styling constants
│   ├── main_window.py         # Root window layout
│   ├── views/                 # View modules (sidebar navigation targets)
│   │   ├── __init__.py
│   │   ├── profiles_view.py   # Profile list, cards
│   │   ├── repositories_view.py
│   │   ├── settings_view.py
│   │   └── import_export_view.py
│   ├── dialogs/               # Modal dialogs
│   │   ├── __init__.py
│   │   ├── password_dialog.py # Master password entry
│   │   ├── profile_dialog.py  # Create/edit profile form
│   │   └── confirm_dialog.py  # Generic confirmation modal
│   ├── components/            # Reusable UI components
│   │   ├── __init__.py
│   │   ├── profile_card.py    # Profile card widget
│   │   └── status_bar.py      # Footer status indicators
│   └── system_tray.py         # pystray integration
└── utils/                     # Cross-cutting utilities
    ├── __init__.py
    ├── paths.py               # %APPDATA% path management
    ├── windows.py             # Windows-specific helpers
    └── notifications.py       # Toast notification wrapper

assets/
├── icons/
│   ├── app_icon.ico           # Application icon
│   └── tray_icon.ico          # System tray icon
└── fonts/                     # Optional bundled fonts

tests/
├── __init__.py
├── conftest.py                # Shared fixtures, mocks
├── unit/
│   ├── __init__.py
│   ├── test_models.py
│   ├── test_crypto.py
│   ├── test_profile_manager.py
│   ├── test_repository_manager.py
│   └── test_validation.py
├── integration/
│   ├── __init__.py
│   ├── test_git_service.py
│   ├── test_ssh_service.py
│   └── test_credential_service.py
├── security/                  # Dedicated security test suite
│   ├── __init__.py
│   ├── test_encryption_roundtrip.py
│   ├── test_no_plaintext_leakage.py
│   └── test_authentication_edge_cases.py
└── e2e/
    └── test_profile_switch_workflow.py

# Configuration files at repo root
pyproject.toml                 # Poetry/pip configuration, pytest, mypy settings
requirements.txt               # Production dependencies
requirements-dev.txt           # Development/test dependencies
build.spec                     # PyInstaller single-file build spec
```

**Structure Decision**: Single desktop application following the constitution's layered architecture mandate. The UI layer (ui/) may only call the Core layer (core/), which may only call the Services layer (services/) and Models (models/). This enables proper dependency injection, testability, and maintains security boundaries.

## Complexity Tracking

> **No violations identified** - Design follows constitution principles without requiring complexity justifications.

---

## Constitution Check - Post-Design Verification

*Re-evaluated after Phase 1 design completion.*

### Security (Section I) - VERIFIED ✅

| Requirement | Design Artifact | Verification |
|-------------|-----------------|--------------|
| AES-256-GCM + PBKDF2 (100k+) | research.md §1, contracts/service-interfaces.md §5 | CryptoServiceProtocol defines encrypt/decrypt with PBKDF2 key derivation |
| Master password never stored | data-model.md §MasterKeyConfig | Only salt + verification_hash stored, never password |
| Secure memory handling | research.md §10 | secure_zero() function + context managers defined |
| Defense in depth | data-model.md validation rules | All models validate inputs in __post_init__ |
| Audit logging | contracts/service-interfaces.md | All service methods documented with error cases |
| Fail secure | data-model.md exceptions | SessionExpiredError, AuthenticationError lock application |

### Test-Driven Development (Section II) - VERIFIED ✅

| Requirement | Design Artifact | Verification |
|-------------|-----------------|--------------|
| Test structure | plan.md project structure | tests/unit/, tests/integration/, tests/security/, tests/e2e/ directories |
| Coverage targets | quickstart.md | pytest --cov configuration ready |
| Test naming | quickstart.md | Convention: test_<method>_<scenario>_<expected_result> |
| Security test suite | plan.md | Dedicated tests/security/ with encryption, leakage, auth tests |

### Code Maintainability (Section III) - VERIFIED ✅

| Requirement | Design Artifact | Verification |
|-------------|-----------------|--------------|
| Single Responsibility | plan.md project structure | Separate modules: crypto.py, session.py, profile_manager.py, etc. |
| Layered Architecture | contracts/service-interfaces.md | Clear layer diagram with strict boundaries documented |
| Dependency Injection | contracts/service-interfaces.md §DI | ServiceContainer with Protocol-based injection |
| Type Safety | quickstart.md | mypy --strict configured in pyproject.toml |
| Docstrings | contracts/service-interfaces.md | All protocols have Google-style Args/Returns/Raises |
| Protocol classes | contracts/service-interfaces.md | 8 Protocol interfaces defined for all services |

### GUI Design (Section IV) - VERIFIED ✅

| Requirement | Design Artifact | Verification |
|-------------|-----------------|--------------|
| Dark theme + cyan accents | research.md §5 | COLORS dict with #00D4FF, #00FFFF defined |
| GPU-accelerated | quickstart.md prerequisites | DearPyGui + OpenGL 3.3+ requirement documented |
| Immediate feedback | spec.md SC-001 | <5 second switch, <100ms UI response targets |
| Keyboard navigation | spec.md FR-026 | Tab, Enter, Escape requirements in spec |

### Windows Platform (Section VI) - VERIFIED ✅

| Requirement | Design Artifact | Verification |
|-------------|-----------------|--------------|
| Windows OpenSSH | research.md §2 | SSHServiceProtocol uses subprocess + ssh-add |
| Credential Manager | research.md §3 | keyring + ctypes Windows API |
| Portable .exe | research.md §9 | PyInstaller build.spec documented |
| System tray | research.md §7 | pystray integration pattern |
| Graceful degradation | data-model.md edge cases, spec.md edge cases | Error handling for missing Git/GPG |

### Development Workflow (Section VII) - VERIFIED ✅

| Requirement | Design Artifact | Verification |
|-------------|-----------------|--------------|
| Spec-driven | This plan exists | /speckit.plan workflow followed |
| Atomic commits | quickstart.md | Commit conventions documented |
| Human approval gates | plan.md Constitution Check | Security changes flagged for review |

**Post-Design Gate Status**: ✅ PASS - All constitution requirements verified in design artifacts

---

## Generated Artifacts Summary

| Artifact | Path | Purpose |
|----------|------|---------|
| Implementation Plan | `specs/001-git-profile-switcher/plan.md` | This file - technical approach and structure |
| Research | `specs/001-git-profile-switcher/research.md` | Technology decisions and implementation patterns |
| Data Model | `specs/001-git-profile-switcher/data-model.md` | Entity definitions, validation rules, state machines |
| Service Interfaces | `specs/001-git-profile-switcher/contracts/service-interfaces.md` | Protocol classes for dependency injection |
| Quickstart | `specs/001-git-profile-switcher/quickstart.md` | Developer setup guide |
| Agent Context | `CLAUDE.md` | AI agent guidance (auto-generated) |

---

## Next Steps

1. Run `/speckit.tasks` to generate `tasks.md` with implementation tasks
2. Run `/speckit.implement` to execute the implementation plan
3. Human review required before implementing security-critical components (crypto.py, session.py)
