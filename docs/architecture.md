# Git-Switch Architecture

This document describes the technical architecture of Git-Switch for developers and contributors.

## Overview

Git-Switch follows a **layered architecture** with strict dependency rules to ensure maintainability, testability, and separation of concerns.

```text
┌───────────────────────────────────────────────────────────────────┐
│                         UI Layer                                  │
│  (DearPyGui views, dialogs, system tray, notifications)          │
│  May ONLY call: Core Layer                                        │
└───────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────────┐
│                        Core Layer                                 │
│  (ProfileManager, SessionManager, RepositoryManager, Crypto)      │
│  May ONLY call: Services Layer, Models                            │
└───────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────────┐
│                      Services Layer                               │
│  (GitService, SSHService, GPGService, CredentialService)          │
│  May ONLY call: Models, External Libraries                        │
└───────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────────┐
│                       Models Layer                                │
│  (Profile, Repository, Settings, Exceptions)                      │
│  No dependencies on other layers                                  │
└───────────────────────────────────────────────────────────────────┘
```

## Layer Descriptions

### Models Layer (`src/models/`)

Pure data structures with validation logic. No external dependencies beyond standard library.

| Model | File | Purpose | Key Fields |
|-------|------|---------|------------|
| `Profile` | `profile.py` | Git identity with credentials | `id`, `name`, `git_username`, `git_email`, `ssh_key`, `gpg_key` |
| `SSHKey` | `profile.py` | SSH key pair (encrypted) | `private_key_encrypted`, `public_key`, `fingerprint`, `passphrase_encrypted` |
| `GPGKey` | `profile.py` | GPG signing config | `enabled`, `key_id`, `private_key_encrypted`, `public_key` |
| `Repository` | `repository.py` | Registered Git repository | `path`, `assigned_profile_id`, `name` |
| `Settings` | `settings.py` | Application preferences | `auto_lock_timeout`, `start_with_windows`, `show_notifications` |
| `MasterKeyConfig` | `settings.py` | Password verification data | `salt`, `verification_hash`, `iterations` |

**Validation**: Models validate their data in `__post_init__` methods, raising `ValueError` for invalid data.

### Services Layer (`src/services/`)

External system integrations. Each service implements a Protocol for dependency injection.

| Service | Protocol | External System | Key Operations |
|---------|----------|-----------------|----------------|
| `GitService` | `GitServiceProtocol` | Git CLI | Read/write global and local config |
| `SSHService` | `SSHServiceProtocol` | Windows OpenSSH | Manage ssh-agent keys |
| `GPGService` | `GPGServiceProtocol` | GnuPG | Import/export GPG keys |
| `CredentialService` | `CredentialServiceProtocol` | Windows Credential Manager | Clear cached Git credentials |

**Error Handling**: Services raise specific `ServiceError` subclasses (e.g., `GitServiceError`, `SSHServiceError`).

### Core Layer (`src/core/`)

Business logic orchestrating services.

| Component | Protocol | Responsibility |
|-----------|----------|----------------|
| `CryptoService` | `CryptoServiceProtocol` | AES-256-GCM encryption, PBKDF2 key derivation |
| `SessionManager` | `SessionManagerProtocol` | Master password, unlock/lock state, auto-lock timer |
| `ProfileManager` | `ProfileManagerProtocol` | Profile CRUD, encrypted storage, profile switching |
| `RepositoryManager` | `RepositoryManagerProtocol` | Repository registration and profile assignment |
| `SettingsManager` | `SettingsManagerProtocol` | Application settings persistence |
| `ValidationService` | - | SSH/GPG credential validation |
| `ImportExportService` | - | Encrypted archive operations |

### UI Layer (`src/ui/`)

DearPyGui-based presentation. Only interacts with Core Layer.

| Component | File | Purpose |
|-----------|------|---------|
| `GitSwitchApp` | `app.py` | Application lifecycle, main loop |
| `MainWindow` | `main_window.py` | Root layout (header, sidebar, content, footer) |
| `SystemTray` | `system_tray.py` | Tray icon and context menu |
| `Theme` | `theme.py` | Colors, fonts, styling constants |

**Views** (`ui/views/`):

| View | Purpose |
|------|---------|
| `ProfilesView` | List, create, edit, delete profiles |
| `RepositoriesView` | Manage repository assignments |
| `SettingsView` | Application preferences |
| `ImportExportView` | Archive operations |

**Dialogs** (`ui/dialogs/`):

| Dialog | Purpose |
|--------|---------|
| `ProfileDialog` | Create/edit profile form |
| `PasswordDialog` | Master password entry |
| `ConfirmDialog` | Confirmation prompts |

**Components** (`ui/components/`):

| Component | Purpose |
|-----------|---------|
| `ProfileCard` | Profile display with actions |
| `StatusBar` | Footer status indicators |

## Data Flow Diagrams

### Profile Switch (Global)

```text
User clicks "Apply Global"
        │
        ▼
┌─────────────────────┐
│ ProfilesView        │ ─────────────────────────────────┐
│ (UI Layer)          │                                   │
└─────────────────────┘                                   │
        │                                                 │
        │ switch_profile(profile_id, "global")            │
        ▼                                                 │
┌─────────────────────┐                                   │
│ ProfileManager      │ ◄─────────────────────────────────┘
│ (Core Layer)        │   Coordinates all operations
│                     │
│ 1. Validate session │
│ 2. Load profile     │
│ 3. Decrypt keys     │
└─────────────────────┘
        │
        ├──────────────┬──────────────┬──────────────┐
        │              │              │              │
        ▼              ▼              ▼              ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│CredService │ │ GitService  │ │ SSHService  │ │ GPGService  │
│             │ │             │ │             │ │ (if enabled)│
│ Clear creds │ │ Update      │ │ Remove keys │ │             │
│             │ │ user.name   │ │ Add new key │ │ Import key  │
│             │ │ user.email  │ │             │ │             │
└─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘
        │              │              │              │
        └──────────────┴──────────────┴──────────────┘
                              │
                              ▼
                    Notification shown
                    Profile marked active
```

### Master Password Verification

```text
Application Launch
        │
        ▼
┌───────────────────────────────┐
│ SessionManager                │
│ has_master_password()?        │
└───────────────────────────────┘
        │
        ├─── No ──────────────────────────────────┐
        │                                          │
        │                                          ▼
        │                            ┌─────────────────────────┐
        │                            │ Create Password Dialog  │
        │                            │                         │
        │                            │ 1. User enters password │
        │                            │ 2. Confirm password     │
        │                            └─────────────────────────┘
        │                                          │
        │                                          ▼
        │                            ┌─────────────────────────┐
        │                            │ setup_master_password() │
        │                            │                         │
        │                            │ 1. Generate 32-byte salt│
        │                            │ 2. Derive key (PBKDF2)  │
        │                            │ 3. Create verify hash   │
        │                            │ 4. Store salt + hash    │
        │                            └─────────────────────────┘
        │                                          │
        │                                          ▼
        │                                   Session Unlocked
        │
        └─── Yes ─────────────────────────────────┐
                                                   │
                                                   ▼
                                    ┌─────────────────────────┐
                                    │ Enter Password Dialog   │
                                    └─────────────────────────┘
                                                   │
                                                   ▼
                                    ┌─────────────────────────┐
                                    │ verify_password()       │
                                    │                         │
                                    │ 1. Load salt from disk  │
                                    │ 2. Derive key (PBKDF2)  │
                                    │ 3. Compare HMAC hashes  │
                                    │ 4. Store key in memory  │
                                    └─────────────────────────┘
                                                   │
                                          ┌───────┴───────┐
                                          │               │
                                       Match          No Match
                                          │               │
                                          ▼               ▼
                                   Session Unlocked   Error Dialog
```

## Storage Architecture

### File Layout

```text
%APPDATA%\GitProfileSwitcher\
├── config.json           # App settings (plaintext, no secrets)
├── master.json           # Salt + verification hash (not password)
├── profiles.dat          # Encrypted profiles (AES-256-GCM)
├── repositories.json     # Repository registry (plaintext)
├── keys\                 # Encrypted key files
│   ├── {uuid}.ssh        # SSH private key (encrypted)
│   └── {uuid}.gpg        # GPG private key (encrypted)
└── logs\                 # Application logs (if enabled)
```

### Encryption Envelope Format

**profiles.dat:**

```text
Offset  Size    Content
------  ----    -------
0       4       Magic number: "GSPR" (0x47535052)
4       4       Version: uint32 little-endian (currently 1)
8       12      Nonce: GCM nonce (random per save)
20      N       Ciphertext: AES-256-GCM encrypted JSON
N+20    16      Auth tag: GCM authentication tag
```

**Key files (*.ssh, *.gpg):**

```text
Offset  Size    Content
------  ----    -------
0       12      Nonce: GCM nonce
12      N       Ciphertext: Encrypted key content
N+12    16      Auth tag: GCM authentication tag
```

### Export Archive Format (.gps)

```text
Offset  Size    Content
------  ----    -------
0       4       Magic: "GSEX" (0x47534558)
4       4       Version: uint32 (1)
8       32      Salt: For archive password derivation
40      12      Nonce: GCM nonce
52      N       Ciphertext: Encrypted ZIP archive
N+52    16      Auth tag: GCM authentication tag
```

The ZIP contains:

- `profiles.json` - Profile metadata
- `keys/{id}.ssh` - SSH keys (re-encrypted with archive password)
- `keys/{id}.gpg` - GPG keys (re-encrypted with archive password)
- `repositories.json` - Repository assignments

## Dependency Injection

All services are wired through `ServiceContainer` in `services/container.py`:

```python
@dataclass
class ServiceContainer:
    # Services layer
    git_service: GitServiceProtocol
    ssh_service: SSHServiceProtocol
    gpg_service: GPGServiceProtocol
    credential_service: CredentialServiceProtocol

    # Core layer
    crypto_service: CryptoServiceProtocol
    session_manager: SessionManagerProtocol
    profile_manager: ProfileManagerProtocol
    repository_manager: RepositoryManagerProtocol
    settings_manager: SettingsManagerProtocol
```

### Factory Functions

```python
def create_container() -> ServiceContainer:
    """Create production container with real services."""
    ...

def create_test_container(
    git_service: GitServiceProtocol | None = None,
    ssh_service: SSHServiceProtocol | None = None,
    # ... other overrides
) -> ServiceContainer:
    """Create test container with mock overrides."""
    ...
```

## Error Handling

### Exception Hierarchy

```text
GitSwitchError (base)
├── AuthenticationError
│   ├── InvalidPasswordError
│   └── SessionExpiredError
├── EncryptionError
├── ProfileError
│   ├── ProfileNotFoundError
│   └── ProfileValidationError
├── ServiceError
│   ├── GitServiceError
│   ├── SSHServiceError
│   ├── GPGServiceError
│   └── CredentialServiceError
├── RepositoryError
│   └── InvalidRepositoryError
└── ImportExportError
    ├── InvalidArchiveError
    └── ArchivePasswordError
```

### Error Strategy by Layer

| Layer | Strategy |
|-------|----------|
| Models | Raise `ValueError` on validation failure in `__post_init__` |
| Services | Raise specific `ServiceError` subclass with context |
| Core | Catch service errors, log details, re-raise or translate |
| UI | Display user-friendly error dialogs, never expose technical details |

## State Machines

### Application State

```text
         ┌──────────────┐
         │   Initial    │
         └──────┬───────┘
                │
                ▼
         ┌──────────────┐
         │    Locked    │◄────────────────┐
         └──────┬───────┘                 │
                │                         │
         Correct password           Auto-lock timeout
                │                    or manual lock
                ▼                         │
         ┌──────────────┐                 │
         │   Unlocked   │─────────────────┘
         └──────────────┘
```

### Profile Switch State

```text
┌────────┐     User request     ┌──────────────────┐
│  Idle  │─────────────────────►│ SwitchRequested  │
└────────┘                      └────────┬─────────┘
    ▲                                    │
    │                      ┌─────────────┴─────────────┐
    │                      │                           │
    │               Confirm enabled?            Confirm disabled
    │                      │                           │
    │                      ▼                           │
    │            ┌──────────────────┐                  │
    │            │ ConfirmDialog    │                  │
    │            └────────┬─────────┘                  │
    │                     │                            │
    │            ┌────────┴────────┐                   │
    │            │                 │                   │
    │         Confirmed         Cancelled              │
    │            │                 │                   │
    │            │                 ▼                   │
    │            │           ┌──────────┐              │
    │            │           │  Idle    │              │
    │            │           └──────────┘              │
    │            ▼                                     │
    │     ┌──────────────┐◄────────────────────────────┘
    │     │  Switching   │
    │     └──────┬───────┘
    │            │
    │     ┌──────┴──────┐
    │     │             │
    │  Success        Error
    │     │             │
    │     ▼             ▼
    │  Notification  Error Dialog
    │     │             │
    └─────┴─────────────┘
```

## Performance Considerations

| Operation | Target | Implementation |
|-----------|--------|----------------|
| Application startup | < 3 seconds | Lazy service initialization, deferred UI rendering |
| Profile switch | < 5 seconds | Parallel SSH/Git operations where possible |
| UI response | < 100 ms | GPU-accelerated DearPyGui rendering |
| Auto-save | < 500 ms | Debounced writes, async where possible |
| Key derivation | ~1 second | 100,000 PBKDF2 iterations (security tradeoff) |

## Security Boundaries

| Boundary | Mechanism | Notes |
|----------|-----------|-------|
| Disk → Memory | AES-256-GCM decryption | Only when session unlocked |
| Memory → Disk | AES-256-GCM encryption | Automatic on save |
| User → Application | Master password + PBKDF2 | 100,000 iterations |
| Application → ssh-agent | Key loaded temporarily | Removed on profile switch if configured |
| Application → GPG | Key imported | May persist in GPG keyring |

## Testing Architecture

### Test Organization

```text
tests/
├── conftest.py          # Shared fixtures
├── unit/                # Isolated tests with mocks
│   ├── test_crypto.py
│   ├── test_models.py
│   ├── test_profile_manager.py
│   └── ...
├── integration/         # Real service interactions
│   ├── test_profile_switch.py
│   └── test_import_export.py
├── security/            # Security-focused tests
│   ├── test_encryption_roundtrip.py
│   ├── test_no_plaintext_leakage.py
│   └── test_command_injection.py
└── e2e/                 # Full workflows
    └── test_complete_workflow.py
```

### Mock Strategy

- **Unit tests**: All services mocked via Protocol interfaces
- **Integration tests**: Real services, isolated file system
- **Security tests**: Real crypto, mocked external services
- **E2E tests**: Minimal mocking, full stack

## Extending the Architecture

### Adding a New Service

1. Define Protocol in `services/protocols.py`
2. Implement service class in `services/`
3. Add to `ServiceContainer`
4. Update `create_container()` and `create_test_container()`
5. Add unit tests with mock
6. Add integration tests

### Adding a New View

1. Create view module in `ui/views/`
2. Add navigation item in `MainWindow`
3. Register in view stack
4. Connect to Core Layer services

### Adding a New Model

1. Define dataclass in `models/`
2. Add validation in `__post_init__`
3. Add serialization helpers if needed
4. Update storage format version if breaking change
