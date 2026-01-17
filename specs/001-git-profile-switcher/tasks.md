# Tasks: Git-Switch Profile Manager

**Input**: Design documents from `/specs/001-git-profile-switcher/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/service-interfaces.md

**Tests**: Included per constitution TDD requirements (Section II)

**Organization**: Tasks grouped by user story to enable independent implementation and testing

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Setup (Shared Infrastructure) COMPLETE

**Purpose**: Project initialization and basic structure

- [x] T001 Create project directory structure per plan.md (src/, tests/, assets/)
- [x] T002 Create pyproject.toml with project metadata, pytest, mypy, black, isort, ruff configuration
- [x] T003 [P] Create requirements.txt with production dependencies (DearPyGui, cryptography, paramiko, GitPython, python-gnupg, keyring, pywin32, pystray, Pillow, win10toast)
- [x] T004 [P] Create requirements-dev.txt with dev dependencies (pytest, pytest-cov, pytest-mock, mypy, types-*, black, isort, ruff, pyinstaller)
- [x] T005 [P] Create empty __init__.py files in all package directories (src/models/, src/services/, src/core/, src/ui/, src/ui/views/, src/ui/dialogs/, src/ui/components/, src/utils/, tests/, tests/unit/, tests/integration/, tests/security/, tests/e2e/)
- [x] T006 [P] Create assets/icons/ directory with placeholder .ico files (app_icon.ico, tray_icon.ico)
- [x] T007 Create tests/conftest.py with shared pytest fixtures

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**CRITICAL**: No user story work can begin until this phase is complete

### Exception Hierarchy

- [x] T008 Create exception hierarchy in src/models/exceptions.py (GitSwitchError, AuthenticationError, InvalidPasswordError, SessionExpiredError, EncryptionError, ProfileError, ProfileNotFoundError, ProfileValidationError, ServiceError, GitServiceError, SSHServiceError, GPGServiceError, CredentialServiceError, RepositoryError, InvalidRepositoryError)
- [x] T009 [P] Write unit tests for exception hierarchy in tests/unit/test_exceptions.py

### Data Models (No Encryption)

- [x] T010 [P] Create SSHKey dataclass in src/models/profile.py with validation (__post_init__)
- [x] T011 [P] Create GPGKey dataclass in src/models/profile.py with validation (__post_init__)
- [x] T012 Create Profile dataclass in src/models/profile.py with validation (depends on T010, T011)
- [x] T013 [P] Create Repository dataclass in src/models/repository.py with validation and is_valid_git_repo()
- [x] T014 [P] Create Settings dataclass in src/models/settings.py with validation
- [x] T015 [P] Create MasterKeyConfig dataclass in src/models/settings.py with validation
- [x] T016 Create GitSwitchEncoder JSON encoder in src/models/serialization.py for UUID, datetime, Path, bytes
- [x] T017 Create src/models/__init__.py exporting all model classes
- [x] T018 Write unit tests for all dataclasses in tests/unit/test_models.py (100% coverage per constitution)

### Service Protocols

- [x] T019 Create all Protocol classes in src/services/protocols.py (GitServiceProtocol, SSHServiceProtocol, GPGServiceProtocol, CredentialServiceProtocol)
- [x] T020 [P] Create core Protocol classes in src/core/protocols.py (CryptoServiceProtocol, SessionManagerProtocol, ProfileManagerProtocol, RepositoryManagerProtocol)
- [x] T021 Create ServiceContainer dataclass in src/services/container.py with create_container() and create_test_container()

### Utility Modules

- [x] T022 [P] Create paths.py in src/utils/paths.py with get_app_data_dir(), get_profiles_path(), get_config_path(), etc.
- [x] T023 [P] Create windows.py in src/utils/windows.py with Windows-specific helpers
- [x] T024 [P] Create notifications.py in src/utils/notifications.py with show_notification() wrapper
- [x] T025 Create src/utils/__init__.py exporting utility functions
- [x] T026 Write unit tests for utility modules in tests/unit/test_utils.py

### Crypto Service (Security Critical)

- [x] T027 Write security tests for crypto in tests/security/test_encryption_roundtrip.py (MUST FAIL first)
- [x] T028 [P] Write security tests for no plaintext leakage in tests/security/test_no_plaintext_leakage.py (MUST FAIL first)
- [x] T029 Implement CryptoService in src/core/crypto.py (derive_key with PBKDF2 100k iterations, encrypt/decrypt with AES-256-GCM, generate_salt, create_verification_hash, verify_password, secure_delete_file, secure_zero helper)
- [x] T030 Verify security tests pass after implementation

**Checkpoint**: Foundation ready - user story implementation can now begin

---

## Phase 3: User Story 1 - Create and Store Git Profile (Priority: P1) MVP

**Goal**: Allow users to create profiles with Git identity, SSH keys, and optional GPG keys, stored encrypted

**Independent Test**: Launch app, enter master password, create profile with Git credentials and SSH key, verify profile appears and persists after restart

### Tests for User Story 1

- [x] T031 [P] [US1] Write unit tests for SessionManager in tests/unit/test_session.py (MUST FAIL first)
- [x] T032 [P] [US1] Write unit tests for ProfileManager CRUD in tests/unit/test_profile_manager.py (MUST FAIL first)
- [x] T033 [P] [US1] Write security tests for authentication edge cases in tests/security/test_authentication_edge_cases.py (MUST FAIL first)

### Implementation for User Story 1

- [x] T034 [US1] Implement SessionManager in src/core/session.py (unlock, lock, setup_master_password, change_master_password, reset_idle_timer, auto-lock timer, has_master_password)
- [x] T035 [US1] Implement ProfileManager CRUD in src/core/profile_manager.py (list_profiles, get_profile, create_profile, update_profile, delete_profile - without switch logic)
- [x] T036 [US1] Implement profile storage file format (profiles.dat) with encrypt/decrypt in ProfileManager
- [x] T037 [US1] Implement SSH key storage in keys/{profile_id}.ssh with encryption
- [x] T038 [US1] Implement GPG key storage in keys/{profile_id}.gpg with encryption (optional, if GPG enabled)
- [x] T039 [US1] Verify all US1 tests pass

**Checkpoint**: User Story 1 complete - profiles can be created and stored securely

---

## Phase 4: User Story 2 - Switch Git Profile Globally (Priority: P1)

**Goal**: Apply a profile globally - update Git config, clear credentials, load SSH key into agent

**Independent Test**: Have two profiles, switch from one to another, verify `git config --global user.name/email` and `ssh -T git@github.com`

### Tests for User Story 2

- [ ] T040 [P] [US2] Write unit tests for GitService in tests/unit/test_git_service.py (MUST FAIL first)
- [ ] T041 [P] [US2] Write unit tests for SSHService in tests/unit/test_ssh_service.py (MUST FAIL first)
- [ ] T042 [P] [US2] Write unit tests for CredentialService in tests/unit/test_credential_service.py (MUST FAIL first)
- [ ] T043 [P] [US2] Write unit tests for GPGService in tests/unit/test_gpg_service.py (MUST FAIL first)
- [ ] T044 [P] [US2] Write unit tests for ProfileManager.switch_profile in tests/unit/test_profile_manager.py (append to existing)
- [ ] T045 [P] [US2] Write integration tests for profile switch in tests/integration/test_profile_switch.py (MUST FAIL first)

### Implementation for User Story 2

- [ ] T046 [US2] Implement GitService in src/services/git_service.py (is_git_installed, get_global_config, set_global_config, get_local_config, set_local_config)
- [ ] T047 [US2] Implement SSHService in src/services/ssh_service.py (is_agent_running, start_agent, list_keys, add_key, remove_all_keys, test_connection, get_key_fingerprint, validate_private_key)
- [ ] T048 [US2] Implement CredentialService in src/services/credential_service.py (list_git_credentials, delete_credential, clear_git_credentials, has_credential)
- [ ] T049 [US2] Implement GPGService in src/services/gpg_service.py (is_gpg_installed, list_keys, import_key, export_key, delete_key, verify_signing_capability, validate_key)
- [ ] T050 [US2] Create src/services/__init__.py exporting all services
- [ ] T051 [US2] Implement ProfileManager.switch_profile in src/core/profile_manager.py (global scope: update git config, clear credentials, update ssh-agent, update GPG if enabled)
- [ ] T052 [US2] Integrate with notifications (show_notification on switch complete)
- [ ] T053 [US2] Verify all US2 tests pass

**Checkpoint**: User Story 2 complete - profiles can be switched globally

---

## Phase 5: User Story 3 - Secure Application Access (Priority: P1)

**Goal**: Protect profiles with master password, auto-lock on idle, lock on demand

**Independent Test**: Set master password on first launch, close/reopen app, verify password prompt, test wrong password (rejection), correct password (access)

### Tests for User Story 3

- [ ] T054 [P] [US3] Write unit tests for idle timer in tests/unit/test_session.py (append to existing, MUST FAIL first)
- [ ] T055 [P] [US3] Write e2e test for password workflow in tests/e2e/test_password_workflow.py (MUST FAIL first)

### Implementation for User Story 3

- [ ] T056 [US3] Implement auto-lock timer in SessionManager (configurable timeout from Settings)
- [ ] T057 [US3] Implement lock callback mechanism for UI notification
- [ ] T058 [US3] Implement secure memory clearing on lock (zero encryption key using secure_zero)
- [ ] T059 [US3] Load Settings from config.json with auto_lock_timeout
- [ ] T060 [US3] Verify all US3 tests pass

**Checkpoint**: User Story 3 complete - application access is secured

---

## Phase 6: User Story 4 - Manage Profiles (Priority: P2)

**Goal**: Edit existing profiles, delete profiles with confirmation

**Independent Test**: Edit an existing profile's email, verify change persists, delete a profile, verify it no longer appears

### Tests for User Story 4

- [ ] T061 [P] [US4] Write unit tests for profile update/delete edge cases in tests/unit/test_profile_manager.py (append, MUST FAIL first)

### Implementation for User Story 4

- [ ] T062 [US4] Enhance ProfileManager.update_profile to handle SSH key replacement
- [ ] T063 [US4] Enhance ProfileManager.delete_profile to clean up key files and handle active profile deletion
- [ ] T064 [US4] Verify all US4 tests pass

**Checkpoint**: User Story 4 complete - profiles can be edited and deleted

---

## Phase 7: User Story 5 - Apply Profile to Specific Repository (Priority: P2)

**Goal**: Register repositories, assign profiles, apply as local Git config

**Independent Test**: Register a repository, assign a profile, apply locally, verify .git/config contains correct user.name/email

### Tests for User Story 5

- [ ] T065 [P] [US5] Write unit tests for RepositoryManager in tests/unit/test_repository_manager.py (MUST FAIL first)
- [ ] T066 [P] [US5] Write integration tests for local config in tests/integration/test_local_config.py (MUST FAIL first)

### Implementation for User Story 5

- [ ] T067 [US5] Implement RepositoryManager in src/core/repository_manager.py (list_repositories, get_repository, add_repository, remove_repository, assign_profile, apply_profile, validate_repository)
- [ ] T068 [US5] Implement repository storage in repositories.json
- [ ] T069 [US5] Enhance ProfileManager.switch_profile to support scope="local" with repo_path
- [ ] T070 [US5] Verify all US5 tests pass

**Checkpoint**: User Story 5 complete - repositories can have per-repo profiles

---

## Phase 8: User Story 6 - System Tray Quick Access (Priority: P2)

**Goal**: System tray icon with context menu for quick profile switching

**Independent Test**: Minimize app to tray, right-click icon, select different profile, verify switch occurs

### Tests for User Story 6

- [ ] T071 [P] [US6] Write unit tests for system tray callbacks in tests/unit/test_system_tray.py (MUST FAIL first)

### Implementation for User Story 6

- [ ] T072 [US6] Implement system tray integration in src/ui/system_tray.py (create_tray_icon, update_menu, callbacks for switch/open/lock/exit)
- [ ] T073 [US6] Integrate tray icon with SessionManager lock state
- [ ] T074 [US6] Handle minimize to tray and restore from tray
- [ ] T075 [US6] Verify all US6 tests pass

**Checkpoint**: User Story 6 complete - quick access via system tray

---

## Phase 9: User Story 7 - Import/Export Profiles (Priority: P3)

**Goal**: Export profiles to encrypted .gps archive, import with merge/replace options

**Independent Test**: Export profiles to .gps file, delete all profiles, import archive, verify profiles restored

### Tests for User Story 7

- [ ] T076 [P] [US7] Write unit tests for import/export in tests/unit/test_import_export.py (MUST FAIL first)

### Implementation for User Story 7

- [ ] T077 [US7] Implement export functionality in src/core/import_export.py (export_profiles with separate archive password)
- [ ] T078 [US7] Implement .gps archive format (encrypted zip with profiles, keys, repository assignments)
- [ ] T079 [US7] Implement import functionality with merge/replace options
- [ ] T080 [US7] Implement conflict resolution for duplicate profile names during merge
- [ ] T081 [US7] Verify all US7 tests pass

**Checkpoint**: User Story 7 complete - profiles can be backed up and transferred

---

## Phase 10: User Story 8 - Validate Profile Credentials (Priority: P3)

**Goal**: Validate SSH keys and GPG keys before use

**Independent Test**: Create profile with valid SSH key, click Validate, verify SSH connection test passes

### Tests for User Story 8

- [ ] T082 [P] [US8] Write unit tests for validation service in tests/unit/test_validation.py (MUST FAIL first)

### Implementation for User Story 8

- [ ] T083 [US8] Implement ValidationService in src/core/validation.py (validate_ssh_key, validate_ssh_connection, validate_gpg_key, validate_gpg_signing)
- [ ] T084 [US8] Integrate validation into ProfileManager.validate_credentials
- [ ] T085 [US8] Verify all US8 tests pass

**Checkpoint**: User Story 8 complete - credentials can be validated

---

## Phase 11: UI Layer (DearPyGui)

**Purpose**: Complete GUI implementation using DearPyGui

### Theme and Base UI

- [ ] T086 Create theme constants in src/ui/theme.py (COLORS dict with cyan/electric blue accents per research.md)
- [ ] T087 Implement theme creation in src/ui/theme.py (create_theme with dark background, styled components)
- [ ] T088 Create main application controller in src/ui/app.py (initialize DearPyGui, apply theme, main loop)
- [ ] T089 Create main window layout in src/ui/main_window.py (sidebar navigation, content area, status bar)

### Dialogs

- [ ] T090 [P] Implement password dialog in src/ui/dialogs/password_dialog.py (master password entry, first-time setup)
- [ ] T091 [P] Implement profile dialog in src/ui/dialogs/profile_dialog.py (create/edit profile form with SSH/GPG fields)
- [ ] T092 [P] Implement confirm dialog in src/ui/dialogs/confirm_dialog.py (generic yes/no modal)
- [ ] T093 Create src/ui/dialogs/__init__.py exporting dialogs

### Components

- [ ] T094 [P] Implement profile card widget in src/ui/components/profile_card.py (display profile info, switch/edit/delete buttons)
- [ ] T095 [P] Implement status bar in src/ui/components/status_bar.py (SSH status, GPG status, active profile)
- [ ] T096 Create src/ui/components/__init__.py exporting components

### Views

- [ ] T097 Implement profiles view in src/ui/views/profiles_view.py (profile list with cards, New Profile button)
- [ ] T098 Implement repositories view in src/ui/views/repositories_view.py (repository list, add/remove, profile assignment)
- [ ] T099 Implement settings view in src/ui/views/settings_view.py (all settings from Settings dataclass)
- [ ] T100 Implement import/export view in src/ui/views/import_export_view.py (export button, import button with options)
- [ ] T101 Create src/ui/views/__init__.py exporting views

### Integration

- [ ] T102 Wire views to navigation in main_window.py
- [ ] T103 Connect UI to ServiceContainer (inject services via controller)
- [ ] T104 Implement idle activity tracking for auto-lock (reset timer on user input)
- [ ] T105 Create src/ui/__init__.py exporting app module
- [ ] T106 Create application entry point in src/main.py

---

## Phase 12: Polish & Cross-Cutting Concerns

**Purpose**: Final quality improvements and packaging

### Build and Distribution

- [ ] T107 Create build.spec PyInstaller configuration for single-file executable
- [ ] T108 Test PyInstaller build produces working .exe
- [ ] T109 Verify executable runs without Python installation

### Code Quality

- [ ] T110 Run mypy --strict on all src/ code, fix any type errors
- [ ] T111 Run ruff check and fix any linting issues
- [ ] T112 Run black and isort for consistent formatting
- [ ] T113 Verify all tests pass with pytest
- [ ] T114 Generate coverage report, verify coverage targets (core 95%, services 85%, models 100%)

### E2E Validation

- [ ] T115 Create e2e test for full profile switch workflow in tests/e2e/test_profile_switch_workflow.py
- [ ] T116 Run quickstart.md validation (all steps work as documented)

### Security Hardening

- [ ] T117 Review all subprocess calls for command injection vulnerabilities
- [ ] T118 Verify no plaintext secrets in logs (run security test suite)
- [ ] T119 Verify master password never stored (only verification hash)

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup - BLOCKS all user stories
- **User Stories (Phase 3-10)**: All depend on Foundational phase completion
  - US1, US2, US3 (P1 priority) should be done first
  - US4, US5, US6 (P2 priority) can proceed after P1 complete
  - US7, US8 (P3 priority) can proceed after P2 complete
- **UI Layer (Phase 11)**: Depends on all services being implemented (through US8)
- **Polish (Phase 12)**: Depends on all features being complete

### User Story Dependencies

- **User Story 1 (P1)**: Foundation only - creates core profile storage
- **User Story 2 (P1)**: Foundation + US1 - adds switch capability
- **User Story 3 (P1)**: Foundation only - security layer (parallel with US1/US2)
- **User Story 4 (P2)**: US1 - extends profile management
- **User Story 5 (P2)**: US1 + US2 - adds repository-specific config
- **User Story 6 (P2)**: US2 - system tray uses switch functionality
- **User Story 7 (P3)**: US1 - import/export operates on profiles
- **User Story 8 (P3)**: US2 - validation uses SSH/GPG services

### Within Each User Story

- Tests MUST be written and FAIL before implementation
- Models before services
- Services before managers
- Core implementation before integration
- Story complete before moving to next priority

### Parallel Opportunities

- All Setup tasks marked [P] can run in parallel
- All Foundational tests/models marked [P] can run in parallel
- All tests for a user story marked [P] can run in parallel
- UI dialogs and components marked [P] can run in parallel
- Different P2/P3 user stories can be worked on in parallel after P1 complete

---

## Parallel Example: User Story 2 Tests

```bash
# Launch all tests for User Story 2 together:
Task: "Write unit tests for GitService in tests/unit/test_git_service.py"
Task: "Write unit tests for SSHService in tests/unit/test_ssh_service.py"
Task: "Write unit tests for CredentialService in tests/unit/test_credential_service.py"
Task: "Write unit tests for GPGService in tests/unit/test_gpg_service.py"
Task: "Write unit tests for ProfileManager.switch_profile in tests/unit/test_profile_manager.py"
Task: "Write integration tests for profile switch in tests/integration/test_profile_switch.py"
```

---

## Implementation Strategy

### MVP First (User Stories 1-3 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1 (Create/Store Profile)
4. Complete Phase 4: User Story 2 (Switch Profile Globally)
5. Complete Phase 5: User Story 3 (Secure Access)
6. **STOP and VALIDATE**: Test core functionality independently
7. Minimal UI: Password dialog + Profile list + Switch button
8. Deploy/demo if ready

### Incremental Delivery

1. Setup + Foundational  Foundation ready
2. Add US1, US2, US3 + minimal UI  MVP Demo (create, switch, secure)
3. Add US4, US5, US6 + enhanced UI  v0.2 (manage, repos, tray)
4. Add US7, US8 + polish  v1.0 (import/export, validation)
5. Each story adds value without breaking previous stories

---

## Summary

| Phase | Task Range | Count | Purpose |
|-------|-----------|-------|---------|
| 1. Setup | T001-T007 | 7 | Project structure |
| 2. Foundational | T008-T030 | 23 | Core infrastructure |
| 3. US1 Create Profile | T031-T039 | 9 | Profile CRUD |
| 4. US2 Switch Profile | T040-T053 | 14 | Profile switching |
| 5. US3 Secure Access | T054-T060 | 7 | Security layer |
| 6. US4 Manage Profiles | T061-T064 | 4 | Edit/delete |
| 7. US5 Repository Config | T065-T070 | 6 | Per-repo profiles |
| 8. US6 System Tray | T071-T075 | 5 | Quick access |
| 9. US7 Import/Export | T076-T081 | 6 | Backup/restore |
| 10. US8 Validation | T082-T085 | 4 | Credential validation |
| 11. UI Layer | T086-T106 | 21 | DearPyGui interface |
| 12. Polish | T107-T119 | 13 | Quality & packaging |
| **Total** | | **119** | |

**Parallel Opportunities**: 47 tasks marked [P]
**MVP Scope**: Phases 1-5 (60 tasks) for core functionality
**Suggested First Demo**: After T060 (Secure Access complete)

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story is independently completable and testable
- Verify tests fail before implementing (TDD per constitution)
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Security-critical code (crypto.py, session.py) requires human review before merge
