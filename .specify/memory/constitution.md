<!--
================================================================================
SYNC IMPACT REPORT
================================================================================
Version Change: 0.0.0 → 1.0.0 (MAJOR - Initial constitution establishment)

Modified Principles: N/A (Initial creation)

Added Sections:
  - I. Security (Highest Priority) - Cryptographic credential protection
  - II. Test-Driven Development - TDD enforcement with coverage requirements
  - III. Code Maintainability - Architecture and design patterns
  - IV. GUI Design & Presentation - Visual identity and interaction standards
  - V. Documentation - Living documentation requirements
  - VI. Windows Platform Integration - Native Windows service constraints
  - VII. Development Workflow - Spec-driven process enforcement
  - Governance - Amendment procedures and compliance rules

Removed Sections: N/A (Initial creation)

Templates Requiring Updates:
  - .specify/templates/plan-template.md: ✅ Compatible (Constitution Check section exists)
  - .specify/templates/spec-template.md: ✅ Compatible (Requirements section supports FR- patterns)
  - .specify/templates/tasks-template.md: ✅ Compatible (Test-first phases supported)
  - .specify/templates/checklist-template.md: ⚠ Review recommended for security checklist items
  - .specify/templates/agent-file-template.md: ⚠ Review recommended for AI agent constraints

Follow-up TODOs:
  - TODO(AGENTS.md): Create AI agent guidance document per Documentation principle
  - TODO(ARCHITECTURE.md): Create architecture diagram document
  - TODO(DEVELOPMENT.md): Create developer setup guide
  - TODO(USER_GUIDE.md): Create end-user documentation
  - TODO(CONTRIBUTING.md): Create contributor guidelines
================================================================================
-->

# Git Profile Switcher Constitution

## Preamble

This constitution establishes the non-negotiable principles, constraints, and governance
rules for the Git Profile Switcher project. It serves as the single source of truth for
"how we build software" in this project.

**Project Summary**: Git Profile Switcher is a Windows desktop application that enables
developers to seamlessly switch between multiple Git/GitHub user profiles. The application
manages Git configurations, SSH keys, GPG signing keys, and Windows Credential Manager
entries through a modern, GPU-accelerated GUI built with DearPyGui.

All contributors—human and AI agents alike—MUST consult this constitution before every
implementation decision. Violations are blocking issues that require remediation before
merge.

---

## Core Principles

### I. Security (Highest Priority)

Security is paramount because this application handles highly sensitive cryptographic
credentials (SSH private keys, GPG private keys, passphrases). A breach would compromise
users' code signing identity and repository access.

**Non-Negotiable Rules**:

1. **Encryption at Rest**: All sensitive data (SSH keys, GPG keys, passphrases) MUST be
   encrypted using AES-256-GCM with keys derived via PBKDF2-HMAC-SHA256 (minimum 100,000
   iterations). No plaintext secrets shall ever touch the filesystem.

2. **Memory Safety**: Decrypted secrets MUST be cleared from memory immediately after use.
   Use secure memory handling patterns (e.g., `SecureString`, zeroing buffers) to prevent
   secrets from lingering in memory or being swapped to disk.

3. **Master Password Architecture**: Implement a master password system where the password
   itself is never stored—only a verification hash. The derived encryption key exists only
   in memory during an unlocked session. Session timeout MUST clear the key.

4. **Defense in Depth**: Assume every layer can fail. Validate inputs at every boundary.
   Never trust data from external sources (files, clipboard, system APIs) without validation.
   Apply the principle of least privilege throughout.

5. **Audit Trail**: Log security-relevant events (unlock attempts, profile switches, export
   operations) without logging actual secret values. Use `[REDACTED]` placeholders for any
   sensitive data in logs.

6. **Fail Secure**: When errors occur in security-critical paths, fail closed (deny access)
   rather than fail open. Never expose secrets in error messages, stack traces, or crash
   reports.

**Rationale**: Users trust this application with their developer identity. Compromise of
SSH/GPG keys can lead to malicious commits, unauthorized repository access, and identity
theft in the developer ecosystem.

---

### II. Test-Driven Development (TDD)

This project MUST follow strict TDD practices to ensure reliability when handling critical
credentials. Untested code paths in security-critical applications are unacceptable risks.

**Non-Negotiable Rules**:

1. **Red-Green-Refactor Cycle**: For all business logic, write a failing test first, then
   write the minimum code to pass, then refactor. No production code without a corresponding
   test. Commits that add untested business logic are blocking issues.

2. **Coverage Requirements**:
   - Core layer (encryption, profile management, validation): **95% minimum**
   - Services layer (Git, SSH, GPG, Credential operations): **85% minimum**
   - Models: **100% coverage**
   - UI layer: Manual testing acceptable, smoke tests encouraged

3. **Test Isolation**: Unit tests MUST be isolated from external systems. Use mocks/stubs
   for Git, SSH agent, GPG keyring, and Windows Credential Manager. Integration tests may
   use real systems but MUST clean up after themselves.

4. **Test Naming Convention**: Test names MUST clearly describe the scenario and expected
   outcome using the pattern: `test_<method>_<scenario>_<expected_result>`.
   Example: `test_decrypt_profile_with_wrong_password_raises_authentication_error`

5. **Regression Prevention**: Every bug fix MUST include a regression test that fails
   without the fix and passes with it. No bug fix PR merges without its regression test.

6. **Security Test Suite**: Maintain a dedicated security test suite (`tests/security/`)
   that verifies encryption correctness, validates no plaintext leakage, and tests
   authentication edge cases.

**Rationale**: Given the security-critical nature of credential management, we cannot afford
untested code paths. TDD provides confidence that security invariants are maintained.

---

### III. Code Maintainability

The codebase must remain maintainable by humans and AI agents alike. Clever code is not
valued; clear code is.

**Non-Negotiable Rules**:

1. **Single Responsibility Principle**: Every module, class, and function MUST have exactly
   one reason to change. Split responsibilities ruthlessly. A class handling both encryption
   AND file I/O violates this principle.

2. **Layered Architecture (Strict Enforcement)**:
   ```
   UI Layer      → May ONLY call Core Layer
   Core Layer    → May ONLY call Services Layer
   Services Layer → May ONLY call Models and external libraries
   ```
   Violations of layer boundaries are blocking issues. No shortcuts.

3. **Dependency Injection**: All external dependencies (file system, system APIs, services)
   MUST be injected, never instantiated directly within business logic. This enables testing
   and future flexibility.

4. **Type Safety**: Use Python type hints on ALL function signatures and class attributes.
   Run mypy in strict mode (`--strict`). Type errors are blocking issues.

5. **Explicit Over Implicit**: Avoid magic. No dynamic attribute access (`getattr`), no
   implicit type coercion, no clever metaprogramming tricks. Code should read like
   documentation.

6. **Documentation as Code**: Google-style docstrings are mandatory for all public classes
   and methods. Docstrings MUST include `Args`, `Returns`, `Raises` sections where applicable.

7. **Minimal Dependencies**: Every external dependency must justify its inclusion in
   `requirements.txt` with a comment. Prefer standard library solutions. New dependencies
   require explicit human approval.

8. **Consistent Patterns**: Establish patterns early and enforce them project-wide:
   - All services follow the same interface pattern (Protocol classes)
   - All models use `@dataclass` decorators
   - All errors use custom exception hierarchies inheriting from `GitSwitchError`

**Rationale**: Maintainability directly impacts our ability to respond to security issues
quickly and confidently.

---

### IV. GUI Design & Presentation

The user interface must embody an ultra-modern, high-tech aesthetic while remaining
intuitive and accessible. Form follows function, but form matters.

**Non-Negotiable Rules**:

1. **Visual Identity**:
   - Dark theme with electric blue (#00D4FF) and cyan (#00FFFF) accent colors
   - GPU-accelerated rendering via DearPyGui
   - Subtle glow effects on interactive elements (hover states, focus indicators)
   - Monospace fonts (JetBrains Mono, Fira Code, or Consolas) for technical data display
   - Sans-serif fonts (Inter, Segoe UI) for labels and descriptions

2. **Information Hierarchy**: Current profile status MUST be immediately visible at all
   times (header bar or persistent sidebar). Critical information (username, email,
   organization) displayed prominently. Secondary information (SSH key fingerprint, GPG key
   ID) accessible but not cluttering the primary view.

3. **Feedback & Responsiveness**:
   - All user actions MUST provide immediate visual feedback (<100ms)
   - Long operations (>500ms) MUST show progress indicators with cancel option
   - Success/failure states MUST be clearly distinguishable (color + icon + text)
   - System tray notifications for background events (profile switched, session locked)

4. **Error Presentation**: Never show raw exceptions or technical errors to users. Translate
   all errors to user-friendly messages with suggested remediation steps. Log technical
   details for debugging.

5. **Accessibility Considerations**:
   - Keyboard navigation for all primary functions (Tab, Enter, Escape, Arrow keys)
   - Sufficient contrast ratios (WCAG AA minimum: 4.5:1 for text)
   - No information conveyed by color alone (always pair with icons/text)
   - Screen reader compatibility where DearPyGui supports it

6. **Consistent Interaction Patterns**:
   - Single-click for selection, double-click for primary action
   - Right-click for context menus
   - Escape to cancel/close modals
   - Enter to confirm
   - Consistent button placement: Confirm/Primary on right, Cancel/Secondary on left

7. **State Persistence**: Remember window position, size, and UI state between sessions.
   Restore user's last view on launch. Persist to `%APPDATA%/GitProfileSwitcher/ui_state.json`.

**Rationale**: A polished UI builds trust—essential for an application handling security
credentials. Poor UX leads to user errors, which in credential management can be costly.

---

### V. Documentation

Documentation is a first-class deliverable, not an afterthought. Undocumented features are
incomplete features.

**Non-Negotiable Rules**:

1. **Living Documentation**: Documentation MUST be updated in the same commit as code
   changes. Stale documentation is a blocking issue. PRs that change behavior without
   updating docs are rejected.

2. **Multiple Audiences**: Maintain separate documentation for:
   - End users: `USER_GUIDE.md` - How to use the application
   - Developers: `DEVELOPMENT.md`, `ARCHITECTURE.md` - How to build and extend
   - AI Agents: `AGENTS.md` - Guardrails, constraints, and patterns for AI assistants
   - Contributors: `CONTRIBUTING.md` - How to submit changes, code style, PR process

3. **Spec-Driven Development**: Feature specifications in `specs/` directory are the source
   of truth. Code implements specs, not the other way around. Specs are versioned and
   reviewed before implementation begins.

4. **Inline Documentation**:
   - Complex algorithms require explanatory comments above the implementation
   - Non-obvious decisions require "why" comments (not "what")
   - Public APIs require complete docstrings with examples
   - Security-critical code requires detailed documentation explaining the threat model

5. **Changelog Discipline**: `CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/)
   format. Every user-visible change MUST be logged. Breaking changes MUST be prominently
   marked with `### BREAKING` sections.

6. **Diagrams Over Prose**: Use Mermaid diagrams for architecture, workflows, and state
   machines. Visual documentation is easier to maintain and understand than lengthy prose.

**Rationale**: Good documentation multiplies developer effectiveness and enables confident
contributions from both humans and AI agents.

---

### VI. Windows Platform Integration

This is a Windows-native application. Platform integration is not optional—it's a core
feature.

**Non-Negotiable Rules**:

1. **Native Services Only**:
   - SSH: Use Windows OpenSSH ssh-agent (not Pageant, not WSL, not third-party agents)
   - Credentials: Use Windows Credential Manager via `keyring` library
   - Notifications: Use Windows Toast Notifications via `win10toast` or similar
   - No Unix assumptions (paths, line endings, process management)

2. **Portable Execution**:
   - Single `.exe` file distribution via PyInstaller
   - No installation required, no admin privileges for normal operation
   - All user data stored in `%APPDATA%/GitProfileSwitcher/`
   - No registry modifications except optional auto-start entry

3. **Graceful Degradation**:
   - If Git is not installed: Show helpful error with download link—don't crash
   - If GPG is not installed: Disable GPG features gracefully—don't block the app
   - If ssh-agent isn't running: Offer to start it or show instructions
   - If Credential Manager is locked: Prompt user appropriately

4. **System Tray Integration**:
   - Minimize to system tray (not taskbar)
   - Quick profile switching from tray context menu
   - Optional auto-start with Windows (user preference)
   - Tray icon reflects current profile state

**Rationale**: Windows developers expect Windows-native behavior. Fighting the platform
creates friction and reduces trust.

---

### VII. Development Workflow

Establish principles for how development proceeds. Process discipline prevents security
and quality regressions.

**Non-Negotiable Rules**:

1. **Spec-Driven Development**: Follow the workflow:
   ```
   /speckit.specify → /speckit.plan → /speckit.tasks → /speckit.implement
   ```
   No implementation without specification. No specification changes without review.

2. **Atomic Commits**: One logical change per commit. Each commit MUST leave the codebase
   in a working state (tests pass, linting passes). Each completed task gets its own commit.

3. **Commit Message Format**: `<type>(<scope>): <description>`
   - Types: `feat`, `fix`, `refactor`, `test`, `docs`, `style`, `chore`, `security`
   - Scope: Module or feature area (e.g., `encryption`, `ssh-service`, `ui`)
   - Example: `feat(encryption): implement AES-256-GCM profile encryption`

4. **Branch Strategy**:
   - Feature branches: `{type}/{###}-{short-description}` (e.g., `feat/001-profile-encryption`)
   - Main branch always deployable
   - No direct commits to main—all changes via PR

5. **Human Approval Gates**: The following changes require explicit human approval:
   - Constitution amendments
   - Security-related changes (encryption, authentication, credential handling)
   - Architecture changes (new layers, service boundaries)
   - Technology substitutions (new dependencies, framework changes)
   - Any change marked `[NEEDS APPROVAL]` in specs

---

## Governance

### Amendment Procedure

1. **Proposal**: Amendments MUST be proposed via PR modifying this constitution file.
2. **Review**: All amendments require explicit human review and approval.
3. **Migration**: Breaking amendments MUST include a migration plan for existing code.
4. **Versioning**: Constitution version follows semantic versioning:
   - MAJOR: Backward-incompatible principle changes or removals
   - MINOR: New principles added or existing principles materially expanded
   - PATCH: Clarifications, typo fixes, non-semantic refinements

### Compliance Review

- All PRs MUST verify compliance with constitution principles in the PR description
- Security-critical PRs MUST explicitly reference Section I compliance
- Test coverage MUST be reported for all code-changing PRs
- Architecture violations are blocking—no exceptions

### Supersession

This constitution supersedes all informal practices, previous documentation, and
assumed conventions. When in doubt, the constitution governs.

### AI Agent Compliance

AI agents (Claude, Copilot, etc.) assisting with this project MUST:
1. Read this constitution before suggesting implementation approaches
2. Refuse to implement code that violates constitution principles
3. Flag potential violations to human reviewers
4. Reference constitution sections when justifying implementation decisions

---

**Version**: 1.0.0 | **Ratified**: 2026-01-17 | **Last Amended**: 2026-01-17
