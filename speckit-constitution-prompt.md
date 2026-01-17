# Constitution Prompt for Git Profile Switcher

Use this prompt with the `/speckit.constitution` command to establish the foundational principles for the Git Profile Switcher project.

---

## Prompt

```
/speckit.constitution

Create a comprehensive project constitution for Git Profile Switcher, a Windows desktop application that enables developers to seamlessly switch between multiple Git/GitHub user profiles. The application manages Git configurations, SSH keys, GPG signing keys, and Windows Credential Manager entries through a modern, GPU-accelerated GUI built with DearPyGui.

The constitution MUST establish the following non-negotiable principles organized by priority:

---

### SECURITY (Highest Priority)

Security is paramount because this application handles highly sensitive cryptographic credentials (SSH private keys, GPG private keys, passphrases). Establish principles that:

1. **Encryption at Rest**: All sensitive data (SSH keys, GPG keys, passphrases) MUST be encrypted using AES-256-GCM with keys derived via PBKDF2-HMAC-SHA256 (minimum 100,000 iterations). No plaintext secrets shall ever touch the filesystem.

2. **Memory Safety**: Decrypted secrets MUST be cleared from memory immediately after use. Use secure memory handling patterns to prevent secrets from lingering in memory or being swapped to disk.

3. **Master Password Architecture**: Implement a master password system where the password itself is never stored—only a verification hash. The derived encryption key exists only in memory during an unlocked session.

4. **Defense in Depth**: Assume every layer can fail. Validate inputs at every boundary. Never trust data from external sources (files, clipboard, system APIs) without validation.

5. **Audit Trail**: Log security-relevant events (unlock attempts, profile switches, export operations) without logging actual secret values. Use [REDACTED] placeholders.

6. **Fail Secure**: When errors occur in security-critical paths, fail closed (deny access) rather than fail open. Never expose secrets in error messages or stack traces.

---

### TEST-DRIVEN DEVELOPMENT (TDD)

This project MUST follow strict TDD practices to ensure reliability when handling critical credentials. Establish principles that:

1. **Red-Green-Refactor Cycle**: For all business logic, write a failing test first, then write the minimum code to pass, then refactor. No production code without a corresponding test.

2. **Coverage Requirements**: 
   - Core layer (encryption, profile management, validation): 95% minimum
   - Services layer (Git, SSH, GPG, Credential operations): 85% minimum  
   - Models: 100% coverage
   - UI layer: Manual testing acceptable, smoke tests encouraged

3. **Test Isolation**: Unit tests MUST be isolated from external systems. Use mocks/stubs for Git, SSH agent, GPG keyring, and Windows Credential Manager. Integration tests may use real systems but must clean up after themselves.

4. **Test Naming Convention**: Test names MUST clearly describe the scenario and expected outcome using the pattern: `test_<method>_<scenario>_<expected_result>`. Example: `test_decrypt_profile_with_wrong_password_raises_authentication_error`

5. **Regression Prevention**: Every bug fix MUST include a regression test that fails without the fix and passes with it.

6. **Security Test Suite**: Maintain a dedicated security test suite that verifies encryption correctness, validates no plaintext leakage, and tests authentication edge cases.

---

### CODE MAINTAINABILITY

The codebase must remain maintainable by humans and AI agents alike. Establish principles that:

1. **Single Responsibility Principle**: Every module, class, and function MUST have exactly one reason to change. Split responsibilities ruthlessly.

2. **Layered Architecture (Strict Enforcement)**:
   - UI Layer → May only call Core Layer
   - Core Layer → May only call Services Layer  
   - Services Layer → May only call Models and external libraries
   - Violations of layer boundaries are blocking issues

3. **Dependency Injection**: All external dependencies (file system, system APIs, services) MUST be injected, never instantiated directly. This enables testing and future flexibility.

4. **Type Safety**: Use Python type hints on ALL function signatures and class attributes. Run mypy in strict mode. Type errors are blocking issues.

5. **Explicit Over Implicit**: Avoid magic. No dynamic attribute access, no implicit type coercion, no clever tricks. Code should read like documentation.

6. **Documentation as Code**: Docstrings are mandatory for all public classes and methods. Use Google-style docstrings with Args, Returns, Raises sections.

7. **Minimal Dependencies**: Every external dependency must justify its inclusion. Prefer standard library solutions. New dependencies require explicit approval.

8. **Consistent Patterns**: Establish patterns early and enforce them. All services follow the same interface pattern. All models use dataclasses. All errors use custom exception hierarchies.

---

### GUI DESIGN & PRESENTATION

The user interface must embody an ultra-modern, high-tech aesthetic while remaining intuitive and accessible. Establish principles that:

1. **Visual Identity**: Dark theme with electric blue/cyan accent colors. GPU-accelerated rendering via DearPyGui. Subtle glow effects on interactive elements. Monospace fonts for technical data display.

2. **Information Hierarchy**: Current profile status MUST be immediately visible at all times. Critical information (username, email, organization) displayed prominently. Secondary information accessible but not cluttering.

3. **Feedback & Responsiveness**: 
   - All user actions must provide immediate visual feedback
   - Long operations (>500ms) must show progress indicators
   - Success/failure states must be clearly distinguishable
   - System tray notifications for background events

4. **Error Presentation**: Never show raw exceptions or technical errors to users. Translate all errors to user-friendly messages with suggested remediation steps.

5. **Accessibility Considerations**: Keyboard navigation for all primary functions. Sufficient contrast ratios. No information conveyed by color alone. Screen reader compatibility where DearPyGui supports it.

6. **Consistent Interaction Patterns**: 
   - Single-click for selection, double-click for primary action
   - Right-click for context menus
   - Escape to cancel/close
   - Enter to confirm
   - Consistent button placement (Confirm right, Cancel left)

7. **State Persistence**: Remember window position, size, and UI state between sessions. Restore user's last view on launch.

---

### DOCUMENTATION

Documentation is a first-class deliverable, not an afterthought. Establish principles that:

1. **Living Documentation**: Documentation MUST be updated in the same commit as code changes. Stale documentation is a blocking issue.

2. **Multiple Audiences**: Maintain separate documentation for:
   - End users (USER_GUIDE.md) - How to use the application
   - Developers (DEVELOPMENT.md, ARCHITECTURE.md) - How to build and extend
   - AI Agents (AGENTS.md) - Guardrails and constraints
   - Contributors (CONTRIBUTING.md) - How to submit changes

3. **Spec-Driven Development**: Feature specifications in `specs/` directory are the source of truth. Code implements specs, not the other way around. Specs are versioned and reviewed.

4. **Inline Documentation**: 
   - Complex algorithms require explanatory comments
   - Non-obvious decisions require "why" comments
   - Public APIs require complete docstrings
   - Security-critical code requires detailed documentation

5. **Changelog Discipline**: CHANGELOG.md follows Keep a Changelog format. Every user-visible change must be logged. Breaking changes must be prominently marked.

6. **Diagrams Over Prose**: Use Mermaid diagrams for architecture, workflows, and state machines. Visual documentation is easier to maintain and understand.

---

### WINDOWS PLATFORM INTEGRATION

This is a Windows-native application. Establish principles that:

1. **Native Services Only**: Use Windows OpenSSH ssh-agent (not Pageant, not third-party). Use Windows Credential Manager via keyring. Use Windows Toast Notifications.

2. **Portable Execution**: Single .exe file, no installation required, no admin privileges for normal operation. User data in %APPDATA%/GitProfileSwitcher.

3. **Graceful Degradation**: If Git is not installed, show helpful error—don't crash. If GPG is not installed, disable GPG features—don't block the app. If ssh-agent isn't running, offer to start it.

4. **System Tray Integration**: Minimize to tray, quick profile switching from tray menu, optional auto-start with Windows.

---

### DEVELOPMENT WORKFLOW

Establish principles for how development proceeds:

1. **Spec-Driven Development**: Follow the /speckit.specify → /speckit.plan → /speckit.tasks → /speckit.implement workflow. No implementation without specification. No specification changes without review.

2. **Atomic Commits**: One logical change per commit. Each commit must leave the codebase in a working state. Each completed task gets its own commit.

3. **Commit Message Format**: `<type>(<scope>): <description>` where type is feat/fix/refactor/test/docs/style/chore. Scope is the module or feature area.

4. **Branch Strategy**: Feature branches named `{type}/{###}-{short-description}`. Main branch always deployable. No direct commits to main.

5. **Human Approval Gates**: Constitution changes, security changes, architecture changes, and technology substitutions require explicit human approval.

---

Synthesize these principles into a cohesive constitution document that AI agents will reference before every implementation decision. The constitution should be the single source of truth for "how we build software" in this project.
```

---

## Usage Instructions

1. Initialize your project with Spec Kit:
   ```bash
   specify init GitProfileSwitcher --ai claude
   ```

2. Open your AI coding agent (Claude Code, Cursor, etc.)

3. Run the `/speckit.constitution` command with the prompt above

4. Review the generated `constitution.md` in `.specify/memory/`

5. Iterate and refine as needed before proceeding to `/speckit.specify`

---

## Expected Output Structure

The constitution command should generate a `constitution.md` file with approximately this structure:

```markdown
# Project Constitution: Git Profile Switcher

## Preamble
[Project purpose and scope]

## Article I: Security Principles
[Security requirements as non-negotiable rules]

## Article II: Test-Driven Development
[TDD practices and coverage requirements]

## Article III: Code Architecture & Maintainability  
[Layered architecture, patterns, type safety]

## Article IV: User Interface Standards
[GUI design principles, visual identity, UX patterns]

## Article V: Documentation Requirements
[Documentation standards and update policies]

## Article VI: Platform Integration
[Windows-specific requirements and constraints]

## Article VII: Development Workflow
[Spec-driven process, commits, approvals]

## Article VIII: Technology Decisions
[Locked technology choices with rationale]

## Article IX: Governance
[How to amend the constitution, approval requirements]

## Appendix A: Quality Gates
[Pre-commit, pre-merge, release checklists]

## Appendix B: Prohibited Practices
[Explicit list of what is forbidden]
```

---

## Notes for AI Agents

When processing this constitution prompt:

1. **Preserve all quantitative requirements** (coverage percentages, iteration counts, etc.)
2. **Maintain the priority ordering** (Security > TDD > Maintainability > GUI > Docs)
3. **Include concrete examples** where the prompt provides them
4. **Cross-reference between sections** where principles interact
5. **Format for quick scanning** with clear headers and bullet points
6. **Include "MUST", "SHALL", "MUST NOT"** language for non-negotiable items
