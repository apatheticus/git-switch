# Feature Specification: Git-Switch Profile Manager

**Feature Branch**: `001-git-profile-switcher`
**Created**: 2026-01-17
**Status**: Draft
**Input**: User description: "Build a Python-based application for managing Git user profiles based on the Product Requirements Document at `ref/design/git-profile-switcher-prd.md`. For the GUI design reference the `ref/design/Git-Switch-DearPyGui-PSEUDOCODE.txt` along with the mockup image at `ref/design/Git-Switch-mockup-02.png`."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Create and Store Git Profile (Priority: P1)

A developer with multiple GitHub accounts needs to create a profile that stores their Git identity (username, email) along with the associated SSH key and optional GPG signing key. This is the foundational capability that all other features depend on.

**Why this priority**: Without the ability to create and securely store profiles, no other functionality is possible. This is the core value proposition of the application.

**Independent Test**: Can be fully tested by launching the application, entering master password, creating a new profile with Git credentials and SSH key, and verifying the profile appears in the list and persists after restart.

**Acceptance Scenarios**:

1. **Given** the application is unlocked, **When** the user clicks "New Profile" and fills in profile name, Git username, email, and selects an SSH private key file, **Then** the profile is created and appears in the profile list with the correct details displayed.
2. **Given** the user is creating a profile with a passphrase-protected SSH key, **When** they provide the passphrase, **Then** the system validates the passphrase unlocks the key and stores it securely.
3. **Given** the user enables GPG signing for a profile, **When** they provide the GPG key ID and import the private key, **Then** the GPG key is associated with the profile.
4. **Given** the user attempts to save a profile without required fields (name, username, email, SSH key), **When** they click Save, **Then** validation errors are displayed indicating which fields are missing.

---

### User Story 2 - Switch Git Profile Globally (Priority: P1)

A developer switching between projects for different organizations needs to quickly apply a different Git profile globally so all Git operations use the new identity.

**Why this priority**: Profile switching is the primary purpose of the application. Without this, stored profiles have no practical use.

**Independent Test**: Can be fully tested by having two profiles, switching from one to another, then running `git config --global user.name` and `git config --global user.email` to verify the change, and testing SSH authentication with `ssh -T git@github.com`.

**Acceptance Scenarios**:

1. **Given** the user has multiple profiles stored, **When** they select a profile and click "Apply Global", **Then** the Git global configuration is updated with the profile's username and email.
2. **Given** the user applies a profile globally, **When** the switch completes, **Then** the Windows Credential Manager's cached GitHub credentials are cleared.
3. **Given** the user applies a profile globally, **When** the switch completes, **Then** only the selected profile's SSH key is loaded in the ssh-agent.
4. **Given** the profile has GPG signing enabled, **When** applied globally, **Then** Git global configuration is updated to enable commit signing with the profile's GPG key.
5. **Given** a profile switch completes successfully, **When** the operation finishes, **Then** a system notification appears confirming the switch and the UI updates to show the new active profile.

---

### User Story 3 - Secure Application Access (Priority: P1)

A developer needs their stored SSH keys and profile data protected by a master password so unauthorized users cannot access their Git credentials.

**Why this priority**: Security is fundamental. Without encrypted storage and access control, users would not trust the application with their sensitive keys.

**Independent Test**: Can be fully tested by setting a master password on first launch, closing and reopening the application, verifying the password prompt appears, entering wrong password (verify rejection), then entering correct password (verify access granted).

**Acceptance Scenarios**:

1. **Given** the application is launched for the first time, **When** no master password exists, **Then** the user is prompted to create a master password.
2. **Given** the application is launched after initial setup, **When** the user enters the correct master password, **Then** the application unlocks and displays the profile list.
3. **Given** the user enters an incorrect master password, **When** they attempt to unlock, **Then** an error message is displayed and the application remains locked.
4. **Given** the application is unlocked and idle for 15 minutes (configurable), **When** the timeout occurs, **Then** the application automatically locks and clears the encryption key from memory.
5. **Given** the application is unlocked, **When** the user clicks the Lock button, **Then** the application immediately locks.

---

### User Story 4 - Manage Profiles (Priority: P2)

A developer needs to edit existing profiles (update email, replace SSH key) or delete profiles that are no longer needed.

**Why this priority**: Profile management is essential for long-term use but not critical for initial value delivery.

**Independent Test**: Can be fully tested by editing an existing profile's email, verifying the change persists, then deleting a profile and verifying it no longer appears.

**Acceptance Scenarios**:

1. **Given** the user has an existing profile, **When** they click the edit button and modify the email, **Then** the profile is updated with the new email.
2. **Given** the user wants to replace an SSH key, **When** they browse and select a new key file in the edit dialog, **Then** the old key is replaced with the new one.
3. **Given** the user clicks delete on a profile, **When** they confirm the deletion, **Then** the profile is permanently removed from storage.
4. **Given** the user attempts to delete the currently active profile, **When** they confirm deletion, **Then** the profile is deleted and no profile is marked as active.

---

### User Story 5 - Apply Profile to Specific Repository (Priority: P2)

A developer working on multiple projects needs to apply different profiles to specific repositories so each repository uses the correct identity locally.

**Why this priority**: Local repository configuration enables fine-grained control but global switching covers most use cases.

**Independent Test**: Can be fully tested by registering a repository, assigning a profile, applying locally, then verifying `.git/config` contains the correct user.name and user.email.

**Acceptance Scenarios**:

1. **Given** the user navigates to the Repositories view, **When** they click "Add Repository" and select a folder containing a `.git` directory, **Then** the repository is registered and appears in the list.
2. **Given** a repository is registered, **When** the user assigns a profile from the dropdown, **Then** the assignment is saved and displayed.
3. **Given** a repository has an assigned profile, **When** the user clicks "Apply Local", **Then** the repository's `.git/config` is updated with the profile's username and email.
4. **Given** the user applies a profile locally to a repository, **When** they apply a different profile globally afterward, **Then** the repository retains its local configuration.

---

### User Story 6 - System Tray Quick Access (Priority: P2)

A developer needs to quickly switch profiles without opening the main application window by using the system tray icon.

**Why this priority**: Convenience feature that improves workflow but not essential for core functionality.

**Independent Test**: Can be fully tested by minimizing the application to tray, right-clicking the tray icon, selecting a different profile, and verifying the switch occurs.

**Acceptance Scenarios**:

1. **Given** the application is running, **When** the user minimizes or closes the window, **Then** the application continues running with an icon in the system tray.
2. **Given** the tray icon is visible, **When** the user right-clicks it, **Then** a context menu appears showing all profiles with the active one checked.
3. **Given** the tray context menu is open, **When** the user clicks a different profile, **Then** that profile is applied globally and a notification confirms the switch.
4. **Given** the tray context menu is open, **When** the user clicks "Open Application", **Then** the main window is shown and brought to focus.

---

### User Story 7 - Import/Export Profiles (Priority: P3)

A developer needs to back up their profiles or transfer them to another machine by exporting and importing encrypted archives.

**Why this priority**: Backup and migration are valuable but secondary to daily profile switching workflow.

**Independent Test**: Can be fully tested by exporting profiles to a .gps file, deleting all profiles, importing the archive, and verifying profiles are restored.

**Acceptance Scenarios**:

1. **Given** the user has profiles stored, **When** they click Export and provide an export password, **Then** an encrypted `.gps` file is created containing all profiles, SSH keys, GPG keys, and repository assignments.
2. **Given** the user has a `.gps` archive, **When** they click Import and enter the correct archive password, **Then** they are prompted to choose Merge or Replace.
3. **Given** the user chooses Merge during import, **When** duplicate profile names exist, **Then** they are prompted to resolve conflicts (rename, skip, or overwrite).
4. **Given** the user chooses Replace during import, **When** the import completes, **Then** all existing profiles are replaced with the imported ones.

---

### User Story 8 - Validate Profile Credentials (Priority: P3)

A developer needs to verify that their SSH key and GPG key are valid and properly configured before using a profile.

**Why this priority**: Validation helps prevent errors but profiles can still function without explicit validation.

**Independent Test**: Can be fully tested by creating a profile with a valid SSH key, clicking Validate, and verifying the SSH connection test passes.

**Acceptance Scenarios**:

1. **Given** the user is creating or editing a profile, **When** they click "Validate Credentials", **Then** the system tests SSH connectivity to GitHub.
2. **Given** the SSH key is valid and matches a GitHub account, **When** validation runs, **Then** a success indicator is displayed.
3. **Given** the SSH key is invalid or passphrase is incorrect, **When** validation runs, **Then** a clear error message explains the problem.
4. **Given** GPG signing is enabled, **When** validation runs, **Then** the GPG key is verified as capable of signing.

---

### Edge Cases

- What happens when Git is not installed on the system?
  - Application displays an error at startup with a link to Git installation instructions.
- What happens when the SSH agent service is not running?
  - Application prompts user with option to start the service automatically.
- What happens when the user's SSH key requires a passphrase but they didn't provide one?
  - Profile save fails with a clear error: "SSH key requires passphrase. Please enter the key passphrase."
- What happens when the Windows Credential Manager access is denied?
  - Switch continues but warns user that cached credentials could not be cleared.
- What happens when profile data file becomes corrupted?
  - Application offers to restore from backup or delete corrupted profiles.
- What happens when user forgets master password?
  - Application cannot recover data. User must delete profile storage and start fresh (documented in help).
- What happens when applying local config to a folder that is not a Git repository?
  - Error displayed: "Selected folder is not a Git repository."

## Requirements *(mandatory)*

### Functional Requirements

**Profile Management**
- **FR-001**: System MUST allow users to create profiles containing: profile name, Git username, Git email, SSH private key, SSH public key, and optional organization name.
- **FR-002**: System MUST allow users to optionally add GPG signing configuration (key ID, private key, public key) to a profile.
- **FR-003**: System MUST allow users to edit all fields of an existing profile.
- **FR-004**: System MUST allow users to delete profiles with confirmation.
- **FR-005**: System MUST display all profiles in a list/card view showing name, email, organization, and active status.

**Profile Switching**
- **FR-006**: System MUST update Git global configuration (user.name, user.email) when applying a profile globally.
- **FR-007**: System MUST clear Windows Credential Manager cached Git/GitHub credentials when switching profiles.
- **FR-008**: System MUST remove all SSH keys from ssh-agent and add only the selected profile's SSH key when switching.
- **FR-009**: System MUST update GPG signing configuration in Git global config when profile has GPG enabled.
- **FR-010**: System MUST support applying a profile to a specific repository's local Git configuration.
- **FR-011**: System MUST display the currently active profile prominently in the header area.

**Security**
- **FR-012**: System MUST require a master password to access stored profile data.
- **FR-013**: System MUST encrypt all sensitive data (SSH keys, GPG keys, passphrases) using AES-256 encryption.
- **FR-014**: System MUST derive encryption key from master password using PBKDF2 with minimum 100,000 iterations.
- **FR-015**: System MUST automatically lock after configurable idle timeout (default 15 minutes).
- **FR-016**: System MUST clear encryption key from memory when locked.
- **FR-017**: System MUST never store sensitive data in plaintext.

**Repository Management**
- **FR-018**: System MUST allow users to register Git repositories by selecting folders containing `.git` directories.
- **FR-019**: System MUST allow users to assign a default profile to each registered repository.
- **FR-020**: System MUST allow users to apply assigned profiles as local Git configuration.
- **FR-021**: System MUST allow users to remove repositories from the registry without affecting the actual repository.

**Import/Export**
- **FR-022**: System MUST allow exporting all profiles to an encrypted archive file (.gps format).
- **FR-023**: System MUST allow importing profiles from encrypted archive files.
- **FR-024**: System MUST prompt for merge or replace strategy when importing.
- **FR-025**: System MUST handle profile name conflicts during merge import.

**User Interface**
- **FR-026**: System MUST provide a modern, dark-themed graphical interface with cyan/electric blue accent colors.
- **FR-027**: System MUST display a system tray icon when running.
- **FR-028**: System MUST provide a system tray context menu for quick profile switching.
- **FR-029**: System MUST display Windows notifications for profile switch events.
- **FR-030**: System MUST include navigation sidebar with sections: Profiles, Repositories, Settings, Import/Export.
- **FR-031**: System MUST display status indicators for SSH connectivity and GPG availability in the footer.

**Settings**
- **FR-032**: System MUST allow configuration of: start with Windows, start minimized, auto-lock timeout, notification preferences, confirmation before switch.

**Validation**
- **FR-033**: System MUST validate SSH key format and passphrase (if protected) when creating/editing profiles.
- **FR-034**: System MUST provide optional SSH connectivity test to GitHub.
- **FR-035**: System MUST validate GPG key can be imported and is capable of signing (when GPG is enabled).

**Deployment**
- **FR-036**: System MUST be deployable as a single portable executable file requiring no installation.
- **FR-037**: System MUST create application data directory on first run for storing encrypted profile data.

### Key Entities

- **Profile**: A saved Git identity configuration including unique ID, display name, Git username, Git email, optional organization, SSH key pair (encrypted), optional SSH passphrase (encrypted), GPG configuration (enabled flag, key ID, key pair), creation timestamp, and last-used timestamp.
- **Repository**: A registered Git repository path with display name (derived from folder), assigned profile ID, and local-config preference flag.
- **Settings**: Application configuration including startup behavior, security timeouts, and user preferences.
- **Master Key**: Derived encryption key (not stored) used to encrypt/decrypt profile data during a session.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Users can complete a profile switch in under 5 seconds from selecting the profile to confirmation notification.
- **SC-002**: Profile switch achievable in 3 or fewer clicks from the main profile list view.
- **SC-003**: Profile switch achievable in 2 clicks from the system tray context menu.
- **SC-004**: Users can create a new profile in under 3 minutes including SSH key selection.
- **SC-005**: Application starts and displays unlock prompt within 3 seconds.
- **SC-006**: 100% of profile data remains encrypted at rest (verified by inspecting storage files).
- **SC-007**: Application runs as a single portable file requiring no installation.
- **SC-008**: Users can successfully import/export profiles between machines without data loss.
- **SC-009**: After profile switch, Git global configuration contains the selected profile's username and email values.
- **SC-010**: After profile switch, SSH authentication to GitHub uses the selected profile's identity.

## Assumptions

- Users have Git installed and available in their system PATH.
- Users have Windows OpenSSH client enabled (standard on Windows 10/11).
- Users have existing SSH keys they want to use (or know how to generate them).
- GPG functionality requires users to have GnuPG installed separately if they want commit signing.
- Users are comfortable with the concept of Git profiles and understand why switching identities is necessary.
- The application will be used on Windows 10 or Windows 11 (64-bit).
- Users have at least basic familiarity with Git operations.

## Dependencies

- Windows OpenSSH client and ssh-agent service availability.
- Windows Credential Manager accessibility.
- Git installation on the target system.
- Optional: GnuPG installation for GPG signing features.
- Display with GPU supporting OpenGL 3.3+ for the GUI framework.

## Out of Scope

- Linux or macOS support (Windows-only for this version).
- GitHub API integration for repository management or account verification.
- Automatic profile detection based on repository remote URL.
- Multi-user support on a single Windows installation.
- Command-line interface (GUI only for this version).
- Light theme option (dark theme only for this version).
- Biometric authentication (Windows Hello integration).
