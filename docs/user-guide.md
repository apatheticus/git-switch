# Git-Switch User Guide

This guide covers everything you need to know to use Git-Switch effectively.

## Table of Contents

- [Getting Started](#getting-started)
- [Profile Management](#profile-management)
- [Switching Profiles](#switching-profiles)
- [Repository Management](#repository-management)
- [Settings](#settings)
- [Import/Export](#importexport)
- [System Tray](#system-tray)
- [Keyboard Shortcuts](#keyboard-shortcuts)
- [Troubleshooting](#troubleshooting)

## Getting Started

### First Launch

When you first launch Git-Switch, you'll be prompted to create a master password.

**Important**: This password **cannot be recovered**. If you forget it, you must delete the data folder and start fresh, losing all stored profiles.

**Password Requirements**:

- Minimum 8 characters (12+ strongly recommended)
- Mix of uppercase, lowercase, numbers, and symbols recommended
- The password is never stored - only a verification hash

**What happens on first launch**:

1. You create and confirm your master password
2. A unique cryptographic salt is generated for your installation
3. Your password is used to derive an encryption key (PBKDF2, 100,000 iterations)
4. The application unlocks and you can start adding profiles

### Main Interface

The Git-Switch window is divided into four main areas:

**Header**:

- Shows the currently active profile (if any)
- Displays connection status indicator

**Sidebar** (left):

- **Profiles**: Manage your Git identities
- **Repositories**: Register and assign repos
- **Settings**: Application preferences
- **Import/Export**: Backup and restore

**Content Area** (center):

- Displays the currently selected view
- Changes based on sidebar selection

**Footer**:

- SSH agent status indicator
- GPG availability indicator
- Current scope (Global/Local)
- Lock button

## Profile Management

### Creating a Profile

1. Click **"Profiles"** in the sidebar
2. Click **"New Profile"** button
3. Fill in the profile details:

| Field | Required | Description |
|-------|----------|-------------|
| Profile Name | Yes | Display name (e.g., "Work", "Personal") |
| Git Username | Yes | Value for `git config user.name` |
| Git Email | Yes | Value for `git config user.email` |
| Organization | No | Company or organization name |

4. **Import SSH Key**:
   - Click **"Browse"** to select your private key file
   - Or paste the key content directly into the text area
   - If your key has a passphrase, enter it in the passphrase field

5. **(Optional) Enable GPG Signing**:
   - Check **"Enable GPG Signing"**
   - Enter your GPG Key ID (last 16 characters of fingerprint)
   - Import your GPG private key

6. Click **"Validate"** to test your credentials:
   - Verifies SSH key format
   - Tests SSH connection to GitHub (optional)
   - Validates GPG key if enabled

7. Click **"Save"** to create the profile

### SSH Key Formats

Git-Switch supports these SSH key formats:

| Format | Header Line |
|--------|-------------|
| OpenSSH | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| PEM (RSA) | `-----BEGIN RSA PRIVATE KEY-----` |
| PEM (EC) | `-----BEGIN EC PRIVATE KEY-----` |

Supported key types:

- Ed25519 (recommended)
- RSA (2048-bit minimum, 4096-bit recommended)
- ECDSA

### Editing a Profile

1. Find the profile in the Profiles view
2. Click the **pencil icon** on the profile card
3. Modify the fields as needed
4. Click **"Validate"** if you changed credentials
5. Click **"Save"**

**Note**: Changing SSH or GPG keys requires re-validation.

### Deleting a Profile

1. Find the profile in the Profiles view
2. Click the **trash icon** on the profile card
3. Confirm the deletion

**Warning**: This action cannot be undone. The SSH key stored in this profile is permanently deleted.

### Profile Cards

Each profile is displayed as a card showing:

- Profile name and organization
- Git username and email
- SSH key fingerprint (SHA256)
- GPG status (enabled/disabled)
- Last used date
- Active indicator (green dot if currently active)

## Switching Profiles

### Global Switch

Applies the profile to **all Git operations** system-wide.

1. Select a profile from the list
2. Click **"Apply Global"**
3. Wait for the confirmation notification

**What happens during a global switch**:

1. Windows Credential Manager cache is cleared (removes cached GitHub logins)
2. `~/.gitconfig` is updated with:
   - `user.name` = profile's Git username
   - `user.email` = profile's Git email
   - `user.signingkey` = GPG key ID (if enabled)
   - `commit.gpgsign` = true/false
3. All keys are removed from ssh-agent (if "Clear SSH agent" is enabled)
4. The profile's SSH key is added to ssh-agent
5. GPG key is imported to keyring (if enabled)
6. Profile is marked as active
7. Success notification is displayed

### Local Switch (Per-Repository)

Applies the profile only to a **specific repository**.

1. Go to **Repositories** view
2. Select a registered repository
3. Choose a profile from the dropdown
4. Click **"Apply Local"**

This updates only the repository's `.git/config` without affecting global settings. Useful when you want different identities for different projects.

### Switching from System Tray

For quick switching without opening the main window:

1. Right-click the Git-Switch icon in the system tray
2. Hover over **"Switch Profile"**
3. Click the desired profile
4. Confirm if prompted (based on settings)

## Repository Management

### Adding a Repository

1. Go to **Repositories** view
2. Click **"Add Repository"**
3. Browse to select a folder containing a `.git` directory
4. The repository is added to your list

### Assigning Profiles

Each repository can have a default profile assigned:

1. Select the repository from the list
2. Choose a profile from the **"Assigned Profile"** dropdown
3. The assignment is saved automatically

### Applying Profiles

| Action | Effect |
|--------|--------|
| **Apply Local** | Updates only `.git/config` for this repository |
| **Apply Global** | Updates `~/.gitconfig` (affects all repos) |

### Batch Operations

To apply assigned profiles to all repositories at once:

1. Ensure each repository has an assigned profile
2. Click **"Apply All Local Configs"**
3. Each repository's `.git/config` is updated with its assigned profile

### Removing a Repository

1. Select the repository
2. Click **"Remove"**
3. Confirm the removal

**Note**: This only removes the repository from Git-Switch's list. It does not delete the actual repository or modify its configuration.

## Settings

Access settings via the **Settings** navigation item.

### Available Settings

| Setting | Description | Default |
|---------|-------------|---------|
| **Start with Windows** | Launch Git-Switch when Windows starts | Off |
| **Start minimized** | Launch directly to system tray | On (when auto-start enabled) |
| **Auto-lock timeout** | Lock after inactivity (0 = disabled) | 15 minutes |
| **Show notifications** | Display Windows toast notifications | On |
| **Confirm before switch** | Show confirmation dialog before switching | Off |
| **Clear SSH agent on switch** | Remove other keys when switching | On |

### Auto-Lock Timeout

The auto-lock feature secures your profiles when you're away:

- Set to 0 to disable auto-lock
- Valid range: 1-1440 minutes (up to 24 hours)
- Recommended: 5-15 minutes for security

When locked:

- Encryption key is cleared from memory
- Profiles cannot be accessed
- Must re-enter master password to unlock

### Changing Master Password

1. Go to **Settings**
2. Click **"Change Master Password"**
3. Enter your current password
4. Enter and confirm your new password
5. Click **"Change Password"**

**What happens**:

- All profile data is re-encrypted with the new key
- A new salt is generated
- Previous password no longer works

## Import/Export

### Exporting Profiles

Creates an encrypted backup of all profiles and credentials.

1. Go to **Import/Export** view
2. Click **"Export All"**
3. Choose a save location and filename (`.gps` extension)
4. Enter an export password
   - Can be different from your master password
   - Used to encrypt the archive
5. Confirm the password
6. Click **"Export"**

**What's included**:

- All profiles with metadata
- SSH private keys (re-encrypted)
- GPG private keys (re-encrypted)
- Repository assignments

**What's NOT included**:

- Master password
- Application settings
- UI state

### Importing Profiles

1. Go to **Import/Export** view
2. Click **"Import"**
3. Select a `.gps` archive file
4. Enter the archive password
5. Choose import mode:

| Mode | Behavior |
|------|----------|
| **Merge** | Adds to existing profiles, handles duplicates |
| **Replace** | Deletes all existing profiles first |

6. If conflicts exist (same profile names), choose resolution:

| Resolution | Effect |
|------------|--------|
| **Rename** | Add suffix to imported profile names |
| **Skip** | Don't import conflicting profiles |
| **Overwrite** | Replace existing with imported |

7. Click **"Import"**

### Archive Security

- Archives are encrypted with AES-256-GCM
- Password is used with PBKDF2 (100,000 iterations)
- Each archive has a unique salt
- Archives can be safely stored in cloud storage

## System Tray

Git-Switch runs in the system tray for quick access.

### Tray Icon

- **Blue icon**: Application running normally
- **Red icon**: Session locked
- **Gray icon**: Error state

### Tray Menu

Right-click the tray icon to access:

| Menu Item | Action |
|-----------|--------|
| **Switch Profile** | Submenu with all profiles for quick switching |
| **Open Git-Switch** | Restore the main window |
| **Lock** | Lock the session (clear encryption key) |
| **Exit** | Close the application completely |

### Minimizing Behavior

- Closing the main window **minimizes to tray** (app keeps running)
- Click the tray icon to **restore** the window
- Use **Exit** from tray menu to fully close

### Notifications

When enabled, Git-Switch shows Windows toast notifications for:

- Successful profile switches
- Auto-lock events
- Errors during operations

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+L` | Lock the application |
| `Ctrl+N` | New profile |
| `Ctrl+,` | Open settings |
| `Escape` | Close dialog / Cancel |

## Troubleshooting

### Common Issues

#### "Git is not installed"

Git-Switch requires Git to be installed and in your PATH.

**Solution**:

1. Install Git from <https://git-scm.com/>
2. Ensure "Git from the command line" option was selected during install
3. Restart Git-Switch

**Verify**:

```bash
git --version
```

#### "SSH agent is not running"

Windows OpenSSH agent service is not running.

**Solution**:

1. Open **Services** (press `Win+R`, type `services.msc`)
2. Find **"OpenSSH Authentication Agent"**
3. Set Startup Type to **"Automatic"**
4. Click **"Start"**

Or run in PowerShell (as Administrator):

```powershell
Set-Service ssh-agent -StartupType Automatic
Start-Service ssh-agent
```

#### "Validation failed: SSH connection"

The SSH key was not accepted by GitHub.

**Possible causes**:

- Key not added to GitHub account
- Wrong key passphrase
- Key has been revoked or expired
- Using the wrong key for this account

**Solution**:

1. Verify the key is in GitHub: Settings → SSH and GPG keys
2. Check the fingerprint matches
3. Try the passphrase manually: `ssh-add ~/.ssh/your_key`
4. Test connection: `ssh -T git@github.com`

#### "GPG not installed"

GPG signing requires GnuPG to be installed.

**Solution**:

1. Download from <https://www.gnupg.org/download/>
2. Or install Gpg4win: <https://www.gpg4win.org/>
3. Restart Git-Switch

**Verify**:

```bash
gpg --version
```

#### Profile switch succeeds but pushes fail

Cached credentials may still be in use.

**Solution**:

1. Open **Credential Manager** (search in Start menu)
2. Click **"Windows Credentials"**
3. Find and remove any entries for:
   - `git:https://github.com`
   - `github.com`
4. Try pushing again

Or use Git-Switch's automatic credential clearing:

1. Go to **Settings**
2. Ensure **"Clear SSH agent on switch"** is enabled

#### Master password forgotten

There is **no recovery option**. You must reset the application.

**Steps**:

1. Close Git-Switch
2. Delete the data folder:

   ```text
   %APPDATA%\Git-Switch\
   ```

3. Restart Git-Switch
4. Create a new master password
5. Re-create your profiles

**Prevention**: Consider exporting profiles regularly as a backup.

#### "Access denied" when starting

The application may be blocked by security software.

**Solution**:

1. Check Windows SmartScreen (click "More info" → "Run anyway")
2. Add Git-Switch to antivirus exclusions
3. Run as Administrator (if needed for SSH agent access)

#### SSH key with passphrase not working

**Solution**:

1. When creating/editing the profile, enter the passphrase in the passphrase field
2. Git-Switch stores the passphrase encrypted alongside the key
3. The passphrase is automatically provided when loading the key

### Getting Help

If you're still having issues:

1. Check [GitHub Issues](https://github.com/apatheticus/git-switch/issues) for known problems
2. Open a new issue with:
   - Git-Switch version
   - Windows version
   - Steps to reproduce
   - Error messages (if any)
3. For security issues, see [SECURITY.md](../SECURITY.md)

### Debug Mode

To get more detailed logging:

```bash
python -m src.main --debug
```

Logs are written to:

```text
%APPDATA%\Git-Switch\logs\
```
