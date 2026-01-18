# Security Policy

Git-Switch is designed with security as a core principle. This document outlines our security policies, features, and how to report vulnerabilities.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x.x   | Yes       |
| < 1.0   | No        |

Only the latest major version receives security updates. Users on older versions should upgrade to receive security fixes.

## Reporting a Vulnerability

### Private Disclosure

**Do NOT open a public issue for security vulnerabilities.**

Instead, please report security vulnerabilities through one of these channels:

1. **GitHub Security Advisories** (Preferred): Use the [Security Advisories](https://github.com/apatheticus/git-switch/security/advisories) feature
2. **Email**: Contact the maintainers directly (see GitHub profiles)

### What to Include

When reporting a vulnerability, please include:

1. **Description** of the vulnerability
2. **Steps to reproduce** the issue
3. **Potential impact** (what could an attacker do?)
4. **Affected versions** (if known)
5. **Suggested fix** (if you have one)

### Response Timeline

| Phase | Timeline |
|-------|----------|
| Acknowledgment | Within 48 hours |
| Initial Assessment | Within 7 days |
| Resolution (Critical) | Within 30 days |
| Resolution (Other) | Within 90 days |

We will keep you informed of our progress throughout the process.

## Security Features

### Encryption at Rest

All sensitive data is encrypted using **AES-256-GCM** (authenticated encryption):

| Data Type | Storage Location | Encryption |
|-----------|------------------|------------|
| SSH Private Keys | `%APPDATA%\GitProfileSwitcher\keys\{id}.ssh` | AES-256-GCM |
| SSH Passphrases | Embedded in profile data | AES-256-GCM |
| GPG Private Keys | `%APPDATA%\GitProfileSwitcher\keys\{id}.gpg` | AES-256-GCM |
| Profile Metadata | `profiles.dat` | AES-256-GCM |

**Encryption Format:**

```text
[12 bytes]  Nonce (randomly generated per encryption)
[N bytes]   Ciphertext
[16 bytes]  GCM Authentication Tag
```

### Master Password

Your master password is **never stored** - only a verification hash:

- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000 (exceeds NIST recommendations)
- **Salt**: 32 bytes, cryptographically random, unique per installation
- **Verification**: HMAC-SHA256 of known constant (not the password itself)

This means:

- We cannot recover your password if forgotten
- Brute-force attacks are computationally expensive
- Each installation has unique cryptographic material

### Memory Protection

- **Encryption keys are zeroed** after use via `ctypes.memset`
- **Session key cleared** when application locks
- **Auto-lock** after configurable inactivity timeout (default: 15 minutes)

### Secure File Operations

- Files containing secrets are **overwritten with random data** before deletion
- Temporary key files are **deleted immediately** after SSH agent addition
- No plaintext secrets are ever written to disk

## Security Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                    User Interface Layer                         │
│                      (DearPyGui)                                │
├─────────────────────────────────────────────────────────────────┤
│                   Session Manager                                │
│     • Unlock/Lock state management                              │
│     • Auto-lock timer (idle detection)                          │
│     • Master password verification                               │
├─────────────────────────────────────────────────────────────────┤
│                   Crypto Service                                 │
│     • AES-256-GCM encryption/decryption                         │
│     • PBKDF2-HMAC-SHA256 key derivation                         │
│     • Secure memory clearing                                     │
├─────────────────────────────────────────────────────────────────┤
│                  Encrypted Storage                               │
│            %APPDATA%\GitProfileSwitcher\                        │
│     • profiles.dat (encrypted profile metadata)                 │
│     • keys/*.ssh (encrypted SSH keys)                           │
│     • keys/*.gpg (encrypted GPG keys)                           │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Startup**: Application prompts for master password
2. **Key Derivation**: PBKDF2 derives encryption key from password + stored salt
3. **Verification**: HMAC verification confirms correct password
4. **Decryption**: Profiles decrypted into memory as needed
5. **Usage**: SSH keys loaded to agent, GPG keys imported temporarily
6. **Lock**: Encryption key zeroed, secrets cleared from memory

## What Is NOT Encrypted

These files contain **no secrets** and are stored in plaintext:

| File | Contents |
|------|----------|
| `config.json` | Application settings (auto-lock timeout, UI preferences) |
| `repositories.json` | Repository paths and profile assignments |
| `master.json` | Salt and verification hash (NOT the password) |

## Known Limitations

### Cannot Prevent

| Limitation | Description |
|------------|-------------|
| **Password Recovery** | If you forget your master password, all data is unrecoverable |
| **Memory Forensics** | A running process may have decrypted data in memory |
| **SSD Wear Leveling** | Deleted file content may persist in flash storage cells |
| **Keyloggers** | Malware can capture your master password as you type |
| **Admin Access** | System administrators can access all user data |
| **Screen Capture** | Malware can screenshot the application window |

### Mitigations

1. **Use a strong, unique master password** (12+ characters recommended)
2. **Enable auto-lock** with a short timeout (5-15 minutes)
3. **Run on trusted, malware-free systems**
4. **Keep Windows and Git-Switch updated**
5. **Lock workstation when stepping away**

## Secure Usage Guidelines

### Do

- Use a strong master password (12+ characters, mixed case, numbers, symbols)
- Enable auto-lock in Settings (default: 15 minutes)
- Lock the application when stepping away (Ctrl+L or Lock button)
- Keep the application updated
- Use passphrase-protected SSH keys (additional layer of security)
- Regularly back up profiles using the export feature

### Don't

- Store your master password in a text file or notes app
- Disable auto-lock on shared or public computers
- Share the `%APPDATA%\GitProfileSwitcher` directory
- Run exported `.gps` archives from untrusted sources
- Use the same password for Git-Switch and your SSH key passphrases
- Leave the application running unlocked unattended

## Dependency Security

Git-Switch relies on these security-critical dependencies:

| Dependency | Version | Security Role |
|------------|---------|---------------|
| cryptography | 41+ | FIPS-validated AES-256-GCM and PBKDF2 |
| paramiko | 3.3+ | SSH key parsing (not used for network connections) |
| keyring | 24+ | Windows Credential Manager access |
| pywin32 | 306+ | Windows API integration |

### Keeping Dependencies Secure

Regularly audit dependencies for known vulnerabilities:

```bash
# Install pip-audit
pip install pip-audit

# Check for vulnerabilities
pip-audit
```

## Compliance Notes

- **Encryption Standard**: AES-256-GCM meets NIST, PCI-DSS, and HIPAA requirements
- **Key Derivation**: PBKDF2 with 100,000 iterations exceeds NIST SP 800-132 recommendations
- **Authenticated Encryption**: GCM mode prevents tampering and provides integrity verification
- **No Telemetry**: Git-Switch makes no network connections except for SSH validation (optional)

## Security Checklist for Contributors

If you're contributing code, please review:

- [ ] No secrets logged (use `[REDACTED]` placeholders)
- [ ] Secrets zeroed after use (`secure_zero()` function)
- [ ] Inputs validated before use
- [ ] Subprocess inputs sanitized (prevent command injection)
- [ ] Error messages don't leak sensitive information
- [ ] New dependencies reviewed for security

## Changelog

### Security-Related Changes

| Version | Change |
|---------|--------|
| 0.1.0 | Initial release with AES-256-GCM encryption |

---

Thank you for helping keep Git-Switch secure!
