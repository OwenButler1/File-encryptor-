# File Encryptor (Windows 11, .NET)

A Windows 11 desktop file-encryption utility focused on **confidentiality + integrity** using modern authenticated encryption, memory-hard password-based key derivation, and a versioned container format for long-term compatibility.

---

## 1) High-level architecture

The application is organized into clear modules so cryptography, file/container logic, and UI concerns stay isolated.

### Module responsibilities

- **UI Layer (WinUI 3 app)**
  - Collects user input (source file/folder, password, output path).
  - Displays progress, warnings, and success/error states.
  - Never implements cryptographic logic directly.

- **Application Layer (Use-case orchestration)**
  - Coordinates encrypt/decrypt workflows.
  - Validates user options and policy constraints.
  - Maps domain errors into user-facing messages.

- **Crypto Layer**
  - Implements key derivation and encryption/decryption primitives.
  - Zeroes/clears sensitive buffers where practical.
  - Enforces algorithm/version policy.

- **Container Layer**
  - Builds/parses the on-disk encrypted container format.
  - Handles header metadata, versioning, and authenticated data binding.
  - Performs strict format validation before decryption.

- **I/O Layer**
  - Streaming reads/writes for large files.
  - Temporary-file handling and atomic replace patterns.
  - Optional post-process hooks (for example, secure-delete best-effort).

- **Diagnostics/Telemetry (optional, privacy-conscious)**
  - Records non-sensitive operational events.
  - Must never log plaintext content, passwords, or derived keys.

---

## 2) Cryptographic algorithms and baseline parameters

This project standardizes on:

- **Encryption:** `AES-256-GCM`
- **KDF:** `Argon2id`

### AES-256-GCM details

- Key size: **256 bits**
- Nonce/IV size: **96 bits (12 bytes)**
- Authentication tag size: **128 bits (16 bytes)**
- AAD (Additional Authenticated Data): container header fields (magic/version/algorithm identifiers and KDF params) are authenticated to detect tampering.

### Argon2id baseline (password mode)

Use these baseline defaults unless policy/hardware tuning requires stricter values:

- Variant: **Argon2id**
- Salt size: **16 bytes minimum** (recommended 16–32 bytes)
- Memory cost: **64 MiB minimum baseline** (`m = 65536 KiB`)
- Iterations/time cost: **3** (`t = 3`)
- Parallelism: **1–4 lanes** (baseline `p = 1`, increase when safe and tested)
- Output length: **32 bytes** (for AES-256 key material)

> Rationale: Argon2id provides balanced resistance to GPU/ASIC attacks and side-channel concerns, while AES-GCM provides confidentiality + integrity in one primitive.

---

## 3) Container format and versioning rationale

A custom container wraps ciphertext with explicit metadata required for deterministic parsing and forward/backward compatibility.

## Container layout (overview)

1. **Magic bytes** (format identifier)
2. **Format version**
3. **Algorithm identifiers**
   - Cipher suite ID (e.g., AES-256-GCM)
   - KDF ID (Argon2id)
4. **KDF parameters**
   - Salt
   - Memory/time/parallelism values
5. **Encryption nonce (IV)**
6. **Ciphertext payload**
7. **Auth tag** (if not stored inline with payload by implementation)

All header fields that affect cryptographic interpretation are bound via **AAD** to prevent unnoticed tampering.

### Versioning rationale

Versioning exists to safely support:

- Parameter upgrades (e.g., stronger Argon2 settings over time)
- New cipher suites in future releases
- Backward-compatible readers for older archives
- Explicit rejection of unsupported/unsafe formats

Recommended policy:

- **Major version bump** for incompatible parsing/semantics changes.
- **Minor/flag changes** for backward-compatible additions.
- Keep old decrypt paths intentionally narrow and reviewed.

---

## 4) Build and run on Windows 11

## Prerequisites

- **Windows 11** (x64/ARM64)
- **.NET SDK 8.0+** (or the exact SDK pinned by `global.json`, if present)
- **Visual Studio 2022** (recommended) with:
  - *Desktop development with .NET*
  - *Windows App SDK / WinUI 3 tooling*
  - Latest Windows 11 SDK

## CLI build (from repository root)

```powershell
dotnet --info
dotnet restore
dotnet build -c Release
```

## Run (development)

```powershell
dotnet run -c Debug
```

If the solution uses packaged WinUI deployment, use Visual Studio to deploy/start with the generated package profile.

---

## 5) Example encrypt/decrypt flow

## Encrypt

1. User selects `QuarterlyReport.xlsx`.
2. User enters a strong password.
3. App generates random:
   - Argon2 salt
   - AES-GCM nonce
4. App derives a 256-bit key via Argon2id.
5. App encrypts plaintext using AES-256-GCM.
6. App writes container header + ciphertext + tag to `QuarterlyReport.xlsx.fenc`.
7. App clears sensitive in-memory buffers where practical.

## Decrypt

1. User selects `QuarterlyReport.xlsx.fenc`.
2. App parses and validates magic/version/algorithm fields.
3. App re-derives key with stored Argon2 parameters and user password.
4. AES-GCM authentication runs during decrypt.
5. If tag validation fails: return **authentication error** (wrong password or tampered data).
6. If validation succeeds: plaintext is written to destination path.

---

## 6) Security assumptions, threat model, and limitations

## In-scope protections

- Protects file **content confidentiality** at rest.
- Detects tampering via AEAD authentication tag.
- Resists brute-force attempts better than legacy KDFs via Argon2id memory hardness.

## Threat model boundaries (out of scope)

- Compromised endpoint (malware/keylogger/screen capture).
- Password reuse or weak user-selected passwords.
- Data exposure while plaintext is open in other applications.
- OS/pagefile/hibernation/swap artifacts beyond application control.
- Adversaries with full live control of the machine at encryption/decryption time.

## Limitations

- Password-based encryption strength depends heavily on password entropy.
- Container corruption may render file undecryptable even with correct password.
- Future algorithm migration requires continued support for old versions or offline migration.

---

## 7) Metadata leakage warning and secure-delete caveats

## Metadata leakage (important)

Even with strong encryption, some metadata can leak **outside** encrypted payload boundaries, such as:

- Encrypted container filename and extension
- File size (approximate plaintext size relationship)
- File timestamps (creation/modification/access)
- Directory structure/path context
- OS-level logs, thumbnail/indexing traces

Mitigations (optional): neutral filenames, metadata scrubbing, encrypted archives/volumes, and minimizing plaintext lifetime.

## Secure-delete caveat (best-effort only)

Any “secure delete” option is platform/filesystem dependent and **cannot be guaranteed** on modern storage due to:

- SSD wear-leveling and remapping
- Journaling/copy-on-write behavior
- Snapshots/cloud sync/versioning
- Backup/restore artifacts

Treat secure-delete as risk reduction, not absolute erasure.

---

## 8) Operational recommendations

- Use long, unique passphrases (or randomly generated passwords) with a password manager.
- Re-encrypt older containers periodically with updated Argon2 parameters.
- Keep offline backups of encrypted files and test restore/decrypt regularly.
- Pin dependency versions and review cryptographic changes with care.

---

## 9) Disclaimer

This software aims to apply modern cryptographic practices, but no software can provide absolute security. Evaluate fitness for your regulatory, organizational, and threat-environment requirements before production use.
