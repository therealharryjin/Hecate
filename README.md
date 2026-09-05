# Hecate

A local-first, encrypted command-line password manager.

Named for the Greek goddess of keys, crossroads, and boundaries — the keeper of
the keys and guardian of thresholds, which is the whole job description here.

Everything lives in a single encrypted file on your machine. There is no
server, no account, no sync, and no telemetry. The only network request Hecate
will ever make is an anonymised breach check you explicitly ask for.

> **Status:** early but usable. The vault core, key derivation, the two-factor
> unlock flow, the recovery key, unlock sessions and the entry commands are
> implemented and tested. The generator, breach checking and import/export are
> not built yet — see [Roadmap](#roadmap).

---

## Contents

- [Installation](#installation)
- [Quick start](#quick-start)
- [Command reference](#command-reference)
- [Configuration](#configuration)
- [How it works](#how-it-works)
- [Threat model](#threat-model)
- [Recovery](#recovery)
- [Project layout](#project-layout)
- [Development](#development)
- [Roadmap](#roadmap)

---

## Installation

Requires Python 3.11 or newer.

```bash
git clone https://github.com/therealharryjin/Hecate.git
cd Hecate
python3 -m venv .venv
./.venv/bin/pip install -e '.[dev]'
```

This installs a `hecate` command into `.venv/bin`. Put that on your `PATH`, or
call it directly as `./.venv/bin/hecate`.

## Quick start

```bash
hecate init                       # create the vault, enroll your authenticator,
                                  # and print the recovery key exactly once
hecate unlock                     # master password, then a 6-digit code
hecate add github --username me   # the password is prompted for, never typed as an argument
hecate get github --show
hecate list
hecate lock                       # end the session now
```

`init` walks you through three things: choosing a master password, scanning an
`otpauth://` URI into your authenticator app, and writing down a recovery key.
**Write the recovery key down before you continue** — it is shown once and
cannot be regenerated. See [Recovery](#recovery).

## Command reference

### Setup

| Command | Description |
| --- | --- |
| `hecate init` | Create the vault, enroll an authenticator, print the recovery key once. `--no-totp` skips enrollment and creates a password-only vault. |
| `hecate enroll-authenticator` | Add or replace the authenticator used to unlock the vault. Requires the master password, and ends any live session. |

### Session

| Command | Description |
| --- | --- |
| `hecate unlock` | Prompt for the master password, then the authenticator code, and start a session. |
| `hecate lock` | End the session immediately. |
| `hecate status` | Show the vault path, the configured timeout, and whether the vault is unlocked and for how much longer. |

### Entries

| Command | Description |
| --- | --- |
| `hecate add TITLE` | Add an entry. Options: `--username`, `--url`, `--notes`, `--tag` (repeatable). The password is always prompted for. |
| `hecate get TITLE` | Show an entry. The password is masked unless you pass `--show`. |
| `hecate edit TITLE` | Update in place. Options: `--title` (rename), `--username`, `--url`, `--notes`, `--password` (flag; prompts), `--add-tag`, `--remove-tag`. |
| `hecate list` | List titles and usernames. `--tag` filters. Never prints passwords. |
| `hecate history TITLE` | Show previous passwords, newest first. Masked unless `--show`. |
| `hecate delete TITLE` | Delete an entry, after confirmation. |

Entries are looked up by exact id first, then by case-insensitive title.

### Settings

| Command | Description |
| --- | --- |
| `hecate config list` | Every setting, its current value, and what it does. |
| `hecate config get NAME` | Print one value. |
| `hecate config set NAME VALUE` | Change one value, validated before it is written. |

### Global options

| Option | Description |
| --- | --- |
| `--vault PATH` | Use a specific vault file instead of the configured default. |
| `--version` | Print the version. |
| `--help` | Available on every command and subcommand. |

### Environment variables

| Variable | Effect |
| --- | --- |
| `HECATE_HOME` | Directory holding the config, default vault, and session. Defaults to `~/.hecate`. |
| `HECATE_VAULT` | Path to the vault file, overriding the default location. |

## Configuration

Settings live in `$HECATE_HOME/config.json`, written `0600`.

| Setting | Default | Range | Meaning |
| --- | --- | --- | --- |
| `session-timeout` | `10` | 0–1440 minutes | Idle minutes before the vault re-locks. `0` disables sessions entirely, prompting on every command. |
| `clipboard-clear` | `15` | 0–300 seconds | Seconds before a copied secret is cleared. **Currently inert** — nothing copies to the clipboard yet. |

```bash
hecate config set session-timeout 30
hecate config set session-timeout 0     # maximum paranoia: always prompt
```

Values are validated at the boundary, so a bad value is rejected with a real
message rather than being written and failing on next read:

```
$ hecate config set session-timeout -1
error: session-timeout: must be between 0 and 1440, got -1
```

---

## How it works

### Key hierarchy

A random 256-bit **data-encryption key (DEK)** encrypts your entries. The DEK
is never derived from anything — it is CSPRNG output. It is instead *wrapped*
twice, under two independent paths, so either one can recover it:

```
                          ┌─────────────────────────────────────────┐
  master password ───────▶│ Argon2id  (256 MiB, t=3, p=4, 16B salt)  │──▶ K_master
                          └─────────────────────────────────────────┘        │
                                                                             ▼
                                                            AES-256-GCM ─▶ keyring
                                                                           ├── DEK
                                                                           └── TOTP secret

                          ┌─────────────────────────────────────────┐
  recovery key (160-bit) ▶│ HKDF-SHA256                             │──▶ K_recovery
                          └─────────────────────────────────────────┘        │
                                                                             ▼
                                                            AES-256-GCM ─▶ { DEK }

  DEK ──── AES-256-GCM ────▶ payload  (every entry, as JSON)
```

**Why two different KDFs.** The master password is low-entropy and guessable,
so it goes through Argon2id, which is deliberately slow and memory-hard —
256 MiB per guess makes GPU and ASIC cracking expensive. The recovery key is
already 160 bits of uniform CSPRNG output, so stretching it would buy nothing;
HKDF is the correct tool for deriving a key from an existing high-entropy
secret. Using Argon2id there would be cargo-culting.

**Why wrap rather than derive.** If the DEK were derived from your password,
changing the password would require re-encrypting every entry. Wrapping means a
password change only re-wraps a few dozen bytes.

### The vault file

One JSON file, default `~/.hecate/vault.hecate`, mode `0600`:

```json
{
  "format": "hecate-vault",
  "version": 1,
  "kdf": { "algorithm": "argon2id", "memory_cost": 262144,
           "parallelism": 4, "time_cost": 3 },
  "master_salt":   "<base64>",
  "recovery_salt": "<base64>",
  "keyring":  { "nonce": "<base64>", "ciphertext": "<base64>" },
  "recovery": { "nonce": "<base64>", "ciphertext": "<base64>" },
  "payload":  { "nonce": "<base64>", "ciphertext": "<base64>" }
}
```

The header is plaintext — it has to be, since you need the KDF parameters
before you can derive a key. That creates an obvious attack: rewrite
`memory_cost` to `8`, and cracking becomes trivial.

**Header binding closes that.** The canonical serialisation of the header is
passed as additional authenticated data to every AES-GCM operation in the file.
Change any header byte and all three authentication tags fail, so a downgrade
is detected instead of honoured. `test_kdf_parameter_downgrade_is_detected`
covers it.

Every nonce is 96 bits, freshly generated from the OS CSPRNG on every
encryption. The API never accepts a caller-supplied nonce, because GCM nonce
reuse under one key is catastrophic.

### The unlock flow

```
  1. hecate unlock
       │
  2.   ├─▶ prompt: master password  (hidden input)
       │        │
       │        └─▶ Argon2id ──▶ K_master ──▶ decrypt keyring
       │                                          │
       │                          wrong password ─┴─▶ authentication fails, stop
       │
  3.   ├─▶ keyring yields { DEK, TOTP secret }
       │
  4.   ├─▶ prompt: 6-digit code    ──▶ verified against the TOTP secret
       │        │                       (±1 time step for clock skew)
       │        └─▶ wrong or expired ──▶ refuse to open, stop
       │
  5.   └─▶ decrypt payload with the DEK, write the session file
```

Unlocking is two-stage in the code (`verify_password()` then
`complete_unlock()`) so the CLI can prompt for the password and *then* the
code without paying the ~1 second Argon2id cost twice.

Note step 3: **the DEK is recovered before the code is checked.** That is not
an accident, and it is the single most important thing to understand about
Hecate's security. See the [threat model](#what-hecate-does-not-defend-against--read-this-part).

### Sessions

Prompting for a password and a phone on every single command would be
unusable, so `unlock` writes a session file at `$HECATE_HOME/session.json`
holding the DEK.

The window is **idle**, not absolute: every command slides it forward, so
active work never expires mid-task, while a terminal you walked away from locks
on schedule.

A session is refused — and deleted — if any of the following hold:

- it has expired,
- it belongs to a different vault path,
- the file is corrupt or unparseable,
- its permissions have been loosened beyond `0600`.

Failing closed here costs one password entry. Failing open would cost the
vault.

The expiry lives *inside* the file, so extending a session means forging it;
backdating the file's mtime does nothing. On `lock`, the file's bytes are
overwritten before it is unlinked — best-effort, since overwriting does not
reliably erase on copy-on-write or log-structured filesystems.

### What is never written to disk

- The master password, and the key derived from it.
- The recovery key. It is printed once by `init` and never stored — Hecate
  keeps only a *wrapped DEK* that the recovery key can open, which is not the
  same thing and cannot be reversed into it.
- Any password, in plaintext, anywhere. `test_vault_file_contains_no_plaintext`
  asserts the vault file contains no entry title, username, or password in the
  clear.

Passwords are prompted for with hidden input, never accepted as command
arguments, so they cannot leak into shell history or `ps` output. `--password`
on `edit` is a *flag* that triggers a prompt, not an option taking a value; a
value passed after it is rejected rather than silently accepted.

### Password history

Changing a password with `hecate edit --password` rotates the old value into
the entry's history with a timestamp, rather than discarding it. `hecate
history` reads it back. Deleting and re-adding an entry loses both the history
and the original creation time — that is why `edit` exists.

---

## Threat model

### What Hecate defends against

- **An attacker who obtains the vault file** — stolen laptop, a disk image, a
  synced backup, a cloud drive. Without the master password the payload is
  AES-256-GCM ciphertext, and guessing is throttled by Argon2id at 256 MiB per
  attempt.
- **Tampering with the vault file.** Every ciphertext is authenticated. Editing
  the payload, swapping a keyring, or weakening the KDF parameters all fail
  closed with a decryption error rather than returning garbage.
- **Casual local access** — someone who sits down at your unlocked machine, or
  watches you type the master password. This is what the authenticator code
  buys you.
- **Password reuse against known breaches**, via Have I Been Pwned k-anonymity
  (planned). Only the first 5 characters of a SHA-1 hash ever leave the machine.

### What Hecate does *not* defend against — read this part

- **TOTP is an authorization gate, not a second cryptographic factor.** The
  TOTP secret lives in the keyring, which the master password alone unwraps.
  An attacker who has your vault file *and* cracks your master password
  recovers the TOTP secret with it and can bypass the prompt entirely. It
  raises the bar for someone at your keyboard; it does not raise the bar for
  offline cracking.

  This is a real limitation, not a hedge.
  `test_documented_limitation_password_alone_recovers_the_payload` in
  `tests/test_vault.py` demonstrates the bypass and is expected to pass. If it
  ever fails, the key hierarchy has changed and this section is out of date.

  Making the second factor genuinely cryptographic requires a *deterministic*
  secret the vault file does not contain — a keyfile on removable media, or
  hardware challenge-response (YubiKey HMAC-SHA1, FIDO2 `hmac-secret`).
  Rotating TOTP codes cannot fill that role, because verifying a rotating code
  requires storing the shared secret it rotates from.

- **The recovery key is equivalent in power to the master password.** It
  unwraps the DEK on its own, with no second factor. Anyone who finds it owns
  the vault. Store it like a spare house key, not like a password hint.

- **The unlock session, while it is live.** After `hecate unlock`, the
  data-encryption key sits in a `0600` file so later commands need no
  password. For that window, any process running as you can read the vault
  without either factor. This is inherent to "don't ask me again for 10
  minutes" — no amount of encrypting that file with a key stored beside it
  would change it. Hecate binds the session to one vault, keeps the expiry
  inside the file, refuses to load it if its permissions have been loosened,
  and defaults the window to 10 minutes. Set `session-timeout` to `0` to opt
  out entirely and be prompted every time.

- **Secrets in process memory.** Python cannot reliably zero secrets: `str` is
  immutable and the garbage collector copies freely. Derived keys are held in
  `bytes` and dropped on lock, but a memory dump or swap file of a running,
  unlocked Hecate can contain plaintext. Out of scope by choice.

- **A compromised machine.** A keylogger, a malicious Python package in the
  environment, or root on your box defeats all of the above. Hecate assumes the
  machine it runs on is trusted at the moment you unlock.

- **Nation-state adversaries and live memory forensics.** Out of scope for a
  personal project.

### Cryptographic dependencies

Hecate hand-rolls no cryptographic primitives. Every one comes from an audited
library, and that is a hard rule rather than a preference:

| Primitive | Library | Entry point |
| --- | --- | --- |
| AES-256-GCM | `cryptography` | `ciphers.aead.AESGCM` |
| Argon2id | `argon2-cffi` | `low_level.hash_secret_raw` |
| HKDF-SHA256 | `cryptography` | `kdf.hkdf.HKDF` |
| TOTP (RFC 6238) | `pyotp` | `pyotp.TOTP` |
| Randomness | Python stdlib | `secrets` (never `random`) |

## Recovery

**There is no server, no backdoor, and no reset.** Access requires either:

1. master password **+** authenticator code, or
2. the one-time recovery key.

The recovery key is 160 bits, displayed exactly once at `hecate init`, and
formatted in grouped base32 so it can be copied onto paper without confusing
`0`/`O` or `1`/`l`:

```
    ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ23-4567
```

It is never written to disk by Hecate and cannot be regenerated.

> **Lose your authenticator device *and* your recovery key, and the vault is
> permanently unreadable.** Not "hard to read" — mathematically unrecoverable.
> Nobody, including the author, can help you. This is the intended design: it
> is the same property that stops a thief with your laptop.

Write the recovery key down on paper and put it somewhere physically safe,
separate from the machine holding the vault.

If you lose only the authenticator, unlock with the recovery key and run
`hecate enroll-authenticator` to enroll a new device. (The CLI path for
recovery-key unlock is still to be wired up — see [Roadmap](#roadmap).)

## Project layout

```
src/hecate/
├── crypto/          no I/O, no CLI concerns — just primitives
│   ├── aead.py      AES-256-GCM wrapper; single error type, no unauthenticated path
│   ├── kdf.py       Argon2id for the password, HKDF for the recovery key
│   └── rng.py       CSPRNG helpers; recovery-key base32 encoding
├── vault/
│   ├── envelope.py  the key hierarchy: wrapping, unwrapping, header binding
│   ├── model.py     Entry and VaultData; password history lives here
│   ├── storage.py   atomic writes, fsync, 0600 at open() time
│   └── vault.py     lifecycle: create, two-stage unlock, enroll, save
├── auth/
│   ├── totp.py      enrollment URIs and code verification, via pyotp
│   └── session.py   the idle-window session file
├── cli/main.py      the click app behind the `hecate` entry point
├── config.py        user settings, as a declarative registry
├── generator/       (not built yet)
└── breach/          (not built yet)
```

The dependency direction is one-way: `crypto` knows nothing about vaults,
`vault` knows nothing about the CLI. That keeps the security-critical core
small and independently testable.

## Development

```bash
./.venv/bin/pytest              # the whole suite
./.venv/bin/pytest -q tests/test_vault.py
```

CI runs the suite on every push and pull request, across Python 3.11–3.14 on
Linux plus 3.13 on macOS. macOS is included deliberately: the atomic-write path
and the `0600` permission handling are filesystem-sensitive, and a Linux-only
matrix would not exercise them where development actually happens.

### On the test vectors

The distinction matters, because a test that checks our code against itself
proves very little:

- The **AES-256-GCM vectors are independent** — Test Cases 13 and 14 from the
  GCM specification NIST adopted. Passing them is real evidence.
- The **Argon2id and HKDF vectors are not**. They are golden values generated
  by this library and pinned as drift guards, catching changes to parameters or
  encoding, not errors in Argon2 itself. The RFC 9106 vector cannot be used:
  it requires the optional secret-key and associated-data inputs, which
  `argon2-cffi`'s raw API does not expose. Correctness of the primitive is
  delegated to that library's own suite, which is where it belongs.

Tests use a deliberately weak Argon2 profile (`FAST_ARGON2_FOR_TESTS`) so the
suite stays fast. It is never used for a real vault.

## Roadmap

Built and tested:

- [x] Encrypted vault core, key derivation, recovery key
- [x] Two-factor unlock flow
- [x] Sessions with a configurable idle timeout
- [x] Entry commands: add, get, edit, list, history, delete

Not yet built:

- [ ] `hecate generate` — Diceware passphrases and character-based passwords,
      with entropy estimates
- [ ] `hecate check-breach` — Have I Been Pwned, k-anonymity only
- [ ] `hecate import` / `hecate export` — encrypted backups, and CSV import
      from other managers
- [ ] Clipboard support, which is what `clipboard-clear` is waiting on
- [ ] Rate limiting and backoff on failed unlock attempts
- [ ] A CLI path for unlocking with the recovery key
