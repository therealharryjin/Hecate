# Hecate

A local-first, encrypted command-line password manager.

Named for the Greek goddess of keys, crossroads, and boundaries — the keeper of
the keys and guardian of thresholds, which is the whole job description here.

> **Status:** early. The encrypted vault core, key derivation, the two-stage
> unlock flow, the recovery key, unlock sessions and the entry commands are
> implemented and tested. The generator, breach checking and import/export
> are not built yet.

## Security design

A random 256-bit **data-encryption key (DEK)** encrypts the vault payload. The
DEK is wrapped twice, under two independent paths, so either can open the vault:

```
  master password ──Argon2id(256 MiB, t=3, p=4)──▶ K_master ──AES-256-GCM──▶ keyring
                                                                              ├── DEK
                                                                              └── TOTP secret
  recovery key (160-bit) ──HKDF-SHA256──▶ K_recovery ──AES-256-GCM──▶ DEK

  DEK ──AES-256-GCM──▶ vault payload (all entries)
```

Two different KDFs, on purpose: the master password is low-entropy and
guessable, so it gets the slow memory-hard treatment. The recovery key is
already 160 bits of CSPRNG output, so HKDF is the right tool — stretching
uniform randomness buys nothing.

**Header binding.** The plaintext header (format version, Argon2 cost
parameters, salts) is fed into every AES-GCM call as additional authenticated
data. An attacker who edits the stored `memory_cost` down to make cracking
cheap invalidates every authentication tag in the file, so the downgrade is
detected rather than silently honoured. There is a test for this.

**Atomic writes.** Vault saves go to a temp file in the same directory, are
fsynced, then `os.replace`d over the target, and the directory is fsynced
afterwards. A crash mid-save cannot corrupt an existing vault. The file is
created `0600` at `open()` time, never chmod'ed after the fact.

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

  This is a real limitation, not a hedge. `test_documented_limitation_
  password_alone_recovers_the_payload` in `tests/test_vault.py` demonstrates
  the bypass and is expected to pass. If it ever fails, the key hierarchy has
  changed and this section is out of date.

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

### The unrecoverable-vault tradeoff

**There is no server, no backdoor, and no reset.** Access requires either:

1. master password **+** authenticator code, or
2. the one-time recovery key.

The recovery key is displayed exactly once, at `hecate init`. It is never
written to disk by Hecate and cannot be regenerated or recovered afterwards.

> **Lose your authenticator device *and* your recovery key, and the vault is
> permanently unreadable.** Not "hard to read" — mathematically unrecoverable.
> Nobody, including the author, can help you. This is the intended design: it
> is the same property that stops a thief with your laptop.

Write the recovery key down on paper and put it somewhere physically safe,
separate from the machine holding the vault.

## Usage

```bash
hecate init                      # create the vault, enroll an authenticator,
                                 # and print the recovery key once
hecate unlock                    # master password, then authenticator code
hecate add github --username me  # password is prompted for, never an argument
hecate get github --show
hecate list
hecate delete github
hecate lock                      # end the session now
hecate status                    # is it unlocked, and for how long
```

### Sessions

Unlocking starts a session so you are not asked for a password and a phone on
every command. The window is **idle** time: each command slides it forward, so
active work does not expire mid-task while a walked-away-from terminal locks on
schedule.

```bash
hecate config list                        # every setting, with explanations
hecate config get session-timeout
hecate config set session-timeout 30      # minutes
hecate config set session-timeout 0       # disable; prompt on every command
```

The default is **10 minutes**. Settings live in `~/.hecate/config.json`
(`0600`). See the threat model for what a live session costs you.

## Development

```bash
python3 -m venv .venv
./.venv/bin/pip install -e '.[dev]'
./.venv/bin/pytest
```

`crypto/` and `vault/` are covered before anything is built on top of them:
independent AES-256-GCM known-answer vectors from the GCM specification,
golden-vector drift guards for Argon2id and HKDF, tamper and downgrade
detection, the TOTP gate, and the recovery path.
