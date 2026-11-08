# Hecate

A local-first, encrypted command-line password manager.

Named for the Greek goddess of keys, crossroads, and boundaries — the keeper of
the keys and guardian of thresholds, which is the whole job description here.

Everything lives in a single encrypted file on your machine. There is no
server, no account, no sync, and no telemetry. The only network request Hecate
will ever make is an anonymised breach check you explicitly ask for.

> **Status:** early but usable. The vault core, key derivation, the two-factor
> unlock flow with backoff on failed attempts, recovery with the recovery key,
> unlock sessions, the entry commands with clipboard copying, the
> password-reuse warning, the password/passphrase generator, breach checking,
> encrypted backups and importing from other managers are implemented and
> tested — see [Roadmap](#roadmap).

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
hecate generate                   # a random password: printed, copied, and offered for saving
hecate check-breach               # has any of your passwords turned up in a known breach?
hecate import bitwarden.csv       # bring entries over from another password manager
hecate export ~/backup.hecate     # an encrypted backup, under the same keys
hecate get github --copy          # onto the clipboard, cleared again after 15 seconds
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
| `hecate enroll-authenticator` | Add or replace the authenticator used to unlock the vault. Requires the master password and, if one is enrolled, a code from the current authenticator — if you have lost it, use `recover`. Wrong answers count as [failed unlocks](#failed-unlocks). Ends any live session. |
| `hecate recover` | Get back in with the recovery key after losing the authenticator, forgetting the master password, or both. Sets a master password (a new one, or the old one again), enrolls a new authenticator, and ends any live session. `--no-totp` finishes with a password-only vault. The recovery key itself does not change. Never makes you wait after failed unlocks, and clears their count. See [Recovery](#recovery). |

### Session

| Command | Description |
| --- | --- |
| `hecate unlock` | Prompt for the master password, then the authenticator code, and start a session. After three failures in a row, each attempt has to wait — see [Failed unlocks](#failed-unlocks). |
| `hecate lock` | End the session immediately. |
| `hecate status` | Show the vault path, the configured timeout, any failed unlock attempts and the wait they have caused, and whether the vault is unlocked and for how much longer. |

### Entries

| Command | Description |
| --- | --- |
| `hecate add TITLE` | Add an entry. Options: `--username`, `--url`, `--notes`, `--tag` (repeatable). The password is always prompted for, and you are warned before reusing one already in the vault. |
| `hecate get TITLE` | Show an entry, with the password masked. `--copy` copies the password to the clipboard and clears it again after `clipboard-clear` seconds, without printing it. `--show` prints it. |
| `hecate edit TITLE` | Update in place. Options: `--title` (rename), `--username`, `--url`, `--notes`, `--password` (flag; prompts, and warns on reuse), `--add-tag`, `--remove-tag`. |
| `hecate list` | List titles and usernames. `--tag` filters. Never prints passwords. |
| `hecate history TITLE` | Show previous passwords, newest first. Masked unless `--show`. |
| `hecate delete TITLE` | Delete an entry, after confirmation. |

Entries are looked up by exact id first, then by case-insensitive title.

`add` and `edit --password` check the password you typed against the ones
already in the vault — see [Password reuse](#password-reuse).

`get --copy` is the way to use a stored password without it landing in your
terminal's scrollback. If `clipboard-clear` is `0`, copying is off and
`--copy` is refused before you are asked to unlock. If there is no clipboard
(a headless Linux box without `xclip`, say), it fails with an error rather
than appearing to succeed. See [Clipboard expiry](#clipboard-expiry).

### Generating passwords

| Command | Description |
| --- | --- |
| `hecate generate` | Make a random password or passphrase, print it on a line of its own, copy it to the clipboard, and offer to save it. No vault or unlock is needed unless you save. |

Every option below overrides the matching [setting](#configuration) for one
run only:

| Option | For | Effect |
| --- | --- | --- |
| `--password` / `--passphrase` | both | Random characters, or random words. Overrides `generate-type`. |
| `--length N` | password | How many characters (8–128). |
| `--uppercase` / `--no-uppercase` | password | Use `A`–`Z`, or not. |
| `--lowercase` / `--no-lowercase` | password | Use `a`–`z`, or not. |
| `--digits` / `--no-digits` | password | Use `0`–`9`, or not. |
| `--symbols TEXT` / `--no-symbols` | password | The special characters to use, or none. |
| `--words N` | passphrase | How many words (4–20). |
| `--separator TEXT` | passphrase | What goes between words: up to 5 spaces or punctuation characters, or `''` for nothing. |
| `--capitalize` / `--no-capitalize` | passphrase | Capitalise every word, or not. |
| `--number` / `--no-number` | passphrase | Add one random digit to one random word, or not. |
| `--no-copy` | both | Do not copy it to the clipboard. |
| `--save` / `--no-save` | both | Save without being asked, or do not offer to save. |

Passing an option for the other kind — `--words` while making a password, say —
is an error rather than being silently ignored.

```
$ hecate generate
k7#Rm2-Lq9^xWz4!pT8e
Password: 20 characters, 125 bits of entropy.
Copied to the clipboard; it will be cleared in 15 seconds.
Save it to Hecate? [Y/n]:
```

**Copying and pasting.** The secret is printed alone on its own line, with no
colour codes, so selecting that line copies exactly the password. It is also
copied to the clipboard and cleared again after `clipboard-clear` seconds;
setting that to `0` turns copying off. Only the secret goes to standard output
— every other line goes to standard error — so redirecting or piping
(`hecate generate --no-save | ...`) captures the password and nothing else.

**Saving.** The save question defaults to yes, because pressing enter without
reading should not lose a password you may already have set on a website.
Saving unlocks the vault if no session is live, then asks for a title and an
optional username. If an entry with that title already exists, you are asked
whether to replace its password; the old one moves into the entry's history, as
with `edit --password`. Turn the question off with
`hecate config set generate-save-prompt off`; `--save` still saves on demand.

### Checking for breaches

| Command | Description |
| --- | --- |
| `hecate check-breach` | Check every password in the vault against Have I Been Pwned's list of breached passwords, and list the entries whose password has turned up, most-seen first. |
| `hecate check-breach TITLE` | Check one entry's password. |

```
$ hecate check-breach
Checking 3 passwords with Have I Been Pwned. Only the first 5 characters of each SHA-1 hash are sent.
  forum: seen 37,359,195 times
  github (harry): seen 17,043 times
2 of 3 passwords appear in known breaches. Change them, most-seen first.
```

This is the only command that uses the network, and it runs only when you ask.
Passwords are never printed, only entry names. "Not found" is not proof that a
password is strong, only that it has not turned up in a breach the service
knows about. The command exits `0` whether or not anything was found, and `1`
if the check could not finish. See [Breach checks](#breach-checks) for exactly
what is sent.

### Backups and importing

| Command | Description |
| --- | --- |
| `hecate export FILE` | Write an encrypted backup of the vault to `FILE`. It opens with the same master password and authenticator as the vault does now, or with the recovery key. Refuses to replace an existing file unless you pass `--force`. |
| `hecate import FILE` | Add the entries from another password manager's CSV export, or from a Hecate backup. Shows what it will add and asks before saving. Never changes an existing entry. |

There is no plaintext export: `export` only writes encrypted backups. See
[Backups](#backups) and [Importing from other managers](#importing-from-other-managers).

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
| `HECATE_HOME` | Directory holding the config, default vault, session, and failed-unlock count. Defaults to `~/.hecate`. |
| `HECATE_VAULT` | Path to the vault file, overriding the default location. |

## Configuration

Settings live in `$HECATE_HOME/config.json`, written `0600`. The backoff on
[failed unlocks](#failed-unlocks) is deliberately not a setting.

| Setting | Default | Range | Meaning |
| --- | --- | --- | --- |
| `session-timeout` | `10` | 0–1440 minutes | Idle minutes before the vault re-locks. `0` disables sessions entirely, prompting on every command. |
| `clipboard-clear` | `15` | 0–300 seconds | Seconds before a copied secret is cleared from the clipboard. `0` turns copying off, so a secret is never left there indefinitely. Used by `generate` and `get --copy`. |
| `generate-type` | `password` | `password`, `passphrase` | What `hecate generate` makes when you do not say. |
| `generate-save-prompt` | `on` | `on`, `off` | Whether `hecate generate` asks to save what it made. |
| `password-length` | `20` | 8–128 | Characters in a generated password. |
| `password-uppercase` | `on` | `on`, `off` | Use `A`–`Z`. |
| `password-lowercase` | `on` | `on`, `off` | Use `a`–`z`. |
| `password-digits` | `on` | `on`, `off` | Use `0`–`9`. |
| `password-symbols` | `'!#$%&*+-.:=?@^_~'` | any printable ASCII punctuation, or `''` | The special characters a generated password may use. Letters, digits and spaces are refused; repeats are dropped. |
| `passphrase-words` | `6` | 4–20 | Words in a generated passphrase. |
| `passphrase-separator` | `'-'` | up to 5 spaces or punctuation characters, or `''` | What goes between words. |
| `passphrase-capitalize` | `off` | `on`, `off` | Capitalise every word. |
| `passphrase-number` | `off` | `on`, `off` | Add one random digit to one random word. |

On/off settings also accept `true`/`false`, `yes`/`no` and `1`/`0`. Text
settings are shown in quotes, so an empty value or a single space is visible.

```bash
hecate config set session-timeout 30
hecate config set session-timeout 0     # maximum paranoia: always prompt
hecate config set generate-type passphrase
hecate config set passphrase-separator ' '
hecate config set password-symbols '!@#$'   # single quotes, so the shell leaves ! and $ alone
```

Each generated password always contains at least one character of every kind
you have switched on, because many sites insist on it. Switching every kind off
is refused when you generate, with a message saying why.

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
changing the password would mean a new DEK and re-encrypting every entry under
it. Wrapping means the DEK never has to change: setting a new password with
`hecate recover` re-wraps the same DEK. (Recovery does re-seal the entries too,
under that same DEK, because the new password's fresh salt changes the
authenticated header — see [Recovery](#recovery).)

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
       ├─▶ still waiting after failed unlocks? ──▶ refuse before asking, stop
       │
  2.   ├─▶ prompt: master password  (hidden input)
       │        │
       │        ├─▶ count the attempt as failed, before checking anything
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
  5.   └─▶ clear the failure count, decrypt payload with the DEK,
           write the session file
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

### Failed unlocks

Hecate counts failed unlocks, and after three in a row it makes you wait before
it will check another. The wait doubles with each further failure, up to an
hour:

| Failures in a row | Wait before the next attempt |
| --- | --- |
| 1–2 | none |
| 3 | 30 seconds |
| 4 | 1 minute |
| 5 | 2 minutes |
| 6 | 4 minutes |
| 7 | 8 minutes |
| 8 | 16 minutes |
| 9 | 32 minutes |
| 10 or more | 1 hour |

```
$ hecate unlock
error: too many failed unlock attempts; try again in 30s.
Lost the authenticator or forgotten the password? 'hecate recover' takes the recovery key and does not wait.
```

While you are waiting, Hecate refuses before asking for anything, so even the
right password is not checked. The rules:

- **An attempt counts the moment you submit a password**, before it is
  checked, and the count is cleared only when the password *and* the code both
  pass. A correct password with a wrong code is a failure, and so is giving up
  at the code prompt. If a correct password reset the count, knowing your
  password would buy unlimited guesses at the code.
- **Counting before checking** means killing the process mid-check cannot get
  a guess through uncounted. The count is updated under an exclusive file lock
  (`fcntl`, on Linux and macOS), so attempts started at the same moment are all
  counted too.
- **`enroll-authenticator` counts the same way**, since it asks for the same
  password and code.
- **`recover` never waits**, and a successful recovery clears the count. The
  recovery key is 160 bits, far too many to guess, so there is nothing to slow
  down.
- **Each vault has its own count**, by path. Unlocking one vault does not clear
  another's.
- **You are told about failures.** The next successful unlock says how many
  failed attempts came before it, and `hecate status` shows the count and any
  wait.
- **It is not a setting**, on purpose. `hecate config set` works without
  unlocking, so a setting would be an off switch for whoever is guessing.

The count lives in `$HECATE_HOME/unlock-attempts.json`, written `0600`. For
each vault path it holds a number and the time of the last failure — nothing
you typed. If the file cannot be read, it counts as no failures: anyone able to
corrupt it could delete it instead, so refusing to unlock would only lock you
out. If the clock goes backwards, a wait never stretches beyond its normal
length.

This slows guessing *through Hecate's prompts* and nothing else. See the
[threat model](#what-hecate-does-not-defend-against--read-this-part) for what
it does not stop.

### What is never written to disk

- The master password, and the key derived from it.
- The recovery key. It is printed once by `init` and never stored — Hecate
  keeps only a *wrapped DEK* that the recovery key can open, which is not the
  same thing and cannot be reversed into it.
- Any password, in plaintext, anywhere. `test_vault_file_contains_no_plaintext`
  asserts the vault file contains no entry title, username, or password in the
  clear.
- A generated password, unless you save it — and then only inside the
  encrypted vault, like any other entry.
- Anything typed at a failed unlock. The failed-unlock record holds only a
  count and a time for each vault.
- Anything about a breach check: no results, and no hash prefixes. See
  [Breach checks](#breach-checks) for why there is no cache.
- A plaintext export. There is none: `export` writes encrypted backups only,
  and `import` reads a CSV without writing its contents anywhere but the
  encrypted vault.

Passwords are prompted for with hidden input, never accepted as command
arguments, so they cannot leak into shell history or `ps` output. `--password`
on `edit` is a *flag* that triggers a prompt, not an option taking a value; a
value passed after it is rejected rather than silently accepted.

### Password history

Changing a password with `hecate edit --password` rotates the old value into
the entry's history with a timestamp, rather than discarding it. `hecate
history` reads it back. Deleting and re-adding an entry loses both the history
and the original creation time — that is why `edit` exists.

### Password reuse

When you set a password — `hecate add`, or `hecate edit --password` — Hecate
compares it against the passwords already in the vault and, if it is already in
use, names the entries using it before asking whether to go ahead:

```
warning: this password is already used by 2 other entries:
  - github (harry)
  - gitlab
Reusing it means one breach exposes every account listed above.
Use this password anyway? [y/N]:
```

**This is a warning, not a rule.** Answering `y` stores the duplicate. You know
things about your accounts that Hecate does not — two entries for the same
login, a throwaway password on a site you do not care about — so the decision
stays yours. The prompt defaults to `N` so that hitting enter without reading
takes the safe path; declining at `add` saves nothing and exits non-zero, while
declining at `edit` drops only the password change and still applies any other
edits you asked for in the same command.

The warning is exact-match and case-sensitive: `Password1` and `password1` are
different secrets and are not reported as duplicates. Entries with no password
set are never treated as sharing one, and password *history* is not searched —
rotating back to a password you previously retired is a different question, and
Hecate does not currently ask it.

Entry passwords are encrypted, never hashed — a password manager has to be able
to give them back to you — so this comparison is a plain lookup over already
decrypted data, not a cryptographic one. It runs through a keyed BLAKE2b digest
under a per-call random pepper, which keeps raw secrets out of dict keys and
traceback reprs. That is hygiene only: the plaintext is already in the process
either way, and it defends against nothing an attacker could do to a running
Hecate. The warning is never printed with the password in it.

### Breach checks

`hecate check-breach` uses Have I Been Pwned's Pwned Passwords service through
its *k-anonymity* range API. For each password:

```
  password ──SHA-1──▶ 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
                      └─┬─┘ └───────────────┬─────────────────┘
          sent to the service               kept on this machine
                        │
                        ▼
  GET https://api.pwnedpasswords.com/range/5BAA6
                        │
                        ▼
  every breached hash starting 5BAA6 (hundreds), each with a count
                        │
                        ▼
  matched against the kept suffix here: found, and how often, or not found
```

- **Only 5 hex characters of each hash leave the machine.** The password and
  its full hash never do. The client refuses to send anything but a
  5-character prefix (`test_fetch_refuses_anything_but_a_prefix`).
- **Replies are padded.** Each request sends `Add-Padding: true`, so the
  service fills its reply with decoy entries and an eavesdropper cannot tell
  from the size which prefix was asked about. Decoys have a count of 0 and are
  ignored.
- **One request per distinct prefix.** A password used by several entries is
  looked up once.
- **HTTPS with certificate checks, no redirects followed.** Anything but a
  plain success is an error, and error messages never include the request URL.
- **No cache, on purpose.** Nothing about a check is written to disk. A saved
  prefix would sit outside the vault's encryption, and for a breached password
  it narrows things down to the few hundred breached passwords sharing it.
- **SHA-1 is used only because the service's list is keyed by it.** It
  protects nothing here.

What the service learns is covered in the
[threat model](#what-hecate-does-not-defend-against--read-this-part).

### Backups

`hecate export FILE` writes the vault, as last saved, to `FILE` as a complete
vault file: the same ciphertext under the same keys. So a backup:

- opens with the master password and authenticator the vault had *when the
  backup was made*, or with the recovery key, which never changes;
- can be opened directly (`hecate --vault FILE list`), merged back in with
  `hecate import FILE`, or copied over a lost or damaged vault file;
- is written atomically and `0600`, like the vault itself.

The vault is unlocked before anything is written, so a vault that no longer
decrypts is refused rather than backed up. A backup is never written over the
vault itself, and an existing file is replaced only with `--force`.

### Importing from other managers

`hecate import FILE` reads a CSV export from another password manager, or a
Hecate backup. A backup is unlocked with *its* master password (and code, if
it has an authenticator). Those attempts count as
[failed unlocks](#failed-unlocks) for the backup file.

CSV columns are matched by name, ignoring case, spaces, underscores and
hyphens, so exports work as they are:

| Hecate field | Column names it answers to, best first |
| --- | --- |
| title | `title`, `name`, `item name`, `account` |
| username | `username`, `login_username`, `user name`, `login name`, `user`, `email` |
| password | `password`, `login_password` |
| url | `url`, `login_uri`, `uri`, `login_url`, `website` |
| notes | `notes`, `note`, `extra`, `comments` |
| tags | `tags` (split on commas), or one tag from `folder`, `grouping`, `group` or `category` |

Exports from Bitwarden, 1Password, LastPass, KeePassXC, Proton Pass, Chrome
and Firefox are tested. Other exports work if their columns use these names.
The import prints which column fed each field and which it ignored, so a
surprise is visible before anything is saved.
A file without a password column is refused before you are asked to unlock.

- **Passwords come across exactly as exported**, spaces and all. Rows without
  a password, such as secure notes or cards, are skipped and counted.
- **Authenticator (TOTP) secrets are never imported.** Hecate is deliberately
  not an authenticator app and has nowhere to keep another service's TOTP
  secret, so columns like `totp`, `login_totp` and `otpauth` are counted,
  reported and dropped. Keep those codes in your authenticator.
- **A missing title** is filled in from the site's host name, then the
  username.

The merge rules are the same for CSVs and backups:

- An entry with the same title (ignoring case and a trailing number like
  `(2)`), username and password as one already in the vault is skipped, so
  importing the same file twice adds nothing.
- An entry whose title is taken is added under the next free number,
  `github (2)`, so nothing is overwritten and nothing is lost.
- Existing entries are never changed. Every added entry gets a new id; its
  notes, tags, timestamps and password history come across unchanged.
- Nothing is saved until you confirm. Afterwards, Hecate warns if any imported
  entry shares its password with another entry.

**The CSV you imported from still holds every password in plain text.** After
an import, Hecate offers to delete it, defaulting to no so you can check the
import first. Deleting overwrites the file with zeros before removing it, but
that is best effort: it does not reliably erase data on SSDs or
copy-on-write filesystems, and it cannot reach copies in backups, sync folders
or the trash.

### Generating passwords and passphrases

Every random choice comes from the operating system's CSPRNG through Python's
`secrets` module, via `crypto/rng.py`. Nothing in the package imports `random`,
and `test_random_module_is_never_imported` keeps it that way.

**Passwords.** Each character is drawn uniformly from the kinds you have
switched on. To guarantee at least one of each kind, Hecate uses rejection
sampling: if a drawn password is missing a kind, it is thrown away and a new one
drawn. That keeps every acceptable password equally likely. The faster shortcut
— patching a missing character into a random position — would quietly skew the
distribution.

**Passphrases.** Words come from the
[EFF large wordlist](https://www.eff.org/dice), shipped unmodified as
`generator/eff_large_wordlist.txt` (SHA-256
`addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`,
© Electronic Frontier Foundation, CC BY 3.0 US). Its four hyphenated words
(`drop-down`, `felt-tip`, `t-shirt`, `yo-yo`) are skipped when it is loaded so a
`-` separator never makes a passphrase ambiguous, leaving 7,772 words. Words
are drawn uniformly and may repeat, exactly as with dice.

**The entropy figure** is log2 of the number of equally likely results your
settings allow — a measure of the settings, not of the one value you got. For
passwords it is counted exactly, by inclusion-exclusion over the kinds that
must appear, and `test_count_matches_brute_force` checks that count against
direct enumeration. For passphrases it is words × log2(7,772), about 12.9 bits
a word; capitalising adds nothing, because every word gets it, and the optional
digit adds log2(10 × words). With an empty separator and no capitals, word
boundaries are invisible and a few word sequences run together into the same
text, so the figure is a slight overstatement. Every extra bit doubles the
guesses needed: the defaults give about 125 bits for a password and 77 for a
passphrase.

### Clipboard expiry

A copied secret is always cleared again — there is no way to copy without a
timer. Because the command exits long before the timer runs out, the clearing
is done by a small detached helper process (`python -m hecate.clipboard`). The
helper is never given the secret: it receives a keyed BLAKE2b fingerprint over a
pipe (never on its command line, where other processes could see it), waits
`clipboard-clear` seconds, and clears the clipboard only if it still holds that
same secret. Anything you copied in the meantime is left alone. Both
`generate` and `get --copy` copy this way.

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
- **Guessing at Hecate's prompts.** After three failures in a row, each attempt
  waits, doubling up to an hour, and only a full unlock resets the count — see
  [Failed unlocks](#failed-unlocks). So someone who knows your master password
  cannot work through the authenticator codes. A 6-digit code takes about
  333,000 guesses on average. With no limit, each guess costs one Argon2id
  derivation, which adds up to hours or days depending on the machine. With
  the limit, once the wait reaches its cap, about 24 guesses a day get
  through, and the average comes to decades.
- **Password reuse across your own entries.** Setting a password that another
  entry already uses prompts for confirmation first. It is a warning you can
  overrule, not an enforced policy, and it is checked only at the moment you
  set a password — there is no command that audits the whole vault yet.
- **Passwords that have turned up in breaches.** `hecate check-breach` looks
  them up in Have I Been Pwned by k-anonymity: only the first 5 characters of
  each SHA-1 hash leave the machine. See [Breach checks](#breach-checks).

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

- **The failed-unlock limit is a gate, not cryptography.** It slows only the
  guesses made through Hecate's own prompts. An attacker with a copy of the
  vault file never sees those prompts. Anyone who can run commands as you can
  delete `unlock-attempts.json`, or simply copy the vault file and attack it
  offline. Against either, what protects you is the strength of the master
  password and the cost of Argon2id. Like the authenticator code, the limit
  raises the bar for someone at your keyboard, not for offline cracking.

- **The recovery key is equivalent in power to the master password.** It
  unwraps the DEK on its own, with no second factor. Anyone who finds it owns
  the vault — and with `hecate recover` can set their own master password and
  authenticator, shutting you out of the normal unlock (your recovery key
  would still work). It cannot be rotated. Store it like a spare house key,
  not like a password hint.

- **The unlock session, while it is live.** After `hecate unlock`, the
  data-encryption key sits in a `0600` file so later commands need no
  password. For that window, any process running as you can read the vault
  without either factor. This is inherent to "don't ask me again for 10
  minutes" — no amount of encrypting that file with a key stored beside it
  would change it. Hecate binds the session to one vault, keeps the expiry
  inside the file, refuses to load it if its permissions have been loosened,
  and defaults the window to 10 minutes. Set `session-timeout` to `0` to opt
  out entirely and be prompted every time.

- **The clipboard, and generated passwords on screen.** While a password sits
  on the clipboard, whether generated or copied with `get --copy`, any program
  running as you can read it.
  Clearing is best effort: it replaces what is on the clipboard *now*, but it
  cannot reach clipboard history (Windows' Win+V, desktop clipboard managers)
  or anything you have already pasted, and if the helper process is killed
  first, nothing is cleared. `generate` also prints the password so you can
  copy it by hand, which leaves it in your terminal's scrollback. Use
  `--no-copy`, or set `clipboard-clear` to `0`, to keep it off the clipboard.

- **Backups, and the files you import from.** A backup is exactly as strong as
  the vault it came from, so store it like the vault. It keeps opening with
  the master password it was made under, even after `recover` sets a new one,
  and with the recovery key for good: retiring a password does not retire old
  backups. A CSV export from another manager is plain text from the moment
  that manager writes it. Hecate offers to delete it after importing, but
  deletion is best effort, and copies in backups, sync folders or the trash
  are out of its reach.

- **What a breach check tells the service.** Have I Been Pwned (served through
  Cloudflare) sees your IP address and the 5-character prefix of each
  password's SHA-1 hash. For a password that is *not* in a breach, the prefix
  is shared with an enormous number of other strings and says next to nothing.
  For one that *is*, it narrows the password down to the few hundred breached
  passwords sharing that prefix. That is the trade k-anonymity makes. A check
  runs only when you ask; to avoid the trade entirely, do not run
  `check-breach`.

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
| BLAKE2b, keyed | Python stdlib | `hashlib.blake2b` — fingerprints for the reuse warning, import de-duplication and clipboard expiry, so raw secrets are never compared or handed around |
| SHA-1 | Python stdlib | `hashlib.sha1(usedforsecurity=False)` — only to look passwords up in Have I Been Pwned, whose list is keyed by it. It protects nothing. |
| TLS | `requests` (urllib3, `certifi` CA bundle) | Breach checks only. Certificate verification is never turned off. |

## Recovery

**There is no server, no backdoor, and no reset without the recovery key.**
Access requires either:

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

### Getting back in

If you lose your authenticator, forget your master password, or both:

```bash
hecate recover
```

It asks for the recovery key (hidden input; spaces, dashes and case do not
matter), then for a master password — a new one, or your old one if you still
know it — and then enrolls a new authenticator the same way `init` does. Pass
`--no-totp` to finish with a password-only vault instead. Any live session is
ended; afterwards, unlock as normal with `hecate unlock`.

`recover` is never held up by [failed unlocks](#failed-unlocks), so it is also
the way back in if you are locked out waiting. A successful recovery clears the
failed-unlock count.

[Backups](#backups) made with `hecate export` open with the recovery key too.
After a recovery they still open with the *old* master password as well, so a
backup taken before you recovered is only as safe as that old password.

Nothing is written until every step has succeeded. A wrong or mistyped
recovery key, or an authenticator code that does not verify, leaves the vault
exactly as it was, and the old credentials keep working.

What changes in the vault file: the master password gets a fresh salt, so one
Argon2id guess cannot be tested against an old copy of the file and the new
one at once. The salt is part of the authenticated header, so all three
ciphertexts — keyring, recovery wrap and entries — are re-sealed under the new
header. The DEK, the recovery salt and the Argon2id parameters stay the same.
The old master password and the old authenticator stop working; **the same
recovery key keeps working.**

**The recovery key cannot be rotated.** Using it does not retire it, and there
is no command to issue a new one. If you think someone else has seen it, the
only remedy today is to create a new vault and re-add your entries to it.

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
│   └── vault.py     lifecycle: create, two-stage unlock, enroll, save, back up
├── auth/
│   ├── totp.py      enrollment URIs and code verification, via pyotp
│   ├── session.py   the idle-window session file
│   └── ratelimit.py backoff on failed unlocks, counted before they are checked
├── audit/
│   └── duplicates.py  password-reuse detection over an unlocked vault
├── generator/
│   ├── password.py    character passwords: rejection sampling, exact entropy
│   ├── passphrase.py  word passphrases from the bundled EFF wordlist
│   ├── result.py      the Generated value; its repr never shows the secret
│   └── eff_large_wordlist.txt
├── cli/main.py      the click app behind the `hecate` entry point
├── clipboard.py     copy with a mandatory expiry; the detached clearing helper
├── config.py        user settings, as a declarative registry
├── transfer/
│   ├── csv_import.py  other managers' CSV exports, matched by column name; never TOTP
│   └── merge.py       what an import adds: skips duplicates, numbers taken titles
└── breach/
    └── hibp.py      Have I Been Pwned range lookups: 5-character prefixes only, no cache
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

No test reaches the network: `tests/conftest.py` makes any real HTTP request
fail the test, and the breach tests use a fake service instead.

## Roadmap

Built and tested:

- [x] Encrypted vault core, key derivation, recovery key
- [x] Two-factor unlock flow
- [x] Sessions with a configurable idle timeout
- [x] Entry commands: add, get, edit, list, history, delete
- [x] Password-reuse warning when adding or changing a password
- [x] Recovery with the recovery key: `hecate recover`
- [x] `hecate generate` — passwords and EFF-wordlist passphrases, configurable,
      with exact entropy figures and an offer to save
- [x] Clipboard copy with automatic clearing, for generated passwords
- [x] Backoff on failed unlocks, for both the master password and the
      authenticator code
- [x] Copying a stored password to the clipboard (`get --copy`)
- [x] `hecate check-breach` — Have I Been Pwned, k-anonymity only
- [x] `hecate import` / `hecate export` — encrypted backups, and CSV import
      from other managers

Everything originally planned is built. Not offered: a plaintext (CSV)
export.
