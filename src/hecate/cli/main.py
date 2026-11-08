"""The ``hecate`` command-line interface."""

from __future__ import annotations

import math
import sys
from pathlib import Path

import click

from .. import clipboard
from .. import config as config_mod
from .. import generator
from ..audit import duplicates
from ..auth import ratelimit
from ..auth import session as session_mod
from ..auth import totp as totp_auth
from ..crypto.aead import DecryptionError
from ..vault.model import Entry
from ..vault.vault import InvalidTotpCodeError, Vault, VaultError


def _fail(message: str) -> None:
    click.secho(f"error: {message}", fg="red", err=True)
    sys.exit(1)


def _vault_path(ctx: click.Context) -> Path:
    override = ctx.obj.get("vault_path")
    return Path(override) if override else config_mod.default_vault_path()


def _format_wait(seconds: float) -> str:
    minutes, secs = divmod(math.ceil(seconds), 60)
    return f"{minutes}m {secs}s" if minutes else f"{secs}s"


def _fail_throttled(wait_seconds: float) -> None:
    _fail(
        f"too many failed unlock attempts; try again in {_format_wait(wait_seconds)}.\n"
        "Lost the authenticator or forgotten the password? 'hecate recover' "
        "takes the recovery key and does not wait."
    )


def _fail_attempt(path: Path, message: str) -> None:
    """Fail an unlock attempt, which ratelimit.begin has already counted."""
    wait = ratelimit.check(path)
    if wait > 0:
        message += f" Too many failed attempts: wait {_format_wait(wait)} before trying again."
    _fail(message)


def _authenticate(path: Path, vault: Vault, code_prompt: str = "Authenticator code") -> None:
    """Take the master password and authenticator code, counting the attempt.

    The attempt is counted as failed before either factor is checked, and
    cleared only once both pass. A correct password alone must not clear it,
    or knowing the password would buy unlimited guesses at the code.
    """
    wait = ratelimit.check(path)
    if wait > 0:
        _fail_throttled(wait)

    password = click.prompt("Master password", hide_input=True).encode("utf-8")
    try:
        earlier_failures = ratelimit.begin(path)
    except ratelimit.Throttled as exc:  # another process failed meanwhile
        _fail_throttled(exc.wait_seconds)

    try:
        pending = vault.verify_password(password)
    except DecryptionError:
        _fail_attempt(path, "incorrect master password.")

    code = click.prompt(code_prompt) if pending.requires_totp else None
    try:
        vault.complete_unlock(pending, code)
    except InvalidTotpCodeError as exc:
        _fail_attempt(path, f"{exc}.")

    ratelimit.reset(path)
    if earlier_failures:
        noun = "attempt" if earlier_failures == 1 else "attempts"
        click.secho(
            f"warning: {earlier_failures} failed unlock {noun} since the vault was "
            "last unlocked. If that was not you, someone else tried to get in.",
            fg="yellow",
            err=True,
        )


def _open_unlocked(ctx: click.Context) -> tuple[Vault, config_mod.Config]:
    """Return an unlocked vault, using a live session or prompting for both factors."""
    cfg = config_mod.load()
    path = _vault_path(ctx)
    if not path.exists():
        _fail(f"no vault at {path}. Run 'hecate init' first.")

    vault = Vault.load(path)

    live = session_mod.load(path) if cfg.session_enabled else None
    if live is not None:
        vault.unlock_with_dek(live.dek)
        session_mod.refresh(live, cfg.session_timeout_minutes)
        return vault, cfg

    _authenticate(path, vault)

    if cfg.session_enabled:
        session_mod.start(path, vault.dek, cfg.session_timeout_minutes)
    return vault, cfg


def _confirm_password_reuse(
    vault: Vault, password: str, *, exclude: Entry | None = None
) -> bool:
    """Warn if this password is already in the vault. True means go ahead.

    Reuse is discouraged, never blocked. The user knows things about their own
    accounts that Hecate does not -- two entries for the same login, a throwaway
    password on sites they do not care about -- so this is a prompt, not a rule.
    The default is "no" because that is the safe answer when someone hits enter
    without reading.
    """
    matches = duplicates.entries_sharing_password(
        vault.data.entries, password, exclude=exclude
    )
    if not matches:
        return True

    noun = "entry" if len(matches) == 1 else "entries"
    click.secho(
        f"warning: this password is already used by {len(matches)} other {noun}:",
        fg="yellow",
    )
    for entry in matches:
        label = f"{entry.title} ({entry.username})" if entry.username else entry.title
        click.secho(f"  - {label}", fg="yellow")
    click.secho(
        "Reusing it means one breach exposes every account listed above.",
        fg="yellow",
    )
    return click.confirm("Use this password anyway?", default=False)


def _describe_window(minutes: int) -> str:
    if minutes <= 0:
        return "sessions are disabled; every command will prompt"
    unit = "minute" if minutes == 1 else "minutes"
    return f"unlocked for {minutes} {unit} of inactivity"


def _enroll_new_authenticator(unchanged_message: str) -> str:
    """Show a fresh TOTP secret and return it once the user proves it works.

    Exits with ``unchanged_message`` if the confirmation code does not verify,
    so a mistyped secret can never lock the user out of their own vault.
    """
    secret = totp_auth.generate_secret()
    account = click.prompt("Account label for the authenticator", default="hecate")
    click.echo("\nEnroll this in your authenticator app:\n")
    click.echo(f"  Secret: {secret}")
    click.echo(f"  URI:    {totp_auth.provisioning_uri(secret, account)}\n")
    if not totp_auth.verify(secret, click.prompt("Enter the current code to confirm")):
        _fail(f"that code did not verify; {unchanged_message}")
    return secret


@click.group()
@click.option("--vault", "vault_path", type=click.Path(), help="Path to the vault file.")
@click.version_option(package_name="hecate")
@click.pass_context
def cli(ctx: click.Context, vault_path: str | None) -> None:
    """Hecate - a local-first, encrypted password manager."""
    ctx.ensure_object(dict)
    ctx.obj["vault_path"] = vault_path


# --- setup ----------------------------------------------------------------


@cli.command()
@click.option("--no-totp", is_flag=True, help="Skip authenticator enrollment.")
@click.pass_context
def init(ctx: click.Context, no_totp: bool) -> None:
    """Create a new vault."""
    path = _vault_path(ctx)
    if path.exists():
        _fail(f"a vault already exists at {path}")

    password = click.prompt(
        "Choose a master password", hide_input=True, confirmation_prompt=True
    ).encode("utf-8")

    secret = None if no_totp else _enroll_new_authenticator("nothing was written.")

    try:
        _vault, recovery_key = Vault.create(path, password, totp_secret=secret)
    except VaultError as exc:
        _fail(str(exc))

    click.echo()
    click.secho("=" * 66, fg="yellow")
    click.secho("  RECOVERY KEY - shown once, never again", fg="yellow", bold=True)
    click.secho("=" * 66, fg="yellow")
    click.echo(f"\n    {recovery_key}\n")
    click.echo(
        "Write this down and store it somewhere physically safe, away from\n"
        "this machine. It is the only way back in if you lose your\n"
        "authenticator.\n\n"
        "Lose both your authenticator and this key and the vault is\n"
        "permanently unreadable. There is no reset and no backdoor.\n"
    )
    click.secho(f"Vault created at {path}", fg="green")


@cli.command("enroll-authenticator")
@click.pass_context
def enroll_authenticator(ctx: click.Context) -> None:
    """Add or replace the authenticator app used to unlock the vault."""
    path = _vault_path(ctx)
    if not path.exists():
        _fail(f"no vault at {path}")

    vault = Vault.load(path)
    _authenticate(path, vault, code_prompt="Current authenticator code")

    secret = _enroll_new_authenticator("the vault is unchanged.")
    vault.enroll_totp(secret)
    vault.save()
    session_mod.clear()
    click.secho("Authenticator enrolled. Existing sessions were ended.", fg="green")


@cli.command()
@click.option(
    "--no-totp",
    is_flag=True,
    help="Do not enroll an authenticator; unlock with the master password alone.",
)
@click.pass_context
def recover(ctx: click.Context, no_totp: bool) -> None:
    """Regain access with the recovery key.

    For a lost authenticator, a forgotten master password, or both: sets a
    master password and enrolls a new authenticator, replacing the old ones.
    The recovery key itself does not change.
    """
    path = _vault_path(ctx)
    if not path.exists():
        _fail(f"no vault at {path}")

    vault = Vault.load(path)
    recovery_key = click.prompt("Recovery key", hide_input=True)
    try:
        vault.unlock_with_recovery_key(recovery_key)
    except ValueError as exc:
        _fail(f"{exc}; nothing was changed.")
    except DecryptionError:
        _fail("that recovery key does not open this vault; nothing was changed.")
    click.secho("Recovery key accepted.", fg="green")

    click.echo("Choose a master password. Your old one is fine if you still know it.")
    password = click.prompt(
        "New master password", hide_input=True, confirmation_prompt=True
    ).encode("utf-8")
    secret = None if no_totp else _enroll_new_authenticator("nothing was changed.")

    vault.reset_credentials(recovery_key, password, totp_secret=secret)
    vault.save()
    session_mod.clear()
    # Holding the recovery key settles who owns the vault, and the old
    # credentials the failures were made against are gone.
    ratelimit.reset(path)

    replaced = "Master password" if no_totp else "Master password and authenticator"
    click.secho(f"{replaced} replaced. Existing sessions were ended.", fg="green")
    if no_totp:
        click.echo("This vault no longer asks for an authenticator code.")
    click.echo(
        "Your recovery key has not changed and still works. "
        "Run 'hecate unlock' to open the vault."
    )


# --- session --------------------------------------------------------------


@cli.command()
@click.pass_context
def unlock(ctx: click.Context) -> None:
    """Unlock the vault and start a session."""
    cfg = config_mod.load()
    if not cfg.session_enabled:
        _fail(
            "sessions are disabled (session-timeout is 0). "
            "Set a timeout with 'hecate config set session-timeout 10'."
        )
    _vault, cfg = _open_unlocked(ctx)
    click.secho(f"Vault unlocked - {_describe_window(cfg.session_timeout_minutes)}.", fg="green")


@cli.command()
def lock() -> None:
    """End the session immediately."""
    session_mod.clear()
    click.secho("Vault locked.", fg="green")


@cli.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show whether the vault is unlocked, and any failed unlock attempts."""
    cfg = config_mod.load()
    path = _vault_path(ctx)
    click.echo(f"Vault:           {path}{'' if path.exists() else ' (does not exist)'}")
    click.echo(f"Session timeout: {cfg.session_timeout_minutes} min")

    attempts = ratelimit.status(path)
    if attempts.failures:
        wait = attempts.wait_seconds()
        when = f"next attempt in {_format_wait(wait)}" if wait > 0 else "next attempt allowed now"
        click.secho(f"Failed unlocks:  {attempts.failures} ({when})", fg="yellow")

    live = session_mod.load(path) if cfg.session_enabled else None
    if live is None:
        click.secho("Status:          locked", fg="yellow")
        return
    remaining = int(live.seconds_remaining())
    click.secho(
        f"Status:          unlocked ({remaining // 60}m {remaining % 60}s of idle time left)",
        fg="green",
    )


# --- settings -------------------------------------------------------------


@cli.group("config")
def config_group() -> None:
    """Read and change user settings."""


@config_group.command("list")
def config_list() -> None:
    """Show every setting, its current value, and what it does."""
    cfg = config_mod.load()
    width = max(len(name) for name in config_mod.SETTINGS)
    for name, setting in sorted(config_mod.SETTINGS.items()):
        click.echo(f"{name:<{width}}  {cfg.show(name)}")
        click.echo(f"{'':<{width}}  {click.style(setting.help, dim=True)}")


@config_group.command("get")
@click.argument("name")
def config_get(name: str) -> None:
    """Print the value of one setting."""
    try:
        click.echo(config_mod.load().show(name))
    except KeyError as exc:
        _fail(str(exc).strip("'"))


# ignore_unknown_options so a negative value reaches our validator and gets a
# real message, instead of click rejecting "-1" as an unknown option.
@config_group.command("set", context_settings={"ignore_unknown_options": True})
@click.argument("name")
@click.argument("value")
def config_set(name: str, value: str) -> None:
    """Change a setting, e.g. 'hecate config set session-timeout 15'."""
    cfg = config_mod.load()
    try:
        parsed = cfg.set(name, value)
    except KeyError as exc:
        _fail(str(exc).strip("'"))
    except ValueError as exc:
        _fail(f"{name}: {exc}")
    config_mod.save(cfg)
    click.secho(f"{name} = {cfg.show(name)}", fg="green")

    if name == "session-timeout":
        click.echo(_describe_window(parsed).capitalize() + ".")
        if parsed == 0:
            session_mod.clear()
            click.echo("Any existing session has been ended.")


# --- generating -----------------------------------------------------------


def _switch(value: bool | None) -> str | None:
    return None if value is None else ("on" if value else "off")


def _offer_to_save(
    ctx: click.Context, secret: str, *, save: bool | None, prompt_enabled: bool
) -> None:
    """Store a generated secret in the vault, if the user wants it there.

    The question defaults to yes. Hitting enter without reading should not
    lose a password that may already have been set on a website.
    """
    if save is False or (save is None and not prompt_enabled):
        return
    path = _vault_path(ctx)
    if not path.exists():
        if save:
            _fail(f"no vault at {path}. Run 'hecate init' first.")
        click.secho(
            "There is no vault yet, so it was not saved. Run 'hecate init' to create one.",
            dim=True,
            err=True,
        )
        return
    if save is None and not click.confirm("Save it to Hecate?", default=True, err=True):
        return

    vault, _cfg = _open_unlocked(ctx)
    title = click.prompt("Title for the entry", err=True).strip()
    if not title:
        _fail("a title is required; nothing was saved.")

    existing = vault.data.find(title)
    if existing is not None:
        replace = click.confirm(
            f"{existing.title!r} already exists. Replace its password? "
            "The old one is kept in its history.",
            default=False,
            err=True,
        )
        if not replace or not _confirm_password_reuse(vault, secret, exclude=existing):
            click.echo("Nothing was saved.", err=True)
            return
        existing.set_password(secret)
        vault.save()
        click.secho(
            f"Replaced the password for {existing.title!r}; the old one is in its history.",
            fg="green",
            err=True,
        )
        return

    username = click.prompt("Username (optional)", default="", show_default=False, err=True)
    if not _confirm_password_reuse(vault, secret):
        click.echo("Nothing was saved.", err=True)
        return
    vault.add(Entry(title=title, username=username, password=secret))
    vault.save()
    click.secho(f"Saved as {title!r}.", fg="green", err=True)


@cli.command()
@click.option("--password", "kind", flag_value="password", help="Make a password of random characters.")
@click.option("--passphrase", "kind", flag_value="passphrase", help="Make a passphrase of random words.")
@click.option("--length", type=int, help="Password: how many characters.")
@click.option("--uppercase/--no-uppercase", default=None, help="Password: use A-Z.")
@click.option("--lowercase/--no-lowercase", default=None, help="Password: use a-z.")
@click.option("--digits/--no-digits", default=None, help="Password: use 0-9.")
@click.option("--symbols", help="Password: the special characters to use.")
@click.option("--no-symbols", is_flag=True, help="Password: no special characters.")
@click.option("--words", type=int, help="Passphrase: how many words.")
@click.option("--separator", help="Passphrase: what goes between words.")
@click.option("--capitalize/--no-capitalize", default=None, help="Passphrase: capitalise each word.")
@click.option("--number/--no-number", default=None, help="Passphrase: add one random digit.")
@click.option("--no-copy", is_flag=True, help="Do not copy it to the clipboard.")
@click.option("--save/--no-save", default=None, help="Save it without asking, or do not offer to.")
@click.pass_context
def generate(
    ctx: click.Context,
    kind: str | None,
    length: int | None,
    uppercase: bool | None,
    lowercase: bool | None,
    digits: bool | None,
    symbols: str | None,
    no_symbols: bool,
    words: int | None,
    separator: str | None,
    capitalize: bool | None,
    number: bool | None,
    no_copy: bool,
    save: bool | None,
) -> None:
    """Generate a random password or passphrase.

    Defaults come from your settings ('hecate config list'); the options here
    change them for this run only. The result is printed on a line of its own,
    copied to the clipboard, and offered for saving into the vault.
    """
    if symbols is not None and no_symbols:
        raise click.UsageError("use --symbols or --no-symbols, not both.")

    cfg = config_mod.load()
    kind = kind or cfg.generate_type

    # Each override goes through its setting's own parser, so a bad value gets
    # the same message 'hecate config set' would give.
    overrides = {
        "password": {
            "--length": ("password-length", None if length is None else str(length)),
            "--uppercase/--no-uppercase": ("password-uppercase", _switch(uppercase)),
            "--lowercase/--no-lowercase": ("password-lowercase", _switch(lowercase)),
            "--digits/--no-digits": ("password-digits", _switch(digits)),
            "--symbols/--no-symbols": ("password-symbols", "" if no_symbols else symbols),
        },
        "passphrase": {
            "--words": ("passphrase-words", None if words is None else str(words)),
            "--separator": ("passphrase-separator", separator),
            "--capitalize/--no-capitalize": ("passphrase-capitalize", _switch(capitalize)),
            "--number/--no-number": ("passphrase-number", _switch(number)),
        },
    }
    other = "passphrase" if kind == "password" else "password"
    stray = [flag for flag, (_name, raw) in overrides[other].items() if raw is not None]
    if stray:
        raise click.UsageError(
            f"{', '.join(stray)}: only for a {other}. Add --{other} to make one."
        )
    for flag, (name, raw) in overrides[kind].items():
        if raw is not None:
            try:
                cfg.set(name, raw)
            except ValueError as exc:
                _fail(f"{flag}: {exc}")

    try:
        if kind == "password":
            result = generator.generate_password(cfg.password_policy())
            size = f"{len(result.value)} characters"
        else:
            result = generator.generate_passphrase(cfg.passphrase_policy())
            size = f"{cfg.passphrase_words} words"
    except ValueError as exc:
        _fail(str(exc))

    # The secret alone goes to stdout, on its own line, so it can be selected,
    # piped or redirected cleanly. Everything else goes to stderr.
    click.echo(result.value)
    click.secho(
        f"{kind.capitalize()}: {size}, {int(result.entropy_bits)} bits of entropy.",
        dim=True,
        err=True,
    )

    if not no_copy and cfg.clipboard_clear_seconds > 0:
        try:
            clipboard.copy(result.value, clear_after=cfg.clipboard_clear_seconds)
        except clipboard.ClipboardUnavailable:
            click.secho(
                "No clipboard is available here; copy it from the line above.",
                fg="yellow",
                err=True,
            )
        else:
            click.echo(
                f"Copied to the clipboard; it will be cleared in "
                f"{cfg.clipboard_clear_seconds} seconds.",
                err=True,
            )

    _offer_to_save(ctx, result.value, save=save, prompt_enabled=cfg.generate_save_prompt)


# --- entries --------------------------------------------------------------


@cli.command()
@click.argument("title")
@click.option("--username", default="", help="Username for the entry.")
@click.option("--url", default="", help="URL for the entry.")
@click.option("--notes", default="", help="Free-form notes.")
@click.option("--tag", "tags", multiple=True, help="Tag; repeatable.")
@click.pass_context
def add(ctx: click.Context, title: str, username: str, url: str, notes: str, tags: tuple[str, ...]) -> None:
    """Add an entry. The password is prompted for, never passed as an argument."""
    vault, _cfg = _open_unlocked(ctx)
    if vault.data.find(title) is not None:
        _fail(f"an entry titled {title!r} already exists.")
    password = click.prompt(
        "Password for this entry", hide_input=True, confirmation_prompt=True
    )
    if not _confirm_password_reuse(vault, password):
        raise click.Abort()
    vault.add(
        Entry(
            title=title,
            username=username,
            password=password,
            url=url,
            notes=notes,
            tags=list(tags),
        )
    )
    vault.save()
    click.secho(f"Added {title!r}.", fg="green")


@cli.command("get")
@click.argument("title")
@click.option("--show", is_flag=True, help="Print the password to the terminal.")
@click.pass_context
def get_entry(ctx: click.Context, title: str, show: bool) -> None:
    """Show an entry. The password is masked unless --show is given."""
    vault, _cfg = _open_unlocked(ctx)
    entry = vault.data.find(title)
    if entry is None:
        _fail(f"no entry titled {title!r}.")

    click.echo(f"Title:    {entry.title}")
    if entry.username:
        click.echo(f"Username: {entry.username}")
    if entry.url:
        click.echo(f"URL:      {entry.url}")
    if entry.tags:
        click.echo(f"Tags:     {', '.join(entry.tags)}")
    if entry.notes:
        click.echo(f"Notes:    {entry.notes}")
    click.echo(f"Password: {entry.password if show else '*' * 8 + '  (--show to reveal)'}")
    click.echo(f"Modified: {entry.modified_at}")


@cli.command()
@click.argument("target", metavar="TITLE")
@click.option("--title", "new_title", help="Rename the entry.")
@click.option("--username", help="Set the username. Pass an empty string to clear it.")
@click.option("--url", help="Set the URL.")
@click.option("--notes", help="Set the notes.")
@click.option(
    "--password",
    "change_password",
    is_flag=True,
    help="Prompt for a new password. Takes no value, so no secret reaches your shell history.",
)
@click.option("--add-tag", "add_tags", multiple=True, help="Add a tag; repeatable.")
@click.option("--remove-tag", "remove_tags", multiple=True, help="Remove a tag; repeatable.")
@click.pass_context
def edit(
    ctx: click.Context,
    target: str,
    new_title: str | None,
    username: str | None,
    url: str | None,
    notes: str | None,
    change_password: bool,
    add_tags: tuple[str, ...],
    remove_tags: tuple[str, ...],
) -> None:
    """Update an entry in place.

    Unlike delete-then-add, this preserves the entry's creation time and its
    password history.
    """
    vault, _cfg = _open_unlocked(ctx)
    entry = vault.data.find(target)
    if entry is None:
        _fail(f"no entry titled {target!r}.")

    requested = [
        new_title,
        username,
        url,
        notes,
        change_password or None,
        add_tags or None,
        remove_tags or None,
    ]
    if all(value is None for value in requested):
        _fail("nothing to change. Run 'hecate edit --help' to see the fields.")

    changed: list[str] = []

    if new_title is not None and new_title != entry.title:
        clash = vault.data.find(new_title)
        if clash is not None and clash is not entry:
            _fail(f"an entry titled {new_title!r} already exists.")
        entry.title = new_title
        changed.append("title")

    for field, value in (("username", username), ("url", url), ("notes", notes)):
        if value is not None and getattr(entry, field) != value:
            setattr(entry, field, value)
            changed.append(field)

    if add_tags or remove_tags:
        tags = list(entry.tags)
        for tag in add_tags:
            if tag not in tags:
                tags.append(tag)
        for tag in remove_tags:
            if tag in tags:
                tags.remove(tag)
        if tags != entry.tags:
            entry.tags = tags
            changed.append("tags")

    if change_password:
        new_password = click.prompt(
            "New password", hide_input=True, confirmation_prompt=True
        )
        if new_password == entry.password:
            click.secho(
                "Password is unchanged; no history entry recorded.", fg="yellow"
            )
        elif not _confirm_password_reuse(vault, new_password, exclude=entry):
            # Only the password is dropped; any other requested edits still
            # apply, so declining here does not throw away the rest of the work.
            click.secho("Password left unchanged.", fg="yellow")
        else:
            # set_password rotates the old value into history for us.
            entry.set_password(new_password)
            changed.append("password")

    if not changed:
        click.echo("No changes made.")
        return

    entry.touch()
    vault.save()
    click.secho(f"Updated {entry.title!r} ({', '.join(changed)}).", fg="green")


@cli.command()
@click.argument("title")
@click.option("--show", is_flag=True, help="Reveal the passwords instead of masking them.")
@click.pass_context
def history(ctx: click.Context, title: str, show: bool) -> None:
    """Show an entry's password history, newest first."""
    vault, _cfg = _open_unlocked(ctx)
    entry = vault.data.find(title)
    if entry is None:
        _fail(f"no entry titled {title!r}.")

    def render(value: str) -> str:
        return value if show else "*" * 8

    click.echo(f"{entry.title}\n")
    click.echo(f"  current   {render(entry.password)}")
    if not entry.password_history:
        click.echo("\n  No previous passwords recorded.")
        return
    for item in reversed(entry.password_history):
        click.echo(f"  previous  {render(item.password)}   replaced {item.replaced_at}")
    if not show:
        click.echo("\n" + click.style("Masked; pass --show to reveal.", dim=True))


@cli.command("list")
@click.option("--tag", help="Only show entries carrying this tag.")
@click.pass_context
def list_entries(ctx: click.Context, tag: str | None) -> None:
    """List entry titles. Never prints passwords."""
    vault, _cfg = _open_unlocked(ctx)
    entries = sorted(vault.data.entries, key=lambda e: e.title.lower())
    if tag:
        entries = [e for e in entries if tag in e.tags]
    if not entries:
        click.echo("No entries.")
        return
    width = max(len(e.title) for e in entries)
    for entry in entries:
        click.echo(f"{entry.title:<{width}}  {entry.username}")


@cli.command()
@click.argument("title")
@click.confirmation_option(prompt="Delete this entry permanently?")
@click.pass_context
def delete(ctx: click.Context, title: str) -> None:
    """Delete an entry."""
    vault, _cfg = _open_unlocked(ctx)
    entry = vault.data.find(title)
    if entry is None:
        _fail(f"no entry titled {title!r}.")
    vault.remove(entry)
    vault.save()
    click.secho(f"Deleted {title!r}.", fg="green")


if __name__ == "__main__":  # pragma: no cover
    cli()
