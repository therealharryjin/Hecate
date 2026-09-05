"""The ``hecate`` command-line interface."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from .. import config as config_mod
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

    password = click.prompt("Master password", hide_input=True).encode("utf-8")
    try:
        pending = vault.verify_password(password)
    except DecryptionError:
        _fail("incorrect master password.")

    code = None
    if pending.requires_totp:
        code = click.prompt("Authenticator code")
    try:
        vault.complete_unlock(pending, code)
    except InvalidTotpCodeError as exc:
        _fail(str(exc))

    if cfg.session_enabled:
        session_mod.start(path, vault.dek, cfg.session_timeout_minutes)
    return vault, cfg


def _describe_window(minutes: int) -> str:
    if minutes <= 0:
        return "sessions are disabled; every command will prompt"
    unit = "minute" if minutes == 1 else "minutes"
    return f"unlocked for {minutes} {unit} of inactivity"


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

    secret = None
    if not no_totp:
        secret = totp_auth.generate_secret()
        account = click.prompt("Account label for the authenticator", default="hecate")
        click.echo("\nEnroll this in your authenticator app:\n")
        click.echo(f"  Secret: {secret}")
        click.echo(f"  URI:    {totp_auth.provisioning_uri(secret, account)}\n")
        code = click.prompt("Enter the current code to confirm enrollment")
        if not totp_auth.verify(secret, code):
            _fail("that code did not verify; nothing was written.")

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
    password = click.prompt("Master password", hide_input=True).encode("utf-8")
    try:
        pending = vault.verify_password(password)
    except DecryptionError:
        _fail("incorrect master password.")
    if pending.requires_totp:
        try:
            vault.complete_unlock(pending, click.prompt("Current authenticator code"))
        except InvalidTotpCodeError as exc:
            _fail(str(exc))
    else:
        vault.complete_unlock(pending)

    secret = totp_auth.generate_secret()
    account = click.prompt("Account label for the authenticator", default="hecate")
    click.echo("\nEnroll this in your authenticator app:\n")
    click.echo(f"  Secret: {secret}")
    click.echo(f"  URI:    {totp_auth.provisioning_uri(secret, account)}\n")
    if not totp_auth.verify(secret, click.prompt("Enter the current code to confirm")):
        _fail("that code did not verify; the vault is unchanged.")

    vault.enroll_totp(secret)
    vault.save()
    session_mod.clear()
    click.secho("Authenticator enrolled. Existing sessions were ended.", fg="green")


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
    """Show whether the vault is currently unlocked."""
    cfg = config_mod.load()
    path = _vault_path(ctx)
    click.echo(f"Vault:           {path}{'' if path.exists() else ' (does not exist)'}")
    click.echo(f"Session timeout: {cfg.session_timeout_minutes} min")

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
        click.echo(f"{name:<{width}}  {cfg.get(name)}")
        click.echo(f"{'':<{width}}  {click.style(setting.help, dim=True)}")


@config_group.command("get")
@click.argument("name")
def config_get(name: str) -> None:
    """Print the value of one setting."""
    try:
        click.echo(config_mod.load().get(name))
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
    click.secho(f"{name} = {parsed}", fg="green")

    if name == "session-timeout":
        click.echo(_describe_window(parsed).capitalize() + ".")
        if parsed == 0:
            session_mod.clear()
            click.echo("Any existing session has been ended.")


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
