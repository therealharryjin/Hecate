"""Reading other managers' CSV exports: columns by name, passwords untouched.

The samples follow each manager's real header layout.
"""

import os

import pytest

from hecate.transfer import csv_import

TOTP_SECRET = "JBSWY3DPEHPK3PXP"

BITWARDEN = (
    "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\r\n"
    f"Social,1,login,github,,,0,https://github.com/login,harry,gh-pass-1,otpauth://totp/GitHub:harry?secret={TOTP_SECRET}\r\n"
    ",,note,Wifi,router is in the closet,,0,,,,\r\n"
    'Work,,login,jira,"line one\r\nline two",,0,https://jira.example.com,harry@example.com,"p,a""ss",\r\n'
)
CHROME = "name,url,username,password,note\ngithub.com,https://github.com/,harry,chrome-pass,\n"
FIREFOX = (
    '"url","username","password","httpRealm","formActionOrigin","guid","timeCreated","timeLastUsed","timePasswordChanged"\n'
    '"https://accounts.example.org","harry","ff-pass",,"https://accounts.example.org","{abc}","1","2","3"\n'
)
LASTPASS = (
    "url,username,password,totp,extra,name,grouping,fav\n"
    "https://example.com,harry,lp-pass,,some notes,Example,Shopping\\Online,0\n"
)
KEEPASSXC = (
    '"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"\n'
    '"Root/Internet","Forum","harry","  spaced  ","forum.example.net","","","0","2024-01-01T00:00:00Z","2024-01-01T00:00:00Z"\n'
)
ONEPASSWORD = (
    "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n"
    'Bank,https://bank.example,harry,1p-pass,,false,false,"finance, important",\n'
)
PROTON = (
    "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n"
    "login,Mail,https://mail.example,harry@proton.me,,proton-pass,,,1,2,Personal\n"
)


@pytest.fixture
def write(tmp_path):
    def _write(text, name="export.csv"):
        path = tmp_path / name
        path.write_bytes(text.encode("utf-8") if isinstance(text, str) else text)
        return path

    return _write


def _only(result):
    (entry,) = result.entries
    return entry


# --- the managers ---------------------------------------------------------


def test_bitwarden(write):
    result = csv_import.read_csv(write(BITWARDEN))
    assert result.rows == 3
    assert result.skipped_without_password == 1  # the secure note
    assert result.rows_with_totp == 1

    github, jira = result.entries
    assert (github.title, github.username, github.password) == ("github", "harry", "gh-pass-1")
    assert github.url == "https://github.com/login"
    assert github.tags == ["Social"]
    assert jira.password == 'p,a"ss'
    assert jira.notes == "line one\r\nline two"
    assert result.columns["password"] == ["login_password"]


def test_chrome(write):
    entry = _only(csv_import.read_csv(write(CHROME)))
    assert (entry.title, entry.username, entry.password) == ("github.com", "harry", "chrome-pass")


def test_firefox_has_no_title_so_the_site_is_used(write):
    entry = _only(csv_import.read_csv(write(FIREFOX)))
    assert entry.title == "accounts.example.org"
    assert entry.password == "ff-pass"


def test_lastpass(write):
    entry = _only(csv_import.read_csv(write(LASTPASS)))
    assert entry.title == "Example"
    assert entry.notes == "some notes"
    assert entry.tags == ["Shopping\\Online"]  # a folder path is one tag


def test_keepassxc_keeps_spaces_in_a_password(write):
    entry = _only(csv_import.read_csv(write(KEEPASSXC)))
    assert entry.title == "Forum"
    assert entry.password == "  spaced  "
    assert entry.tags == ["Root/Internet"]


def test_1password_splits_its_tags(write):
    result = csv_import.read_csv(write(ONEPASSWORD))
    assert _only(result).tags == ["finance", "important"]
    assert result.rows_with_totp == 0  # the OTPAuth column is there but empty


def test_proton_falls_back_to_the_email_column(write):
    entry = _only(csv_import.read_csv(write(PROTON)))
    assert entry.username == "harry@proton.me"


# --- what is never imported ------------------------------------------------


def test_totp_secrets_are_counted_but_never_kept(write):
    result = csv_import.read_csv(write(BITWARDEN))
    for entry in result.entries:
        assert TOTP_SECRET not in repr(entry.as_dict())
    assert "login_totp" not in result.ignored_columns  # reported separately


def test_unknown_columns_are_reported_as_ignored(write):
    result = csv_import.read_csv(write(BITWARDEN))
    assert result.ignored_columns == ["favorite", "type", "fields", "reprompt"]


# --- reading the file -----------------------------------------------------


def test_a_byte_order_mark_is_ignored(write):
    entry = _only(csv_import.read_csv(write("﻿" + CHROME)))
    assert entry.title == "github.com"


def test_header_case_and_separators_do_not_matter(write):
    entry = _only(csv_import.read_csv(write("ITEM-NAME,Login_Username,PASS WORD,Password\nx,harry,,secret\n")))
    assert (entry.title, entry.username, entry.password) == ("x", "harry", "secret")


@pytest.mark.parametrize(
    "row, title",
    [
        (",https://shop.example/cart,harry,pw", "shop.example"),
        (",shop.example,harry,pw", "shop.example"),
        (",,harry,pw", "harry"),
        (",,,pw", csv_import.FALLBACK_TITLE),
    ],
)
def test_a_missing_title_falls_back_to_the_site_then_the_username(write, row, title):
    entry = _only(csv_import.read_csv(write(f"name,url,username,password\n{row}\n")))
    assert entry.title == title


def test_a_file_without_a_password_column_is_refused(write):
    with pytest.raises(csv_import.ImportFormatError, match="no password column"):
        csv_import.read_csv(write("name,url,username\ngithub,https://github.com,harry\n"))


def test_an_empty_file_is_refused(write):
    with pytest.raises(csv_import.ImportFormatError, match="is empty"):
        csv_import.read_csv(write(""))


def test_a_file_that_is_not_utf8_is_refused(write):
    with pytest.raises(csv_import.ImportFormatError, match="not UTF-8"):
        csv_import.read_csv(write(b"name,password\nb\xe9b\xe9,\xff\xfe\n"))


def test_errors_never_quote_a_value(write):
    with pytest.raises(csv_import.ImportFormatError) as caught:
        csv_import.read_csv(write("name,secret\ngithub,hunter2\n"))
    assert "hunter2" not in str(caught.value)


# --- deleting the export --------------------------------------------------


def test_remove_plaintext_overwrites_before_deleting(write, tmp_path):
    path = write(CHROME)
    other_name = tmp_path / "same-file.csv"
    os.link(path, other_name)  # a second name for the same bytes, to look at afterwards

    csv_import.remove_plaintext(path)
    assert not path.exists()
    assert set(other_name.read_bytes()) == {0}
