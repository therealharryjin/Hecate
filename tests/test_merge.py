"""What an import adds: nothing existing changes, nothing incoming is lost."""

from hecate.audit import duplicates
from hecate.transfer import merge
from hecate.vault.model import Entry, PasswordHistoryItem


def _existing():
    return [Entry(title="github", username="harry", password="hunter2")]


def test_new_entries_are_added_with_fresh_ids():
    incoming = [Entry(title="gitlab", username="harry", password="other")]
    plan = merge.plan_merge(_existing(), incoming)
    (added,) = plan.added
    assert added.title == "gitlab"
    assert added.id != incoming[0].id


def test_an_identical_entry_is_skipped():
    plan = merge.plan_merge(_existing(), [Entry(title="GitHub", username="harry", password="hunter2")])
    assert plan.added == []
    assert plan.already_present == 1


def test_a_taken_title_gets_the_next_free_number():
    incoming = [
        Entry(title="github", username="work", password="a"),
        Entry(title="github", username="old", password="b"),
    ]
    plan = merge.plan_merge(_existing(), incoming)
    assert [e.title for e in plan.added] == ["github (2)", "github (3)"]
    assert plan.renamed == [("github", "github (2)"), ("github", "github (3)")]


def test_importing_the_same_thing_twice_adds_nothing_the_second_time():
    incoming = [Entry(title="github", username="work", password="a")]
    vault = _existing()
    vault += merge.plan_merge(vault, incoming).added  # added as "github (2)"

    again = merge.plan_merge(vault, incoming)
    assert again.added == []
    assert again.already_present == 1


def test_duplicates_within_one_import_collapse():
    entry = Entry(title="forum", username="harry", password="x")
    plan = merge.plan_merge([], [entry, Entry(title="forum", username="harry", password="x")])
    assert len(plan.added) == 1
    assert plan.already_present == 1


def test_existing_entries_are_never_modified():
    existing = _existing()
    before = [e.as_dict() for e in existing]
    merge.plan_merge(existing, [Entry(title="github", username="harry", password="changed")])
    assert [e.as_dict() for e in existing] == before


def test_a_backup_entry_keeps_its_history_tags_and_timestamps():
    old = Entry(
        title="bank",
        password="new",
        tags=["finance"],
        created_at="2024-01-01T00:00:00+00:00",
        modified_at="2025-01-01T00:00:00+00:00",
        password_history=[PasswordHistoryItem(password="old", replaced_at="2025-01-01T00:00:00+00:00")],
    )
    (added,) = merge.plan_merge([], [old]).added
    assert added.tags == ["finance"]
    assert added.created_at == old.created_at
    assert added.modified_at == old.modified_at
    assert [h.password for h in added.password_history] == ["old"]

    added.tags.append("changed")  # the plan's copy is its own
    assert old.tags == ["finance"]


# --- shared passwords across many entries ---------------------------------


def test_entries_with_shared_passwords():
    a = Entry(title="a", password="same")
    b = Entry(title="b", password="same")
    c = Entry(title="c", password="unique")
    d = Entry(title="d", password="")
    e = Entry(title="e", password="")
    assert duplicates.entries_with_shared_passwords([a, b, c, d, e]) == [a, b]


def test_shared_passwords_are_exact_matches():
    a = Entry(title="a", password="Password1")
    b = Entry(title="b", password="password1")
    assert duplicates.entries_with_shared_passwords([a, b]) == []
