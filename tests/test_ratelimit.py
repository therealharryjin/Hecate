"""Backoff on failed unlocks: the schedule, the record, and failing safe."""

import json
import multiprocessing
import os
import time

import pytest

from hecate import config as config_mod
from hecate.auth import ratelimit

NOW = 1_800_000_000.0


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv(config_mod.HOME_ENV, str(tmp_path / "home"))


@pytest.fixture
def vault_path(tmp_path):
    path = tmp_path / "vault.hecate"
    path.write_bytes(b"{}")
    return path


def _fail(vault_path, times, *, at=NOW):
    """Fail this many attempts, each as soon as it is allowed."""
    now = at
    for _ in range(times):
        now += ratelimit.check(vault_path, now=now)
        ratelimit.begin(vault_path, now=now)


# --- the schedule ---------------------------------------------------------


def test_the_first_failures_cost_nothing():
    for failures in range(ratelimit.FREE_ATTEMPTS):
        assert ratelimit.delay_after(failures) == 0


def test_the_wait_doubles_after_the_free_attempts():
    free = ratelimit.FREE_ATTEMPTS
    assert ratelimit.delay_after(free) == 30
    assert ratelimit.delay_after(free + 1) == 60
    assert ratelimit.delay_after(free + 2) == 120
    assert ratelimit.delay_after(free + 3) == 240


def test_the_wait_is_capped_at_an_hour():
    assert ratelimit.delay_after(10) == ratelimit.MAX_DELAY_SECONDS == 3600
    assert ratelimit.delay_after(11) == 3600


def test_a_doctored_failure_count_cannot_hang_the_check():
    assert ratelimit.delay_after(10**12) == ratelimit.MAX_DELAY_SECONDS


# --- counting -------------------------------------------------------------


def test_an_attempt_is_counted_before_it_is_checked(vault_path):
    """begin() records a failure up front; nothing else needs to happen."""
    assert ratelimit.begin(vault_path, now=NOW) == 0
    assert ratelimit.status(vault_path).failures == 1


def test_begin_reports_the_failures_before_this_attempt(vault_path):
    _fail(vault_path, 2)
    assert ratelimit.begin(vault_path, now=NOW) == 2


def test_the_free_attempts_run_back_to_back(vault_path):
    _fail(vault_path, ratelimit.FREE_ATTEMPTS)  # none of these raise


def test_the_next_attempt_is_refused_until_the_wait_passes(vault_path):
    _fail(vault_path, ratelimit.FREE_ATTEMPTS)
    with pytest.raises(ratelimit.Throttled) as refused:
        ratelimit.begin(vault_path, now=NOW + 10)
    assert refused.value.wait_seconds == pytest.approx(20)

    ratelimit.begin(vault_path, now=NOW + 31)  # allowed again


def test_a_refused_attempt_is_not_counted(vault_path):
    """Refusal must not stretch the wait, or the owner could never get back in."""
    _fail(vault_path, ratelimit.FREE_ATTEMPTS)
    for _ in range(5):
        with pytest.raises(ratelimit.Throttled):
            ratelimit.begin(vault_path, now=NOW + 1)
    assert ratelimit.status(vault_path).failures == ratelimit.FREE_ATTEMPTS


def test_check_reports_the_wait_without_counting(vault_path):
    _fail(vault_path, ratelimit.FREE_ATTEMPTS)
    assert ratelimit.check(vault_path, now=NOW) == pytest.approx(30)
    assert ratelimit.status(vault_path).failures == ratelimit.FREE_ATTEMPTS


def test_reset_forgets_the_failures(vault_path):
    _fail(vault_path, 5)
    ratelimit.reset(vault_path)
    assert ratelimit.status(vault_path).failures == 0
    assert ratelimit.check(vault_path, now=NOW) == 0


# --- one record per vault -------------------------------------------------


def test_failures_on_one_vault_do_not_throttle_another(vault_path, tmp_path):
    other = tmp_path / "other.hecate"
    other.write_bytes(b"{}")
    _fail(vault_path, 6)
    assert ratelimit.check(other, now=NOW) == 0


def test_unlocking_one_vault_does_not_clear_another(vault_path, tmp_path):
    """Otherwise a vault of your own would reset the count on someone else's."""
    other = tmp_path / "other.hecate"
    other.write_bytes(b"{}")
    _fail(vault_path, 4)
    ratelimit.begin(other, now=NOW)
    ratelimit.reset(other)
    assert ratelimit.status(vault_path).failures == 4


def _attempt(vault_path):
    try:
        ratelimit.begin(vault_path, now=NOW)
    except ratelimit.Throttled:
        return False
    return True


@pytest.mark.skipif(ratelimit.fcntl is None, reason="needs fcntl file locking")
def test_racing_processes_cannot_slip_past_the_count(vault_path):
    """Many attempts at once still get only the free ones through."""
    with multiprocessing.get_context("spawn").Pool(8) as pool:
        allowed = pool.map(_attempt, [vault_path] * 40)
    assert sum(allowed) == ratelimit.FREE_ATTEMPTS
    assert ratelimit.status(vault_path).failures == ratelimit.FREE_ATTEMPTS


def test_two_spellings_of_one_path_share_a_record(vault_path):
    roundabout = vault_path.parent / "." / vault_path.name
    _fail(roundabout, 2)
    assert ratelimit.status(vault_path).failures == 2


# --- the file -------------------------------------------------------------


def test_looking_without_failing_writes_nothing(vault_path):
    assert ratelimit.check(vault_path) == 0
    ratelimit.reset(vault_path)
    assert not ratelimit.attempts_path().exists()


def test_the_record_file_is_owner_only(vault_path):
    ratelimit.begin(vault_path, now=NOW)
    assert os.stat(ratelimit.attempts_path()).st_mode & 0o777 == 0o600


def test_the_record_holds_no_more_than_a_count_and_a_time(vault_path):
    ratelimit.begin(vault_path, now=NOW)
    data = json.loads(ratelimit.attempts_path().read_text())
    assert data == {
        str(vault_path.resolve()): {"failures": 1, "last_failure_at": NOW}
    }


@pytest.mark.parametrize(
    "content",
    [
        "{ not json",
        "[1, 2, 3]",
        '{"%s": {"failures": -4, "last_failure_at": 0}}',
        '{"%s": {"failures": "many", "last_failure_at": 0}}',
        '{"%s": {"failures": 9}}',
        b"\xff\xfe not utf-8",
    ],
)
def test_an_unreadable_record_counts_as_no_failures(vault_path, content):
    """Anyone able to corrupt the file could delete it, so this costs nothing."""
    path = ratelimit.attempts_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        key = json.dumps(str(vault_path.resolve()))[1:-1]
        content = content.replace("%s", key).encode("utf-8")
    path.write_bytes(content)

    assert ratelimit.check(vault_path, now=NOW) == 0
    ratelimit.begin(vault_path, now=NOW)
    assert ratelimit.status(vault_path).failures == 1  # rewritten cleanly


def test_a_clock_set_back_cannot_stretch_the_wait(vault_path):
    """A failure stamped in the future waits one full delay, not until then."""
    _fail(vault_path, ratelimit.FREE_ATTEMPTS, at=NOW + 7 * 24 * 3600)
    assert ratelimit.check(vault_path, now=NOW) == pytest.approx(30)


def test_real_time_is_used_when_none_is_given(vault_path):
    for _ in range(ratelimit.FREE_ATTEMPTS):
        ratelimit.begin(vault_path)
    assert 25 < ratelimit.check(vault_path) <= 30
    assert ratelimit.status(vault_path).last_failure_at == pytest.approx(time.time(), abs=5)
