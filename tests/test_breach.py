"""Have I Been Pwned lookups: only a 5-character prefix ever leaves the machine.

No test reaches the network: a fake session records what would have been sent.
"""

import pytest
import requests

from hecate.breach import hibp

# SHA-1("password"), split the way the range API splits it.
PASSWORD_PREFIX = "5BAA6"
PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8"


class FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class FakeSession:
    def __init__(self, bodies=None, *, status=200, error=None):
        self.bodies = bodies or {}
        self.status = status
        self.error = error
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if self.error is not None:
            raise self.error
        return FakeResponse(self.status, self.bodies.get(url.rsplit("/", 1)[-1], ""))


def _counts(passwords, session):
    return hibp.breach_counts(passwords, fetch=hibp.Client(session).fetch_range)


# --- what is sent ---------------------------------------------------------


def test_sha1_matches_the_known_answer():
    assert hibp.sha1_hex("password") == PASSWORD_PREFIX + PASSWORD_SUFFIX


def test_only_the_five_character_prefix_is_sent():
    session = FakeSession()
    _counts(["password"], session)

    (url, kwargs), = session.calls
    assert url == hibp.API_URL + PASSWORD_PREFIX
    sent = url + repr(kwargs)
    assert PASSWORD_SUFFIX not in sent
    assert "password" not in sent.replace("pwnedpasswords", "")


def test_padding_is_requested_and_redirects_are_not_followed():
    session = FakeSession()
    _counts(["password"], session)
    _url, kwargs = session.calls[0]
    assert kwargs["headers"]["Add-Padding"] == "true"
    assert kwargs["allow_redirects"] is False
    assert kwargs["timeout"] == hibp.TIMEOUT
    assert "verify" not in kwargs  # certificate checks stay at requests' default: on


@pytest.mark.parametrize(
    "prefix",
    ["5BAA61E4C9B93F3F", "5baa6", "5BAA", "password", "5BAAG", ""],
)
def test_fetch_refuses_anything_but_a_prefix(prefix):
    """A guard, so no caller can send more of a hash by mistake."""
    session = FakeSession()
    with pytest.raises(ValueError):
        hibp.Client(session).fetch_range(prefix)
    assert session.calls == []


def test_each_distinct_prefix_is_fetched_once():
    """A password shared by several entries costs one request."""
    session = FakeSession()
    _counts(["password", "password", "letmein", "password"], session)
    assert len(session.calls) == 2


# --- reading the answer ---------------------------------------------------


def test_a_breached_password_reports_how_often_it_was_seen():
    body = f"0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n{PASSWORD_SUFFIX}:9659365\r\n"
    session = FakeSession({PASSWORD_PREFIX: body})
    assert _counts(["password"], session) == [9659365]


def test_a_password_not_in_the_list_counts_zero():
    session = FakeSession({PASSWORD_PREFIX: "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n"})
    assert _counts(["password"], session) == [0]


def test_padding_decoys_count_as_not_found():
    session = FakeSession({PASSWORD_PREFIX: f"{PASSWORD_SUFFIX}:0\r\n"})
    assert _counts(["password"], session) == [0]


def test_results_line_up_with_the_passwords_given():
    session = FakeSession({PASSWORD_PREFIX: f"{PASSWORD_SUFFIX}:7\n"})
    assert _counts(["letmein", "password", "letmein"], session) == [0, 7, 0]


def test_suffixes_match_whatever_their_case():
    session = FakeSession({PASSWORD_PREFIX: f"{PASSWORD_SUFFIX.lower()}:5\n"})
    assert _counts(["password"], session) == [5]


def test_malformed_lines_are_skipped():
    body = f"garbage\n:\nABC:notanumber\n{PASSWORD_SUFFIX}:12\n"
    assert hibp.parse_range(body) == {PASSWORD_SUFFIX: 12}


# --- failures -------------------------------------------------------------


def test_an_unreachable_service_is_reported_without_the_url():
    error = requests.ConnectionError(f"failed to reach {hibp.API_URL}{PASSWORD_PREFIX}")
    with pytest.raises(hibp.BreachCheckError) as caught:
        _counts(["password"], FakeSession(error=error))
    assert "ConnectionError" in str(caught.value)
    assert PASSWORD_PREFIX not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("status", [301, 429, 500, 503])
def test_anything_but_success_is_an_error(status):
    with pytest.raises(hibp.BreachCheckError, match=f"HTTP {status}"):
        _counts(["password"], FakeSession(status=status))


def test_the_suite_cannot_reach_the_network():
    """The guard in conftest.py, which keeps every other test honest."""
    with pytest.raises(AssertionError, match="real network request"):
        requests.Session().get("https://example.com")
