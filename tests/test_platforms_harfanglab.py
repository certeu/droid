"""
Tests of the HarfangLab platform
"""

import pytest
import yaml

from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

from droid.color import ColorLogger
from droid.integrity import integrity_rule_harfanglab
from droid.platforms.harfanglab import HarfangLabPlatform

LOGGER_PARAM = {
    "debug_mode": False,
    "json_enabled": False,
    "json_stdout": False,
    "log_file": None,
}

RULE_ID = "5f5d1b1e-9f2a-4a2b-8e4e-1c2d3e4f5a6b"
CORRELATION_RULE_ID = "7a8b9c0d-2222-3333-4444-555566667777"
HL_ID = "e0d1f2a3-1111-2222-3333-444455556666"
SOURCE_ID = "a-source-id"
CORRELATION_SOURCE_ID = "a-correlation-source-id"
SIGMA_RULE_URL = "https://hurukai.example/api/data/threat_intelligence/SigmaRule/"
CORRELATION_RULE_URL = "https://hurukai.example/api/data/threat_intelligence/CorrelationRule/"

# The Sigma document as emitted by the backend
RULE_CONVERTED = """title: A rule
id: 5f5d1b1e-9f2a-4a2b-8e4e-1c2d3e4f5a6b
status: experimental
level: high
logsource:
  product: windows
detection:
  selection:
    Image|endswith: evil.exe
  condition: selection
"""

# The very same document as HarfangLab stores it: different key order, different
# indentation and quoting
RULE_CONVERTED_RESERIALISED = """detection:
    condition: 'selection'
    selection:
        Image|endswith: "evil.exe"
level: "high"
logsource:
    product: windows
status: experimental
id: "5f5d1b1e-9f2a-4a2b-8e4e-1c2d3e4f5a6b"
title: A rule
"""

ANOTHER_RULE_CONVERTED = """title: A rule
id: 5f5d1b1e-9f2a-4a2b-8e4e-1c2d3e4f5a6b
status: experimental
level: high
logsource:
  product: windows
detection:
  selection:
    Image|endswith: harmless.exe
  condition: selection
"""


# A correlation file converts into the referenced rules followed by the
# correlation itself, as the backend emits them
CORRELATION_CONVERTED = """title: An embedded rule
id: 11111111-1111-1111-1111-111111111111
name: an_embedded_rule
logsource:
  product: windows
detection:
  selection:
    Image|endswith: evil.exe
  condition: selection
level: high

---
title: A correlation
id: 7a8b9c0d-2222-3333-4444-555566667777
correlation:
  type: temporal
  rules:
    - an_embedded_rule
  timespan: 10m
  group-by: null
level: high
"""


class FakeResponse:
    """Minimal stand-in for a requests.Response"""

    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body
        self.content = b"" if body is None else b"a-body"
        self.text = "" if body is None else str(body)

    def json(self):
        if self._body is None:
            raise ValueError("no body to decode")
        return self._body


class RequestRecorder:
    """Capture the calls made to requests.request and replay canned responses"""

    def __init__(self, responses):
        self._responses = list(responses)
        self.calls = []

    def __call__(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, **kwargs})
        if not self._responses:
            raise AssertionError(f"Unexpected {method} request to {url}")
        return self._responses.pop(0)


@contextmanager
def mocked_requests(*responses):
    recorder = RequestRecorder(responses)
    with patch("droid.platforms.harfanglab.requests.request", recorder):
        yield recorder


def build_platform(**overrides):
    parameters = {
        "url": "https://hurukai.example/",
        "token": "a-token",
        "source_id": SOURCE_ID,
        "source_id_correlation": CORRELATION_SOURCE_ID,
    }
    parameters.update(overrides)
    return HarfangLabPlatform(parameters, LOGGER_PARAM)


def build_rule_content(**overrides):
    rule_content = {
        "id": RULE_ID,
        "title": "A rule",
        "status": "experimental",
        "level": "high",
        "logsource": {"product": "windows"},
        "detection": {
            "selection": {"Image|endswith": "evil.exe"},
            "condition": "selection",
        },
    }
    rule_content.update(overrides)
    return rule_content


def build_correlation_content(**overrides):
    """The rule content droid loads for a correlation file, correlation doc merged in"""
    rule_content = {
        "id": CORRELATION_RULE_ID,
        "title": "A correlation",
        "logsource": {"product": "windows"},
        "correlation": {
            "type": "temporal",
            "rules": ["an_embedded_rule"],
            "timespan": "10m",
        },
        "level": "high",
    }
    rule_content.update(overrides)
    return rule_content


def build_existing_rule(**overrides):
    existing_rule = {
        "id": HL_ID,
        "rule_id": RULE_ID,
        "name": "A rule",
        "content": RULE_CONVERTED,
        "source_id": SOURCE_ID,
        "enabled": True,
        "global_state": "alert",
        "hl_status": "testing",
        "block_on_agent": False,
        "quarantine_on_agent": False,
        "rule_level_override": "high",
    }
    existing_rule.update(overrides)
    return existing_rule


def search_results(*rules):
    return FakeResponse(200, {"count": len(rules), "results": list(rules)})


def run_integrity(platform, rule_content, rule_converted):
    parameters = SimpleNamespace(platform="harfang_lab", mssp=False, sentinel_xdr=False)
    logger = ColorLogger("droid.tests.harfanglab", **LOGGER_PARAM)
    return integrity_rule_harfanglab(
        rule_converted, rule_content, platform, "a_rule.yml", parameters, logger, False
    )


# Configuration


def test_missing_url_is_rejected():
    with pytest.raises(ValueError, match="'url' is not set"):
        HarfangLabPlatform({"token": "a-token", "source_id": SOURCE_ID}, LOGGER_PARAM)


def test_missing_token_is_rejected():
    with pytest.raises(ValueError, match="'token' is not set"):
        HarfangLabPlatform(
            {"url": "https://hurukai.example", "source_id": SOURCE_ID}, LOGGER_PARAM
        )


def test_missing_source_id_is_rejected():
    with pytest.raises(ValueError, match="'source_id' is not set"):
        HarfangLabPlatform(
            {"url": "https://hurukai.example", "token": "a-token"}, LOGGER_PARAM
        )


def test_invalid_global_state_is_rejected():
    with pytest.raises(ValueError, match="invalid 'global_state' value 'nope'"):
        build_platform(global_state="nope")


def test_invalid_hl_status_is_rejected():
    with pytest.raises(ValueError, match="invalid 'hl_status' value 'nope'"):
        build_platform(hl_status="nope")


def test_defaults_are_applied():
    platform = build_platform()

    assert platform._tls_verify is True
    assert platform._global_state == "alert"
    assert platform._hl_status == "testing"
    assert platform._block_on_agent is False
    assert platform._quarantine_on_agent is False
    assert platform._api_base_url == "https://hurukai.example/api"


# get_rule


def test_get_rule_returns_the_exact_match():
    """The fuzzy search of the API is narrowed down on the client side"""
    platform = build_platform()
    expected = build_existing_rule()

    with mocked_requests(
        search_results(
            build_existing_rule(id="another-hl-id", rule_id="a-different-rule-id"),
            expected,
            build_existing_rule(id="a-third-hl-id", rule_id=RULE_ID + "-copy"),
        )
    ) as recorder:
        rule = platform.get_rule(RULE_ID)

    assert rule == expected
    assert recorder.calls[0]["method"] == "GET"
    assert recorder.calls[0]["url"] == SIGMA_RULE_URL
    assert recorder.calls[0]["params"] == {
        "source_id": SOURCE_ID,
        "search": RULE_ID,
        "limit": 100,
        "offset": 0,
    }
    assert recorder.calls[0]["headers"]["Authorization"] == "Token a-token"


def test_get_rule_returns_none_without_an_exact_match():
    platform = build_platform()

    with mocked_requests(
        search_results(build_existing_rule(rule_id="a-different-rule-id"))
    ):
        assert platform.get_rule(RULE_ID) is None


def test_get_rule_raises_on_an_error_status():
    platform = build_platform()

    with mocked_requests(FakeResponse(403, {"detail": "forbidden"})):
        with pytest.raises(Exception, match="Could not search for the rule id"):
            platform.get_rule(RULE_ID)


def test_get_rule_raises_on_an_unexpected_body():
    """A 200 carrying something else than the pagination object is an error"""
    platform = build_platform()

    with mocked_requests(FakeResponse(200, "<html>a portal login page</html>")):
        with pytest.raises(Exception, match="Could not search for the rule id"):
            platform.get_rule(RULE_ID)


def test_get_rule_walks_through_the_pages():
    """The fuzzy search can push the rule past the first page of results"""
    platform = build_platform()
    expected = build_existing_rule()

    first_page = FakeResponse(
        200,
        {
            "count": 2,
            "next": SIGMA_RULE_URL + "?offset=1",
            "results": [build_existing_rule(id="another-hl-id", rule_id="another-id")],
        },
    )
    second_page = FakeResponse(200, {"count": 2, "next": None, "results": [expected]})

    with mocked_requests(first_page, second_page) as recorder:
        assert platform.get_rule(RULE_ID) == expected

    assert [call["params"]["offset"] for call in recorder.calls] == [0, 1]


# get_rule_name


def test_get_rule_name_without_a_prefix():
    platform = build_platform()

    assert platform.get_rule_name(build_rule_content()) == "A rule"


def test_get_rule_name_applies_the_prefix():
    platform = build_platform(alert_prefix="DROID")

    assert platform.get_rule_name(build_rule_content()) == "DROID - A rule"


def test_get_rule_name_is_truncated():
    platform = build_platform(alert_prefix="DROID")
    rule_content = build_rule_content(title="A" * 200)

    name = platform.get_rule_name(rule_content, "a_rule.yml")

    assert len(name) == 100
    assert name == ("DROID - " + "A" * 200)[:100]


def test_get_rule_name_truncated_on_a_space_is_trimmed():
    """HarfangLab trims the name it stores, so a cut landing on a space would
    otherwise never compare equal to what was sent"""
    platform = build_platform(alert_prefix="DROID")
    # "DROID - " is 8 characters, so the space lands on the 100th one and the
    # cut would keep it as a trailing space
    title = "B" * 91 + " tail"
    rule_content = build_rule_content(title=title)

    name = platform.get_rule_name(rule_content, "a_rule.yml")

    assert name == "DROID - " + "B" * 91
    assert not name.endswith(" ")


# get_rule_parameters


def test_get_rule_parameters_uses_the_platform_defaults():
    platform = build_platform()

    assert platform.get_rule_parameters(build_rule_content()) == {
        "global_state": "alert",
        "hl_status": "testing",
        "block_on_agent": False,
        "quarantine_on_agent": False,
        "enabled": True,
    }


def test_get_rule_parameters_disables_the_rule():
    platform = build_platform()
    rule_content = build_rule_content(custom={"disabled": True})

    assert platform.get_rule_parameters(rule_content) == {
        "global_state": "disabled",
        "hl_status": "testing",
        "block_on_agent": False,
        "quarantine_on_agent": False,
        "enabled": False,
    }


def test_get_rule_parameters_applies_the_rule_overrides():
    platform = build_platform(global_state="alert", hl_status="testing")
    rule_content = build_rule_content(
        custom={
            "harfanglab": {
                "global_state": "block",
                "hl_status": "stable",
                "quarantine_on_agent": True,
            }
        }
    )

    # Quarantining implies blocking, which is the state HarfangLab would settle on
    assert platform.get_rule_parameters(rule_content) == {
        "global_state": "quarantine",
        "hl_status": "stable",
        "block_on_agent": True,
        "quarantine_on_agent": True,
        "enabled": True,
    }


def test_get_rule_parameters_raises_the_state_to_match_the_agent_flags():
    """Asking for a block on a rule left in the default state is honoured"""
    platform = build_platform(global_state="alert")
    rule_content = build_rule_content(custom={"harfanglab": {"block_on_agent": True}})

    parameters = platform.get_rule_parameters(rule_content)
    assert parameters["global_state"] == "block"
    assert parameters["block_on_agent"] is True
    assert parameters["quarantine_on_agent"] is False


def test_get_rule_parameters_derives_the_agent_flags_from_the_state():
    """A state asking for more than the flags do wins over them"""
    platform = build_platform(global_state="quarantine")
    rule_content = build_rule_content()

    parameters = platform.get_rule_parameters(rule_content)
    assert parameters["block_on_agent"] is True
    assert parameters["quarantine_on_agent"] is True


def test_get_rule_parameters_clears_the_agent_flags_of_a_disabled_rule():
    """A disabled rule cannot block nor quarantine, whatever the flags ask for"""
    platform = build_platform(global_state="quarantine")
    rule_content = build_rule_content(
        custom={"disabled": True, "harfanglab": {"block_on_agent": True}}
    )

    assert platform.get_rule_parameters(rule_content) == {
        "global_state": "disabled",
        "hl_status": "testing",
        "block_on_agent": False,
        "quarantine_on_agent": False,
        "enabled": False,
    }


def test_get_rule_parameters_normalises_backend_alert():
    """HarfangLab stores 'backend_alert' as 'alert', so droid sends 'alert'"""
    platform = build_platform(global_state="backend_alert")

    assert platform.get_rule_parameters(build_rule_content())["global_state"] == "alert"


def test_get_rule_parameters_rejects_an_invalid_override():
    platform = build_platform()
    rule_content = build_rule_content(custom={"harfanglab": {"global_state": "nope"}})

    with pytest.raises(ValueError, match="invalid 'global_state' value 'nope'"):
        platform.get_rule_parameters(rule_content)


# build_rule_payload


def test_build_rule_payload_holds_the_rule():
    platform = build_platform()

    payload = platform.build_rule_payload(
        build_rule_content(), RULE_CONVERTED, "a_rule.yml"
    )

    assert payload["name"] == "A rule"
    assert payload["content"] == RULE_CONVERTED
    assert payload["source_id"] == SOURCE_ID
    assert payload["enabled"] is True
    assert payload["global_state"] == "alert"
    assert payload["hl_status"] == "testing"


def test_build_rule_payload_maps_the_level():
    platform = build_platform()

    payload = platform.build_rule_payload(
        build_rule_content(level="critical"), RULE_CONVERTED, "a_rule.yml"
    )

    assert payload["rule_level_override"] == "critical"


def test_build_rule_payload_clears_an_unknown_level():
    """An unknown level clears the override instead of being sent as is"""
    platform = build_platform()

    payload = platform.build_rule_payload(
        build_rule_content(level="catastrophic"), RULE_CONVERTED, "a_rule.yml"
    )

    assert payload["rule_level_override"] is None


def test_build_rule_payload_includes_the_references():
    platform = build_platform()
    references = ["https://example.org/an-article"]

    payload = platform.build_rule_payload(
        build_rule_content(references=references), RULE_CONVERTED, "a_rule.yml"
    )

    assert payload["references"] == references


def test_build_rule_payload_empties_absent_references():
    """Absent references are sent as an empty list so an update clears them"""
    platform = build_platform()

    payload = platform.build_rule_payload(
        build_rule_content(), RULE_CONVERTED, "a_rule.yml"
    )

    assert payload["references"] == []


# create_rule


def test_create_rule_posts_a_new_rule():
    platform = build_platform()

    with mocked_requests(
        search_results(),
        FakeResponse(201, {"id": HL_ID}),
        # the rule is read back to collect the parsing feedback
        search_results(build_existing_rule()),
    ) as recorder:
        platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")

    assert [call["method"] for call in recorder.calls] == ["GET", "POST", "GET"]
    assert recorder.calls[1]["url"] == SIGMA_RULE_URL
    assert recorder.calls[1]["json"]["content"] == RULE_CONVERTED
    assert recorder.calls[1]["json"]["name"] == "A rule"
    assert recorder.calls[1]["json"]["source_id"] == SOURCE_ID


def test_create_rule_reports_errors_found_after_the_creation():
    """The creation response carries no parsing feedback, the rule is read back"""
    platform = build_platform()

    with mocked_requests(
        search_results(),
        FakeResponse(201, {"id": HL_ID}),
        search_results(build_existing_rule(errors="unknown correlation type")),
    ):
        with pytest.raises(Exception, match="could not parse the rule"):
            platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")


def test_create_rule_raises_when_the_content_is_rejected():
    """The creation endpoint answers 201 even when the Sigma content is refused"""
    platform = build_platform()
    body = {
        "status": [
            {
                "status": False,
                "code": "invalid_sigma_content",
                "content": "the rule could not be parsed",
            }
        ]
    }

    with mocked_requests(search_results(), FakeResponse(201, body)):
        with pytest.raises(Exception, match="invalid_sigma_content"):
            platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")


def test_create_rule_raises_when_the_status_flag_is_omitted():
    """The status flag defaults to false, so an absent one is a rejection too"""
    platform = build_platform()
    body = {"status": [{"code": "duplicate_rule", "content": "already there"}]}

    with mocked_requests(search_results(), FakeResponse(201, body)):
        with pytest.raises(Exception, match="duplicate_rule"):
            platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")


def test_create_rule_hints_at_a_duplicate_id_in_the_status():
    """HarfangLab tells rules apart on their Sigma id, the hint has to say so"""
    platform = build_platform()
    body = {"status": [{"code": "duplicate_rule", "content": "already there"}]}

    with mocked_requests(search_results(), FakeResponse(201, body)):
        with pytest.raises(Exception, match="same Sigma id"):
            platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")


def test_create_rule_hints_at_a_duplicate_id_refused_on_creation():
    """A rule holding the same id in another source is invisible to the lookup"""
    platform = build_platform()
    body = {"id": ["Sigma rule with this Id already exists."]}

    with mocked_requests(search_results(), FakeResponse(400, body)):
        with pytest.raises(Exception, match="same Sigma id"):
            platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")


def test_create_rule_raises_on_an_error_status():
    platform = build_platform()

    with mocked_requests(search_results(), FakeResponse(500, {"detail": "boom"})):
        with pytest.raises(Exception, match="Could not create the rule"):
            platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")


def test_create_rule_raises_plainly_on_an_unrelated_rejection():
    """Only a rejection naming the id gets the duplicate hint"""
    platform = build_platform()

    with mocked_requests(search_results(), FakeResponse(400, {"name": ["too long"]})):
        with pytest.raises(Exception, match="Could not create the rule - 400"):
            platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")


def test_create_rule_patches_a_changed_rule():
    platform = build_platform()
    existing_rule = build_existing_rule(content=ANOTHER_RULE_CONVERTED)

    with mocked_requests(
        search_results(existing_rule), FakeResponse(200, {"id": HL_ID})
    ) as recorder:
        platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")

    assert [call["method"] for call in recorder.calls] == ["GET", "PATCH"]
    assert recorder.calls[1]["url"] == SIGMA_RULE_URL + HL_ID + "/"
    assert recorder.calls[1]["json"]["content"] == RULE_CONVERTED


def test_create_rule_patches_a_rule_changed_on_a_field_only():
    platform = build_platform(hl_status="stable")

    with mocked_requests(
        search_results(build_existing_rule()), FakeResponse(200, {"id": HL_ID})
    ) as recorder:
        platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")

    assert [call["method"] for call in recorder.calls] == ["GET", "PATCH"]
    assert recorder.calls[1]["json"]["hl_status"] == "stable"


def test_create_rule_raises_when_the_update_fails():
    platform = build_platform()
    existing_rule = build_existing_rule(content=ANOTHER_RULE_CONVERTED)

    with mocked_requests(search_results(existing_rule), FakeResponse(400, {"detail": "boom"})):
        with pytest.raises(Exception, match="Could not update the rule"):
            platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")


def test_create_rule_skips_an_unchanged_rule():
    platform = build_platform()

    with mocked_requests(search_results(build_existing_rule())) as recorder:
        platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")

    assert [call["method"] for call in recorder.calls] == ["GET"]


def test_create_rule_skips_a_reserialised_rule():
    """HarfangLab stores its own serialisation of the very same rule"""
    platform = build_platform()
    existing_rule = build_existing_rule(content=RULE_CONVERTED_RESERIALISED)

    with mocked_requests(search_results(existing_rule)) as recorder:
        platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")

    assert [call["method"] for call in recorder.calls] == ["GET"]


def test_create_rule_raises_when_harfanglab_reports_parsing_errors():
    platform = build_platform()
    existing_rule = build_existing_rule(content=ANOTHER_RULE_CONVERTED)
    updated_rule = build_existing_rule(errors=["unsupported field"])

    with mocked_requests(
        search_results(existing_rule), FakeResponse(200, updated_rule)
    ):
        with pytest.raises(Exception, match="could not parse the rule"):
            platform.create_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")


# remove_rule


def test_remove_rule_deletes_the_rule():
    platform = build_platform()

    with mocked_requests(
        search_results(build_existing_rule()), FakeResponse(204)
    ) as recorder:
        platform.remove_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")

    assert [call["method"] for call in recorder.calls] == ["GET", "DELETE"]
    assert recorder.calls[1]["url"] == SIGMA_RULE_URL + HL_ID + "/"


def test_remove_rule_is_a_no_op_when_the_rule_is_absent():
    platform = build_platform()

    with mocked_requests(search_results()) as recorder:
        platform.remove_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")

    assert [call["method"] for call in recorder.calls] == ["GET"]


def test_remove_rule_raises_when_linked_to_correlation_rules():
    platform = build_platform()
    body = {
        "code": "linked_sigma_rule",
        "linked_correlation": [
            {"correlation_rule_name": "A correlation rule"},
            {"correlation_rule_name": "Another correlation rule"},
        ],
    }

    with mocked_requests(search_results(build_existing_rule()), FakeResponse(400, body)):
        with pytest.raises(Exception, match="A correlation rule, Another correlation rule"):
            platform.remove_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")


def test_remove_rule_raises_on_an_error_status():
    platform = build_platform()

    with mocked_requests(search_results(build_existing_rule()), FakeResponse(500, {"detail": "boom"})):
        with pytest.raises(Exception, match="Could not remove the rule"):
            platform.remove_rule(build_rule_content(), RULE_CONVERTED, "a_rule.yml")


# correlation rules


def test_correlation_rules_are_told_apart():
    platform = build_platform()

    assert platform.is_correlation_rule(build_rule_content()) is False
    assert platform.is_correlation_rule(build_correlation_content()) is True


def test_correlation_rule_without_a_source_is_rejected():
    """The correlation source is only required once a correlation rule shows up"""
    platform = build_platform(source_id_correlation=None)

    with pytest.raises(ValueError, match="'source_id_correlation' is not set"):
        platform.create_rule(
            build_correlation_content(), CORRELATION_CONVERTED, "a_correlation.yml"
        )


def test_create_rule_posts_a_correlation_to_its_own_collection():
    """A correlation rule goes to the correlation endpoint and correlation source"""
    platform = build_platform()

    with mocked_requests(
        search_results(),
        FakeResponse(201, {"id": HL_ID}),
        search_results(build_existing_rule(rule_id=CORRELATION_RULE_ID)),
    ) as recorder:
        platform.create_rule(
            build_correlation_content(), CORRELATION_CONVERTED, "a_correlation.yml"
        )

    assert [call["method"] for call in recorder.calls] == ["GET", "POST", "GET"]
    assert recorder.calls[0]["url"] == CORRELATION_RULE_URL
    assert recorder.calls[0]["params"]["source_id"] == CORRELATION_SOURCE_ID
    assert recorder.calls[1]["url"] == CORRELATION_RULE_URL
    assert recorder.calls[1]["json"]["source_id"] == CORRELATION_SOURCE_ID


def test_remove_rule_deletes_a_correlation_from_its_own_collection():
    platform = build_platform()

    with mocked_requests(
        search_results(build_existing_rule(rule_id=CORRELATION_RULE_ID)), FakeResponse(204)
    ) as recorder:
        platform.remove_rule(
            build_correlation_content(), CORRELATION_CONVERTED, "a_correlation.yml"
        )

    assert recorder.calls[1]["method"] == "DELETE"
    assert recorder.calls[1]["url"] == CORRELATION_RULE_URL + HL_ID + "/"


def test_remove_rule_raises_when_linked_to_another_correlation_rule():
    """The correlation collection reports the dependency with its own code"""
    platform = build_platform()
    body = {
        "code": "linked_correlation_rule",
        "linked_correlation": [{"correlation_rule_name": "A parent correlation"}],
    }

    with mocked_requests(
        search_results(build_existing_rule(rule_id=CORRELATION_RULE_ID)),
        FakeResponse(400, body),
    ):
        with pytest.raises(Exception, match="A parent correlation"):
            platform.remove_rule(
                build_correlation_content(), CORRELATION_CONVERTED, "a_correlation.yml"
            )


def test_correlation_content_is_adapted_to_the_harfanglab_dialect():
    """HarfangLab refuses a null correlation key and untagged embedded rules"""
    platform = build_platform()

    content = platform.get_rule_content(build_correlation_content(), CORRELATION_CONVERTED)
    documents = list(yaml.safe_load_all(content))

    assert len(documents) == 2
    # The embedded atomic rule must not be compiled as a standalone detection
    assert documents[0]["generate"] is False
    # The backend emits "group-by: null", which the API rejects
    assert "group-by" not in documents[1]["correlation"]
    assert documents[1]["correlation"]["timespan"] == "10m"


def test_atomic_content_is_left_untouched():
    platform = build_platform()

    assert platform.get_rule_content(build_rule_content(), RULE_CONVERTED) == RULE_CONVERTED


def test_correlation_content_adaptation_is_idempotent():
    """The adaptation becomes a no-op once the backend emits the dialect itself"""
    platform = build_platform()
    rule_content = build_correlation_content()

    once = platform.get_rule_content(rule_content, CORRELATION_CONVERTED)
    twice = platform.get_rule_content(rule_content, once)

    assert list(yaml.safe_load_all(once)) == list(yaml.safe_load_all(twice))


def test_content_matches_a_reserialised_correlation():
    """A multi document correlation compares structurally too"""
    platform = build_platform()
    adapted = platform.get_rule_content(build_correlation_content(), CORRELATION_CONVERTED)
    reserialised = "---\n".join(
        yaml.safe_dump(document, sort_keys=True, indent=6)
        for document in yaml.safe_load_all(adapted)
    )

    assert platform.content_matches(reserialised, adapted) is True


# content_matches


def test_content_matches_a_reserialised_rule():
    platform = build_platform()

    assert platform.content_matches(RULE_CONVERTED_RESERIALISED, RULE_CONVERTED) is True


def test_content_matches_rejects_a_different_rule():
    platform = build_platform()

    assert platform.content_matches(ANOTHER_RULE_CONVERTED, RULE_CONVERTED) is False


# integrity


def test_integrity_rule_matching_the_platform():
    """A rule matching the platform is not an integrity error"""
    platform = build_platform()
    existing_rule = build_existing_rule(content=RULE_CONVERTED_RESERIALISED)

    with mocked_requests(search_results(existing_rule)):
        error = run_integrity(platform, build_rule_content(), RULE_CONVERTED)

    assert not error


def test_integrity_rule_not_matching_the_platform():
    """A rule differing from the platform is an integrity error"""
    platform = build_platform()
    existing_rule = build_existing_rule(content=ANOTHER_RULE_CONVERTED)

    with mocked_requests(search_results(existing_rule)):
        error = run_integrity(platform, build_rule_content(), RULE_CONVERTED)

    assert error


def test_integrity_rule_name_not_matching_the_platform():
    """A rule renamed on the platform is an integrity error"""
    platform = build_platform()
    existing_rule = build_existing_rule(name="Another name")

    with mocked_requests(search_results(existing_rule)):
        error = run_integrity(platform, build_rule_content(), RULE_CONVERTED)

    assert error


def test_integrity_rule_absent_from_the_platform():
    """A rule missing from the platform is an integrity error"""
    platform = build_platform()

    with mocked_requests(search_results()):
        error = run_integrity(platform, build_rule_content(), RULE_CONVERTED)

    assert error


def test_integrity_removed_rule_absent_from_the_platform():
    """A removed rule already deleted from the platform is not an integrity error"""
    platform = build_platform()
    rule_content = build_rule_content(custom={"removed": True})

    with mocked_requests(search_results()):
        error = run_integrity(platform, rule_content, RULE_CONVERTED)

    assert not error


def test_integrity_rule_with_parsing_errors():
    """A rule HarfangLab could not parse is an integrity error"""
    platform = build_platform()
    existing_rule = build_existing_rule(errors=["unsupported field"])

    with mocked_requests(search_results(existing_rule)):
        error = run_integrity(platform, build_rule_content(), RULE_CONVERTED)

    assert error


def test_integrity_rule_disabled_on_the_platform():
    """A rule not enabled on the platform is an integrity error"""
    platform = build_platform()
    existing_rule = build_existing_rule(enabled=False)

    with mocked_requests(search_results(existing_rule)):
        error = run_integrity(platform, build_rule_content(), RULE_CONVERTED)

    assert error


def test_integrity_disabled_rule_disabled_on_the_platform():
    """A rule disabled as expected is not an integrity error"""
    platform = build_platform()
    existing_rule = build_existing_rule(enabled=False)
    rule_content = build_rule_content(custom={"disabled": True})

    with mocked_requests(search_results(existing_rule)):
        error = run_integrity(platform, rule_content, RULE_CONVERTED)

    assert not error


def test_raw_rules_are_never_raw_on_harfanglab():
    """HarfangLab only takes Sigma, so a rule sitting in the raw directory is
    not treated as a raw one"""
    from droid.config import is_raw_rule

    parameters = SimpleNamespace(platform="harfang_lab", rules="rules-raw/harfang_lab")
    assert is_raw_rule(parameters, {"raw_rules_directory": "rules-raw"}) is False
