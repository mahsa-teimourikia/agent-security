"""Focused invariants for Intermediate 06 egress and SSRF security."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from datetime import timedelta
import importlib.util
from pathlib import Path
import sys

import pytest


COURSE = Path(__file__).parents[1] / "curriculum" / "roadmap" / "intermediate" / "06-network-egress-ssrf-and-external-resource-security"
SPEC = importlib.util.spec_from_file_location("intermediate_06_egress_tests", COURSE / "lab.py")
assert SPEC and SPEC.loader
LAB = importlib.util.module_from_spec(SPEC)
sys.modules.setdefault(SPEC.name, LAB)
SPEC.loader.exec_module(LAB)


SAFE_URL = "https://research.example.test/docs/guide"


def issue_safe(scenario, request_id: str = "test:issue"):
    return scenario.broker.issue(
        "attest:north", LAB.FetchProposal(request_id, SAFE_URL), now=LAB.NOW
    )


def execute_safe(scenario, grant, request_id: str = "test:execute"):
    return scenario.executor.execute(
        "attest:north", grant.grant_id, request_id=request_id, now=LAB.NOW
    )


def test_declared_evaluation_has_exact_populations_and_semantics() -> None:
    report, observations = LAB.evaluate_controls()
    assert (report.cases, report.valid_cases, report.attack_cases, report.failure_cases) == (33, 5, 26, 2)
    assert (report.forbidden_destination_cases, report.redirect_cases, report.resource_cases) == (12, 4, 4)
    assert report.valid_fetch_completion_rate == 1.0
    assert report.forbidden_destination_success_rate == 0.0
    assert report.redirect_policy_bypass_rate == 0.0
    assert report.resource_limit_enforcement_rate == 1.0
    assert report.tls_bypass_rate == 0.0
    assert report.replay_acceptance_rate == 0.0
    assert report.dependency_failure_error_rate == 1.0
    assert report.trace_completeness_rate == 1.0
    assert report.baseline_bypass_rate == 1.0
    assert report.simulated_valid_p95_elapsed_ms == 160
    assert report.max_valid_body_admitted_bytes == 10_000
    assert all(item.status == "error" for item in observations if item.kind is LAB.CaseKind.FAILURE)


@pytest.mark.parametrize(
    ("url", "reason"),
    [
        ("http://research.example.test/docs/guide", "url-scheme"),
        ("file:///etc/passwd", "url-scheme"),
        ("https://user:pass@research.example.test/docs/guide", "url-userinfo"),
        ("https://169.254.169.254/latest/meta-data", "url-ip-literal"),
        ("https://[::1]/", "url-ip-literal"),
        ("https://research.example.test:444/docs/guide", "url-port"),
        ("https://research.example.test/docs/guide#admin", "url-fragment"),
        ("https://research.example.test/docs/../admin", "url-dot-segment"),
        ("https://research.example.test/docs/%252e%252e/admin", "url-encoding-depth"),
        ("https://research.example.test/docs\\admin", "url-backslash"),
        ("https://research.example.test/\nadmin", "url-control-character"),
    ],
)
def test_canonicalization_rejects_ambiguous_or_dangerous_urls(
    url: str, reason: str
) -> None:
    assert LAB.canonicalize_url(url)[1] == reason


def test_canonicalization_normalizes_host_default_port_and_unreserved_path() -> None:
    canonical, reason = LAB.canonicalize_url(
        "HTTPS://Research.Example.Test.:443/docs/%67uide?view=full"
    )
    assert reason == "url-canonical"
    assert canonical.host == "research.example.test"
    assert canonical.port == 443
    assert canonical.normalized == "https://research.example.test/docs/guide?view=full"


@pytest.mark.parametrize(
    ("addresses", "reason"),
    [
        (("127.0.0.1",), "dns-non-global-address"),
        (("10.0.0.8",), "dns-non-global-address"),
        (("100.64.0.1",), "dns-non-global-address"),
        (("169.254.169.254",), "dns-metadata-address"),
        (("fd00:ec2::254",), "dns-metadata-address"),
        (("fd20:ce::254",), "dns-metadata-address"),
        (("::ffff:127.0.0.1",), "dns-non-global-address"),
        (("not-an-ip",), "dns-address-invalid"),
        ((), "dns-empty"),
    ],
)
def test_address_admission_rejects_special_and_metadata_ranges(
    addresses: tuple[str, ...], reason: str
) -> None:
    policy = LAB.build_scenario().policies.policies["north"]
    assert LAB.validate_addresses(addresses, policy)[1] == reason


def test_all_dns_answers_must_be_safe_and_count_is_bounded() -> None:
    policy = LAB.build_scenario().policies.policies["north"]
    assert LAB.validate_addresses(("93.184.216.34", "10.0.0.8"), policy)[0] is None
    assert LAB.validate_addresses(
        ("1.1.1.1", "8.8.8.8", "9.9.9.9", "93.184.216.34", "2606:4700:4700::1111"),
        policy,
    )[1] == "dns-answer-limit"


def test_original_allowed_url_api_uses_shared_parser_and_address_policy() -> None:
    policy = LAB.FetchPolicy(frozenset({"research.example.test"}))
    allowed = LAB.allowed_url(SAFE_URL, policy, resolved_ip="93.184.216.34")
    denied = LAB.allowed_url(SAFE_URL, policy, resolved_ip="127.0.0.1")
    assert allowed["allow"] and allowed["approved_addresses"] == ("93.184.216.34",)
    assert not denied["allow"] and denied["reason"] == "dns-non-global-address"


def test_valid_fetch_pins_connection_authority_and_returns_untrusted_provenance() -> None:
    scenario = LAB.build_scenario()
    response = scenario.application.fetch(
        attestation_id="attest:north", url=SAFE_URL,
        request_id="test:valid", now=LAB.NOW,
    )
    assert response.status is LAB.DecisionStatus.ALLOW
    assert response.result.trust_label == "external-untrusted"
    assert response.result.peer_address == "93.184.216.34"
    assert response.result.body_digest == LAB.digest(response.result.body)
    assert scenario.transport.dispatches == [
        (SAFE_URL, "93.184.216.34", "research.example.test")
    ]
    assert scenario.transport.host_network_calls == 0


def test_redirect_is_manually_reauthorized_resolved_and_pinned_per_hop() -> None:
    scenario = LAB.build_scenario()
    response = scenario.application.fetch(
        attestation_id="attest:north",
        url="https://research.example.test/docs/redirect",
        request_id="test:redirect", now=LAB.NOW,
    )
    assert response.status is LAB.DecisionStatus.ALLOW
    assert response.result.redirect_count == 1
    assert scenario.transport.dispatches == [
        ("https://research.example.test/docs/redirect", "93.184.216.34", "research.example.test"),
        ("https://status.example.test/public/service", "1.1.1.1", "status.example.test"),
    ]


def test_cross_tenant_destination_is_denied_before_transport() -> None:
    scenario = LAB.build_scenario()
    response = scenario.application.fetch(
        attestation_id="attest:north",
        url="https://partner.example.test/docs/guide",
        request_id="test:cross-tenant", now=LAB.NOW,
    )
    assert (response.status, response.reason) == (LAB.DecisionStatus.DENY, "host-denied")
    assert not scenario.transport.dispatches


def test_dns_rebinding_is_rejected_before_transport() -> None:
    scenario = LAB.build_scenario()
    scenario.resolver.sequences["research.example.test"] = (
        ("93.184.216.34",), ("10.0.0.8",),
    )
    response = scenario.application.fetch(
        attestation_id="attest:north", url=SAFE_URL,
        request_id="test:rebind", now=LAB.NOW,
    )
    assert response.status is LAB.DecisionStatus.DENY
    assert response.reason == "dns-non-global-address"
    assert not scenario.transport.dispatches


def test_public_dns_rotation_requires_a_new_grant() -> None:
    scenario = LAB.build_scenario()
    scenario.resolver.sequences["research.example.test"] = (
        ("93.184.216.34",), ("1.1.1.1",),
    )
    response = scenario.application.fetch(
        attestation_id="attest:north", url=SAFE_URL,
        request_id="test:rotate", now=LAB.NOW,
    )
    assert (response.status, response.reason) == (
        LAB.DecisionStatus.DENY, "dns-answer-changed"
    )
    assert not scenario.transport.dispatches


@pytest.mark.parametrize(
    ("fixture", "reason"),
    [
        (LAB.response_fixture(peer="10.0.0.8"), "connection-peer-mismatch"),
        (LAB.response_fixture(tls_name="evil.example.test"), "tls-identity"),
        (LAB.response_fixture(tls_valid=False), "tls-identity"),
        (LAB.response_fixture(elapsed_ms=1_501), "response-deadline"),
        (LAB.response_fixture(body="x", content_length="10001"), "response-wire-limit"),
        (LAB.response_fixture(body="x" * 10_001, wire_bytes=10_001), "response-wire-limit"),
        (LAB.response_fixture(body="x" * 20_001, wire_bytes=9_000), "response-decoded-limit"),
        (LAB.response_fixture(body="x" * 5_000, wire_bytes=100), "response-expansion-limit"),
        (LAB.response_fixture(content_type="application/octet-stream"), "response-content-type"),
    ],
)
def test_executor_enforces_peer_tls_deadline_stream_and_type_boundaries(
    fixture, reason: str
) -> None:
    scenario = LAB.build_scenario()
    scenario.transport.fixtures[SAFE_URL] = fixture
    response = scenario.application.fetch(
        attestation_id="attest:north", url=SAFE_URL,
        request_id=f"test:{reason}", now=LAB.NOW,
    )
    assert (response.status, response.reason, response.result) == (
        LAB.DecisionStatus.DENY, reason, None
    )


def test_sender_workload_and_confirmation_key_are_bound() -> None:
    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:sender").grant
    wrong_sender = scenario.executor.execute(
        "attest:stolen", grant.grant_id,
        request_id="test:wrong-sender", now=LAB.NOW,
    )
    assert wrong_sender.reason == "fetch-sender"

    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:key").grant
    original = scenario.workloads.attestations["attest:north"]
    scenario.workloads.attestations["attest:north"] = replace(
        original, key_thumbprint="key:attacker"
    )
    wrong_key = execute_safe(scenario, grant, "test:wrong-key")
    assert wrong_key.reason == "fetch-sender-key"


def test_expiry_revocation_policy_and_integrity_are_current() -> None:
    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:expiry").grant
    assert scenario.broker.validate_current(
        grant, now=LAB.NOW + timedelta(seconds=30)
    )[1] == "fetch-grant-expired"

    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:revoke").grant
    assert scenario.broker.revoke(grant.grant_id, "incident")
    assert scenario.broker.validate_current(grant, now=LAB.NOW)[1] == "fetch-grant-revoked"

    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:policy").grant
    scenario.policies.policies["north"] = replace(
        scenario.policies.policies["north"], version="egress-policy-v5"
    )
    assert scenario.broker.validate_current(grant, now=LAB.NOW)[1] == "egress-policy-version-changed"

    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:integrity").grant
    tampered = replace(grant, tenant="south")
    scenario.broker.grants[grant.grant_id] = tampered
    assert scenario.broker.validate_current(tampered, now=LAB.NOW)[1] == "fetch-grant-integrity"


def test_atomic_claim_allows_one_concurrent_fetch() -> None:
    scenario = LAB.build_scenario()
    grant = issue_safe(scenario, "test:race").grant

    def invoke(index: int):
        return execute_safe(scenario, grant, f"test:race:{index}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        decisions = list(pool.map(invoke, range(8)))
    assert sum(item.status is LAB.DecisionStatus.ALLOW for item in decisions) == 1
    assert sum(item.reason == "fetch-grant-replayed" for item in decisions) == 7
    assert len(scenario.transport.dispatches) == 1


def test_idempotency_returns_same_grant_and_rejects_collision() -> None:
    scenario = LAB.build_scenario()
    proposal = LAB.FetchProposal("test:idempotent", SAFE_URL)
    first = scenario.broker.issue("attest:north", proposal, now=LAB.NOW)
    retry = scenario.broker.issue("attest:north", proposal, now=LAB.NOW)
    collision = scenario.broker.issue(
        "attest:north", replace(proposal, url="https://research.example.test/docs/html"),
        now=LAB.NOW,
    )
    assert retry.status is LAB.DecisionStatus.IDEMPOTENT
    assert retry.grant == first.grant
    assert (collision.status, collision.reason) == (
        LAB.DecisionStatus.DENY, "request-id-collision"
    )


def test_dependency_failures_are_errors_without_host_fallback() -> None:
    for dependency in ("workloads", "policies", "resolver", "broker", "transport"):
        scenario = LAB.build_scenario()
        if dependency == "transport":
            issued = issue_safe(scenario, "test:transport-down")
            scenario.transport.available = False
            decision = execute_safe(scenario, issued.grant, "test:transport-down:execute")
            assert decision.status is LAB.DecisionStatus.ERROR
        else:
            setattr(getattr(scenario, dependency), "available", False)
            response = scenario.application.fetch(
                attestation_id="attest:north", url=SAFE_URL,
                request_id=f"test:{dependency}-down", now=LAB.NOW,
            )
            assert response.status is LAB.DecisionStatus.ERROR
        assert scenario.application.fallback_fetch_count == 0
        assert scenario.transport.host_network_calls == 0


def test_receipts_are_allowlisted_and_exclude_query_body_and_credentials() -> None:
    scenario = LAB.build_scenario()
    response = scenario.application.fetch(
        attestation_id="attest:north",
        url=f"{SAFE_URL}?token=synthetic-sensitive-value",
        request_id="test:audit", now=LAB.NOW,
    )
    assert response.status is LAB.DecisionStatus.DENY  # no fixture for the query URL
    serialized = str([asdict(item) for item in response.receipts])
    assert "synthetic-sensitive-value" not in serialized
    assert "status\":\"current" not in serialized
    assert "key:north-v4" not in serialized
    assert "password" not in serialized.lower()
