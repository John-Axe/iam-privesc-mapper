import os

import pytest

from iam_privesc.detect import run_detection
from iam_privesc.parser import load_authorization_details

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample_account.json")


@pytest.fixture(scope="module")
def detection_result():
    auth_details = load_authorization_details(FIXTURE_PATH)
    return run_detection(auth_details)


def _findings_for(detection_result, principal_name):
    _principals, _graph, findings = detection_result
    return [f for f in findings if f.principal_name == principal_name]


def test_alice_create_policy_version(detection_result):
    findings = _findings_for(detection_result, "alice")
    assert any(f.technique_id == "create_policy_version" for f in findings)


def test_bob_passrole_lambda(detection_result):
    findings = _findings_for(detection_result, "bob")
    assert any(f.technique_id == "passrole_lambda" and f.target == "AppRole" for f in findings)


def test_carol_put_user_policy(detection_result):
    findings = _findings_for(detection_result, "carol")
    assert any(f.technique_id == "put_user_policy" for f in findings)


def test_eve_assume_role_chain_to_admin(detection_result):
    findings = _findings_for(detection_result, "eve")
    assert any(f.technique_id == "assume_role_chain" and "AdminRole" in (f.target or "") for f in findings)


def test_frank_create_access_key(detection_result):
    findings = _findings_for(detection_result, "frank")
    assert any(f.technique_id == "create_access_key" for f in findings)


def test_grace_iam_wildcard(detection_result):
    findings = _findings_for(detection_result, "grace")
    assert any(f.technique_id == "iam_wildcard" for f in findings)


def test_henry_rollback_to_admin_version(detection_result):
    findings = _findings_for(detection_result, "henry")
    assert any(f.technique_id == "set_default_policy_version" for f in findings)


def test_irene_passrole_ec2(detection_result):
    findings = _findings_for(detection_result, "irene")
    assert any(f.technique_id == "passrole_ec2" for f in findings)


def test_judy_attach_user_policy(detection_result):
    findings = _findings_for(detection_result, "judy")
    assert any(f.technique_id == "attach_user_policy" for f in findings)


def test_dave_clean_principal_has_no_findings(detection_result):
    findings = _findings_for(detection_result, "dave")
    assert findings == []


def test_all_findings_are_ranked_by_severity(detection_result):
    from iam_privesc.techniques import SEVERITY_ORDER

    _principals, _graph, findings = detection_result
    ranks = [SEVERITY_ORDER[f.severity] for f in findings]
    assert ranks == sorted(ranks)


def test_no_crash_on_empty_account():
    _principals, graph, findings = run_detection(
        {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    )
    assert findings == []
    assert graph.number_of_nodes() == 0
