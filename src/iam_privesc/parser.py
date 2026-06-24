"""Parse `get-account-authorization-details`-shaped JSON into Principals + a graph."""

from __future__ import annotations

import json

import networkx as nx

from .models import Principal


def _policy_documents_by_arn(policies: list[dict]) -> dict[str, dict]:
    """Map a managed policy ARN to its *default* version document, and also
    keep every version around (needed for the SetDefaultPolicyVersion check)."""
    out: dict[str, dict] = {}
    for policy in policies:
        versions = {v["VersionId"]: v for v in policy.get("PolicyVersionList", [])}
        default = next((v for v in versions.values() if v.get("IsDefaultVersion")), None)
        out[policy["Arn"]] = {
            "name": policy.get("PolicyName", policy["Arn"]),
            "default_document": default["Document"] if default else {},
            "default_version_id": default["VersionId"] if default else None,
            "all_versions": versions,
        }
    return out


def load_authorization_details(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build_principals(auth_details: dict) -> dict[str, Principal]:
    policy_index = _policy_documents_by_arn(auth_details.get("Policies", []))
    principals: dict[str, Principal] = {}

    for user in auth_details.get("UserDetailList", []):
        p = Principal(name=user["UserName"], arn=user["Arn"], kind="user")
        for attached in user.get("AttachedManagedPolicies", []):
            entry = policy_index.get(attached["PolicyArn"])
            if entry:
                p.add_document(entry["default_document"], f"managed:{entry['name']}")
        for inline in user.get("UserPolicyList", []):
            p.add_document(inline["PolicyDocument"], f"inline:{inline['PolicyName']}")
        principals[p.arn] = p

    for role in auth_details.get("RoleDetailList", []):
        p = Principal(name=role["RoleName"], arn=role["Arn"], kind="role")
        trust_doc = role.get("AssumeRolePolicyDocument", {})
        p.trust_statements = trust_doc.get("Statement", [])
        for attached in role.get("AttachedManagedPolicies", []):
            entry = policy_index.get(attached["PolicyArn"])
            if entry:
                p.add_document(entry["default_document"], f"managed:{entry['name']}")
        for inline in role.get("RolePolicyList", []):
            p.add_document(inline["PolicyDocument"], f"inline:{inline['PolicyName']}")
        principals[p.arn] = p

    return principals


def non_default_policy_versions(auth_details: dict) -> dict[str, list[dict]]:
    """ARN -> list of {version_id, document} for *non-default* versions.

    Used by the SetDefaultPolicyVersion technique: a principal who can flip
    the default version can resurrect an old, over-permissive version.
    """
    out: dict[str, list[dict]] = {}
    for policy in auth_details.get("Policies", []):
        versions = policy.get("PolicyVersionList", [])
        non_default = [v for v in versions if not v.get("IsDefaultVersion")]
        if non_default:
            out[policy["Arn"]] = non_default
    return out


def build_graph(principals: dict[str, Principal]) -> nx.DiGraph:
    """A directed graph with one node per principal. Plain capability edges
    (e.g. AssumeRole, PassRole) are added here; escalation edges are added
    later by the detector so they can be styled distinctly when rendered.
    """
    graph = nx.DiGraph()
    for arn, p in principals.items():
        graph.add_node(arn, label=p.name, kind=p.kind)

    for arn, p in principals.items():
        if p.is_admin_equivalent():
            continue  # already at the top; capability edges out of it are noise

        if p.has_action("sts:assumerole"):
            for target_arn, target in principals.items():
                if target.kind != "role" or target_arn == arn:
                    continue
                if not p.grants_resource("sts:assumerole", target_arn):
                    continue
                if _trust_allows(target, arn):
                    graph.add_edge(arn, target_arn, kind="assume_role", label="sts:AssumeRole")

        if p.has_action("iam:passrole"):
            for target_arn, target in principals.items():
                if target.kind != "role":
                    continue
                if p.grants_resource("iam:passrole", target_arn):
                    graph.add_edge(arn, target_arn, kind="pass_role", label="iam:PassRole")

    return graph


def _trust_allows(role: Principal, principal_arn: str) -> bool:
    for stmt in role.trust_statements:
        if stmt.get("Effect") != "Allow":
            continue
        aws_principals = stmt.get("Principal", {}).get("AWS", [])
        if isinstance(aws_principals, str):
            aws_principals = [aws_principals]
        if principal_arn in aws_principals:
            return True
    return False
