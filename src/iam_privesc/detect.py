"""Detect IAM privilege-escalation techniques across a set of principals."""

from __future__ import annotations

from dataclasses import dataclass, field

import networkx as nx

from .models import Principal
from .parser import build_graph, non_default_policy_versions
from .techniques import SEVERITY_ORDER, TECHNIQUES


@dataclass
class Finding:
    principal_arn: str
    principal_name: str
    technique_id: str
    technique_name: str
    severity: str
    description: str
    enabling_permissions: list[str] = field(default_factory=list)
    target: str | None = None  # human-readable: role/user name, policy ARN, or chain
    target_arn: str | None = None  # ARN of the reached principal, if any (used for graph edges)

    def to_dict(self) -> dict:
        return {
            "principal": self.principal_name,
            "principal_arn": self.principal_arn,
            "technique_id": self.technique_id,
            "technique": self.technique_name,
            "severity": self.severity,
            "description": self.description,
            "enabling_permissions": self.enabling_permissions,
            "target": self.target,
            "target_arn": self.target_arn,
        }


def _admin_equivalent_principals(principals: dict[str, Principal]) -> set[str]:
    return {arn for arn, p in principals.items() if p.is_admin_equivalent()}


def detect_self_grant_and_wildcard(principals: dict[str, Principal]) -> list[Finding]:
    """Self-grant/wildcard techniques describe a principal gaining admin
    powers it doesn't already have; an already-admin-equivalent principal
    exercising those same powers isn't an escalation, so it's excluded."""
    findings: list[Finding] = []
    for technique in TECHNIQUES:
        if technique["category"] not in ("self_grant", "wildcard"):
            continue
        for arn, p in principals.items():
            if p.is_admin_equivalent():
                continue
            if all(p.has_action(action) for action in technique["required_actions"]):
                findings.append(
                    Finding(
                        principal_arn=arn,
                        principal_name=p.name,
                        technique_id=technique["id"],
                        technique_name=technique["name"],
                        severity=technique["severity"],
                        description=technique["description"],
                        enabling_permissions=technique["required_actions"],
                    )
                )
    return findings


def _role_trust_allows_service(role: Principal, service_principal: str) -> bool:
    for stmt in role.trust_statements:
        if stmt.get("Effect") != "Allow":
            continue
        services = stmt.get("Principal", {}).get("Service", [])
        if isinstance(services, str):
            services = [services]
        if service_principal in services:
            return True
    return False


def detect_pass_role(principals: dict[str, Principal], graph: nx.DiGraph) -> list[Finding]:
    findings: list[Finding] = []
    service_actions = {
        "passrole_lambda": ("lambda:createfunction", "lambda:invokefunction", "lambda.amazonaws.com"),
        "passrole_ec2": ("ec2:runinstances", "ec2.amazonaws.com"),
    }
    by_id = {t["id"]: t for t in TECHNIQUES}

    for technique_id, spec in service_actions.items():
        *actions, service_principal = spec
        technique = by_id[technique_id]
        for arn, p in principals.items():
            if p.is_admin_equivalent():
                continue
            if not p.has_action("iam:passrole"):
                continue
            if not all(p.has_action(a) for a in actions):
                continue
            passed_roles = [
                v for u, v, d in graph.out_edges(arn, data=True) if d.get("kind") == "pass_role"
            ]
            for role_arn in passed_roles:
                role = principals[role_arn]
                if not role.allow_statements:
                    continue  # role grants nothing interesting
                if not _role_trust_allows_service(role, service_principal):
                    continue  # the service can't actually assume this role
                findings.append(
                    Finding(
                        principal_arn=arn,
                        principal_name=p.name,
                        technique_id=technique["id"],
                        technique_name=technique["name"],
                        severity=technique["severity"],
                        description=technique["description"],
                        enabling_permissions=["iam:PassRole", *actions],
                        target=role.name,
                        target_arn=role_arn,
                    )
                )
    return findings


def detect_rollback(principals: dict[str, Principal], auth_details: dict) -> list[Finding]:
    """iam:SetDefaultPolicyVersion: flag when a principal can flip the
    default version of a policy attached to it that has a more permissive
    non-default version sitting around."""
    findings: list[Finding] = []
    technique = next(t for t in TECHNIQUES if t["id"] == "set_default_policy_version")
    versions_by_policy = non_default_policy_versions(auth_details)

    arn_to_attached_policy_arns: dict[str, list[str]] = {}
    for user in auth_details.get("UserDetailList", []):
        arn_to_attached_policy_arns[user["Arn"]] = [
            a["PolicyArn"] for a in user.get("AttachedManagedPolicies", [])
        ]
    for role in auth_details.get("RoleDetailList", []):
        arn_to_attached_policy_arns[role["Arn"]] = [
            a["PolicyArn"] for a in role.get("AttachedManagedPolicies", [])
        ]

    for arn, p in principals.items():
        if p.is_admin_equivalent():
            continue
        if not p.has_action("iam:setdefaultpolicyversion"):
            continue
        for policy_arn in arn_to_attached_policy_arns.get(arn, []):
            non_default = versions_by_policy.get(policy_arn, [])
            risky = [
                v
                for v in non_default
                if any(
                    s.get("Effect") == "Allow" and s.get("Action") == "*" and s.get("Resource") == "*"
                    for s in v.get("Document", {}).get("Statement", [])
                )
            ]
            if risky:
                findings.append(
                    Finding(
                        principal_arn=arn,
                        principal_name=p.name,
                        technique_id=technique["id"],
                        technique_name=technique["name"],
                        severity=technique["severity"],
                        description=technique["description"],
                        enabling_permissions=technique["required_actions"],
                        target=policy_arn,
                    )
                )
    return findings


def detect_assume_role_chains(principals: dict[str, Principal], graph: nx.DiGraph) -> list[Finding]:
    findings: list[Finding] = []
    technique = next(t for t in TECHNIQUES if t["id"] == "assume_role_chain")
    admin_arns = _admin_equivalent_principals(principals)

    assume_edges = [(u, v) for u, v, d in graph.edges(data=True) if d.get("kind") == "assume_role"]
    chain_graph = nx.DiGraph(assume_edges)

    for arn, p in principals.items():
        if p.is_admin_equivalent() or arn not in chain_graph:
            continue
        for admin_arn in admin_arns:
            if admin_arn == arn or admin_arn not in chain_graph:
                continue
            if nx.has_path(chain_graph, arn, admin_arn):
                path = nx.shortest_path(chain_graph, arn, admin_arn)
                findings.append(
                    Finding(
                        principal_arn=arn,
                        principal_name=p.name,
                        technique_id=technique["id"],
                        technique_name=technique["name"],
                        severity=technique["severity"],
                        description=technique["description"],
                        enabling_permissions=["sts:AssumeRole"],
                        target=" -> ".join(principals[a].name for a in path),
                        target_arn=admin_arn,
                    )
                )
    return findings


def run_detection(auth_details: dict) -> tuple[dict[str, Principal], nx.DiGraph, list[Finding]]:
    from .parser import build_principals

    principals = build_principals(auth_details)
    graph = build_graph(principals)

    findings: list[Finding] = []
    findings += detect_self_grant_and_wildcard(principals)
    findings += detect_pass_role(principals, graph)
    findings += detect_rollback(principals, auth_details)
    findings += detect_assume_role_chains(principals, graph)

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.principal_name, f.technique_id))

    for f in findings:
        if f.target_arn and f.target_arn in principals:
            graph.add_edge(
                f.principal_arn,
                f.target_arn,
                kind="escalation",
                technique=f.technique_id,
                label=f.technique_name,
            )

    return principals, graph, findings
