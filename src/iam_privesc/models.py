"""Data model for IAM principals built from authorization-details JSON.

We deliberately do NOT implement a full IAM policy evaluator (no Condition
blocks, no NotAction/NotResource, no SCPs, no permission boundaries). The
goal is to surface *plausible* escalation paths for triage, not to be an
authoritative policy simulator. Resource scoping is honored only where it
materially changes the finding (CreateAccessKey, PassRole, AssumeRole);
everywhere else an Allow on the relevant action is treated as sufficient,
which is conservative (favors false positives over false negatives).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


@dataclass
class Statement:
    effect: str
    actions: list[str]
    resources: list[str]

    @classmethod
    def from_dict(cls, d: dict) -> Statement:
        return cls(
            effect=d.get("Effect", "Deny"),
            actions=[a.lower() for a in _as_list(d.get("Action"))],
            resources=_as_list(d.get("Resource")) or ["*"],
        )


def statements_from_document(document: dict) -> list[Statement]:
    return [Statement.from_dict(s) for s in document.get("Statement", [])]


@dataclass
class Principal:
    """A flattened view of a user or role: who it is and what it can do."""

    name: str
    arn: str
    kind: str  # "user" | "role"
    allow_statements: list[Statement] = field(default_factory=list)
    deny_statements: list[Statement] = field(default_factory=list)
    trust_statements: list[dict] = field(default_factory=list)  # role only
    source_policies: list[str] = field(default_factory=list)  # human-readable provenance

    def add_document(self, document: dict, source: str) -> None:
        for stmt in statements_from_document(document):
            if stmt.effect == "Allow":
                self.allow_statements.append(stmt)
            else:
                self.deny_statements.append(stmt)
        self.source_policies.append(source)

    def has_action(self, action: str) -> bool:
        """Does any Allow statement's action pattern cover `action`, and is it
        not cancelled out by a Deny on the same action with a `*` resource?"""
        action = action.lower()
        allowed = any(
            fnmatch.fnmatch(action, pattern) for stmt in self.allow_statements for pattern in stmt.actions
        )
        if not allowed:
            return False
        denied = any(
            fnmatch.fnmatch(action, pattern) and "*" in stmt.resources
            for stmt in self.deny_statements
            for pattern in stmt.actions
        )
        return not denied

    def resources_for_action(self, action: str) -> list[str]:
        """Resource patterns granted for a given action across Allow statements."""
        action = action.lower()
        out: list[str] = []
        for stmt in self.allow_statements:
            if any(fnmatch.fnmatch(action, pattern) for pattern in stmt.actions):
                out.extend(stmt.resources)
        return out

    def grants_resource(self, action: str, target_arn: str) -> bool:
        patterns = self.resources_for_action(action)
        return any(fnmatch.fnmatch(target_arn, p) for p in patterns)

    def is_admin_equivalent(self) -> bool:
        """Direct `*`:`*` wildcard, the AWS-managed AdministratorAccess shape."""
        return any(
            "*" in stmt.actions and "*" in stmt.resources for stmt in self.allow_statements
        )
