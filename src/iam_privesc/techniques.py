"""Data-driven catalog of known IAM privilege-escalation techniques.

Sourced from the Rhino Security Labs research ("AWS IAM Privilege
Escalation - Methods and Mitigation"). Adding a new technique is a matter
of appending an entry here and, for the simple `self_grant` / `wildcard`
categories, no detector code changes are required at all.

category meanings (consumed by detect.py):
  self_grant  - principal can grant itself more permissions directly.
  wildcard    - a blanket action wildcard that implies the technique.
  pass_role   - iam:PassRole + a service action that lets a privileged
                role's permissions be exercised by the principal.
  rollback    - iam:SetDefaultPolicyVersion style rollback to an old,
                over-permissive policy version.
  assume_role - handled via graph traversal (assume_role edges), not a
                direct action check; kept here for documentation/severity.
"""

from __future__ import annotations

TECHNIQUES = [
    {
        "id": "create_policy_version",
        "name": "iam:CreatePolicyVersion",
        "category": "self_grant",
        "severity": "critical",
        "required_actions": ["iam:CreatePolicyVersion"],
        "description": (
            "Can create a new default version of any customer-managed policy "
            "(CreatePolicyVersion with SetAsDefault=true), including policies "
            "attached to privileged principals, and set arbitrary permissions."
        ),
    },
    {
        "id": "set_default_policy_version",
        "name": "iam:SetDefaultPolicyVersion",
        "category": "rollback",
        "severity": "critical",
        "required_actions": ["iam:SetDefaultPolicyVersion"],
        "description": (
            "Can roll back an attached customer-managed policy to a prior, "
            "non-default version that grants broader permissions."
        ),
    },
    {
        "id": "attach_user_policy",
        "name": "iam:AttachUserPolicy",
        "category": "self_grant",
        "severity": "critical",
        "required_actions": ["iam:AttachUserPolicy"],
        "description": "Can attach an administrator-equivalent managed policy to itself.",
    },
    {
        "id": "attach_role_policy",
        "name": "iam:AttachRolePolicy",
        "category": "self_grant",
        "severity": "critical",
        "required_actions": ["iam:AttachRolePolicy"],
        "description": "Can attach an administrator-equivalent managed policy to a role it controls.",
    },
    {
        "id": "put_user_policy",
        "name": "iam:PutUserPolicy",
        "category": "self_grant",
        "severity": "critical",
        "required_actions": ["iam:PutUserPolicy"],
        "description": "Can write an inline policy granting itself any permission.",
    },
    {
        "id": "put_role_policy",
        "name": "iam:PutRolePolicy",
        "category": "self_grant",
        "severity": "critical",
        "required_actions": ["iam:PutRolePolicy"],
        "description": "Can write an inline policy granting a controlled role any permission.",
    },
    {
        "id": "add_user_to_group",
        "name": "iam:AddUserToGroup",
        "category": "self_grant",
        "severity": "high",
        "required_actions": ["iam:AddUserToGroup"],
        "description": "Can add itself to a more-privileged IAM group.",
    },
    {
        "id": "create_access_key",
        "name": "iam:CreateAccessKey (on another user)",
        "category": "self_grant",
        "severity": "critical",
        "required_actions": ["iam:CreateAccessKey"],
        "description": "Can mint access keys for other users, impersonating them.",
    },
    {
        "id": "passrole_lambda",
        "name": "iam:PassRole + lambda:CreateFunction",
        "category": "pass_role",
        "severity": "critical",
        "required_actions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "description": (
            "Can pass a privileged role to a new Lambda function and invoke it, "
            "executing arbitrary code with that role's permissions."
        ),
    },
    {
        "id": "passrole_ec2",
        "name": "iam:PassRole + ec2:RunInstances",
        "category": "pass_role",
        "severity": "critical",
        "required_actions": ["iam:PassRole", "ec2:RunInstances"],
        "description": (
            "Can launch an EC2 instance with a privileged instance profile and "
            "retrieve its credentials via the instance metadata service."
        ),
    },
    {
        "id": "iam_wildcard",
        "name": "iam:* wildcard",
        "category": "wildcard",
        "severity": "critical",
        "required_actions": ["iam:*"],
        "description": "Holds a blanket iam:* allow, equivalent to full account compromise.",
    },
    {
        "id": "full_wildcard",
        "name": "*:* wildcard (de facto AdministratorAccess)",
        "category": "wildcard",
        "severity": "critical",
        "required_actions": ["*"],
        "description": "Holds an Action:* / Resource:* allow statement -- already an administrator.",
    },
    {
        "id": "assume_role_chain",
        "name": "sts:AssumeRole chain to a privileged role",
        "category": "assume_role",
        "severity": "high",
        "required_actions": ["sts:AssumeRole"],
        "description": "Can assume a role (directly or transitively) that is administrator-equivalent.",
    },
]

TECHNIQUES_BY_ID = {t["id"]: t for t in TECHNIQUES}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
