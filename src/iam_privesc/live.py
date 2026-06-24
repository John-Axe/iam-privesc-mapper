"""Pull authorization details from a real AWS account, read-only.

Uses exactly one IAM API, paginated: GetAccountAuthorizationDetails. It
returns the same shape this tool's offline fixtures use, including inline
and attached managed policies with full version lists, plus trust policies
for roles -- no other AWS calls are made and nothing is ever written.
"""

from __future__ import annotations

from typing import Any


def fetch_authorization_details(profile: str | None = None, region: str | None = None) -> dict[str, Any]:
    import boto3

    session = boto3.Session(profile_name=profile, region_name=region)
    iam = session.client("iam")
    paginator = iam.get_paginator("get_account_authorization_details")

    merged: dict[str, Any] = {
        "UserDetailList": [],
        "GroupDetailList": [],
        "RoleDetailList": [],
        "Policies": [],
    }
    for page in paginator.paginate():
        for key in merged:
            merged[key].extend(page.get(key, []))

    return merged
