"""Render Finding lists as JSON and Markdown reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .detect import Finding

SEVERITY_EMOJI = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED]", "low": "[LOW]"}


def to_json(findings: list[Finding], account_label: str = "sample_account") -> str:
    payload = {
        "account": account_label,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def to_markdown(findings: list[Finding], account_label: str = "sample_account") -> str:
    lines = [
        "# IAM Privilege-Escalation Findings",
        "",
        f"Account: `{account_label}`",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        f"Total findings: **{len(findings)}**",
        "",
    ]

    if not findings:
        lines.append("No privilege-escalation paths detected.")
        return "\n".join(lines) + "\n"

    lines += [
        "| Severity | Principal | Technique | Enabling Permissions | Target |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        tag = SEVERITY_EMOJI.get(f.severity, f.severity.upper())
        perms = ", ".join(f"`{p}`" for p in f.enabling_permissions)
        target = f.target or "-"
        lines.append(f"| {tag} {f.severity} | {f.principal_name} | {f.technique_name} | {perms} | {target} |")

    lines += ["", "## Details", ""]
    for f in findings:
        lines.append(f"### {f.principal_name}: {f.technique_name} ({f.severity})")
        lines.append("")
        lines.append(f.description)
        lines.append("")
        lines.append(f"- Enabling permissions: {', '.join(f.enabling_permissions)}")
        if f.target:
            lines.append(f"- Target: {f.target}")
        lines.append("")

    return "\n".join(lines) + "\n"
