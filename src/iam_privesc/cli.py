"""iam-privesc: map AWS IAM privilege-escalation paths from authorization details."""

from __future__ import annotations

import argparse
import os
import sys

from .detect import run_detection
from .parser import load_authorization_details
from .render import render_png, to_mermaid
from .report import to_json, to_markdown

DEFAULT_FIXTURE = os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "sample_account.json")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-privesc",
        description="Map AWS IAM privilege-escalation paths and render them as a graph.",
    )
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--input",
        default=None,
        help="Path to a get-account-authorization-details JSON file (default: bundled sample fixture).",
    )
    source.add_argument(
        "--from-account",
        action="store_true",
        help="Pull authorization details live from AWS via boto3 (read-only IAM calls).",
    )
    parser.add_argument("--profile", default=None, help="AWS profile to use with --from-account.")
    parser.add_argument("--region", default=None, help="AWS region to use with --from-account.")
    parser.add_argument("--out-dir", default="out", help="Directory to write reports/graph into.")
    parser.add_argument(
        "--account-label", default=None, help="Label for the account in reports (default: input filename)."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    os.makedirs(args.out_dir, exist_ok=True)

    if args.from_account:
        from .live import fetch_authorization_details

        auth_details = fetch_authorization_details(profile=args.profile, region=args.region)
        account_label = args.account_label or "live-account"
    else:
        input_path = args.input or DEFAULT_FIXTURE
        auth_details = load_authorization_details(input_path)
        account_label = args.account_label or os.path.basename(input_path)

    _principals, graph, findings = run_detection(auth_details)

    json_path = os.path.join(args.out_dir, "findings.json")
    md_path = os.path.join(args.out_dir, "findings.md")
    png_stem = os.path.join(args.out_dir, "graph")
    mmd_path = os.path.join(args.out_dir, "graph.mmd")

    with open(json_path, "w", encoding="utf-8") as f:
        f.write(to_json(findings, account_label))
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(to_markdown(findings, account_label))
    with open(mmd_path, "w", encoding="utf-8") as f:
        f.write(to_mermaid(graph) + "\n")
    png_path = render_png(graph, png_stem + ".png")

    print(f"Principals analyzed: {graph.number_of_nodes()}")
    print(f"Findings: {len(findings)}")
    for finding in findings:
        print(f"  [{finding.severity.upper()}] {finding.principal_name}: {finding.technique_name}")
    print(f"\nWrote {json_path}, {md_path}, {mmd_path}, {png_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
