import os
import shutil

import pytest

from iam_privesc.detect import run_detection
from iam_privesc.parser import load_authorization_details
from iam_privesc.render import render_png, to_mermaid

FIXTURE_PATH = os.path.join(os.path.dirname(__file__), "..", "fixtures", "sample_account.json")


def test_to_mermaid_marks_escalation_edges_red():
    auth_details = load_authorization_details(FIXTURE_PATH)
    _principals, graph, _findings = run_detection(auth_details)
    mermaid = to_mermaid(graph)
    assert mermaid.startswith("graph LR")
    assert "linkStyle" in mermaid
    assert "#e74c3c" in mermaid


@pytest.mark.skipif(shutil.which("dot") is None, reason="graphviz `dot` binary not installed")
def test_render_png_writes_file(tmp_path):
    auth_details = load_authorization_details(FIXTURE_PATH)
    _principals, graph, _findings = run_detection(auth_details)
    out_path = render_png(graph, str(tmp_path / "graph.png"))
    assert os.path.exists(out_path)
    assert os.path.getsize(out_path) > 0
