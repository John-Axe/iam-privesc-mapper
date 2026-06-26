#!/usr/bin/env python3
"""Atheris fuzz target: feed arbitrary bytes as JSON to build_principals."""
import json
import sys

import atheris

with atheris.instrument_imports():
    from iam_privesc.parser import build_principals


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    try:
        text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
        auth = json.loads(text)
        if isinstance(auth, dict):
            build_principals(auth)
    except (json.JSONDecodeError, KeyError, TypeError, ValueError, UnicodeDecodeError):
        pass


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
