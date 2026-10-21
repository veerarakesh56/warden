"""The watched applications' own tests, run by CI · apps (_apps-check.yml) - where a code fix's test lands (the code
gate's `test_paths`, data/code_fix.yaml, register B4).

Every Lambda's module is named `app`, so a test loads one by its folder's name with `load_app` instead of importing
it. This file is a person's: the code gate never lets a code fix change a `conftest.py`.
"""

from __future__ import annotations

import importlib.util
import pathlib
from types import ModuleType

import pytest

FULLSTACK = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture
def load_app():
    """`load_app("notifier")`: scenarios/fullstack/lambdas/notifier/app.py as a fresh module; `load_app("app")`: the
    container's scenarios/fullstack/app/app.py."""

    def load(name: str) -> ModuleType:
        path = FULLSTACK / "app" / "app.py" if name == "app" else FULLSTACK / "lambdas" / name / "app.py"
        spec = importlib.util.spec_from_file_location(f"fullstack_{name.replace('-', '_')}", path)
        if spec is None or spec.loader is None:
            raise FileNotFoundError(path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    return load
