"""Builds a small synthetic repository that exercises every analysis path."""

from __future__ import annotations

import subprocess
import textwrap
from pathlib import Path

import pytest

FILES = {
    "pyproject.toml": """
        [build-system]
        requires = ["hatchling"]
        build-backend = "hatchling.build"

        [project]
        name = "demo"
        version = "0.0.1"
        dependencies = ["faiss-cpu>=1.7", "openai", "numpy", "requests", "unused-thing"]

        [project.optional-dependencies]
        ml = ["scikit-learn"]

        [dependency-groups]
        dev = ["pytest"]

        [project.scripts]
        demo = "demo.cli:main"
    """,
    "LICENSE": "Permission is hereby granted, free of charge, to any person obtaining a copy",
    "src/demo/__init__.py": '__all__ = ["run"]\nfrom demo.core.engine import run\n',
    "src/demo/cli.py": """
        import argparse
        from demo.core import engine

        def main():
            parser = argparse.ArgumentParser()
            engine.run()

        if __name__ == "__main__":
            main()
    """,
    "src/demo/api/__init__.py": "",
    "src/demo/api/app.py": """
        from fastapi import FastAPI
        from ..core.engine import run

        app = FastAPI()

        @app.get("/")
        def root():
            return run()
    """,
    "src/demo/core/__init__.py": "",
    "src/demo/core/engine.py": """
        import os
        from typing import TYPE_CHECKING
        from demo.retrieval import index

        if TYPE_CHECKING:
            from demo.api.app import app  # type-only: must not create a runtime cycle

        MODEL = os.getenv("DEMO_MODEL", "gpt")

        def run():
            from demo.core import helpers  # lazy import
            return index.search([0.0]) + helpers.x()
    """,
    "src/demo/core/helpers.py": """
        from demo.core import engine  # closes a runtime cycle engine -> helpers -> engine (lazy side)

        def x():
            return 1
    """,
    "src/demo/retrieval/__init__.py": "",
    "src/demo/retrieval/index.py": """
        import faiss
        import numpy as np
        from openai import OpenAI

        def build(d):
            return faiss.IndexHNSWFlat(d, 32)

        def search(q):
            client = OpenAI()
            return np.zeros(3)
    """,
    "src/demo/flask.py": """
        # an internal module named like a third-party framework: must not trigger signatures
        def Flask(name):
            return name
    """,
    "src/demo/uses_internal.py": """
        from demo.flask import Flask
        Flask("x")
    """,
    "tests/test_engine.py": """
        import pytest
        import subprocess
        from demo.core.engine import run

        def test_run():
            assert run() is not None

        class TestThing:
            def test_a(self):
                pass
    """,
    "examples/celery_app/requirements.txt": "celery\nredis\n",
    "examples/celery_app/tasks.py": "import celery\n",
    "scripts/run.py": "import helper\nhelper.go()\n",
    "scripts/helper.py": "def go():\n    pass\n",
    "notebook.ipynb": "{}",
    "README.md": "# demo\n",
}


def write_repo(root: Path, files: dict[str, str] = FILES, git: bool = True) -> Path:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content).lstrip("\n"), encoding="utf-8")
    if git:
        env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
               "GIT_COMMITTER_EMAIL": "t@t", "PATH": __import__("os").environ["PATH"], "HOME": str(root)}
        for cmd in (["git", "init", "-q"], ["git", "add", "-A"], ["git", "commit", "-qm", "init"]):
            subprocess.run(cmd, cwd=root, check=True, env=env)
    return root


@pytest.fixture(scope="session")
def demo_repo(tmp_path_factory) -> Path:
    return write_repo(tmp_path_factory.mktemp("demo"))


@pytest.fixture(scope="session")
def demo_analysis(demo_repo, tmp_path_factory):
    from repo_forensics.analyze import run
    out = tmp_path_factory.mktemp("out")
    report = run(str(demo_repo), out)
    return out, report
