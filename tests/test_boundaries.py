# SPDX-License-Identifier: Apache-2.0
"""Architecture rules: the layers of the package may only depend downwards.

    core  <-  agent            (the host agent ships alone in .deb/.pkg/zipapp packages)
    core  <-  dtrack  <-  ci   (Dependency-Track client and administration, then the CI jobs)
    core, dtrack  <-  bridge
"""
import ast
import importlib
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent / "patchwatch"
# layer -> layers it may import (besides itself)
ALLOWED = {"core": set(), "agent": {"core"}, "dtrack": {"core"}, "ci": {"core", "dtrack"}, "bridge": {"core", "dtrack"}}


def layer(path: Path) -> str:
    first = path.relative_to(ROOT).parts[0]
    return first.removesuffix(".py")


def imported_layers(path: Path):
    """Layers imported by ``path``, resolving relative imports against the file's package."""
    package = list(path.relative_to(ROOT.parent).parts[:-1])
    found = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                base = package[: len(package) - node.level + 1]
                parts = base + (node.module.split(".") if node.module else [])
            else:
                parts = (node.module or "").split(".")
            if parts[:1] == ["patchwatch"] and len(parts) > 1:
                found.add(parts[1])
            elif parts == ["patchwatch"]:
                found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            found.update(a.name.split(".")[1] for a in node.names if a.name.startswith("patchwatch."))
    return found


class LayerTests(unittest.TestCase):
    def test_layers_only_import_downwards(self):
        for path in sorted(ROOT.rglob("*.py")):
            own = layer(path)
            if own not in ALLOWED:
                continue
            with self.subTest(module=str(path.relative_to(ROOT))):
                self.assertLessEqual(imported_layers(path) - {own}, ALLOWED[own])

    def test_agent_and_core_use_only_the_standard_library(self):
        stdlib = set(__import__("sys").stdlib_module_names)
        for folder in ("agent", "core"):
            for path in sorted((ROOT / folder).rglob("*.py")):
                for node in ast.walk(ast.parse(path.read_text())):
                    names = []
                    if isinstance(node, ast.Import):
                        names = [a.name for a in node.names]
                    elif isinstance(node, ast.ImportFrom) and not node.level:
                        names = [node.module]
                    for name in names:
                        with self.subTest(module=str(path.relative_to(ROOT)), imports=name):
                            self.assertIn(name.split(".")[0], stdlib)

    def test_every_import_resolves_including_those_inside_functions(self):
        """Entry points import lazily; a stale path there would only fail in production."""
        for path in sorted(ROOT.rglob("*.py")):
            package = ".".join(path.relative_to(ROOT.parent).parts[:-1])
            for node in ast.walk(ast.parse(path.read_text())):
                if not isinstance(node, ast.ImportFrom) or not (node.level or (node.module or "").startswith("patchwatch")):
                    continue
                target = ("." * node.level) + (node.module or "")
                with self.subTest(module=str(path.relative_to(ROOT)), line=node.lineno):
                    module = importlib.import_module(target, package)
                    for alias in node.names:
                        self.assertTrue(hasattr(module, alias.name) or importlib.util.find_spec(module.__name__ + "." + alias.name),
                                        f"{target}.{alias.name}")


if __name__ == "__main__":
    unittest.main()
