"""The README's test counts and scenario-kind claims are derived from the tree, not typed by hand.

Rust: `#[test]` attributes under crates/. Python: test functions under helios-ai/tests, each
`@pytest.mark.parametrize` over a literal list multiplying it (what pytest collects). Viewer:
`it(`/`test(` calls in web/src. Scripts: what `unittest discover -s scripts` loads.
    python -m unittest discover -s scripts
"""

from __future__ import annotations

import ast
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


def rust() -> int:
    return sum(p.read_text(encoding="utf-8").count("#[test]") for p in (ROOT / "crates").rglob("*.rs"))


def _cases(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    n = 1
    for d in fn.decorator_list:
        if (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute)
                and d.func.attr == "parametrize" and len(d.args) >= 2):
            values = d.args[1]
            assert isinstance(values, (ast.List, ast.Tuple)), f"{fn.name}: non-literal parametrize"
            n *= len(values.elts)
    return n


def python() -> int:
    total = 0
    for p in sorted((ROOT / "helios-ai" / "tests").rglob("test_*.py")):
        for node in ast.walk(ast.parse(p.read_text(encoding="utf-8"))):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
                total += _cases(node)
    return total


def viewer() -> int:
    calls = re.compile(r"^\s*(?:it|test)\(", re.M)
    return sum(len(calls.findall(p.read_text(encoding="utf-8")))
               for p in (ROOT / "web" / "src").rglob("*.test.ts*"))


def scripts() -> int:
    return unittest.defaultTestLoader.discover(str(ROOT / "scripts")).countTestCases()


def scenario_kinds() -> list[str]:
    src = (ROOT / "crates" / "helios-engine" / "src" / "scenario.rs").read_text(encoding="utf-8")
    body = src.split("pub enum ScenarioKind {", 1)[1].split("\n}", 1)[0]
    names = re.findall(r"^    ([A-Z]\w+) \{", body, re.M)
    return [re.sub(r"(?<!^)([A-Z])", r"-\1", n).lower() for n in names]


WORDS = {5: "Five", 6: "Six", 7: "Seven", 8: "Eight"}


class ReadmeCounts(unittest.TestCase):
    def test_the_header_and_the_tests_section_state_the_real_counts(self):
        r, p, w, s = rust(), python(), viewer(), scripts()
        header = (f"**{r + p} tests ({r} Rust, {p} Python), plus {w} for the viewer and {s} for "
                  f"the repository scripts.**")
        self.assertIn(header, README)
        self.assertIn(f"**{r + p} tests (plus {w} for the web viewer and {s} for the scripts in "
                      f"`scripts/`):**", README)
        self.assertIn(f"| Rust | **{r}** ", README)
        self.assertIn(f"| Python | **{p}** ", README)

    def test_every_scenario_kind_is_counted_listed_and_has_an_example(self):
        kinds = scenario_kinds()
        self.assertGreaterEqual(len(kinds), 6, kinds)
        self.assertIn(f"{len(kinds)} failure scenarios", README)
        self.assertIn(f"{WORDS[len(kinds)]} kinds, one example each in `fixtures/scenarios/`", README)
        for kind in kinds:
            self.assertIn(f"| `{kind}` |", README, kind)
            self.assertTrue((ROOT / "fixtures" / "scenarios" / f"{kind}.yaml").is_file(), kind)


if __name__ == "__main__":
    unittest.main()
