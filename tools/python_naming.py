"""Enforce the owner-defined Python naming contract without executing checked source."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

VARIABLE = re.compile(r"_*[a-z][A-Za-z0-9]*\Z")
CONSTANT = re.compile(r"_*[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*\Z")
CALLABLE = re.compile(r"_*[A-Z][A-Za-z0-9]*\Z")
TEST = re.compile(r"test_[A-Z][A-Za-z0-9]*\Z")
PYTEST_FIXTURES = frozenset({
    "tmp_path", "tmp_path_factory", "monkeypatch", "capsys", "capfd", "caplog", "pytestconfig",
    "request", "record_property", "record_testsuite_property", "record_xml_attribute", "recwarn",
    "doctest_namespace", "cache", "testdir", "pytester",
})
SPECIAL = frozenset({
    "__init__", "__post_init__", "__new__", "__str__", "__repr__", "__getattr__", "__getattribute__",
    "__enter__", "__exit__", "__iter__", "__next__", "__len__", "__eq__", "__hash__", "__call__",
    "__getitem__", "__setitem__", "__delitem__", "__bool__", "__fspath__", "__contains__",
    "__class_getitem__", "__name__", "__file__", "__all__", "__doc__", "__package__", "__spec__",
    "__version__", "__path__", "__annotations__", "__dict__", "__slots__", "__class__", "__qualname__",
    "__module__",
})

# Exact paths and qualified definitions only; new overrides require an explicit contract review.
EXTERNAL_METHODS: dict[tuple[str, str], str] = {
    ('src/flayer/__main__.py', 'DiagnosticArgumentParser.error'): 'External protocol callback or exact standard-library test double interface',
    ('src/flayer/extensions/discovery.py', '_EntryPointsParser.optionxform'): 'External protocol callback or exact standard-library test double interface',
    ('src/flayer/extensions/registry.py', '_SnapshotImporter.find_spec'): 'External protocol callback or exact standard-library test double interface',
    ('src/flayer/extensions/registry.py', '_SnapshotImporter.create_module'): 'External protocol callback or exact standard-library test double interface',
    ('src/flayer/extensions/registry.py', '_SnapshotImporter.exec_module'): 'External protocol callback or exact standard-library test double interface',
    ('src/flayer/profiles/_amnezia_export.py', '_AwgConfigParser.optionxform'): 'External protocol callback or exact standard-library test double interface',
    ('tests/conftest.py', 'pytest_collection_modifyitems'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakeHttpConnection.request'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakeHttpConnection.getresponse'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakeHttpConnection.read'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakeHttpConnection.close'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakePipe.poll'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakePipe.recv'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakePipe.send'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakePipe.close'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakeProcess.start'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakeProcess.is_alive'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakeProcess.terminate'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakeProcess.join'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakeProcess.kill'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_diagnostics_benchmark.py', 'FakeProcess.close'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_vless_profile.py', 'test_RealityTargetRequiresValidatedTlsAndHttp2.Channel.version'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_vless_profile.py', 'test_RealityTargetRequiresValidatedTlsAndHttp2.Channel.selected_alpn_protocol'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_vless_profile.py', 'test_RealityTargetRequiresValidatedTlsAndHttp2.Context.set_alpn_protocols'): 'External protocol callback or exact standard-library test double interface',
    ('tests/unit/test_vless_profile.py', 'test_RealityTargetRequiresValidatedTlsAndHttp2.Context.wrap_socket'): 'External protocol callback or exact standard-library test double interface',
    ('tools/documentation_gates.py', 'PageParser.handle_starttag'): 'External protocol callback or exact standard-library test double interface',
    ('tools/generated_localization.py', '_ProseParser.handle_starttag'): 'External protocol callback or exact standard-library test double interface',
    ('tools/generated_localization.py', '_ProseParser.handle_endtag'): 'External protocol callback or exact standard-library test double interface',
    ('tools/generated_localization.py', '_ProseParser.handle_data'): 'External protocol callback or exact standard-library test double interface',
    ('tools/release_validation.py', 'ConsoleScriptsParser.optionxform'): 'External protocol callback or exact standard-library test double interface',
    ('tools/translated_docstrings.py', 'TranslatedDocstrings.on_instance'): 'External protocol callback or exact standard-library test double interface',
    ('tools/translated_docstrings.pyi', 'TranslatedDocstrings.on_instance'): 'External protocol callback or exact standard-library test double interface',
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_ClassDef'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_FunctionDef'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_AsyncFunctionDef'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_arg'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_Name'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_Attribute'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_ExceptHandler'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_alias'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_Call'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_MatchAs'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_MatchStar'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_MatchMapping'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_Global'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_Nonlocal'): "ast.NodeVisitor dispatch contract",
    ('tools/python_naming.py', 'FindViolations.Visitor.visit_Lambda'): "ast.NodeVisitor dispatch contract",
    ('tools/build_api_reference.py', 'FLayerImportGuard.find_spec'): "Generated importlib MetaPathFinder hook",
}
EXTERNAL_PARAMETERS: dict[tuple[str, str, str], str] = {
    ('tests/unit/test_vless_profile.py', 'test_RealityTargetRequiresValidatedTlsAndHttp2.Context.wrap_socket', 'server_hostname'): 'External protocol callback or exact standard-library test double interface',
    ("tests/unit/test_core_state.py", "test_TemporaryCleanupFailureRaisesStateErrorWithRecoveryEvidence.RejectTemporaryCleanup", "missing_ok"): "Path.unlink test double keyword",
    ("tests/unit/test_core_state.py", "test_LockCleanupFailureIsReportedAfterSuccessfulCommit.RejectLockCleanup", "missing_ok"): "Path.unlink test double keyword",
    ("tests/unit/test_core_state.py", "test_RemoveFailurePreservesSnapshotAndReleasesLock.RejectSnapshotRemoval", "missing_ok"): "Path.unlink test double keyword",
    ("tests/unit/test_lifecycle.py", "test_CompletedOperationWithUnclearableJournalRecoversWithoutDuplication.FailedJournalUnlink", "missing_ok"): "Path.unlink test double keyword",
    ("tests/unit/test_lifecycle.py", "test_UnavailableStorageAndUnreleasableLockFailExplicitly.FailedMkdir", "exist_ok"): "Path.mkdir test double keyword",
    ("tests/unit/test_lifecycle.py", "test_UnavailableStorageAndUnreleasableLockFailExplicitly.FailedLockUnlink", "missing_ok"): "Path.unlink test double keyword",
    ("tests/unit/test_lifecycle.py", "test_TemporaryJournalCleanupFailureBlocksCloudWork.FailedTemporaryUnlink", "missing_ok"): "Path.unlink test double keyword",
    ("tests/unit/test_gateway_artifacts.py", "test_PartialRemovalFailurePreservesManifestForRecovery.FailSecond", "dir_fd"): "os.unlink test double keyword",
}
EXTERNAL_ATTRIBUTES: dict[tuple[str, str, str], str] = {
    ("src/flayer/profiles/_vless_guest.py", "_TargetHealth", "minimum_version"): "ssl.SSLContext setting",
    ("tests/contract/test_release_validation.py", "test_ZipAndTarLinksRejected", "external_attr"): "zipfile.ZipInfo metadata",
    ("tests/contract/test_release_validation.py", "test_WheelRejectsAllSpecialUnixMemberTypes", "external_attr"): "zipfile.ZipInfo metadata",
    ("tests/contract/test_release_validation.py", "test_ZipAndTarLinksRejected", "create_system"): "zipfile.ZipInfo metadata",
    ("tests/contract/test_release_validation.py", "test_WheelRejectsAllSpecialUnixMemberTypes", "create_system"): "zipfile.ZipInfo metadata",
    ("tests/unit/test_vless_profile.py", "Archive", "external_attr"): "zipfile.ZipInfo metadata",
}


@dataclass(frozen=True)
class Violation:
    """One source-bound naming failure, independent of runtime behavior."""

    path: str
    line: int
    name: str
    kind: str

    def Render(self) -> str:
        """Return a compiler-style diagnostic suitable for local and CI logs."""

        return f"{self.path}:{self.line}: {self.kind} identifier {self.name!r} violates Python naming"


def _Variable(name: str) -> bool:
    """Accept camelCase bindings, constants and explicitly known Python special names."""

    return name == "_" or name in SPECIAL or bool(VARIABLE.fullmatch(name) or CONSTANT.fullmatch(name))


def _Fixture(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Identify explicit pytest fixture decorators without importing the module."""

    return any(isinstance(target, ast.Attribute) and target.attr == "fixture" for target in (
        item.func if isinstance(item, ast.Call) else item for item in node.decorator_list
    ))


def FindViolations(source: str, sourcePath: str = "<source>") -> tuple[Violation, ...]:
    """Inspect bindings and definitions while preserving narrowly identified external contracts."""

    try:
        tree = ast.parse(source, filename=sourcePath)

    except SyntaxError as error:
        return (Violation(sourcePath, error.lineno or 1, "<syntax>", "syntax"),)

    failures: list[Violation] = []
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    functionNames = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    namespaceNames = {
        node.arg for node in ast.walk(tree) if isinstance(node, ast.arg) and (
            isinstance(node.annotation, ast.Attribute) and node.annotation.attr == "Namespace"
            or isinstance(node.annotation, ast.Name) and node.annotation.id == "Namespace"
        )
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute) and node.value.func.attr == "parse_args":
            namespaceNames.update(target.id for target in node.targets if isinstance(target, ast.Name))

    class Visitor(ast.NodeVisitor):
        """Track qualified definitions so exceptions cannot suppress unrelated identifiers."""

        def __init__(self) -> None:
            """Start in module scope with no implicit framework exceptions."""

            self.scopes: list[str] = []
            self.pytestParameters = False

        def Scope(self) -> str:
            """Identify the exact current definition."""

            return ".".join(self.scopes)

        def Check(self, node: ast.AST, name: str, kind: str) -> None:
            """Report only names rejected by the rule for their declaration category."""

            valid = _Variable(name)

            if kind == "function":
                valid = name in SPECIAL or bool(CALLABLE.fullmatch(name) or TEST.fullmatch(name))

            elif kind == "class":
                valid = bool(CALLABLE.fullmatch(name))

            if not valid:
                failures.append(Violation(sourcePath, getattr(node, "lineno", 1), name, kind))

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            """Require PascalCase classes while retaining normal nested scope."""

            self.Check(node, node.name, "class")
            self.scopes.append(node.name)
            self.generic_visit(node)
            self.scopes.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            """Check functions, property fields and framework-owned call signatures."""

            qualified = ".".join([*self.scopes, node.name])
            external = (sourcePath, qualified) in EXTERNAL_METHODS
            propertyField = any(
                isinstance(item, ast.Name) and item.id == "property" or
                isinstance(item, ast.Attribute) and item.attr in {"setter", "deleter"}
                for item in node.decorator_list
            )

            if not external:
                if not propertyField or not (_Variable(node.name) or CALLABLE.fullmatch(node.name)):
                    self.Check(node, node.name, "function")

            previous = self.pytestParameters
            self.pytestParameters = sourcePath.startswith("tests/") and (
                node.name.startswith("test_") or _Fixture(node)
            )
            self.scopes.append(node.name)
            self.generic_visit(node)
            self.scopes.pop()
            self.pytestParameters = previous

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            """Apply the same naming rules through the standard async AST callback."""

            self.visit_FunctionDef(node)

        def visit_arg(self, node: ast.arg) -> None:
            """Retain pytest's actual injected fixture names and reviewed callback arguments."""

            builtinFixture = self.pytestParameters and node.arg in PYTEST_FIXTURES
            exception = (sourcePath, self.Scope(), node.arg) in EXTERNAL_PARAMETERS

            if not builtinFixture and not exception:
                self.Check(node, node.arg, "parameter")

            self.generic_visit(node)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            """Do not inherit pytest fixture injection for ordinary lambda parameters."""

            previous = self.pytestParameters
            self.pytestParameters = False
            self.generic_visit(node)
            self.pytestParameters = previous

        def visit_Global(self, node: ast.Global) -> None:
            """Check explicit references to module-owned bindings."""

            for name in node.names:
                self.Check(node, name, "global binding")

        def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
            """Check explicit references to enclosing owned bindings."""

            for name in node.names:
                self.Check(node, name, "nonlocal binding")

        def visit_Name(self, node: ast.Name) -> None:
            """Check assignment, loop, comprehension and context-manager bindings."""

            if isinstance(node.ctx, (ast.Store, ast.Del)):
                owner = parents.get(node)
                value = getattr(owner, "value", None)
                methodAlias = (
                    isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in {"staticmethod", "classmethod"}
                    or isinstance(value, ast.Attribute) and bool(CALLABLE.fullmatch(value.attr))
                )
                typeAlias = isinstance(owner, ast.AnnAssign) and isinstance(owner.annotation, ast.Name) and owner.annotation.id == "TypeAlias"

                if not ((methodAlias or typeAlias) and CALLABLE.fullmatch(node.id)):
                    self.Check(node, node.id, "variable")

        def visit_Attribute(self, node: ast.Attribute) -> None:
            """Check assigned fields while allowing exact standard-library adapter contracts."""

            if isinstance(node.ctx, ast.Store) and (sourcePath, self.Scope(), node.attr) not in EXTERNAL_ATTRIBUTES:
                value = getattr(parents.get(node), "value", None)
                methodPatch = isinstance(value, ast.Name) and value.id in functionNames

                if not (methodPatch and CALLABLE.fullmatch(node.attr)):
                    self.Check(node, node.attr, "field")

            elif isinstance(node.value, ast.Name) and node.value.id in namespaceNames:
                self.Check(node, node.attr, "CLI field")

            self.generic_visit(node)

        def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
            """Check exception aliases, which are not represented as assignment Name nodes."""

            if node.name:
                self.Check(node, node.name, "variable")

            self.generic_visit(node)

        def visit_alias(self, node: ast.alias) -> None:
            """Keep imported API names but enforce the aliases chosen by this project."""

            if node.asname and node.asname != node.name:
                self.Check(node, node.asname, "import alias")

        def visit_Call(self, node: ast.Call) -> None:
            """Check owned argparse destinations and reflected namespace fields."""

            if isinstance(node.func, ast.Attribute) and node.func.attr == "add_argument":
                destination = next((item.value for item in node.keywords if item.arg == "dest"), None)

                if isinstance(destination, ast.Constant) and isinstance(destination.value, str):
                    self.Check(destination, destination.value, "CLI destination")

                elif node.args:
                    flags = [item for item in node.args if isinstance(item, ast.Constant) and isinstance(item.value, str)]
                    argument = next((item for item in flags if isinstance(item.value, str) and item.value.startswith("--")), flags[0] if flags else None)

                    if argument is None:
                        self.generic_visit(node)

                        return

                    assert isinstance(argument.value, str)
                    option = argument.value

                    if option.startswith("--"):
                        self.Check(argument, option[2:].replace("-", "_"), "implicit CLI destination")

                    elif not option.startswith("-"):
                        self.Check(argument, option, "positional CLI destination")

            if isinstance(node.func, ast.Name) and node.func.id in {"getattr", "setattr", "delattr"} and len(node.args) > 1:
                receiver, attribute = node.args[:2]

                if isinstance(receiver, ast.Name) and receiver.id in namespaceNames and isinstance(attribute, ast.Constant) and isinstance(attribute.value, str):
                    self.Check(attribute, attribute.value, "reflected CLI field")

            self.generic_visit(node)

        def visit_MatchAs(self, node: ast.MatchAs) -> None:
            """Check Python pattern-capture bindings."""

            if node.name:
                self.Check(node, node.name, "pattern binding")

            self.generic_visit(node)

        def visit_MatchStar(self, node: ast.MatchStar) -> None:
            """Check starred pattern-capture bindings."""

            if node.name:
                self.Check(node, node.name, "pattern binding")

        def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
            """Check the rest binding of a mapping pattern."""

            if node.rest:
                self.Check(node, node.rest, "pattern binding")

            self.generic_visit(node)

    Visitor().visit(tree)

    return tuple(sorted(set(failures), key=lambda item: (item.path, item.line, item.name, item.kind)))


def _Paths(root: Path) -> tuple[Path, ...]:
    """Enumerate authored repository files without entering ignored/private storage."""

    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root, capture_output=True, check=True, timeout=30,
    )

    return tuple(root / name for name in sorted(set(result.stdout.decode().split("\0"))) if name)


def Inventory(root: Path) -> tuple[Path, ...]:
    """Include tracked and newly authored Python modules and stubs."""

    return tuple(path for path in _Paths(root) if path.suffix in {".py", ".pyi"})


def PythonBlocks(source: str, suffix: str) -> tuple[tuple[int, str], ...]:
    """Extract explicit Markdown Python fences and workflow Python heredocs."""

    blocks = []
    lines = source.splitlines()
    start = 0
    closing = ""

    for index, line in enumerate(lines):
        if closing:
            if line.strip() == closing:
                blocks.append((start + 1, textwrap.dedent("\n".join(lines[start:index]))))
                closing = ""

        elif suffix in {".md", ".toml"}:
            match = re.match(r"\s*(`{3,}|~{3,})\s*(?:python|py)\s*$", line)

            if match:
                start, closing = index + 1, match[1]

        if not closing:
            match = re.search(r"\bpython(?:3)?\s+-\s*<<\s*['\"]?([A-Za-z_][A-Za-z_0-9]*)['\"]?\s*$", line)

            if match:
                start, closing = index + 1, match[1]

    return tuple(blocks)


def EmbeddedSources(source: str) -> tuple[tuple[int, str], ...]:
    """Inventory parseable embedded modules without mistaking TOML or JSON fixtures for Python."""

    blocks = []
    tree = ast.parse(source)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str) or "\n" not in node.value:
            continue

        code = textwrap.dedent(node.value)

        try:
            embedded = ast.parse(code)

        except SyntaxError:
            continue

        if any(isinstance(item, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
               for item in ast.walk(embedded)):
            blocks.append((node.lineno, code))

    return tuple(blocks)


def Audit(root: Path) -> tuple[Violation, ...]:
    """Check owned source, embedded modules, documentation examples and workflow heredocs."""

    failures: list[Violation] = []

    for path in _Paths(root):
        name = path.relative_to(root).as_posix()
        source = path.read_text(encoding="utf-8-sig") if path.suffix in {".py", ".pyi", ".md", ".yml", ".yaml", ".toml"} else ""
        blocks: tuple[tuple[int, str], ...] = ()

        if path.suffix in {".py", ".pyi"}:
            failures.extend(FindViolations(source, name))

            # This validator's test strings are deliberately invalid data, never executable fixtures.
            if name != "tests/unit/test_python_naming.py":
                try:
                    blocks = EmbeddedSources(source)

                except SyntaxError:
                    pass  # FindViolations already reports the original syntax failure.

        elif path.suffix in {".md", ".yml", ".yaml"} or name.startswith("docs/i18n/generated/") and path.suffix == ".toml":
            blocks = PythonBlocks(source, path.suffix)

        for firstLine, code in blocks:
            failures.extend(Violation(name, firstLine + item.line - 1, item.name, item.kind)
                            for item in FindViolations(code, name))

    return tuple(failures)


def Main(arguments: Sequence[str] | None = None) -> int:
    """Fail CI on any owned naming violation without importing project modules."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--format", choices=("text", "json"), default="text")
    options = parser.parse_args(arguments)
    failures = Audit(options.root.resolve())

    if options.format == "json":
        print(json.dumps({"violations": [item.Render() for item in failures]}, sort_keys=True))

    elif failures:
        for item in failures:
            print(item.Render())

    else:
        print("Python naming: all owned identifiers follow the house style")

    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(Main())
