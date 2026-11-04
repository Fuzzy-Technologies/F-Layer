"""Enforce the owner-defined Python naming contract without executing checked source."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
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

    Visitor().visit(tree)

    return tuple(sorted(set(failures), key=lambda item: (item.path, item.line, item.name, item.kind)))


def Inventory(root: Path) -> tuple[Path, ...]:
    """Include tracked and newly authored Python sources without traversing ignored storage."""

    result = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=root, capture_output=True, check=True, timeout=30,
    )

    return tuple(root / name for name in sorted(set(result.stdout.decode().split("\0")))
                 if name and Path(name).suffix in {".py", ".pyi"})


def Audit(root: Path) -> tuple[Violation, ...]:
    """Check every repository Python module and stub with deterministic ordering."""

    failures: list[Violation] = []

    for path in Inventory(root):
        failures.extend(FindViolations(path.read_text(encoding="utf-8-sig"), path.relative_to(root).as_posix()))

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
