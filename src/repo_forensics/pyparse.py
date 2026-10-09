"""Python AST extraction. Parsing never executes code (see `ast.parse`).

Extracted per file: imports (with kind: module / lazy / type_checking), qualified
calls and decorators, `if __name__ == "__main__"` guards, environment variables
read, and test-function counts.

Known limitations (documented, not hidden):
- alias tracking is file-global, not scope-aware
- method calls on objects are invisible (no type inference): `client.chat(...)`
  is not resolved, but the constructor `openai.OpenAI(...)` is
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

TRACKED_BUILTINS = {"open", "eval", "exec", "compile", "__import__"}


@dataclass
class ImportRef:
    module: str           # absolute dotted module (relative imports resolved)
    names: list[str]      # imported names for `from X import a, b` ("*" for star)
    line: int
    kind: str             # "module" | "lazy" | "type_checking"
    relative: bool = False
    unresolved: bool = False


@dataclass
class CallRef:
    qualname: str
    line: int
    kind: str = "call"    # "call" | "decorator"
    in_function: bool = False


@dataclass
class FileFacts:
    path: str
    module: str
    is_package: bool
    imports: list[ImportRef] = field(default_factory=list)
    calls: list[CallRef] = field(default_factory=list)
    main_guard_line: int | None = None
    env_vars: list[tuple[str, int]] = field(default_factory=list)
    test_functions: int = 0
    functions: int = 0
    classes: int = 0
    defines_all: bool = False
    syntax_error: str | None = None


def _dotted(node: ast.AST) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    if isinstance(node, ast.Call):  # e.g. foo().bar -> unresolvable chain
        return None
    return None


def _is_type_checking(test: ast.AST) -> bool:
    d = _dotted(test)
    return d in ("TYPE_CHECKING", "typing.TYPE_CHECKING", "t.TYPE_CHECKING")


def _is_main_guard(test: ast.AST) -> bool:
    if not isinstance(test, ast.Compare) or len(test.ops) != 1 or not isinstance(test.ops[0], ast.Eq):
        return False
    sides = [test.left, test.comparators[0]]
    has_name = any(isinstance(s, ast.Name) and s.id == "__name__" for s in sides)
    has_main = any(isinstance(s, ast.Constant) and s.value == "__main__" for s in sides)
    return has_name and has_main


class _Visitor(ast.NodeVisitor):
    def __init__(self, facts: FileFacts) -> None:
        self.f = facts
        self.aliases: dict[str, str] = {}
        self.func_depth = 0
        self.tc_depth = 0
        self.class_stack: list[str] = []
        parts = facts.module.split(".") if facts.module else []
        self.package_parts = parts if facts.is_package else parts[:-1]

    # ---------- helpers
    def _kind(self) -> str:
        if self.tc_depth:
            return "type_checking"
        if self.func_depth:
            return "lazy"
        return "module"

    def qualify(self, node: ast.AST) -> str | None:
        d = _dotted(node)
        if not d:
            return None
        head, _, rest = d.partition(".")
        if head in self.aliases:
            base = self.aliases[head]
            return f"{base}.{rest}" if rest else base
        if head in TRACKED_BUILTINS and not rest:
            return f"builtins.{head}"
        return None

    def _resolve_relative(self, level: int, module: str | None) -> tuple[str, bool]:
        up = level - 1
        if up > len(self.package_parts):
            return ("." * level + (module or "")), True
        base = self.package_parts[: len(self.package_parts) - up]
        if module:
            base = base + module.split(".")
        return ".".join(base), False

    # ---------- imports
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.f.imports.append(ImportRef(a.name, [], node.lineno, self._kind()))
            if a.asname:
                self.aliases[a.asname] = a.name
            else:
                top = a.name.split(".")[0]
                self.aliases[top] = top

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            mod, unresolved = self._resolve_relative(node.level, node.module)
        else:
            mod, unresolved = node.module or "", False
        names = [a.name for a in node.names]
        self.f.imports.append(ImportRef(mod, names, node.lineno, self._kind(),
                                        relative=bool(node.level), unresolved=unresolved))
        if not unresolved:
            for a in node.names:
                if a.name != "*":
                    self.aliases[a.asname or a.name] = f"{mod}.{a.name}" if mod else a.name

    # ---------- structure
    def _visit_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.f.functions += 1
        if node.name.startswith("test") and (self.func_depth == 0) and (
                not self.class_stack or self.class_stack[-1].startswith("Test")):
            self.f.test_functions += 1
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            q = self.qualify(target)
            if q:
                self.f.calls.append(CallRef(q, dec.lineno, "decorator", self.func_depth > 0))
            if isinstance(dec, ast.Call):
                for a in dec.args + [k.value for k in dec.keywords]:
                    self.visit(a)
        for d in node.args.defaults + node.args.kw_defaults:
            if d is not None:
                self.visit(d)
        self.func_depth += 1
        for stmt in node.body:
            self.visit(stmt)
        self.func_depth -= 1

    visit_FunctionDef = _visit_func
    visit_AsyncFunctionDef = _visit_func

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.f.classes += 1
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            q = self.qualify(target)
            if q:
                self.f.calls.append(CallRef(q, dec.lineno, "decorator", self.func_depth > 0))
        for b in node.bases:
            self.visit(b)
        self.class_stack.append(node.name)
        for stmt in node.body:
            self.visit(stmt)
        self.class_stack.pop()

    def visit_If(self, node: ast.If) -> None:
        if _is_type_checking(node.test):
            self.tc_depth += 1
            for s in node.body:
                self.visit(s)
            self.tc_depth -= 1
            for s in node.orelse:
                self.visit(s)
            return
        if _is_main_guard(node.test) and self.func_depth == 0:
            self.f.main_guard_line = node.lineno
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if (len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "__all__" and self.func_depth == 0):
            self.f.defines_all = True
        self.generic_visit(node)

    # ---------- calls & config
    def visit_Call(self, node: ast.Call) -> None:
        q = self.qualify(node.func)
        if q:
            self.f.calls.append(CallRef(q, node.lineno, "call", self.func_depth > 0))
            if q in ("os.getenv", "os.environ.get", "os.environ.setdefault") and node.args:
                a0 = node.args[0]
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str):
                    self.f.env_vars.append((a0.value, node.lineno))
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if self.qualify(node.value) == "os.environ":
            s = node.slice
            if isinstance(s, ast.Constant) and isinstance(s.value, str):
                self.f.env_vars.append((s.value, node.lineno))
        self.generic_visit(node)


def parse_file(path: str, source: bytes, module: str, is_package: bool) -> FileFacts:
    facts = FileFacts(path=path, module=module, is_package=is_package)
    try:
        tree = ast.parse(source, filename=path)
    except (SyntaxError, ValueError) as e:
        facts.syntax_error = f"{type(e).__name__}: {e}"[:300]
        return facts
    _Visitor(facts).visit(tree)
    return facts
