#!/usr/bin/env python3
"""
Python AST Extractor for Semantic Diffs.

Extracts functions, classes, and imports from Python files
and compares before/after versions to generate semantic diffs.
"""

import ast
import argparse
import hashlib
import json
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

MAX_AST_FILE_SIZE = 10 * 1024 * 1024


@dataclass
class Param:
    name: str
    type: str = ""


@dataclass
class FuncSig:
    params: list[Param]
    returns: list[str]
    is_async: bool = False
    decorators: list[str] = field(default_factory=list)
    is_exported: bool = True
    start_line: int = 0
    end_line: int = 0


@dataclass
class FunctionDiff:
    name: str
    change_type: str  # added, removed, modified, renamed
    before: Optional[FuncSig] = None
    after: Optional[FuncSig] = None
    body_diff: str = ""


@dataclass
class FieldDiff:
    name: str
    change_type: str
    old_type: str = ""
    new_type: str = ""


@dataclass
class TypeDiff:
    name: str
    kind: str  # class, dataclass
    change_type: str
    fields: list[FieldDiff] = field(default_factory=list)
    start_line: int = 0
    end_line: int = 0


@dataclass
class ImportDiff:
    path: str
    alias: str = ""
    change_type: str = ""


@dataclass
class VarDiff:
    name: str
    kind: str  # var, const
    change_type: str
    old_type: str = ""
    new_type: str = ""
    old_value: str = ""
    new_value: str = ""
    start_line: int = 0
    end_line: int = 0


@dataclass
class ChangeSummary:
    functions_added: int = 0
    functions_removed: int = 0
    functions_modified: int = 0
    types_added: int = 0
    types_removed: int = 0
    types_modified: int = 0
    variables_added: int = 0
    variables_removed: int = 0
    variables_modified: int = 0
    imports_added: int = 0
    imports_removed: int = 0


@dataclass
class SemanticDiff:
    language: str
    file_path: str
    functions: list[FunctionDiff]
    types: list[TypeDiff]
    variables: list[VarDiff]
    imports: list[ImportDiff]
    summary: ChangeSummary
    error: str = ""


@dataclass
class ParsedFunc:
    name: str
    params: list[Param]
    returns: list[str]
    is_async: bool
    decorators: list[str]
    is_exported: bool
    start_line: int
    end_line: int
    body_hash: str


@dataclass
class ParsedClass:
    name: str
    is_dataclass: bool
    fields: dict[str, str]  # name -> type
    methods: list[str]
    is_exported: bool
    start_line: int
    end_line: int


@dataclass
class ParsedVar:
    name: str
    kind: str
    type: str
    value: str
    start_line: int
    end_line: int


@dataclass
class ParsedFile:
    functions: dict[str, ParsedFunc]
    classes: dict[str, ParsedClass]
    variables: dict[str, ParsedVar]
    imports: dict[str, str]  # module -> alias
    error: str = ""


def get_annotation_str(node: Optional[ast.expr]) -> str:
    """Convert an annotation AST node to string."""
    if node is None:
        return ""
    return ast.unparse(node)


def parse_file(file_path: str) -> ParsedFile:
    """Parse a Python file and extract semantic information."""
    result = ParsedFile(functions={}, classes={}, variables={}, imports={})

    if not file_path or not Path(file_path).exists():
        return result

    file_info = Path(file_path).stat()
    if file_info.st_size > MAX_AST_FILE_SIZE:
        result.error = f"file exceeds maximum allowed size ({MAX_AST_FILE_SIZE} bytes): {file_path}"
        return result

    content = Path(file_path).read_text()
    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        result.error = f"Syntax error: {e.msg} at line {e.lineno}"
        return result

    for node in ast.walk(tree):
        # Extract imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                result.imports[alias.name] = alias.asname or ""

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                key = f"{module}.{alias.name}" if module else alias.name
                result.imports[key] = alias.asname or ""

    # Process top-level definitions
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func = _parse_function(node, content)
            result.functions[func.name] = func

        elif isinstance(node, ast.ClassDef):
            cls = _parse_class(node, content)
            result.classes[cls.name] = cls

            # Extract methods as functions
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    method = _parse_function(item, content)
                    method.name = f"{cls.name}.{method.name}"
                    result.functions[method.name] = method

        elif isinstance(node, ast.Assign):
            value = ast.unparse(node.value) if node.value is not None else ""
            for target in node.targets:
                if isinstance(target, ast.Name):
                    name = target.id
                    result.variables[name] = ParsedVar(
                        name=name,
                        kind="const" if name.isupper() else "var",
                        type="",
                        value=value,
                        start_line=node.lineno,
                        end_line=node.end_lineno or node.lineno,
                    )

        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            name = node.target.id
            result.variables[name] = ParsedVar(
                name=name,
                kind="const" if name.isupper() else "var",
                type=get_annotation_str(node.annotation),
                value=ast.unparse(node.value) if node.value is not None else "",
                start_line=node.lineno,
                end_line=node.end_lineno or node.lineno,
            )

    return result


def _parse_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef, content: str
) -> ParsedFunc:
    """Parse a function definition."""
    params = []
    for arg in node.args.args:
        params.append(Param(name=arg.arg, type=get_annotation_str(arg.annotation)))

    returns = []
    if node.returns:
        returns.append(get_annotation_str(node.returns))

    decorators = []
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name):
            decorators.append(dec.id)
        elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
            decorators.append(dec.func.id)
        elif isinstance(dec, ast.Attribute):
            decorators.append(ast.unparse(dec))

    # Hash the function implementation body (excluding signature/decorators)
    end_line = node.end_lineno if node.end_lineno else node.lineno
    body_start_line = node.body[0].lineno if node.body else node.lineno
    body_lines = content.split("\n")[body_start_line - 1 : end_line]
    body_hash = hashlib.sha256("\n".join(body_lines).encode("utf-8")).hexdigest()

    return ParsedFunc(
        name=node.name,
        params=params,
        returns=returns,
        is_async=isinstance(node, ast.AsyncFunctionDef),
        decorators=decorators,
        is_exported=not node.name.startswith("_"),
        start_line=node.lineno,
        end_line=node.end_lineno or node.lineno,
        body_hash=body_hash,
    )


def _parse_class(node: ast.ClassDef, content: str) -> ParsedClass:
    """Parse a class definition."""
    is_dataclass = any(
        (isinstance(d, ast.Name) and d.id == "dataclass")
        or (
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Name)
            and d.func.id == "dataclass"
        )
        for d in node.decorator_list
    )

    fields: dict[str, str] = {}
    methods: list[str] = []

    for item in node.body:
        if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            fields[item.target.id] = get_annotation_str(item.annotation)
        elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            methods.append(item.name)

    return ParsedClass(
        name=node.name,
        is_dataclass=is_dataclass,
        fields=fields,
        methods=methods,
        is_exported=not node.name.startswith("_"),
        start_line=node.lineno,
        end_line=node.end_lineno or node.lineno,
    )


def compare_functions(
    before: dict[str, ParsedFunc], after: dict[str, ParsedFunc]
) -> list[FunctionDiff]:
    """Compare functions between before and after versions."""
    diffs = []

    # Find removed and modified
    for name, before_func in before.items():
        after_func = after.get(name)
        if after_func is None:
            diffs.append(
                FunctionDiff(
                    name=name,
                    change_type="removed",
                    before=FuncSig(
                        params=before_func.params,
                        returns=before_func.returns,
                        is_async=before_func.is_async,
                        decorators=before_func.decorators,
                        is_exported=before_func.is_exported,
                        start_line=before_func.start_line,
                        end_line=before_func.end_line,
                    ),
                )
            )
            continue

        # Check for modifications
        changes = []
        if before_func.params != after_func.params:
            changes.append("parameters changed")
        if before_func.returns != after_func.returns:
            changes.append("return type changed")
        if before_func.is_async != after_func.is_async:
            changes.append("async modifier changed")
        if before_func.decorators != after_func.decorators:
            changes.append("decorators changed")
        if before_func.body_hash != after_func.body_hash:
            changes.append("implementation changed")

        if changes:
            diffs.append(
                FunctionDiff(
                    name=name,
                    change_type="modified",
                    before=FuncSig(
                        params=before_func.params,
                        returns=before_func.returns,
                        is_async=before_func.is_async,
                        decorators=before_func.decorators,
                        is_exported=before_func.is_exported,
                        start_line=before_func.start_line,
                        end_line=before_func.end_line,
                    ),
                    after=FuncSig(
                        params=after_func.params,
                        returns=after_func.returns,
                        is_async=after_func.is_async,
                        decorators=after_func.decorators,
                        is_exported=after_func.is_exported,
                        start_line=after_func.start_line,
                        end_line=after_func.end_line,
                    ),
                    body_diff=", ".join(changes),
                )
            )

    # Find added
    for name, after_func in after.items():
        if name not in before:
            diffs.append(
                FunctionDiff(
                    name=name,
                    change_type="added",
                    after=FuncSig(
                        params=after_func.params,
                        returns=after_func.returns,
                        is_async=after_func.is_async,
                        decorators=after_func.decorators,
                        is_exported=after_func.is_exported,
                        start_line=after_func.start_line,
                        end_line=after_func.end_line,
                    ),
                )
            )

    return diffs


def compare_classes(
    before: dict[str, ParsedClass], after: dict[str, ParsedClass]
) -> list[TypeDiff]:
    """Compare classes between before and after versions."""
    diffs = []

    for name, before_cls in before.items():
        after_cls = after.get(name)
        if after_cls is None:
            diffs.append(
                TypeDiff(
                    name=name,
                    kind="dataclass" if before_cls.is_dataclass else "class",
                    change_type="removed",
                    start_line=before_cls.start_line,
                    end_line=before_cls.end_line,
                )
            )
            continue

        # Compare fields
        field_diffs = []
        for field_name, field_type in before_cls.fields.items():
            after_type = after_cls.fields.get(field_name)
            if after_type is None:
                field_diffs.append(
                    FieldDiff(
                        name=field_name,
                        change_type="removed",
                        old_type=field_type,
                    )
                )
            elif after_type != field_type:
                field_diffs.append(
                    FieldDiff(
                        name=field_name,
                        change_type="modified",
                        old_type=field_type,
                        new_type=after_type,
                    )
                )

        for field_name, field_type in after_cls.fields.items():
            if field_name not in before_cls.fields:
                field_diffs.append(
                    FieldDiff(
                        name=field_name,
                        change_type="added",
                        new_type=field_type,
                    )
                )

        if field_diffs or before_cls.is_dataclass != after_cls.is_dataclass:
            diffs.append(
                TypeDiff(
                    name=name,
                    kind="dataclass" if after_cls.is_dataclass else "class",
                    change_type="modified",
                    fields=field_diffs,
                    start_line=after_cls.start_line,
                    end_line=after_cls.end_line,
                )
            )

    for name, after_cls in after.items():
        if name not in before:
            diffs.append(
                TypeDiff(
                    name=name,
                    kind="dataclass" if after_cls.is_dataclass else "class",
                    change_type="added",
                    start_line=after_cls.start_line,
                    end_line=after_cls.end_line,
                )
            )

    return diffs


def compare_imports(before: dict[str, str], after: dict[str, str]) -> list[ImportDiff]:
    """Compare imports between before and after versions."""
    diffs = []

    for path, alias in before.items():
        if path not in after:
            diffs.append(ImportDiff(path=path, alias=alias, change_type="removed"))
        elif after[path] != alias:
            diffs.append(
                ImportDiff(path=path, alias=after[path], change_type="modified")
            )

    for path, alias in after.items():
        if path not in before:
            diffs.append(ImportDiff(path=path, alias=alias, change_type="added"))

    return diffs


def compare_variables(
    before: dict[str, ParsedVar], after: dict[str, ParsedVar]
) -> list[VarDiff]:
    """Compare module-level variables between before and after versions."""
    diffs = []

    for name, before_var in before.items():
        after_var = after.get(name)
        if after_var is None:
            diffs.append(
                VarDiff(
                    name=name,
                    kind=before_var.kind,
                    change_type="removed",
                    old_type=before_var.type,
                    old_value=before_var.value,
                    start_line=before_var.start_line,
                    end_line=before_var.end_line,
                )
            )
            continue

        if before_var.type != after_var.type or before_var.value != after_var.value:
            diffs.append(
                VarDiff(
                    name=name,
                    kind=after_var.kind,
                    change_type="modified",
                    old_type=before_var.type,
                    new_type=after_var.type,
                    old_value=before_var.value,
                    new_value=after_var.value,
                    start_line=after_var.start_line,
                    end_line=after_var.end_line,
                )
            )

    for name, after_var in after.items():
        if name not in before:
            diffs.append(
                VarDiff(
                    name=name,
                    kind=after_var.kind,
                    change_type="added",
                    new_type=after_var.type,
                    new_value=after_var.value,
                    start_line=after_var.start_line,
                    end_line=after_var.end_line,
                )
            )

    return diffs


def extract_diff(before_path: str, after_path: str) -> SemanticDiff:
    """Extract semantic diff between two Python files."""
    before = parse_file(before_path)
    after = parse_file(after_path)

    functions = compare_functions(before.functions, after.functions)
    types = compare_classes(before.classes, after.classes)
    variables = compare_variables(before.variables, after.variables)
    imports = compare_imports(before.imports, after.imports)

    summary = ChangeSummary(
        functions_added=sum(1 for f in functions if f.change_type == "added"),
        functions_removed=sum(1 for f in functions if f.change_type == "removed"),
        functions_modified=sum(1 for f in functions if f.change_type == "modified"),
        types_added=sum(1 for t in types if t.change_type == "added"),
        types_removed=sum(1 for t in types if t.change_type == "removed"),
        types_modified=sum(1 for t in types if t.change_type == "modified"),
        variables_added=sum(1 for v in variables if v.change_type == "added"),
        variables_removed=sum(1 for v in variables if v.change_type == "removed"),
        variables_modified=sum(1 for v in variables if v.change_type == "modified"),
        imports_added=sum(1 for i in imports if i.change_type == "added"),
        imports_removed=sum(1 for i in imports if i.change_type == "removed"),
    )

    return SemanticDiff(
        language="python",
        file_path=after_path or before_path,
        functions=functions,
        types=types,
        variables=variables,
        imports=imports,
        summary=summary,
    )


def dataclass_to_dict(obj):
    """Recursively convert dataclass to dict, omitting empty values.

    NOTE: dataclass field names are part of the JSON contract consumed by Go.
    Renaming fields is a breaking change for downstream consumers.
    """
    if hasattr(obj, "__dataclass_fields__"):
        result = {}
        for key, value in asdict(obj).items():
            if value is None:
                continue
            if isinstance(value, list) and not value:
                continue
            if isinstance(value, str) and not value:
                continue
            result[key] = value
        return result
    elif isinstance(obj, list):
        return [dataclass_to_dict(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: dataclass_to_dict(v) for k, v in obj.items()}
    return obj


def _is_within_base(path: Path, base: Path) -> bool:
    try:
        path.relative_to(base)
        return True
    except ValueError:
        return False


def resolve_base_dir(base_dir: str) -> Path:
    raw = Path(base_dir) if base_dir else Path.cwd()
    try:
        resolved = raw.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError(f"base directory does not exist: {raw}") from exc
    if not resolved.is_dir():
        raise ValueError(f"base directory is not a directory: {resolved}")
    return resolved


def validate_input_path(file_path: str, base_dir: Path) -> str:
    if not file_path:
        return ""

    candidate = Path(file_path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    normalized = candidate.resolve(strict=False)

    if not _is_within_base(normalized, base_dir):
        raise ValueError(f"file path escapes base directory: {file_path}")

    if candidate.exists():
        real = candidate.resolve(strict=True)
        if not _is_within_base(real, base_dir):
            raise ValueError(
                f"file path escapes base directory via symlink: {file_path}"
            )
        if real.is_dir():
            raise ValueError(f"path is not a file: {real}")
        if real.stat().st_size > MAX_AST_FILE_SIZE:
            raise ValueError(
                f"file exceeds maximum allowed size ({MAX_AST_FILE_SIZE} bytes): {real}"
            )

    return str(normalized)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="ast_extractor.py",
        description="Extract semantic diff between before/after Python files.",
    )
    parser.add_argument("--before", default="", help="Path to before version")
    parser.add_argument("--after", default="", help="Path to after version")
    parser.add_argument(
        "--base-dir", default="", help="Allowed base directory for input paths"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help='Optional positional paths for backward compatibility: <before> <after>. Use empty string "" for new/deleted files.',
    )

    args = parser.parse_args()

    before_path = args.before
    after_path = args.after
    base_dir = args.base_dir

    if args.paths:
        if not before_path and len(args.paths) >= 1:
            before_path = args.paths[0]
        if not after_path and len(args.paths) >= 2:
            after_path = args.paths[1]
        if len(args.paths) > 2:
            parser.error("too many positional arguments; expected at most 2")

    # Handle empty string markers
    if before_path in ('""', "''"):
        before_path = ""
    if after_path in ('""', "''"):
        after_path = ""

    if not before_path and not after_path:
        parser.error("at least one of --before or --after must be provided")

    try:
        resolved_base_dir = resolve_base_dir(base_dir)
        before_path = validate_input_path(before_path, resolved_base_dir)
        after_path = validate_input_path(after_path, resolved_base_dir)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        diff = extract_diff(before_path, after_path)
        output = dataclass_to_dict(diff)
        print(json.dumps(output, indent=2))
    except Exception as e:
        error_diff = SemanticDiff(
            language="python",
            file_path=after_path or before_path,
            functions=[],
            types=[],
            variables=[],
            imports=[],
            summary=ChangeSummary(),
            error=str(e),
        )
        print(json.dumps(dataclass_to_dict(error_diff), indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
