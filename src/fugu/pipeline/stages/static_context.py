"""Syntax-only context for static matches. Never imports or evaluates auditee code."""
from __future__ import annotations

import ast
import io
from pathlib import PurePosixPath
import tokenize


def source_context(text: str, rel: str) -> dict[int, list[tuple[int, int, str]]]:
    """Line/column spans; uncertainty leaves the original alert unchanged."""
    spans: dict[int, list[tuple[int, int, str]]] = {}
    lines = text.splitlines()
    byte_column_maps: dict[int, dict[int, int]] = {}

    def add(start: tuple[int, int], end: tuple[int, int], kind: str) -> None:
        for line in range(start[0], end[0] + 1):
            left = start[1] if line == start[0] else 0
            right = end[1] if line == end[0] else len(lines[line - 1])
            spans.setdefault(line, []).append((left, right, kind))

    def character_column(line_number: int, byte_column: int) -> int:
        columns = byte_column_maps.get(line_number)
        if columns is None:
            columns = {0: 0}
            byte_offset = 0
            for character_column, character in enumerate(lines[line_number - 1], start=1):
                byte_offset += len(character.encode('utf-8'))
                columns[byte_offset] = character_column
            byte_column_maps[line_number] = columns
        try:
            return columns[byte_column]
        except KeyError as exc:
            # AST positions are UTF-8 byte offsets and must land on code-point
            # boundaries. If that invariant changes, fail closed on context.
            raise ValueError('AST column is not a UTF-8 character boundary') from exc

    def add_ast_span(start_line: int, start_byte_column: int,
                     end_line: int, end_byte_column: int, kind: str) -> None:
        add((start_line, character_column(start_line, start_byte_column)),
            (end_line, character_column(end_line, end_byte_column)), kind)

    if rel.endswith('.py'):
        try:
            for token in tokenize.generate_tokens(io.StringIO(text).readline):
                if token.type == tokenize.COMMENT:
                    add(token.start, token.end, 'comment_reference')
            tree = ast.parse(text)
            nodes = list(ast.walk(tree))
            parents: dict[ast.AST, ast.AST] = {}
            load_uses: dict[str, list[ast.Name]] = {}
            binding_counts: dict[str, int] = {}
            for node in nodes:
                for child in ast.iter_child_nodes(node):
                    parents[child] = node
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    load_uses.setdefault(node.id, []).append(node)
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                    binding_counts[node.id] = binding_counts.get(node.id, 0) + 1
                elif isinstance(node, ast.arg):
                    binding_counts[node.arg] = binding_counts.get(node.arg, 0) + 1
                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    binding_counts[node.name] = binding_counts.get(node.name, 0) + 1
                elif isinstance(node, ast.alias):
                    name = node.asname or node.name.split('.')[0]
                    binding_counts[name] = binding_counts.get(name, 0) + 1

            def bound_count(name: str) -> int:
                return binding_counts.get(name, 0)

            def collection_kind(node: ast.AST) -> str:
                assignment = parents.get(node)
                if not isinstance(assignment, ast.Assign) or len(assignment.targets) != 1 or not isinstance(assignment.targets[0], ast.Name):
                    return 'literal_collection'
                name = assignment.targets[0].id
                uses = load_uses.get(name, [])
                if not uses or bound_count(name) != 1:
                    return 'literal_collection'
                deny_uses = []
                detector_uses = []
                for use in uses:
                    parent = parents.get(use)
                    guard = parents.get(parent)
                    deny_uses.append(isinstance(parent, ast.Compare) and len(parent.ops) == 1
                                     and isinstance(parent.ops[0], ast.In) and parent.comparators == [use]
                                     and isinstance(guard, ast.If) and guard.test is parent
                                     and bool(guard.body) and isinstance(guard.body[0], ast.Raise))
                    generator = parents.get(parent)
                    call = parents.get(generator)
                    is_detector = (isinstance(parent, ast.comprehension) and parent.iter is use
                                   and isinstance(parent.target, ast.Name) and not parent.ifs
                                   and isinstance(generator, ast.GeneratorExp) and len(generator.generators) == 1
                                   and isinstance(generator.elt, ast.Compare) and len(generator.elt.ops) == 1
                                   and isinstance(generator.elt.ops[0], ast.In)
                                   and isinstance(generator.elt.left, ast.Name)
                                   and generator.elt.left.id == parent.target.id
                                   and isinstance(generator.elt.comparators[0], ast.Name)
                                   and isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                                   and call.func.id == 'any' and bound_count('any') == 0
                                   and isinstance(parents.get(call), ast.Return))
                    detector_uses.append(is_detector)
                if all(deny_uses):
                    return 'denylist_reference'
                if all(detector_uses):
                    return 'detector_vocabulary'
                return 'literal_collection'

            for node in nodes:
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'next' and bound_count('next') == 0 and node.args:
                    generator = node.args[0]
                    if isinstance(generator, ast.GeneratorExp) and len(generator.generators) == 1:
                        comp = generator.generators[0]
                        items = comp.iter
                        is_items = (isinstance(items, ast.Call) and isinstance(items.func, ast.Attribute)
                                    and items.func.attr == 'items' and isinstance(items.func.value, ast.Attribute)
                                    and items.func.value.attr == 'environ' and isinstance(items.func.value.value, ast.Name)
                                    and items.func.value.value.id == 'os')
                        if is_items and isinstance(comp.target, ast.Tuple) and len(comp.target.elts) == 2 and all(isinstance(item, ast.Name) for item in comp.target.elts) and len(comp.ifs) == 1:
                            key, value = comp.target.elts
                            condition = comp.ifs[0]
                            if (isinstance(condition, ast.Compare) and len(condition.ops) == 1
                                and isinstance(condition.ops[0], ast.Eq) and isinstance(condition.left, ast.Name)
                                and condition.left.id == key.id and isinstance(condition.comparators[0], (ast.Name, ast.Constant))
                                and isinstance(generator.elt, ast.Name) and generator.elt.id == value.id):
                                add_ast_span(generator.lineno, generator.col_offset,
                                             generator.end_lineno or generator.lineno,
                                             generator.end_col_offset or 0,
                                             'single_key_env_lookup')
                if isinstance(node, (ast.List, ast.Tuple, ast.Set)) and node.elts and all(
                    isinstance(item, ast.Constant) and isinstance(item.value, str) for item in node.elts
                ):
                    add_ast_span(node.lineno, node.col_offset,
                                 node.end_lineno or node.lineno,
                                 node.end_col_offset or 0, collection_kind(node))
        except (SyntaxError, ValueError, tokenize.TokenError, IndentationError, RecursionError):
            # Do not use partial syntax information as an exemption.
            return {}
    elif rel.endswith(('.js', '.ts', '.mjs', '.cjs', '.jsx', '.tsx')):
        # Skip complete quoted/template literals; never treat text inside them
        # as comments. Template interpolation is deliberately not inferred.
        i = 0
        line = 1
        column = 0
        quote = None
        while i < len(text):
            ch = text[i]
            if quote:
                if ch == '\\' and i + 1 < len(text):
                    column += 2
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in ('"', "'", '`'):
                quote = ch
            elif text.startswith('//', i) or text.startswith('/*', i):
                start = (line, column)
                end = text.find('\n', i) if text.startswith('//', i) else text.find('*/', i + 2)
                if end == -1:
                    end = len(text)
                elif text.startswith('/*', i):
                    end += 2
                segment = text[i:end]
                chunks = segment.split('\n')
                end_line = line + len(chunks) - 1
                end_column = column + len(segment) if len(chunks) == 1 else len(chunks[-1])
                add(start, (end_line, end_column), 'comment_reference')
                line, column, i = end_line, end_column, end
                continue
            if ch == '\n':
                line += 1
                column = 0
            else:
                column += 1
            i += 1
    return spans


def file_role(rel: str) -> str:
    parts = PurePosixPath(rel).parts
    name = parts[-1]
    if 'tests' in parts or 'testdata' in parts or name.startswith('test_') or name.endswith('_test.go'):
        return 'test_source'
    if name.endswith('.lock') or name in ('package-lock.json', 'yarn.lock'):
        return 'dependency_lock'
    return 'source'
