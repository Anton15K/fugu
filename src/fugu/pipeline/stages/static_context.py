"""Syntax-only context for static matches. Never imports or evaluates auditee code."""
from __future__ import annotations

import ast
import builtins
import io
from bisect import bisect_right
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
        unsupported_line_separators = {'\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029'}
        for offset, character in enumerate(text):
            if character in unsupported_line_separators:
                return spans
            if character == '\r' and not text.startswith('\r\n', offset):
                return spans
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
                elif isinstance(node, ast.ExceptHandler) and node.name is not None:
                    binding_counts[node.name] = binding_counts.get(node.name, 0) + 1
                elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name is not None:
                    binding_counts[node.name] = binding_counts.get(node.name, 0) + 1
                elif isinstance(node, ast.MatchMapping) and node.rest is not None:
                    binding_counts[node.rest] = binding_counts.get(node.rest, 0) + 1

            def bound_count(name: str) -> int:
                return binding_counts.get(name, 0)

            def safe_denylist_guard(guard: ast.AST | None) -> bool:
                if not isinstance(guard, ast.If) or not guard.body:
                    return False
                statement = guard.body[0]
                if not isinstance(statement, ast.Raise) or not isinstance(statement.exc, ast.Call):
                    return False
                call = statement.exc
                if not isinstance(call.func, ast.Name) or bound_count(call.func.id):
                    return False
                exception_type = getattr(builtins, call.func.id, None)
                if (not isinstance(exception_type, type)
                        or not issubclass(exception_type, BaseException)):
                    return False
                if call.keywords or any(not isinstance(argument, ast.Constant) for argument in call.args):
                    return False
                cause = statement.cause
                return cause is None or (isinstance(cause, ast.Constant) and cause.value is None)

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
                                     and isinstance(parent.left, ast.Name)
                                     and isinstance(parent.ops[0], ast.In) and parent.comparators == [use]
                                     and isinstance(guard, ast.If) and guard.test is parent
                                     and safe_denylist_guard(guard))
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
        # Python's splitlines() is also used for scanner hits. Unsupported
        # boundaries therefore fail closed rather than shifting a context span.
        unsupported_separators = {'\v', '\f', '\x1c', '\x1d', '\x1e', '\x85'}
        if any(character in unsupported_separators for character in text):
            return spans
        line_starts = [0]
        offset = 0
        while offset < len(text):
            character = text[offset]
            if character == '\r':
                offset += 2 if text.startswith('\r\n', offset) else 1
                line_starts.append(offset)
            elif character in ('\n', '\u2028', '\u2029'):
                offset += 1
                line_starts.append(offset)
            else:
                offset += 1

        def position(offset: int) -> tuple[int, int]:
            # splitlines() omits a trailing empty line; clamp EOF to its last
            # represented line so add() only addresses existing entries.
            if lines and offset == len(text) and line_starts[-1] == len(text):
                return len(lines), len(lines[-1])
            line_index = bisect_right(line_starts, offset) - 1
            return line_index + 1, offset - line_starts[line_index]

        # Skip complete quoted/template literals and conservatively recognize
        # regex literals before looking for comments inside their text.
        i = 0
        regex_allowed = True
        previous_word = None
        control_parens: list[bool] = []

        def regex_end(start: int) -> int | None:
            cursor = start + 1
            in_character_class = False
            escaped = False
            while cursor < len(text):
                character = text[cursor]
                if character in ('\r', '\n', '\u2028', '\u2029'):
                    return None
                if escaped:
                    escaped = False
                elif character == '\\':
                    escaped = True
                elif in_character_class:
                    if character == ']':
                        in_character_class = False
                elif character == '[':
                    in_character_class = True
                elif character == '/':
                    cursor += 1
                    flags_start = cursor
                    while cursor < len(text) and text[cursor].isascii() and text[cursor].isalpha():
                        cursor += 1
                    flags = text[flags_start:cursor]
                    if (any(flag not in 'dgimsuvy' for flag in flags)
                            or len(set(flags)) != len(flags)
                            or ('u' in flags and 'v' in flags)):
                        return None
                    if cursor < len(text) and (text[cursor].isalnum() or text[cursor] in '_$'):
                        return None
                    return cursor
                cursor += 1
            return None

        prefix_keywords = {
            'return', 'throw', 'case', 'delete', 'void', 'typeof', 'instanceof',
            'in', 'of', 'yield', 'await', 'new', 'else', 'do', 'extends', 'default',
        }
        control_keywords = {'if', 'while', 'for', 'with', 'switch', 'catch'}
        line_terminators = ('\r', '\n', '\u2028', '\u2029')
        while i < len(text):
            ch = text[i]
            if ch.isspace():
                i += 1
                continue
            if ch in ('"', "'", '`'):
                quote = ch
                cursor = i + 1
                closed = False
                while cursor < len(text):
                    character = text[cursor]
                    if character == '\\':
                        if cursor + 1 >= len(text):
                            break
                        following = text[cursor + 1]
                        if following == '\r' and text.startswith('\r\n', cursor + 1):
                            cursor += 3
                        else:
                            cursor += 2
                    elif character == quote:
                        cursor += 1
                        closed = True
                        break
                    elif character in line_terminators:
                        # An unescaped line terminator invalidates a quoted
                        # literal; later comment boundaries are uncertain.
                        return spans
                    else:
                        cursor += 1
                if not closed:
                    return spans
                i = cursor
                regex_allowed = False
                previous_word = None
                continue
            if text.startswith('//', i):
                start = position(i)
                end = i + 2
                while end < len(text) and text[end] not in line_terminators:
                    end += 1
                add(start, position(end), 'comment_reference')
                i = end
                continue
            if text.startswith('/*', i):
                start = position(i)
                close = text.find('*/', i + 2)
                end = len(text) if close == -1 else close + 2
                add(start, position(end), 'comment_reference')
                i = end
                continue
            if ch == '/':
                end = regex_end(i)
                if end is not None:
                    i = end
                    regex_allowed = False
                    previous_word = None
                    continue
                if regex_allowed:
                    # A likely but malformed regex makes later boundaries
                    # uncertain; leave them unclassified.
                    return spans
                i += 1
                regex_allowed = True
                previous_word = None
                continue
            if ch.isalpha() or ch in '_$':
                cursor = i + 1
                while cursor < len(text) and (text[cursor].isalnum() or text[cursor] in '_$'):
                    cursor += 1
                word = text[i:cursor]
                i = cursor
                regex_allowed = word in prefix_keywords
                previous_word = word
                continue
            if ch.isdigit():
                cursor = i + 1
                while cursor < len(text) and (text[cursor].isalnum() or text[cursor] in '._'):
                    cursor += 1
                i = cursor
                regex_allowed = False
                previous_word = None
                continue
            if ch == '(':
                control_parens.append(previous_word in control_keywords)
                regex_allowed = True
            elif ch == ')':
                regex_allowed = control_parens.pop() if control_parens else False
            elif ch == ']':
                regex_allowed = False
            elif ch == '}':
                regex_allowed = True
            elif ch == '.':
                regex_allowed = False
            elif ch in '([{,:;!?&|+-*%^~<>=':
                regex_allowed = True
            else:
                regex_allowed = False
            i += 1
            previous_word = None

    return spans


def file_role(rel: str) -> str:
    parts = PurePosixPath(rel).parts
    name = parts[-1]
    if 'tests' in parts or 'testdata' in parts or name.startswith('test_') or name.endswith('_test.go'):
        return 'test_source'
    if name.endswith('.lock') or name in ('package-lock.json', 'yarn.lock'):
        return 'dependency_lock'
    return 'source'
