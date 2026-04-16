"""
JavaScript beautification module.
Formats minified JS for readability using jsbeautifier.
"""
import re
from typing import Optional

try:
    import jsbeautifier
    HAS_JSBEAUTIFIER = True
except ImportError:
    HAS_JSBEAUTIFIER = False


DEFAULT_OPTS = {
    "indent_size": 2,
    "indent_char": " ",
    "max_preserve_newlines": 2,
    "preserve_newlines": True,
    "keep_array_indentation": False,
    "break_chained_methods": False,
    "indent_scripts": "normal",
    "brace_style": "collapse",
    "space_before_conditional": True,
    "unescape_strings": False,
    "jslint_happy": False,
    "end_with_newline": True,
    "wrap_line_length": 0,
    "indent_empty_lines": False,
    "comma_first": False,
    "e4x": False,
    "operator_position": "before-newline",
}


def beautify(js_content: str, opts: Optional[dict] = None) -> str:
    """
    Beautify minified JavaScript.
    Falls back to basic formatting if jsbeautifier is not installed.
    """
    if not js_content or not js_content.strip():
        return js_content

    if HAS_JSBEAUTIFIER:
        options = jsbeautifier.default_options()
        merged = {**DEFAULT_OPTS, **(opts or {})}
        for key, value in merged.items():
            if hasattr(options, key):
                setattr(options, key, value)
        try:
            return jsbeautifier.beautify(js_content, options)
        except Exception:
            pass  # Fall through to basic formatter

    # Basic fallback formatter
    return _basic_format(js_content)


def _basic_format(js: str) -> str:
    """
    Minimal JS formatter without external dependencies.
    Handles brace insertion and semicolon newlines.
    """
    result = []
    indent = 0
    i = 0
    in_string = False
    string_char = None
    in_comment = False
    in_block_comment = False

    while i < len(js):
        c = js[i]
        nc = js[i + 1] if i + 1 < len(js) else ""

        # Block comment
        if not in_string and not in_comment and c == "/" and nc == "*":
            in_block_comment = True
            result.append(c)
            i += 1
        elif in_block_comment:
            result.append(c)
            if c == "*" and nc == "/":
                in_block_comment = False
                result.append(nc)
                i += 1
        # Line comment
        elif not in_string and not in_block_comment and c == "/" and nc == "/":
            in_comment = True
            result.append(c)
        elif in_comment and c == "\n":
            in_comment = False
            result.append("\n")
        elif in_comment:
            result.append(c)
        # String handling
        elif not in_string and c in ('"', "'", "`"):
            in_string = True
            string_char = c
            result.append(c)
        elif in_string and c == string_char and (i == 0 or js[i - 1] != "\\"):
            in_string = False
            result.append(c)
        elif in_string:
            result.append(c)
        # Braces
        elif c == "{":
            result.append(" {\n" + "  " * (indent + 1))
            indent += 1
        elif c == "}":
            indent = max(0, indent - 1)
            result.append("\n" + "  " * indent + "}")
        elif c == ";":
            result.append(";\n" + "  " * indent)
        elif c == ",":
            result.append(",\n" + "  " * indent)
        else:
            result.append(c)
        i += 1

    return "".join(result)


def is_minified(js_content: str, threshold: float = 0.8) -> bool:
    """
    Heuristic to detect if JS is minified.
    Checks average line length — minified code has very long lines.
    """
    if not js_content:
        return False
    lines = js_content.splitlines()
    if not lines:
        return False
    non_empty = [l for l in lines if l.strip()]
    if not non_empty:
        return False
    avg_len = sum(len(l) for l in non_empty) / len(non_empty)
    # If average line is > 200 chars, likely minified
    return avg_len > 200


def extract_string_literals(js_content: str) -> list[str]:
    """
    Extract all string literals from JavaScript.
    Used by the analysis engine to find URLs, paths, and secrets.
    """
    strings = []
    # Single-quoted strings
    for m in re.finditer(r"'((?:[^'\\]|\\.)*)'", js_content):
        s = m.group(1).strip()
        if s:
            strings.append(s)
    # Double-quoted strings
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', js_content):
        s = m.group(1).strip()
        if s:
            strings.append(s)
    # Template literals (backtick)
    for m in re.finditer(r'`((?:[^`\\]|\\.)*)`', js_content):
        s = m.group(1).strip()
        if s:
            strings.append(s)
    return strings
