"""C++→Go translator for the per-build Key()/IV() bodies in cmf-key.cpp.

The generator side is best-effort but covers every construct currently
present in upstream CascLib (uint/const-uint/int locals, += -= --
mutations, switch/case, casts, Constrain, SignedMod, Math.Max,
post-increment-in-index). Any function whose body falls outside the
supported pattern set is skipped; cmfkeygen emits a stub provider for
those builds so the registry still has an entry.

This module is imported by tools/cmfkeygen/main.py.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Substitutions applied to a raw C++ statement before emission.
# Order matters; longer/more-specific patterns must come first.
# ---------------------------------------------------------------------------

# Header field accesses → CMFHeader Go fields with explicit casts so all
# arithmetic happens in uint32. DataCount/EntryCount are int32 in Go
# (matching the C++ struct), so we wrap them.
_HEADER_RE = [
    (re.compile(r"\(uint\)\s*header\.m_buildVersion"), "hdr.BuildVersion"),
    (re.compile(r"\(uint\)\s*header\.m_dataCount"),    "uint32(hdr.DataCount)"),
    (re.compile(r"\(uint\)\s*header\.m_entryCount"),   "uint32(hdr.EntryCount)"),
    (re.compile(r"header\.m_buildVersion"), "hdr.BuildVersion"),
    (re.compile(r"header\.m_dataCount"),    "uint32(hdr.DataCount)"),
    (re.compile(r"header\.m_entryCount"),   "uint32(hdr.EntryCount)"),
    (re.compile(r"header\.GetNonEncryptedMagic\s*\(\s*\)"), "nonEncryptedMagic(hdr)"),
]

# Constants and helpers (those that don't need paren-balanced args).
_HELPER_RE = [
    (re.compile(r"\bSHA1_DIGESTSIZE\b"), "sha1DigestSize"),
    (re.compile(r"\bKeytable\["), "keytable["),
    # Strip C/C++ integer literal suffixes (u, U, ul, ULL, ...).
    (re.compile(r"(\b[0-9]+|0[xX][0-9a-fA-F]+)[uUlL]+\b"), r"\1"),
]

# Cast normalisations done by hand: find `(TYPE)` and replace with
# `TYPE(<operand>)` where <operand> is the next paren-balanced group or
# the next identifier-with-postfix token.
_CAST_TYPES = {
    "byte":   "byte",
    "uint":   "uint32",
    # ushort: emit as `uint32(uint16(...))` to preserve 16-bit
    # truncation while keeping the result uint32 for arithmetic.
    "ushort": "uint32_uint16",
    "int":    "uint32",
}

_CAST_FIND = re.compile(r"\(\s*(byte|uint|ushort|int)\s*\)\s*")


def _apply_casts(s: str) -> str:
    out = []
    i = 0
    while i < len(s):
        m = _CAST_FIND.match(s, i)
        if not m:
            out.append(s[i])
            i += 1
            continue
        typ = _CAST_TYPES[m.group(1)]
        if typ == "uint32_uint16":
            wrap_open = "uint32(uint16("
            wrap_close = "))"
        else:
            wrap_open = f"{typ}("
            wrap_close = ")"
        i = m.end()
        if i < len(s) and s[i] == "(":
            depth = 1
            j = i + 1
            while j < len(s) and depth > 0:
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                j += 1
            operand = _apply_casts(s[i+1:j-1])
            out.append(f"{wrap_open}{operand}{wrap_close}")
            i = j
        elif i < len(s) and (s[i].isalpha() or s[i] == "_"):
            j = i
            while j < len(s) and (s[j].isalnum() or s[j] == "_"):
                j += 1
            while j < len(s):
                if s[j] == ".":
                    j += 1
                    while j < len(s) and (s[j].isalnum() or s[j] == "_"):
                        j += 1
                elif s[j] in "[(":
                    open_c, close_c = s[j], "]" if s[j] == "[" else ")"
                    depth = 1
                    j += 1
                    while j < len(s) and depth > 0:
                        if s[j] == open_c:
                            depth += 1
                        elif s[j] == close_c:
                            depth -= 1
                        j += 1
                else:
                    break
            operand = s[i:j]
            out.append(f"{wrap_open}{operand}{wrap_close}")
            i = j
        elif i < len(s) and s[i].isdigit():
            j = i
            while j < len(s) and (s[j].isalnum() or s[j] in "_xX"):
                j += 1
            out.append(f"{wrap_open}{s[i:j]}{wrap_close}")
            i = j
        else:
            out.append(m.group(0))
    return "".join(out)


_CAST_RE: list = []  # not used; kept for backwards compatibility


def _apply(rules, s: str) -> str:
    for pat, rep in rules:
        s = pat.sub(rep, s)
    return s


# ---------------------------------------------------------------------------
# Per-line statement translator.
# ---------------------------------------------------------------------------

_DECL_UINT = re.compile(r"^uint\s+(\w+)\s*=\s*(.+?);\s*$")
_DECL_UINT_BARE = re.compile(r"^uint\s+(\w+)\s*;\s*$")
_DECL_UINT_MULTI = re.compile(r"^uint\s+(\w+(?:\s*,\s*\w+)+)\s*;\s*$")
_DECL_CONST_UINT = re.compile(r"^const\s+uint\s+(\w+)\s*=\s*(.+?);\s*$")
_DECL_INT = re.compile(r"^int\s+(\w+)\s*=\s*(.+?);\s*$")
_DECL_INT_BARE = re.compile(r"^int\s+(\w+)\s*;\s*$")
_DECL_LONG = re.compile(r"^(?:LONGLONG|long\s+long)\s+(\w+)\s*=\s*(.+?);\s*$")
# Chained assignment without declaration: X = Y = Z;
_CHAINED = re.compile(r"^(\w+)\s*=\s*(\w+)\s*=\s*(.+?);\s*$")
_FOR_INT = re.compile(
    r"^for\s*\(\s*(?:int|uint)\s+i\s*=\s*0\s*;\s*i\s*!=\s*length\s*;\s*\+\+i\s*\)\s*$"
)
_RETURN_BUF = re.compile(r"^return\s+buffer\s*;\s*$")
_PLAIN = re.compile(r"^[A-Za-z_].*?;\s*$")  # generic stmt ending in ;

# Inline post-increment fix: `digest[ividx++ % SHA1_DIGESTSIZE]`
_POST_INC = re.compile(r"(\w+)\+\+")


def _strip_cpp_assign_semi(s: str) -> str:
    return s.strip().rstrip(";").strip()


def _stmt_with_ternary(lhs: str, op: str, rhs: str) -> str | None:
    """If RHS is a ternary expression, emit an if/else over LHS op= ...
    Returns None if RHS contains no top-level ternary."""
    parts = _split_ternary(rhs)
    if parts is None:
        return None
    cond, a, b = parts
    cond_t = _translate_expr(cond)
    a_t = _translate_expr(a)
    b_t = _translate_expr(b)
    return (
        f"if {cond_t} {{\n\t\t\t{lhs} {op} {a_t}\n\t\t}} else {{\n"
        f"\t\t\t{lhs} {op} {b_t}\n\t\t}}"
    )


def _split_ternary(rhs: str) -> tuple[str, str, str] | None:
    """If `rhs` is `cond ? a : b`, return (cond, a, b). Otherwise None."""
    # Find top-level `?`.
    depth = 0
    qmark = -1
    for i, ch in enumerate(rhs):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "?" and depth == 0:
            qmark = i
            break
    if qmark < 0:
        return None
    depth = 0
    colon = -1
    for i in range(qmark + 1, len(rhs)):
        ch = rhs[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == ":" and depth == 0:
            colon = i
            break
    if colon < 0:
        return None
    return rhs[:qmark].strip(), rhs[qmark + 1:colon].strip(), rhs[colon + 1:].strip()


def _rewrite_ternary(s: str) -> str:
    """Rewrite a bare `cond ? a : b` expression into a closure call.

    Only invoked when the ternary lives inside a deeper expression
    (e.g. as a function argument). Statement-level ternaries are
    handled in _translate_stmt.
    """
    parts = _split_ternary(s)
    if parts is None:
        return s
    cond, a, b = parts
    return (
        f"func() uint32 {{ if {cond} {{ return uint32({a}) }}; "
        f"return uint32({b}) }}()"
    )


def _balanced_call(s: str, name: str) -> tuple[int, int, str] | None:
    """Find the next call to `name(...)` and return (start, end, args).

    `start` is the position of `name`, `end` is one past the closing `)`,
    `args` is the contents between the parens.
    """
    pat = re.compile(r"\b" + re.escape(name) + r"\s*\(")
    m = pat.search(s)
    if not m:
        return None
    i = m.end()
    depth = 1
    j = i
    while j < len(s) and depth > 0:
        if s[j] == "(":
            depth += 1
        elif s[j] == ")":
            depth -= 1
            if depth == 0:
                return (m.start(), j + 1, s[i:j])
        j += 1
    return None


def _split_top_args(args: str) -> list[str]:
    out = []
    depth = 0
    last = 0
    for i, ch in enumerate(args):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(args[last:i])
            last = i + 1
    out.append(args[last:])
    return [a.strip() for a in out]


def _rewrite_balanced(s: str) -> str:
    """Translate Constrain(...) / SignedMod(...) / Math.Max(...) using
    paren-balanced argument extraction."""
    # Constrain
    while True:
        r = _balanced_call(s, "Constrain")
        if not r:
            break
        st, en, args = r
        s = s[:st] + f"constrain(int64({args.strip()}))" + s[en:]
    # SignedMod
    while True:
        r = _balanced_call(s, "SignedMod")
        if not r:
            break
        st, en, args = r
        parts = _split_top_args(args)
        if len(parts) != 2:
            return s
        s = s[:st] + f"signedMod(int64({parts[0]}), int64({parts[1]}))" + s[en:]
    # Math.Max
    while True:
        r = _balanced_call(s, "Math.Max")
        if not r:
            break
        st, en, args = r
        parts = _split_top_args(args)
        if len(parts) != 2:
            return s
        # Common idiom in this table: Math.Max(EXPR % MOD, 0). The C++
        # / C# code relies on signed arithmetic in EXPR; if EXPR is
        # negative (e.g. `2 * digest[13] - length`), C/C# % can return
        # a negative value, and Math.Max clamps to 0.
        #
        # If we let the default int32(arg0) wrap our uint32-promoted
        # expression *after* the % has already happened, the modulus
        # is computed on unsigned values and never goes negative, so
        # the clamp becomes a no-op and the recipe drifts.
        #
        # Detect this idiom and emit `signedMod(int64(EXPR),
        # int64(MOD))`, which mirrors the C++ exactly.
        first = parts[0].strip()
        second = parts[1].strip()
        modlhs, modrhs = _split_top_mod(first)
        if modlhs is not None and second == "0":
            replacement = (
                f"signedMod(int64(int32({modlhs})), int64({modrhs}))"
            )
        else:
            replacement = (
                f"maxInt32(int32({parts[0]}), int32({parts[1]}))"
            )
        s = s[:st] + replacement + s[en:]
    return s


def _split_top_mod(expr: str) -> tuple[str | None, str | None]:
    """Split `EXPR % MOD` at the top-level `%`; return (None, None) if
    no top-level `%` exists. Skips `%` inside parens / brackets."""
    depth = 0
    for i in range(len(expr) - 1, -1, -1):
        c = expr[i]
        if c in ")]":
            depth += 1
        elif c in "([":
            depth -= 1
        elif c == "%" and depth == 0:
            return expr[:i].strip(), expr[i + 1:].strip()
    return None, None


def _translate_index(idx: str) -> str:
    """Translate an array index expression. The result is used inside a
    Go `[...]` and must evaluate to an integer; we go through
    _translate_expr so casts and helpers apply, but ensure the final
    expression is index-compatible (Go allows uint32, int, etc.)."""
    return _translate_expr(idx)


def _wrap_indexed(s: str, name: str) -> str:
    """Wrap `<name>[X]` in `uint32(...)` so it can mix with uint32 arithmetic.
    Recurses into the index expression."""
    out = []
    i = 0
    pat = re.compile(r"\b" + re.escape(name) + r"\[")
    while i < len(s):
        m = pat.match(s, i)
        if not m:
            out.append(s[i])
            i += 1
            continue
        j = m.end()
        depth = 1
        while j < len(s) and depth > 0:
            if s[j] == "[":
                depth += 1
            elif s[j] == "]":
                depth -= 1
            j += 1
        inner = _wrap_indexed(s[m.end():j-1], name)
        out.append(f"uint32({name}[{inner}])")
        i = j
    return "".join(out)


def _wrap_keytable(s: str) -> str:
    s = _wrap_indexed(s, "keytable")
    s = _wrap_indexed(s, "digest")
    return s


def _translate_expr(expr: str) -> str:
    """Translate one RHS expression from C++ to Go semantics."""
    e = _apply(_HEADER_RE, expr)
    e = _apply_casts(e)
    e = _rewrite_balanced(e)
    e = _apply(_HELPER_RE, e)
    e = _wrap_keytable(e)
    # length is Go int; force uint32 in expressions.
    e = re.sub(r"\blength\b", "uint32(length)", e)
    # i is the Go int loop counter; force uint32 in arithmetic contexts.
    e = re.sub(r"\bi\b", "uint32(i)", e)
    e = _rewrite_ternary(e)
    return e


def _translate_stmt(stmt: str, post_incs: list[str]) -> str | None:
    """Translate a single C++ statement to Go.

    Returns None on unsupported constructs (caller marks the whole
    function unsupported).
    `post_incs` is mutated to record any post-increment vars seen inside
    array indices: we emit `++X` lines after the host statement.
    """
    s = stmt.strip()
    if not s:
        return ""

    # Capture pattern `var++` inside subscripts and rewrite to plain var,
    # noting that we owe a `var++` after the host statement.
    def repl(m: re.Match[str]) -> str:
        post_incs.append(m.group(1))
        return m.group(1)

    # Only rewrite postfix ++ when it appears inside [...] (index pos).
    s2 = re.sub(
        r"\[([^\[\]]*?)\]",
        lambda m: "[" + _POST_INC.sub(repl, m.group(1)) + "]",
        s,
    )
    s = s2

    # uint X = expr;
    if m := _DECL_UINT.match(s):
        rhs = m.group(2)
        # Chained assignment: uint X = Y = Z;
        cm = re.match(r"^(\w+)\s*=\s*(.+)$", rhs)
        if cm:
            inner_var = cm.group(1)
            inner_rhs = cm.group(2)
            return (
                f"{inner_var} = {_translate_expr(inner_rhs)}\n"
                + "\t\t" + f"{m.group(1)} := uint32({inner_var})"
            )
        return f"{m.group(1)} := uint32({_translate_expr(rhs)})"
    if m := _DECL_UINT_BARE.match(s):
        return f"var {m.group(1)} uint32"
    if m := _DECL_UINT_MULTI.match(s):
        names = [n.strip() for n in m.group(1).split(",")]
        return "\n\t\t".join(f"var {n} uint32" for n in names)
    if m := _CHAINED.match(s):
        # X = Y = Z;  →  Y = Z; X = Y  (both vars must be pre-declared)
        return (
            f"{m.group(2)} = {_translate_expr(m.group(3))}\n"
            + "\t\t" + f"{m.group(1)} = {m.group(2)}"
        )
    if m := _DECL_CONST_UINT.match(s):
        return f"const {m.group(1)} = uint32({_translate_expr(m.group(2))})"
    if m := _DECL_INT.match(s):
        return f"{m.group(1)} := uint32({_translate_expr(m.group(2))})"
    if m := _DECL_INT_BARE.match(s):
        return f"var {m.group(1)} uint32"
    if m := _DECL_LONG.match(s):
        return f"{m.group(1)} := int64({_translate_expr(m.group(2))})"

    # Special case: buffer[i] = Keytable[expr];  keep byte type.
    if mm := re.match(r"^buffer\[i\]\s*=\s*Keytable\[(.+)\]\s*;\s*$", s):
        return f"buffer[i] = keytable[{_translate_index(mm.group(1))}]"
    # Special case: buffer[i] = digest[expr];  keep byte type.
    if mm := re.match(r"^buffer\[i\]\s*=\s*digest\[(.+)\]\s*;\s*$", s):
        return f"buffer[i] = digest[{_translate_index(mm.group(1))}]"
    # Special case: buffer[i] ^= digest[expr];  keep byte type.
    if mm := re.match(r"^buffer\[i\]\s*\^=\s*digest\[(.+)\]\s*;\s*$", s):
        return f"buffer[i] ^= digest[{_translate_index(mm.group(1))}]"

    # Compound assignment with ternary RHS:  LHS op= cond ? a : b;
    cm = re.match(r"^(\w+)\s*([+\-*/]?=)\s*(.+);\s*$", s)
    if cm:
        rhs = cm.group(3)
        ternary = _stmt_with_ternary(cm.group(1), cm.group(2), rhs)
        if ternary is not None:
            return ternary

    # for-loops handled by line scanner.
    if _FOR_INT.match(s):
        return "for i := 0; i != length; i++ {"

    # `++X;` / `--X;`
    if mm := re.match(r"^\+\+(\w+)\s*;\s*$", s):
        return f"{mm.group(1)}++"
    if mm := re.match(r"^--(\w+)\s*;\s*$", s):
        return f"{mm.group(1)}--"

    # generic expression-stmt ending in `;` (compound-assign, calls...)
    if _RETURN_BUF.match(s):
        return ""  # generated function returns implicitly via mutation

    if s.endswith(";"):
        body = _strip_cpp_assign_semi(s)
        body = _translate_expr(body)
        return body

    # bare `case N:` and `break;` and braces handled by line scanner.
    return None


# ---------------------------------------------------------------------------
# Function body translator.
# ---------------------------------------------------------------------------

@dataclass
class Translated:
    name: str            # "Key" or "IV"
    body: str            # Go body (without surrounding func() {})
    ok: bool = True


_FUNC_HEAD_KEY = re.compile(
    r"LPBYTE\s+Key\s*\(.*?\)\s*\{(?P<body>.*?)\n\s{4}\}",
    re.DOTALL,
)
_FUNC_HEAD_IV = re.compile(
    r"LPBYTE\s+IV\s*\(.*?\)\s*\{(?P<body>.*?)\n\s{4}\}",
    re.DOTALL,
)


def _add_missing_braces(src: str) -> str:
    """Wrap single-statement `for(...) stmt;` / `if(...) stmt; [else stmt;]`
    bodies in explicit braces. CascLib's autogenerated cmf-key.cpp
    occasionally omits braces."""
    lines = src.splitlines()
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        # `if (cond) stmt; else stmt;` on consecutive lines.
        m_if = re.match(r"^(\s*)if\s*\((.+)\)\s*(.+;)\s*$", line)
        if m_if:
            indent = m_if.group(1)
            cond = m_if.group(2)
            stmt = m_if.group(3)
            # peek next non-empty line for `else stmt;`
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            m_else = None
            if j < len(lines):
                m_else = re.match(r"^(\s*)else\s+(.+;)\s*$", lines[j])
            if m_else:
                out.append(f"{indent}if ({cond}) {{")
                out.append(f"{indent}    {stmt}")
                out.append(f"{indent}}} else {{")
                out.append(f"{indent}    {m_else.group(2)}")
                out.append(f"{indent}}}")
                i = j + 1
                continue
            # plain single-line if without else: leave for the per-line
            # translator (it already handles that case).
        m_for_if = re.match(r"^(\s*)(for|if)\s*\(.+\)\s*$", line)
        if m_for_if:
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or lines[j].lstrip().startswith("//")):
                j += 1
            if j < len(lines) and lines[j].strip() != "{":
                indent = m_for_if.group(1)
                out.append(line)
                out.append(indent + "{")
                out.append(lines[j])
                out.append(indent + "}")
                i = j + 1
                continue
        out.append(line)
        i += 1
    return "\n".join(out)


def _translate_body(body_src: str) -> str | None:
    """Walk the C++ body line-by-line, emit Go statements.

    Returns None if any line is unsupported.
    """
    body_src = _add_missing_braces(body_src)
    out: list[str] = []
    indent = "\t"
    depth = 1  # start inside outer function
    skip_open_brace = False  # set when previous line opened the block

    for raw in body_src.splitlines():
        line = raw.strip()
        if not line:
            out.append("")
            continue
        # comments
        if line.startswith("//"):
            out.append(indent * depth + "// " + line[2:].strip())
            continue

        # Block-control tokens.
        if line == "{":
            if skip_open_brace:
                skip_open_brace = False
                continue
            out.append(indent * depth + "{")
            depth += 1
            continue
        if line == "}":
            depth -= 1
            out.append(indent * depth + "}")
            continue
        if line == "} else {":
            out.append(indent * (depth - 1) + "} else {")
            continue

        # for-loop with brace on same line: `for (...) {`
        if mm := re.match(
            r"^for\s*\(\s*(?:int|uint)\s+i\s*=\s*0\s*;\s*i\s*!=\s*length\s*;\s*\+\+i\s*\)\s*(\{?)\s*$",
            line,
        ):
            out.append(indent * depth + "for i := 0; i != length; i++ {")
            depth += 1
            skip_open_brace = mm.group(1) != "{"
            continue

        if mm := re.match(r"^switch\s*\((.+?)\)\s*(\{?)\s*$", line):
            out.append(indent * depth + f"switch {_translate_expr(mm.group(1))} {{")
            depth += 1
            skip_open_brace = mm.group(2) != "{"
            continue

        if mm := re.match(r"^case\s+([0-9]+)\s*:\s*$", line):
            out.append(indent * (depth - 1) + f"case {mm.group(1)}:")
            continue

        if line == "break;":
            # Go switch cases don't fall through; suppress break.
            continue

        if line == "default:":
            out.append(indent * (depth - 1) + "default:")
            continue

        # `if (cond) stmt;` single-line — match "if ... ;" with a
        # statement on the same line.
        if mm := re.match(r"^if\s*\((.+?)\)\s*(.+;)\s*$", line):
            cond = _translate_expr(mm.group(1))
            inner = _translate_stmt(mm.group(2), [])
            if inner is None:
                return None
            out.append(indent * depth + f"if {cond} {{")
            out.append(indent * (depth + 1) + inner)
            out.append(indent * depth + "}")
            continue

        # plain `if (cond) {` (with optional brace on same line)
        if mm := re.match(r"^if\s*\((.+?)\)\s*(\{?)\s*$", line):
            out.append(indent * depth + f"if {_translate_expr(mm.group(1))} {{")
            depth += 1
            skip_open_brace = mm.group(2) != "{"
            continue

        post: list[str] = []
        translated = _translate_stmt(line, post)
        if translated is None:
            return None
        if translated:
            out.append(indent * depth + translated)
        for v in post:
            out.append(indent * depth + f"{v}++")

    return "\n".join(out)


def translate_namespace(scope: str) -> tuple[Translated | None, Translated | None]:
    """Translate the Key() and IV() functions inside one namespace block."""
    key = None
    iv = None

    if mk := _FUNC_HEAD_KEY.search(scope):
        body = _translate_body(mk.group("body"))
        key = Translated(name="Key", body=body or "", ok=body is not None)

    if mi := _FUNC_HEAD_IV.search(scope):
        body = _translate_body(mi.group("body"))
        iv = Translated(name="IV", body=body or "", ok=body is not None)

    return key, iv
