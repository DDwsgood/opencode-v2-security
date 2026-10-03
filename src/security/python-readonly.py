#!/usr/bin/env python3
"""Static read-only prover for small Python programs.

Reads one JSON request on stdin:
    {"source": "...", "searchDirs": ["/abs/dir", ...]}
and writes one JSON verdict on stdout:
    {"ok": true, "paths": [...]}            program is provably read-only
    {"ok": false, "reason": "..."}          not proven (caller keeps review)

The program is only parsed with `ast`; nothing in it is imported or executed.
"Read-only" means: no file writes, no deletion, no process spawning, no
network, no dynamic code evaluation, and no import that could resolve to a
file the agent controls. Anything the analysis cannot resolve is rejected,
so a False verdict is always safe; only a True verdict needs to be sound.
`paths` lists string constants that look like filesystem paths so the caller
can apply its own sensitive-path policy.
"""

import ast
import json
import os
import re
import sys

MAX_SOURCE_CHARS = 200_000

# Modules whose whole public surface is read-only / pure computation. File
# handles they open still pass through the generic `mode=` and write-method
# checks below.
FREE_MODULES = {
    "json", "re", "math", "cmath", "collections", "itertools", "functools",
    "statistics", "datetime", "time", "decimal", "fractions", "random",
    "string", "textwrap", "pprint", "hashlib", "base64", "binascii", "struct",
    "zlib", "gzip", "bz2", "lzma", "zipfile", "tarfile", "csv", "glob",
    "fnmatch", "difflib", "unicodedata", "uuid", "enum", "dataclasses",
    "typing", "abc", "heapq", "bisect", "copy", "operator", "contextlib",
    "traceback", "warnings", "ast", "tokenize", "keyword", "locale",
    "calendar", "html", "xml", "email", "mimetypes", "pathlib", "sqlite3",
    "numbers", "secrets", "shlex", "colorsys", "array", "errno", "stat",
    "filecmp", "zoneinfo", "graphlib", "tomllib", "configparser", "reprlib",
    "codecs", "platform", "argparse", "textwrap", "quopri", "binhex",
    "__future__",
    # Third-party computation / document readers.
    "numpy", "sympy", "scipy", "pandas", "mpmath", "PIL", "openpyxl",
    "tabulate", "bs4", "jsonschema", "pptx", "docx", "fitz", "networkx",
    "matplotlib",
}

# Restricted modules: only the listed attribute paths may be used.
RESTRICTED = {
    "os": {
        "path", "listdir", "scandir", "walk", "getcwd", "stat", "lstat",
        "fspath", "sep", "linesep", "pathsep", "curdir", "pardir", "extsep",
        "cpu_count", "getpid", "getppid", "get_terminal_size", "name",
        "fsdecode", "fsencode", "devnull", "getuid", "getgid", "uname",
        "readlink", "access", "isatty", "strerror", "R_OK", "F_OK", "X_OK",
        "W_OK", "SEEK_SET", "SEEK_END", "SEEK_CUR", "DirEntry", "stat_result",
    },
    "sys": {
        "argv", "stdin", "stdout", "stderr", "exit", "version",
        "version_info", "platform", "maxsize", "getsizeof",
        "getrecursionlimit", "setrecursionlimit", "getdefaultencoding",
        "getfilesystemencoding", "byteorder", "executable", "float_info",
        "int_info", "hexversion", "implementation", "flags",
        "set_int_max_str_digits", "get_int_max_str_digits", "maxunicode",
    },
    "shutil": {"which", "get_terminal_size", "disk_usage"},
    "io": {"StringIO", "BytesIO", "TextIOWrapper", "FileIO", "open", "SEEK_SET", "SEEK_END"},
    "urllib": {"parse"},
    "yaml": {
        "safe_load", "safe_load_all", "safe_dump", "YAMLError", "SafeLoader",
        "CSafeLoader",
    },
}

ALLOWED_DUNDERS = {"__name__", "__doc__", "__version__", "__file__", "__qualname__", "__module__", "__init__"}

DENIED_BUILTINS = {
    "eval", "exec", "compile", "__import__", "globals", "locals", "vars",
    "setattr", "delattr", "breakpoint", "help", "__builtins__", "__loader__",
    "__spec__", "memoryview",
}

# Attribute names that reach a module object from another module
# (`glob.os.system`) are rejected unless the base is the module itself.
ESCAPE_ATTRS = {
    "os", "sys", "subprocess", "shutil", "socket", "builtins", "importlib",
    "ctypes", "posix", "nt", "pty", "_os", "_posixsubprocess", "system",
    "popen", "urllib", "http", "requests", "pickle", "marshal",
    # Frame/code objects reach the real builtins without any dunder name
    # (`(x for x in ()).gi_frame.f_builtins["exec"]`).
    "f_builtins", "f_globals", "f_locals", "f_back", "f_code", "gi_frame",
    "gi_code", "cr_frame", "cr_code", "ag_frame", "ag_code", "tb_frame",
    "tb_next", "func_globals", "ctypeslib", "load_library", "CDLL", "cdll",
    "attrgetter", "methodcaller",
}

# Callables that write, delete, spawn, evaluate code, or talk to the network
# whatever the receiver is. Referencing one at all (not just calling it) is
# rejected, so `f = p.unlink; f()` cannot slip through. Ambiguous names
# (`replace`, `rename`, `dump`, `to_*`) are judged by call shape instead.
WRITE_METHODS = {
    "write_text", "write_bytes", "unlink", "rmdir", "mkdir", "makedirs",
    "touch", "chmod", "lchmod", "chown", "symlink_to", "hardlink_to",
    "link_to", "truncate", "save", "savefig", "savetxt", "savez",
    "savez_compressed", "tofile", "executescript", "enable_load_extension",
    "load_extension", "backup", "extract", "extractall", "urlopen",
    "urlretrieve", "system", "popen", "spawn", "spawnl", "spawnv", "fork",
    "kill", "killpg", "terminate", "send", "sendall", "sendto", "writestr",
    "putenv", "unsetenv", "chdir", "rmtree", "copyfile",
    "copytree", "move", "eval", "read_pickle", "sympify", "parse_expr",
    "write_image", "write_html", "to_file", "writexml", "set_executable",
    "create_subprocess_exec", "create_subprocess_shell", "ExcelWriter",
    "HDFStore", "PdfPages", "ez_save", "saveIncr", "save_incr", "pil_save",
    "writePNG", "writeImage", "lambdify", "autowrap", "ufuncify",
    "binary_function", "load_library", "imsave", "imwrite",
}
WRITE_PREFIX = re.compile(r"^(?:write_|save_|export_)")
AMBIGUOUS_METHODS = {"replace", "rename", "dump", "open"}
DUNDER_IN_STR = re.compile(r"__(?!main__|name__|init__|future__|version__|file__|doc__)[A-Za-z]\w*__")

SQL_START = re.compile(r"^\s*(?:\(\s*)*(SELECT|WITH|PRAGMA|EXPLAIN|VALUES)\b", re.I)
# Method calls that mutate a container in place; a name that ever receives one
# can no longer be resolved from its assigned literal (args[1]='w',
# d.update(...), del xs[0] all make `*args`/`**kw` expansions unprovable).
CONTAINER_MUTATORS = {
    "append", "extend", "insert", "update", "setdefault", "pop", "popitem",
    "remove", "discard", "add", "clear", "sort", "reverse",
}
SQL_DENY = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|REPLACE|ATTACH|DETACH|VACUUM|REINDEX|ANALYZE|"
    r"load_extension|writefile|edit|fts3_tokenizer)\b",
    re.I,
)
MODE_WRITE = re.compile(r"[wax+]")
ROOT_SCANNERS = {"walk", "listdir", "scandir", "glob", "iglob", "rglob", "iterdir", "Path", "PurePath", "PosixPath"}
# Every way to obtain a writable file handle goes through one of these (or
# `open`/`.open`), so `.write()` on whatever object they return is safe once
# their mode is proven read-only.
OPENERS_MODE_AT_1 = {
    "io.open", "io.FileIO", "codecs.open", "gzip.open", "bz2.open",
    "lzma.open", "tarfile.open", "tarfile.TarFile", "zipfile.ZipFile",
    "zipfile.PyZipFile", "gzip.GzipFile", "bz2.BZ2File", "lzma.LZMAFile",
}
# Names a getattr() result may hold whose callability cannot be judged at the
# getattr site: plain write methods (file objects are reached dynamically),
# flush (commits buffered output), and the mode-sensitive memmap openers whose
# positional-mode checks only run on resolved calls.
GETATTR_DENIED = {"write", "writelines", "flush", "memmap", "open_memmap"}
PATH_LIKE = re.compile(r"^(?:~|/|\.{1,2}/|[\w.-]+/)[^\n\x00]*$|^\.?[\w-]*\.(?:env|pem|key|json|ya?ml|toml|ini|cfg|conf|db|sqlite3?|txt|csv)$")
URL_LIKE = re.compile(r"\b(?:https?|ftp|s3|gs|wss?)://", re.I)
# Credential stores reachable by joining path pieces (`os.path.join(home,
# ".ssh", "id_rsa")`), so individual literals are screened, not just paths.
SENSITIVE_NAME = re.compile(
    r"(?:^|[/\\])\.(?:ssh|aws|gnupg|kube|docker|netrc|pgpass|git-credentials|npmrc|pypirc|password-store)(?:[/\\]|$)"
    r"|(?:^|[/\\])id_(?:rsa|dsa|ecdsa|ed25519)\b"
    r"|\.(?:pem|p12|pfx|key|keystore|jks)$"
    r"|(?:^|[/\\])\.env(?:\.(?!example\b|sample\b|template\b)[\w-]+)?$"
    r"|(?:^|[/\\])(?:credentials(?:\.json)?|hosts\.yml|auth\.json|\.bash_history|\.zsh_history|Login Data|Cookies)$"
    r"|^/etc/(?:shadow|gshadow|sudoers)",
    re.I,
)


SQL_QUOTE_CLOSE = {"'": "'", '"': '"', "`": "`", "[": "]"}


def sql_visible(text):
    """SQL text with comments and quoted spans blanked to single spaces.

    `--`/`/* */` are only comments OUTSIDE quotes — `'--'` is data, not a
    comment, so the naive regex strip (`re.sub(r"--.*")`) would erase real
    write statements smuggled behind a quoted marker. SQLite quotes:
    'string' ('' escapes), "identifier" ("" escapes), `identifier`, and
    [identifier] (]] escapes). An unterminated quote keeps the rest visible —
    it can only add deny keywords, never hide them."""
    out = []
    i, n = 0, len(text)
    while i < n:
        closer = SQL_QUOTE_CLOSE.get(text[i])
        if closer is not None:
            j = i + 1
            while j < n:
                if text[j] == closer:
                    if j + 1 < n and text[j + 1] == closer:
                        j += 2  # doubled quote is an escaped literal char
                        continue
                    j += 1
                    break
                j += 1
            if j < n:
                # A quoted token used as a callee — "load_extension"('x'),
                # `writefile`(a,b), [f](x) (SQLite accepts all four quote
                # styles, even 'name'(), in function position) — must keep
                # its name visible or the deny scan loses it.
                k = j
                while k < n:
                    if text[k] in " \t\r\n\f\v":
                        k += 1
                    elif text.startswith("--", k):
                        nl = text.find("\n", k)
                        k = n if nl < 0 else nl
                    elif text.startswith("/*", k):
                        end = text.find("*/", k + 2)
                        k = n if end < 0 else end + 2
                    else:
                        break
                if k < n and text[k] == "(":
                    out.append(text[i + 1 : j - 1])
                else:
                    out.append(" ")
                i = j
            else:
                out.append(text[i:])
                break
        elif text.startswith("--", i):
            nl = text.find("\n", i)
            out.append(" ")
            i = n if nl < 0 else nl
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            out.append(" ")
            i = n if end < 0 else end + 2
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


class NotProven(Exception):
    pass


def fail(reason):
    raise NotProven(reason)


def const_str(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


class Prover(ast.NodeVisitor):
    def __init__(self, search_dirs):
        self.search_dirs = search_dirs
        self.aliases = {}  # local name -> dotted origin ("os", "os.path.join", "numpy")
        self.str_assign = {}  # name -> list of value nodes assigned to it
        # Names also bound some other way (augmented assignment, loop target,
        # parameter, `with ... as`, walrus): their value cannot be resolved.
        self.rebound = set()
        self.mutated = set()  # names whose bound container is written in place
        self.stored_into = {}  # container name -> ids stored into it via [k]/attr
        # Names passed to a call as a plain positional/keyword argument escape
        # into code we cannot see (`outer = identity(args)` keeps a reference;
        # `outer[1] = 'w'` then rewrites what `open(*args)` expands). `*`/`**`
        # expansion itself copies, so it never escapes the container.
        self.escaped = set()
        self.paths = []
        self.attr_bases = set()  # id() of Name nodes used as Attribute.value
        self.call_funcs = set()  # id() of nodes in call position

    # -- imports -----------------------------------------------------------
    def check_module(self, dotted):
        top = dotted.split(".")[0]
        if top not in FREE_MODULES and top not in RESTRICTED:
            fail(f"import of non-allowlisted module {top}")
        if top in RESTRICTED and "." in dotted:
            sub = dotted.split(".")[1]
            if sub not in RESTRICTED[top]:
                fail(f"import of restricted submodule {dotted}")
        for base in self.search_dirs:
            if os.path.exists(os.path.join(base, top + ".py")) or os.path.isdir(os.path.join(base, top)):
                fail(f"module {top} may resolve to a local file")

    def visit_Import(self, node):
        for alias in node.names:
            self.check_module(alias.name)
            if alias.asname:
                self.aliases[alias.asname] = alias.name
            else:
                top = alias.name.split(".")[0]
                self.aliases[top] = top
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.level and node.level > 0:
            fail("relative import")
        module = node.module or ""
        self.check_module(module)
        top = module.split(".")[0]
        for alias in node.names:
            if alias.name == "*":
                if top in RESTRICTED or top in ("pathlib", "shutil"):
                    fail("star import from restricted module")
                continue
            dotted = f"{module}.{alias.name}"
            if top in RESTRICTED:
                parts = dotted.split(".")
                if len(parts) < 2 or parts[1] not in RESTRICTED[top]:
                    fail(f"restricted import {dotted}")
            if alias.name in ESCAPE_ATTRS or alias.name in DENIED_BUILTINS:
                fail(f"import of {dotted}")
            self.aliases[alias.asname or alias.name] = dotted
        self.generic_visit(node)

    # -- names and attributes ---------------------------------------------
    def resolve(self, node):
        """Dotted origin of a Name/Attribute chain, or None."""
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            base = self.resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def visit_Name(self, node):
        if node.id in DENIED_BUILTINS:
            fail(f"use of {node.id}")
        if node.id.startswith("__") and node.id.endswith("__") and node.id not in ALLOWED_DUNDERS:
            fail(f"dunder name {node.id}")
        origin = self.aliases.get(node.id)
        if origin is not None and isinstance(node.ctx, ast.Load):
            top = origin.split(".")[0]
            if top in RESTRICTED and origin == top and id(node) not in self.attr_bases:
                fail(f"restricted module {top} used as a value")
            leaf = origin.split(".")[-1]
            if leaf in WRITE_METHODS or WRITE_PREFIX.match(leaf):
                fail(f"reference to {origin}")
        if isinstance(node.ctx, ast.Store) and node.id in self.aliases:
            # Rebinding an alias makes later resolution ambiguous.
            fail(f"alias {node.id} rebound")

    def visit_Attribute(self, node):
        attr = node.attr
        if attr.startswith("__") and attr.endswith("__") and attr not in ALLOWED_DUNDERS:
            fail(f"dunder attribute {attr}")
        if isinstance(node.value, ast.Name):
            self.attr_bases.add(id(node.value))
        if attr in WRITE_METHODS or WRITE_PREFIX.match(attr):
            fail(f"write/exec attribute {attr}")
        if attr in AMBIGUOUS_METHODS and id(node) not in self.call_funcs:
            fail(f"uncalled reference to {attr}")
        if attr in ("environ", "getenv", "environb"):
            fail("environment access")
        origin = self.resolve(node)
        if origin:
            parts = origin.split(".")
            top = parts[0]
            if top in RESTRICTED and len(parts) >= 2 and parts[1] not in RESTRICTED[top] and parts[1] != "__version__":
                fail(f"restricted attribute {origin}")
            if attr in ESCAPE_ATTRS and not (len(parts) == 2 and parts[0] == attr):
                fail(f"attribute {attr} reached through {parts[0]}")
        elif attr in ESCAPE_ATTRS:
            fail(f"attribute {attr} on unresolved object")
        self.generic_visit(node)

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Attribute):
                origin = self.resolve(target.value)
                if origin and origin.split(".")[0] in RESTRICTED:
                    fail(f"assignment into module attribute {origin}")
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            if URL_LIKE.search(node.value):
                fail("URL literal")
            if SENSITIVE_NAME.search(node.value):
                fail("credential-like path literal")
            if DUNDER_IN_STR.search(node.value):
                fail("dunder name inside a string")
            value = node.value.strip()
            # A lone "/" is almost always a separator (`"/".join`, `split("/")`);
            # scanning the root itself is rejected at the call site instead.
            if 1 < len(value) < 4096 and "\n" not in value and PATH_LIKE.match(value):
                self.paths.append(value)

    # -- calls ---------------------------------------------------------------
    def sql_parts(self, node, depth=0):
        """Constant text pieces of an SQL expression, or None if unresolvable."""
        if depth > 4:
            return None
        if const_str(node):
            return [node.value]
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if const_str(value):
                    parts.append(value.value)
                elif isinstance(value, ast.FormattedValue):
                    parts.append(" x ")
                else:
                    return None
            return parts
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            left = self.sql_parts(node.left, depth + 1)
            if left is None:
                return None
            if isinstance(node.op, ast.Mod):
                return left + [" x "]
            right = self.sql_parts(node.right, depth + 1)
            return None if right is None else left + right
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            return self.sql_parts(node.func.value, depth + 1)
        if isinstance(node, ast.Name):
            values = self.str_assign.get(node.id)
            if not values or node.id in self.rebound:
                return None
            out = []
            for value in values:
                parts = self.sql_parts(value, depth + 1)
                if parts is None:
                    return None
                out.extend(parts)
            return out
        return None

    def check_sql(self, node):
        parts = self.sql_parts(node)
        if parts is None:
            fail("unresolvable SQL text")
        text = sql_visible("".join(parts))
        if not SQL_START.match(text):
            fail("SQL is not a read statement")
        if SQL_DENY.search(text):
            fail("SQL contains a write or attach keyword")
        if re.search(r"\bPRAGMA\b[^;]*=", text, re.I):
            fail("PRAGMA assignment")

    def star_items(self, node, depth=0):
        """Elements of a `*` expansion, or None when unresolvable."""
        if depth > 4:
            return None
        if isinstance(node, (ast.List, ast.Tuple)):
            return list(node.elts)
        if isinstance(node, ast.Name) and node.id not in self.rebound and node.id not in self.escaped:
            values = self.str_assign.get(node.id)
            # Only a name bound exactly once is provable: a second assignment
            # would splice both lists' elements into one arg list and shift
            # the mode position.
            if values is None or len(values) != 1:
                return None
            return self.star_items(values[0], depth + 1)
        return None

    def kwarg_items(self, node, depth=0):
        """(name, value_node) pairs of a `**` mapping, or None."""
        if depth > 4:
            return None
        if isinstance(node, ast.Dict):
            out = []
            for key, value in zip(node.keys, node.values):
                if key is None:  # {**sub, ...}
                    sub = self.kwarg_items(value, depth + 1)
                    if sub is None:
                        return None
                    out.extend(sub)
                elif const_str(key):
                    out.append((key.value, value))
                else:
                    return None
            return out
        if isinstance(node, ast.Name) and node.id not in self.rebound and node.id not in self.escaped:
            values = self.str_assign.get(node.id)
            if values is None or len(values) != 1:
                return None
            return self.kwarg_items(values[0], depth + 1)
        return None

    def call_args(self, node):
        """Positional args and (name, value) keywords with literal `*`/`**`
        expansions inlined. A `*` or `**` whose contents cannot be resolved
        fails: a hidden argument could carry the write mode or an extra file
        operand past every check below."""
        args = []
        for arg in node.args:
            if isinstance(arg, ast.Starred):
                items = self.star_items(arg.value)
                if items is None:
                    fail("unresolvable * argument")
                args.extend(items)
            else:
                args.append(arg)
        kwargs = []
        for kw in node.keywords:
            if kw.arg is not None:
                kwargs.append((kw.arg, kw.value))
                continue
            items = self.kwarg_items(kw.value)
            if items is None:
                fail("unresolvable ** mapping")
            kwargs.extend(items)
        return args, kwargs

    def callable_targets(self, name, depth=0):
        """Possible call targets of a simply-assigned name.

        Returns a list of ("bare", id) / ("origin", dotted) / ("local",) for
        lambdas, or None when any assigned value cannot be resolved — the call
        then cannot be proven, since `f = open; f("x", "w")` must face the
        same checks as `open("x", "w")`."""
        if depth > 4 or name in self.rebound:
            return None
        values = self.str_assign.get(name)
        if values is None:
            return None
        out = []
        for value in values:
            if isinstance(value, ast.Name):
                if value.id in self.aliases:
                    out.append(("origin", self.aliases[value.id]))
                elif value.id in self.str_assign or value.id in self.rebound:
                    sub = self.callable_targets(value.id, depth + 1)
                    if sub is None:
                        return None
                    out.extend(sub)
                else:
                    # A builtin or a locally defined function/class: the bare
                    # name carries no module origin but may still need the
                    # per-callable checks below (open, getattr).
                    out.append(("bare", value.id))
            elif isinstance(value, ast.Attribute):
                origin = self.resolve(value)
                if origin is None:
                    return None
                out.append(("origin", origin))
            elif isinstance(value, ast.Lambda):
                # The body is visited like any other code, so calling it adds
                # no unchecked surface.
                out.append(("local", None))
            else:
                return None
        return out

    def check_mode(self, args, kwargs, positional_index):
        mode = None
        if positional_index is not None and len(args) > positional_index:
            mode = args[positional_index]
        for k, v in kwargs:
            if k == "mode":
                mode = v
        if mode is None:
            return
        if not const_str(mode):
            fail("non-literal file mode")
        if MODE_WRITE.search(mode.value):
            fail("file opened for writing")

    def check_memmap_mode(self, args, kwargs, positional_index):
        """numpy memmap/open_memmap default to mode='r+' (writable), so only a
        literal mode='r' proves the mapping read-only."""
        mode = args[positional_index] if len(args) > positional_index else None
        for k, v in kwargs:
            if k == "mode":
                mode = v
        if not (const_str(mode) and mode.value == "r"):
            fail("memmap without an explicit read-only mode")

    def check_getattr(self, args):
        if len(args) < 2 or not const_str(args[1]):
            fail("dynamic getattr")
        attr = args[1].value
        if (
            attr.startswith("__")
            or attr in ESCAPE_ATTRS
            or attr in WRITE_METHODS
            or WRITE_PREFIX.match(attr)
            or attr in AMBIGUOUS_METHODS
            or attr in GETATTR_DENIED
        ):
            fail(f"getattr of {attr}")
        base = self.resolve(args[0])
        if base:
            # Mirror visit_Attribute: only the second level of a restricted
            # module is governed by the allowlist (os.path.join stays fine).
            parts = f"{base}.{attr}".split(".")
            if parts[0] in RESTRICTED and len(parts) >= 2 and parts[1] not in RESTRICTED[parts[0]] and parts[1] != "__version__":
                fail(f"getattr of restricted attribute {base}.{attr}")

    def check_origin_call(self, origin, args, kwargs):
        """Checks a resolved callee must pass whatever local name it rode in
        on (`f = np.memmap`, `from io import open as o`)."""
        leaf = origin.split(".")[-1]
        if leaf in ROOT_SCANNERS and any(
            const_str(arg) and arg.value.strip() in ("/", "//") for arg in args
        ):
            fail("filesystem root scan")
        if origin in OPENERS_MODE_AT_1:
            self.check_mode(args, kwargs, 1)
        if leaf == "memmap":
            self.check_memmap_mode(args, kwargs, 2)
        elif leaf == "open_memmap":
            self.check_memmap_mode(args, kwargs, 1)
        if leaf == "connect" and origin != "sqlite3.connect":
            fail("connect on a non-sqlite object")
        if leaf in ("read_sql", "read_sql_query") and args:
            self.check_sql(args[0])
        if leaf == "load":
            # numpy.load(file, mmap_mode, allow_pickle): every supplied value —
            # positional or keyword, after */** expansion — must check out.
            # Duplicates are a runtime TypeError, so checking all candidates
            # (instead of last-wins) is safe and simpler.
            modes = list(args[1:2]) + [v for k, v in kwargs if k == "mmap_mode"]
            for mm in modes:
                if const_str(mm):
                    if MODE_WRITE.search(mm.value):
                        fail("writable mmap_mode")
                elif not (isinstance(mm, ast.Constant) and mm.value is None):
                    fail("non-literal mmap_mode")
            pickles = list(args[2:3]) + [v for k, v in kwargs if k == "allow_pickle"]
            for ap in pickles:
                if not (isinstance(ap, ast.Constant) and ap.value is False):
                    fail("pickle loading")
        if origin in ("yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.full_load"):
            fail("unsafe yaml load")

    def visit_Call(self, node):
        func = node.func
        if not isinstance(func, (ast.Name, ast.Attribute)):
            # A call result, subscript, lambda, or walrus in call position is
            # a computed callee (`getattr(p, "replace")("b")`, `f()()`): no
            # per-callee check can run on it, so it is never proven.
            fail("call through a computed callee")
        origin = self.resolve(func)
        name = func.id if isinstance(func, ast.Name) else None
        method = func.attr if isinstance(func, ast.Attribute) else None
        self.call_funcs.add(id(func))

        args, kwargs = self.call_args(node)

        if (method or name or "") in ROOT_SCANNERS and any(
            const_str(arg) and arg.value.strip() in ("/", "//") for arg in args
        ):
            fail("filesystem root scan")

        for k, v in kwargs:
            if k in ("mode", "filemode") and not (const_str(v) and not MODE_WRITE.search(v.value)):
                fail("write-capable mode argument")
            if k == "allow_pickle" and not (isinstance(v, ast.Constant) and v.value is False):
                fail("pickle loading")
            if k in ("shell", "executable", "preexec_fn"):
                fail(f"process keyword {k}")

        if name is not None and origin is None and (name in self.str_assign or name in self.rebound):
            targets = self.callable_targets(name)
            if targets is None:
                fail(f"call through unresolved name {name}")
            for kind, value in targets:
                if kind == "bare":
                    if value == "open":
                        self.check_mode(args, kwargs, 1)
                    elif value == "getattr":
                        self.check_getattr(args)
                    elif value in DENIED_BUILTINS:
                        fail(f"use of {value}")
                elif kind == "origin":
                    self.check_origin_call(value, args, kwargs)
                # ("local",) lambdas need no per-callee checks.
        elif name == "open" and name not in self.aliases:
            self.check_mode(args, kwargs, 1)
        elif name == "getattr":
            self.check_getattr(args)
        if origin:
            self.check_origin_call(origin, args, kwargs)

        if method is not None:
            if method == "open" and not origin:
                # Path.open(mode) / ZipFile.open(name, mode): any literal mode
                # string must be read-only and nothing may be computed.
                for arg in (*args, *(v for _, v in kwargs)):
                    if const_str(arg) and re.fullmatch(r"[rwxabtU+]{1,4}", arg.value):
                        if MODE_WRITE.search(arg.value):
                            fail("file opened for writing")
                    elif not const_str(arg):
                        fail("non-literal argument to open()")
            if method == "replace" and len(args) < 2:
                fail("Path.replace")
            if method == "rename" and (args or kwargs):
                fail("rename")
            if method == "dump" and (len(args) == 1 or kwargs):
                fail("ndarray.dump")
            if method.startswith("to_") and method not in ("to_dict", "to_list", "to_numpy", "to_string", "to_records", "to_frame", "to_series", "to_datetime", "to_timedelta", "to_numeric", "to_period", "to_timestamp", "to_pydatetime", "to_bytes"):
                if args or any(k in ("path_or_buf", "path", "excel_writer", "buf", "fname", "filename") for k, _ in kwargs):
                    fail(f"{method} with an output target")
            if method in ("execute", "executemany", "read_sql", "read_sql_query"):
                if args:
                    self.check_sql(args[0])
                for k, v in kwargs:
                    if k in ("sql", "query", "operation"):
                        self.check_sql(v)
            if method == "connect" and origin != "sqlite3.connect":
                fail("connect on a non-sqlite object")
        self.generic_visit(node)


def prove(source, search_dirs):
    if len(source) > MAX_SOURCE_CHARS:
        fail("program too large")
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError) as exc:
        fail(f"syntax error: {exc.__class__.__name__}")
    prover = Prover(search_dirs)
    # Pre-pass: aliases and name assignments are collected before the full
    # walk so a use that precedes its import or assignment in traversal order
    # (function bodies, SQL held in variables) still resolves consistently.
    simple_targets = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            prover.visit(node)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and node.value is not None:
                    prover.str_assign.setdefault(target.id, []).append(node.value)
                    simple_targets.add(id(target))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)) and id(node) not in simple_targets:
            prover.rebound.add(node.id)
        elif isinstance(node, ast.arg):
            prover.rebound.add(node.arg)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            prover.rebound.update(node.names)
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            # A subscript/attribute store (`args[1] = 'w'`, `obj.k = v`) mutates
            # the bound object in place; its base name is no longer provable
            # from the assigned literal.
            targets = node.targets if isinstance(node, (ast.Assign, ast.Delete)) else [node.target]
            for target in targets:
                for part in ast.walk(target):
                    if isinstance(part, (ast.Subscript, ast.Attribute)):
                        base = part.value
                        while isinstance(base, (ast.Subscript, ast.Attribute)):
                            base = base.value
                        if isinstance(base, ast.Name):
                            prover.mutated.add(base.id)
                            prover.rebound.add(base.id)
            # `box['v'] = args` / `box.items = args` store a reference into a
            # container: later mutation of `box` reaches `args`.
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                names = {n.id for n in ast.walk(node.value) if isinstance(n, ast.Name)}
                for target in targets:
                    for part in ast.walk(target):
                        if isinstance(part, (ast.Subscript, ast.Attribute)):
                            base = part.value
                            while isinstance(base, (ast.Subscript, ast.Attribute)):
                                base = base.value
                            if isinstance(base, ast.Name):
                                prover.stored_into.setdefault(base.id, set()).update(names)
        elif isinstance(node, ast.Call):
            # args.append('w') / d.update({...}) mutate in place; the receiver
            # may itself be nested (`outer[0].append('w')` mutates whatever
            # outer[0] refers to), so taint the base name.
            if isinstance(node.func, ast.Attribute) and node.func.attr in CONTAINER_MUTATORS:
                base = node.func.value
                while isinstance(base, (ast.Subscript, ast.Attribute)):
                    base = base.value
                if isinstance(base, ast.Name):
                    prover.mutated.add(base.id)
                    prover.rebound.add(base.id)
            # A container handed to a call as a plain argument may be kept and
            # mutated later — `outer = make(args)` leaves args' contents
            # unprovable even though `outer` itself never expands.
            for arg in node.args:
                if not isinstance(arg, ast.Starred):
                    prover.escaped.update(n.id for n in ast.walk(arg) if isinstance(n, ast.Name))
            for kw in node.keywords:
                if kw.arg is not None:
                    prover.escaped.update(n.id for n in ast.walk(kw.value) if isinstance(n, ast.Name))
    # Mutating a container corrupts every name reachable through it —
    # `outer = [args]; outer[0][1] = 'w'` rewrites what `open(*args)` expands.
    # Propagate mutation through each mutated name's own bound values and
    # through references stored into it, to a fixpoint.
    changed = True
    while changed:
        changed = False
        for name in list(prover.mutated):
            inside = set(prover.stored_into.get(name, ()))
            for value in prover.str_assign.get(name, ()):
                inside.update(n.id for n in ast.walk(value) if isinstance(n, ast.Name))
            for nid in inside - prover.mutated:
                prover.mutated.add(nid)
                prover.rebound.add(nid)
                changed = True
    prover.visit(tree)
    return prover.paths


def main():
    try:
        request = json.loads(sys.stdin.read())
        source = request["source"]
        search_dirs = [d for d in request.get("searchDirs", []) if isinstance(d, str) and d]
        paths = prove(source, search_dirs)
        out = {"ok": True, "paths": sorted(set(paths))[:200]}
    except NotProven as exc:
        out = {"ok": False, "reason": str(exc)}
    except Exception as exc:  # noqa: BLE001 - any analyzer fault is "not proven"
        out = {"ok": False, "reason": f"analyzer error: {exc.__class__.__name__}"}
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
