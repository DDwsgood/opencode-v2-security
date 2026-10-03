"""Release-blocker regressions for the Python read-only AST prover.

Every program below is analyzed as TEXT ONLY through prove(); nothing is
executed. A "reject" verdict is always safe — it only means the caller keeps
its normal dynamic review — so the tests pin both directions: writes that
must never be proven, and ordinary reads that must keep their proof.
"""

import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "src" / "security" / "python-readonly.py"
SPEC = importlib.util.spec_from_file_location("python_readonly_under_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
prover = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prover)


def proven(source: str) -> bool:
    try:
        prover.prove(source, [])
        return True
    except prover.NotProven:
        return False


def rejected(source: str) -> str:
    try:
        prover.prove(source, [])
    except prover.NotProven as exc:
        return str(exc)
    raise AssertionError(f"wrongly proven read-only: {source}")


def sql(source_sql: str) -> str:
    return "import sqlite3; sqlite3.connect('a.db').execute(%r)" % source_sql


# --- the mirrored P1 payloads -------------------------------------------

P1_PAYLOADS = [
    # builtin aliased to a plain name, then called with a write mode
    "f=open; f('probe-destination.db','w').write('probe')",
    # write mode hidden behind a literal ** mapping
    "open('probe-destination.db', **{'mode':'w'}).write('probe')",
    # Path.replace reached dynamically through getattr
    "from pathlib import Path; getattr(Path('probe-source.db'),'replace')('probe-destination.db')",
    # np.memmap without a mode argument defaults to writable 'r+'
    "import numpy as np; a=np.memmap('probe.bin',dtype='uint8'); a[0]=1",
    # container mutated after its literal assignment, then *-expanded
    "args=['probe.db','r']; args[1]='w'; open(*args).write('probe')",
    # dict mutated after assignment, then **-expanded
    "kw={'mode':'r'}; kw['mode']='w'; open('probe.db',**kw).write('probe')",
    # two assignments splice into one arg list and shift the mode position
    "args=('probe.db','r');\nif True:\n    args=('probe.db','w')\nopen(*args).write('probe')",
    # np.load positional arg 3 is allow_pickle
    "import numpy as np; np.load('probe.npy', None, True)",
    # np.load keyword mmap_mode bypassed the positional check
    "import numpy as np; np.load('probe.npy', mmap_mode='r+'); a[0]=1",
    # '--' inside a string literal erased a real UPDATE
    "import sqlite3; sqlite3.connect('a.db').execute(\"WITH x AS (SELECT '--') UPDATE t SET v=7\")",
    # quoted function names: the quote was blanked before the deny scan
    sql('SELECT "load_extension"(\'probe\')'),
    sql('SELECT "writefile"(\'probe\',\'x\')'),
    # mutating a container through an alias name corrupts the original
    "args=['probe.db','r']; b=args; b[1]='w'; open(*args).write('probe')",
]


class TestP1Payloads(unittest.TestCase):
    def test_all_p1_payloads_rejected(self):
        for source in P1_PAYLOADS:
            with self.subTest(source=source):
                rejected(source)


class TestAliasedCallables(unittest.TestCase):
    """A name carrying a callable must face that callable's own checks."""

    def test_builtin_open_alias_write_mode(self):
        for source in (
            "f=open; f('x','w')",
            "f=open; f('x','a')",
            "g=open; f=g; f('x','w')",          # transitive alias chain
            "f=open; f('x', **{'mode':'w'})",   # alias + mapping together
            "for f in [open]: f('x','w')",      # rebound name is unresolvable
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_builtin_open_alias_read_still_proven(self):
        for source in (
            "f=open; print(f('x').read())",
            "f=open; print(f('x','r').read())",
            "f=open; print(f('x', mode='rb').read())",
        ):
            with self.subTest(source=source):
                self.assertTrue(proven(source))

    def test_imported_opener_alias_write_mode(self):
        for source in (
            "import io; f=io.open; f('x','w')",
            "from io import open as o; o('x','w')",
            "import io; f=io.FileIO; f('x','w')",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_alias_of_scanner_still_blocks_root(self):
        rejected("import os; w=os.walk; list(w('/'))")

    def test_alias_of_unsafe_loader_rejected(self):
        rejected("import yaml; f=yaml.load; f('x')")

    def test_alias_of_sql_executor_is_unresolved(self):
        # `c` holds a connection object, so `c.execute` cannot resolve to a
        # module origin; the call through the alias is simply not proven.
        rejected("import sqlite3; c=sqlite3.connect('a.db'); e=c.execute; e('DELETE FROM t')")

    def test_unknown_source_never_proven(self):
        for source in (
            "import functools; w=functools.partial(open,'x','w'); w()",
            "d={'f':open}; f=d['f']; f('x','w')",
            "t=type(open('x')); t('y','w')",
            "def make():\n    return open\nf=make(); f('x','w')",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_local_defs_and_lambdas_still_proven(self):
        for source in (
            "def helper():\n    return open('x').read()\nprint(helper())",
            "f = lambda x: x + 1\nprint(f(2))",
        ):
            with self.subTest(source=source):
                self.assertTrue(proven(source))


class TestCallShapeExpansion(unittest.TestCase):
    """Literal */** expansions are inlined; unresolvable ones fail closed."""

    def test_write_mode_behind_kwargs(self):
        for source in (
            "open('x', **{'mode':'w'})",
            "d={'mode':'w'}; open('x', **d)",
            "d={'a':1}; open('x', **{**d, 'mode':'w'})",
            "open('x', mode='r', **{'mode':'w'})",  # later binding wins at runtime
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_unresolvable_kwargs_never_proven(self):
        for source in (
            "open('x', **d)",
            "import sys; open('x', **vars())",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_write_mode_behind_starargs(self):
        for source in (
            "open(*['x','w'])",
            "args=['x','w']; open(*args)",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_literal_expansions_of_reads_still_proven(self):
        for source in (
            "kw={'mode':'r'}; open('x', **kw).read()",
            "args=['x','r']; open(*args).read()",
            "print(*[1,2,3])",
            "d={'sep':','}; print('a','b',**d)",
        ):
            with self.subTest(source=source):
                self.assertTrue(proven(source))

    def test_mutated_containers_never_proven(self):
        # Any in-place change after the literal assignment — subscript store,
        # delete, mutator method — makes the expansion unprovable.
        for source in (
            "args=['x','r']; args[1]='w'; open(*args)",
            "args=['x','r']; del args[0]; open(*args)",
            "args=['x','r']; args += ['w']; open(*args)",
            "args=['x','r']; args.append('w'); open(*args)",
            "args=['x','r']; args.extend(['w']); open(*args)",
            "args=['x','r']; args.insert(1, 'w'); open(*args)",
            "kw={'mode':'r'}; kw['mode']='w'; open('x', **kw)",
            "d={'mode':'r'}; d.update({'mode':'w'}); open('x', **d)",
            "d={}; d.setdefault('mode','w'); open('x', **d)",
            "args=['x','r']; args=('x','w'); open(*args)",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_alias_mutation_never_proven(self):
        # `b = args` shares one list object: mutating either name corrupts
        # what `open(*args)` expands to.
        for source in (
            "args=['x','r']; b=args; b[1]='w'; open(*args)",
            "args=['x','r']; b=args; b.append('w'); open(*args)",
            "b=['x','r']; args=b; del b[1]; open(*args)",
            "args=['x','r']; b=args; c=b; c[1]='w'; open(*args)",
            "kw={'mode':'r'}; k2=kw; k2['mode']='w'; open('x', **kw)",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_nested_container_mutation_never_proven(self):
        # `outer = [args]` lets `outer[0][1] = 'w'` rewrite what `*args`
        # expands; mutation taints every name reachable through the container.
        for source in (
            "args=['x','r']; outer=[args]; outer[0][1]='w'; open(*args)",
            "args=['x','r']; d={'a':args}; d['a'][1]='w'; open(*args)",
            "args=['x','r']; box={}; box['v']=args; box['v'][1]='w'; open(*args)",
            "args=['x','r']; outer=list([args]); outer[0][1]='w'; open(*args)",
            "args=['x','r']; b=args; c=[b]; c[0][1]='w'; open(*args)",
            "args=['x','r']; outer=[args]; outer[0].append('w'); open(*args)",
            "kw={'mode':'r'}; wrap=[kw]; wrap[0]['mode']='w'; open('x', **kw)",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_call_argument_escape_never_proven(self):
        # A container handed to a call as a plain argument may be retained and
        # mutated behind our backs — `outer = identity(args)` then
        # `outer[1] = 'w'` rewrites the object `*args` expands. Expansion
        # itself copies, so only non-Starred / non-`**` arguments escape.
        for source in (
            "def identity(x):\n    return x\nargs=['db','r']; outer=identity(args); outer[1]='w'; open(*args)",
            "def identity(x):\n    return x\nkw={'mode':'r'}; outer=identity(kw); outer['mode']='w'; open('x',**kw)",
            "args=['db','r']; box=[]; box.append(args); box[0][1]='w'; open(*args)",
            "args=['db','r']; f(x=args); open(*args)",
            "args=['db','r']; outer=identity(args); open(*args)",  # hand-off alone suffices
            "args=['db','r']; print(args); open(*args)",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_expansion_position_does_not_escape(self):
        for source in (
            "args=['x','r']; open(*args).read()",
            "kw={'mode':'r'}; open('x',**kw).read()",
            "args=['x','r']; b=args; open(*args).read()",
            "args=['x','r']; outer=[args]; open(*args).read()",
            "d={'sep':','}; print('a','b',**d)",
        ):
            with self.subTest(source=source):
                self.assertTrue(proven(source))

    def test_referenced_but_untouched_containers_still_proven(self):
        # Sharing the container without mutating it keeps the proof.
        for source in (
            "args=['x','r']; outer=[args]; open(*args).read()",
            "kw={'mode':'r'}; wrap=[kw]; open('x',**kw).read()",
            "args=['x','r']; b=args; open(*args).read()",
            "items=['a']; items[0].upper(); print(items)",
            "data=[1,2,3]; data.append(4); print(data)",
        ):
            with self.subTest(source=source):
                self.assertTrue(proven(source))

    def test_path_open_write_mode_behind_kwargs(self):
        rejected("from pathlib import Path; Path('x').open(**{'mode':'w'})")


class TestGetattr(unittest.TestCase):
    def test_getattr_of_write_or_ambiguous_names(self):
        for source in (
            "getattr(open('x'),'write')('y')",
            "w=getattr(open('x'),'write'); w('y')",
            "getattr(open('x'),'write_text')('y')",
            "getattr(open('x'),'flush')()",
            "import os; getattr(os,'remove')('x')",
            "import numpy as np; getattr(np,'memmap')('b','uint8','r+')",
            "import numpy as np; getattr(np,'open_memmap')('b')",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_getattr_result_call_never_proven(self):
        # Even an allowed attribute name leaves an unchecked callee
        # (e.g. getattr(c,'execute') would skip the SQL gate), so a call of a
        # getattr result is not proven; the inner attribute is still vetted.
        rejected("import os; getattr(os,'getcwd')()")
        rejected("import sqlite3; c=sqlite3.connect('a.db'); getattr(c,'execute')('DELETE FROM t')")

    def test_getattr_benign_reference_still_proven(self):
        self.assertTrue(proven("import os; p = getattr(os.path, 'join'); print(p)"))

    def test_computed_callee_never_proven(self):
        for source in (
            "d={'f':open}; d['f']('x','w')",
            "(lambda: open('x','w'))()",
            "import functools; functools.partial(open,'x','w')()",
        ):
            with self.subTest(source=source):
                rejected(source)


class TestMemmap(unittest.TestCase):
    def test_memmap_without_literal_r_mode(self):
        for source in (
            "import numpy as np; np.memmap('b.bin',dtype='uint8')",
            "import numpy as np; np.memmap('b.bin','uint8','r+')",
            "import numpy as np; np.memmap('b.bin','uint8','w+')",
            "import numpy as np; np.memmap('b.bin', mode='c')",
            "import numpy as np; m=np.memmap; m('b.bin','uint8')",
            "import numpy as np; np.lib.format.open_memmap('b.bin')",
            "import numpy as np; np.lib.format.open_memmap('b.bin', mode='r+')",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_memmap_explicit_read_mode_proven(self):
        for source in (
            "import numpy as np; a=np.memmap('b.bin', dtype='uint8', mode='r'); print(a[0])",
            "import numpy as np; np.memmap('b.bin', 'uint8', 'r')[0]",
        ):
            with self.subTest(source=source):
                self.assertTrue(proven(source))


class TestNpLoad(unittest.TestCase):
    """np.load(file, mmap_mode, allow_pickle): positionals face the same
    checks the keyword scan applies."""

    def test_positional_write_modes_and_pickle_rejected(self):
        for source in (
            "import numpy as np; np.load('p.npy', None, True)",
            "import numpy as np; np.load('p.npy', 'r+')",
            "import numpy as np; np.load('p.npy', 'w+')",
            "import numpy as np; np.load('p.npy', m, False)",
            "import numpy as np; np.load(*['p.npy', None, True])",
            "import numpy as np; f=np.load; f('p.npy', None, True)",
            "import numpy as np; np.load('p.npy', allow_pickle=True)",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_keyword_and_expanded_modes_and_pickle_rejected(self):
        # mmap_mode=/allow_pickle= as keywords or behind ** dicts face the
        # same checks as the positional form; duplicates are checked on both
        # sides (a runtime TypeError anyway).
        for source in (
            "import numpy as np; np.load('p.npy', mmap_mode='r+')",
            "import numpy as np; np.load('p.npy', mmap_mode='w+')",
            "import numpy as np; np.load('p.npy', mmap_mode=m)",
            "import numpy as np; np.load('p.npy', None, allow_pickle=True)",
            "import numpy as np; np.load('p.npy', **{'mmap_mode':'r+'})",
            "import numpy as np; np.load('p.npy', **{'allow_pickle':True})",
            "import numpy as np; kw={'mmap_mode':'w+'}; np.load('p.npy', **kw)",
            "import numpy as np; np.load('p.npy', 'r', mmap_mode='r+')",
            "import numpy as np; f=np.load; f('p.npy', mmap_mode='r+')",
            "import numpy as np; np.load(*['p.npy', 'r+'])",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_read_only_loads_still_proven(self):
        for source in (
            "import numpy as np; np.load('p.npy')",
            "import numpy as np; np.load('p.npy', 'r')",
            "import numpy as np; np.load('p.npy', 'c')",
            "import numpy as np; np.load('p.npy', None)",
            "import numpy as np; np.load('p.npy', 'r', False)",
            "import numpy as np; np.load('p.npy', mmap_mode='r')",
            "import numpy as np; np.load('p.npy', mmap_mode='c')",
            "import numpy as np; np.load('p.npy', mmap_mode=None)",
            "import numpy as np; np.load('p.npy', mmap_mode='r', allow_pickle=False)",
            "import numpy as np; np.load('p.npy', allow_pickle=False)",
            "import numpy as np; np.load('p.npy', **{'mmap_mode':'r'})",
        ):
            with self.subTest(source=source):
                self.assertTrue(proven(source))


class TestAmbiguousMethods(unittest.TestCase):
    def test_path_replace_via_keywords(self):
        for source in (
            "from pathlib import Path; Path('a').replace(target='b')",
            "from pathlib import Path; Path('a').rename(target='b')",
            "p.replace('y')",  # base unresolved: cannot be proven a str.replace
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_str_replace_still_proven(self):
        self.assertTrue(proven("print('a b'.replace('a','b'))"))
        self.assertTrue(proven("s='a'; print(s.replace('a','b'))"))

    def test_sql_keyword_arguments_checked(self):
        rejected("import sqlite3; sqlite3.connect('a.db').execute(sql='DELETE FROM t')")
        self.assertTrue(proven(
            "import sqlite3\n"
            "con = sqlite3.connect('file:a.db?mode=ro', uri=True)\n"
            "for row in con.execute(sql='SELECT 1'):\n"
            "    print(row)"
        ))

    def test_comment_markers_inside_quotes_are_data(self):
        # '--'/''/* */'' inside SQLite quotes must NOT start a comment;
        # otherwise a quoted marker can erase a real write statement.
        for source in (
            "import sqlite3; sqlite3.connect('a.db').execute(\"WITH x AS (SELECT '--') UPDATE t SET v=7\")",
            "import sqlite3; sqlite3.connect('a.db').execute(\"SELECT '--'); DELETE FROM t\")",
            "import sqlite3; sqlite3.connect('a.db').execute('SELECT \"a\"); DELETE FROM t')",
            "import sqlite3; sqlite3.connect('a.db').execute('SELECT `x`); DELETE FROM t')",
            "import sqlite3; sqlite3.connect('a.db').execute('SELECT [x]); DELETE FROM t')",
            "import sqlite3; sqlite3.connect('a.db').execute(\"SELECT 1 /* ' */ DELETE FROM t\")",
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_quoted_function_names_stay_visible(self):
        # SQLite accepts all four quote styles (including 'name'()) in
        # function position; blanking the token would hide the deny word.
        for source in (
            sql('SELECT "load_extension"(\'probe\')'),
            sql("SELECT `load_extension`('probe')"),
            sql("SELECT [load_extension]('probe')"),
            sql("SELECT 'load_extension'('probe')"),
            sql('SELECT "writefile"(\'probe\',\'x\')'),
            sql("SELECT \"load_extension\" /* c */ ('probe')"),
            sql("SELECT \"load_extension\" -- c\n('probe')"),
        ):
            with self.subTest(source=source):
                rejected(source)

    def test_reads_with_literals_and_real_comments_still_proven(self):
        for source in (
            "import sqlite3; sqlite3.connect('a.db').execute(\"SELECT '--'\")",
            "import sqlite3; sqlite3.connect('a.db').execute('SELECT 1 -- real comment')",
            "import sqlite3; sqlite3.connect('a.db').execute('SELECT 1 /* real comment */')",
            "import sqlite3; sqlite3.connect('a.db').execute('SELECT \\'it\\'\\'s\\', \"a\"\"b\", `c`, [d] FROM t')",
            "import sqlite3; sqlite3.connect('a.db').execute(\"SELECT * FROM t WHERE n = 'x--y' AND m = 'z/*w*/'\")",
        ):
            with self.subTest(source=source):
                self.assertTrue(proven(source))


class TestOrdinaryReadsUnchanged(unittest.TestCase):
    """The everyday read-only corpus keeps its proof (no over-tightening)."""

    def test_reads_still_proven(self):
        for source in (
            "import json,sys; print(json.dumps({'a': 1}))",
            "import json; print(json.load(open('package.json'))['name'])",
            "for i in range(10):\n    print(i)",
            "import sqlite3\n"
            "con = sqlite3.connect('file:a.db?mode=ro', uri=True)\n"
            "q = \"SELECT id FROM t WHERE x = 1\"\n"
            "for row in con.execute(q):\n"
            "    print(row)",
            'import sys; sys.stdout.write("x")',
            "open('x').read()",
            "open('x','r').read()",
            "open('x', mode='rb').read()",
            "from pathlib import Path; Path('x').read_text()",
            "from pathlib import Path; Path('x').open().read()",
            "from pathlib import Path; Path('x').open(mode='r').read()",
            "import numpy as np; np.load('a.npy', allow_pickle=False)",
            "import gzip; gzip.open('f.gz','rt').read()",
            "import io; io.open('x','r').read(); io.FileIO('x','r').read()",
            "r = open('x').read()\nprint(r)",
        ):
            with self.subTest(source=source):
                self.assertTrue(proven(source))


if __name__ == "__main__":
    unittest.main()
