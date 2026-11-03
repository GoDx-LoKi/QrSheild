"""Full-featured lightweight pytest runner supporting fixtures, parametrize, raises, monkeypatch, capsys, caplog, tmp_path."""
from __future__ import annotations
import contextlib
import importlib.util
import inspect
import io
import logging
import os
import shutil
import sys
import tempfile
import traceback
from pathlib import Path
from typing import Any

class _ExceptionInfo:
    def __init__(self):
        self.value = None
        self.type = None

@contextlib.contextmanager
def raises(expected_exc, match=None):
    info = _ExceptionInfo()
    try:
        yield info
    except expected_exc as exc:
        info.value = exc
        info.type = type(exc)
        if match is not None:
            import re
            if not re.search(match, str(exc)):
                raise AssertionError(f"Regex {match!r} did not match {str(exc)!r}")
        return
    raise AssertionError(f"DID NOT RAISE {expected_exc}")

def fixture(func=None, *, scope="function", autouse=False):
    def deco(f):
        f._pytest_fixture = True
        f._pytest_scope = scope
        f._pytest_autouse = autouse
        return f
    if func is not None and callable(func):
        return deco(func)
    return deco

class _Mark:
    @staticmethod
    def parametrize(argnames, argvalues, ids=None):
        if isinstance(argnames, str):
            names = [x.strip() for x in argnames.split(",") if x.strip()]
        else:
            names = list(argnames)
        vals = list(argvalues)
        def deco(f):
            existing = getattr(f, "_pytest_params", [])
            existing.append((names, vals, ids))
            f._pytest_params = existing
            return f
        return deco

mark = _Mark()

class MonkeyPatch:
    def __init__(self):
        self._undo = []
    def setattr(self, target, name, value=..., raising=True):
        if value is ...:
            # target is dotted string
            parts = target.rsplit(".", 1)
            mod = importlib.import_module(parts[0])
            target, name, value = mod, parts[1], name
        had = hasattr(target, name)
        old = getattr(target, name, None)
        if not had and raising:
            raise AttributeError(f"{target} has no attribute {name}")
        setattr(target, name, value)
        self._undo.append((target, name, had, old))
    def setenv(self, name, value, prepend=None):
        had = name in os.environ
        old = os.environ.get(name)
        os.environ[name] = str(value)
        self._undo.append(("env", name, had, old))
    def delenv(self, name, raising=True):
        had = name in os.environ
        old = os.environ.get(name)
        if not had and raising:
            raise KeyError(name)
        os.environ.pop(name, None)
        self._undo.append(("env", name, had, old))
    def undo(self):
        for item in reversed(self._undo):
            if item[0] == "env":
                _, name, had, old = item
                if had:
                    os.environ[name] = old
                else:
                    os.environ.pop(name, None)
            else:
                target, name, had, old = item
                if had:
                    setattr(target, name, old)
                else:
                    try:
                        delattr(target, name)
                    except Exception:
                        pass
        self._undo.clear()

class TempPathFactory:
    def __init__(self, base: Path):
        self._base = base
        self._counter = 0
    def mktemp(self, basename: str, numbered: bool = True) -> Path:
        self._counter += 1
        p = self._base / (f"{basename}_{self._counter}" if numbered else basename)
        p.mkdir(parents=True, exist_ok=True)
        return p

class CaptureResult:
    def __init__(self, out: str, err: str):
        self.out = out
        self.err = err

class CapSys:
    def __init__(self):
        self._out = io.StringIO()
        self._err = io.StringIO()
        self._orig_out = sys.stdout
        self._orig_err = sys.stderr
        sys.stdout = self._out
        sys.stderr = self._err
    def readouterr(self) -> CaptureResult:
        out = self._out.getvalue()
        err = self._err.getvalue()
        self._out.seek(0); self._out.truncate(0)
        self._err.seek(0); self._err.truncate(0)
        return CaptureResult(out, err)
    def close(self):
        sys.stdout = self._orig_out
        sys.stderr = self._orig_err

class _CapLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []
        self.stream = io.StringIO()
    def emit(self, record):
        self.records.append(record)
        self.stream.write(self.format(record) + "\n")

class CapLog:
    def __init__(self):
        self.handler = _CapLogHandler()
        logging.getLogger().addHandler(self.handler)
    @property
    def text(self) -> str:
        return self.handler.stream.getvalue()
    @property
    def records(self):
        return self.handler.records
    @contextlib.contextmanager
    def at_level(self, level, logger=None):
        lg = logging.getLogger(logger) if logger else logging.getLogger()
        old_level = lg.level
        lg.setLevel(level)
        lg.addHandler(self.handler)
        try:
            yield
        finally:
            lg.setLevel(old_level)
            if lg is not logging.getLogger():
                lg.removeHandler(self.handler)
    def close(self):
        logging.getLogger().removeHandler(self.handler)


try:
    import starlette.testclient as _stc
    _orig_tc_init = _stc.TestClient.__init__
    import inspect as _ins
    if "client" not in _ins.signature(_orig_tc_init).parameters:
        def _patched_tc_init(self, app, *args, client=None, **kwargs):
            if client is not None:
                _orig_app = app
                async def _wrapped_app(scope, receive, send):
                    if scope.get("type") in ("http", "websocket"):
                        scope = dict(scope)
                        scope["client"] = client
                    return await _orig_app(scope, receive, send)
                app = _wrapped_app
                self._wrapped_orig_app = _orig_app
            _orig_tc_init(self, app, *args, **kwargs)
        _stc.TestClient.__init__ = _patched_tc_init
except Exception:
    pass

def main(argv=None) -> int:
    import itertools
    argv = list(sys.argv[1:] if argv is None else argv)
    quiet = "-q" in argv or "--quiet" in argv
    paths = [a for a in argv if not a.startswith("-")]
    cwd = Path.cwd()
    if str(cwd) not in sys.path:
        sys.path.insert(0, str(cwd))
    search_roots = [cwd / p for p in paths] if paths else [cwd / "tests"]

    base_tmp = Path(tempfile.mkdtemp(prefix="pytest_run_"))
    tmp_factory = TempPathFactory(base_tmp)
    session_fixtures = {}
    session_cache = {}

    conftest_candidates = [cwd / "tests" / "conftest.py", cwd / "source" / "tests" / "conftest.py"]
    conftest_path = next((cp for cp in conftest_candidates if cp.is_file()), conftest_candidates[0])
    if conftest_path.is_file():
        spec = importlib.util.spec_from_file_location("tests.conftest", conftest_path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["tests.conftest"] = mod
        sys.modules["conftest"] = mod
        spec.loader.exec_module(mod)
        for name, obj in inspect.getmembers(mod):
            if getattr(obj, "_pytest_fixture", False):
                session_fixtures[name] = obj

    test_files = []
    for sr in search_roots:
        if sr.is_file():
            test_files.append(sr)
        elif sr.is_dir():
            test_files.extend(sorted(sr.rglob("test_*.py")))

    collected = []
    for tf in test_files:
        mod_name = ".".join(tf.relative_to(cwd).with_suffix("").parts) if tf.is_relative_to(cwd) else tf.stem
        spec = importlib.util.spec_from_file_location(mod_name, tf)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
        mod_fixtures = dict(session_fixtures)
        for name, obj in inspect.getmembers(mod):
            if getattr(obj, "_pytest_fixture", False):
                mod_fixtures[name] = obj
        mod_cache = {}
        for name, obj in inspect.getmembers(mod, inspect.isfunction):
            if not name.startswith("test_"):
                continue
            params_list = getattr(obj, "_pytest_params", [])
            if not params_list:
                collected.append((tf, mod, name, obj, {}, mod_fixtures, mod_cache))
            else:
                # handle one or more @pytest.mark.parametrize decorators
                combos = [{}]
                for p_names, p_vals, p_ids in reversed(params_list):
                    new_combos = []
                    for c in combos:
                        for v in p_vals:
                            c2 = dict(c)
                            if len(p_names) == 1:
                                c2[p_names[0]] = v
                            else:
                                for k, val in zip(p_names, v):
                                    c2[k] = val
                            new_combos.append(c2)
                    combos = new_combos
                for idx, c in enumerate(combos):
                    collected.append((tf, mod, f"{name}[{idx}]", obj, c, mod_fixtures, mod_cache))

    passed = 0
    failed = 0
    failures = []

    for tf, mod, tname, func, param_kwargs, mod_fixtures, mod_cache in collected:
        mp = MonkeyPatch()
        capsys_inst = None
        caplog_inst = None
        fn_cache = {}

        def resolve_fixture(fname):
            if fname in param_kwargs:
                return param_kwargs[fname]
            if fname in fn_cache:
                return fn_cache[fname]
            if fname == "tmp_path_factory":
                return tmp_factory
            if fname == "tmp_path":
                val = tmp_factory.mktemp("test_tmp")
                fn_cache[fname] = val
                return val
            if fname == "monkeypatch":
                return mp
            if fname == "capsys":
                nonlocal capsys_inst
                if capsys_inst is None:
                    capsys_inst = CapSys()
                return capsys_inst
            if fname == "caplog":
                nonlocal caplog_inst
                if caplog_inst is None:
                    caplog_inst = CapLog()
                return caplog_inst
            if fname in mod_fixtures:
                fdef = mod_fixtures[fname]
                scope = getattr(fdef, "_pytest_scope", "function")
                if scope == "session" and fname in session_cache:
                    return session_cache[fname]
                if scope == "module" and fname in mod_cache:
                    return mod_cache[fname]
                sig = inspect.signature(fdef)
                fargs = {k: resolve_fixture(k) for k in sig.parameters}
                val = fdef(**fargs)
                if inspect.isgenerator(val):
                    val = next(val)
                if scope == "session":
                    session_cache[fname] = val
                elif scope == "module":
                    mod_cache[fname] = val
                else:
                    fn_cache[fname] = val
                return val
            raise KeyError(f"Unknown fixture: {fname}")

        try:
            sig = inspect.signature(func)
            call_kwargs = {}
            for pname in sig.parameters:
                if pname in param_kwargs:
                    call_kwargs[pname] = param_kwargs[pname]
                else:
                    call_kwargs[pname] = resolve_fixture(pname)
            func(**call_kwargs)
            passed += 1
            if not quiet:
                print(f"PASSED {tf.name}::{tname}")
        except Exception as exc:
            failed += 1
            failures.append((tf.name, tname, traceback.format_exc()))
            if not quiet:
                print(f"FAILED {tf.name}::{tname}: {exc}")
        finally:
            if capsys_inst is not None:
                capsys_inst.close()
            if caplog_inst is not None:
                caplog_inst.close()
            mp.undo()

    shutil.rmtree(base_tmp, ignore_errors=True)
    for fn, tn, tb in failures:
        print(f"=== FAIL: {fn}::{tn} ===\n{tb}", file=sys.stderr)
    print(f"{passed} passed, {failed} failed ({len(collected)} collected)")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    raise SystemExit(main())
