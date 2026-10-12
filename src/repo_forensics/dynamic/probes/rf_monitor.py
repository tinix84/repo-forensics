"""Runtime call-graph collector (PEP 669 sys.monitoring). Stdlib only: runs inside the target venv.

Records, for every function in the repository that starts executing, who called it: another
repository function, or an external frame (e.g. a plugin manager), which is how dynamic
dispatch becomes visible. Code outside the repository is disabled after its first event.
"""

import json
import os
import sys

ROOT = os.path.realpath(os.environ.get("RF_ROOT", "."))
TOOL = 3  # free tool id (0 debugger, 1 coverage, 2 profiler, 5 optimizer are reserved by convention)
_edges = {}
_loaded = set()
_MAX = 200000


def _inside(filename):
    if not filename or filename.startswith("<"):  # <frozen ...>, <string>: not files in the repo
        return False
    try:
        return os.path.realpath(filename).startswith(ROOT + os.sep)
    except (TypeError, ValueError):
        return False


def _label(code):
    return f"{os.path.relpath(os.path.realpath(code.co_filename), ROOT)}::{getattr(code, 'co_qualname', code.co_name)}"


def _on_start(code, offset):
    if not _inside(code.co_filename):
        return sys.monitoring.DISABLE
    # Inside a PY_START callback, frame 1 is the function that is starting; its f_back is the caller.
    f = sys._getframe(1).f_back
    caller = f.f_code if f is not None else None
    if caller is not None and _inside(caller.co_filename):
        src = _label(caller)
    else:
        name = f.f_globals.get("__name__", "?") if f is not None else "?"
        if caller is not None and caller.co_filename.startswith("<") and not caller.co_filename.startswith("<frozen"):
            # code compiled at runtime (dataclass __init__, namedtuple, exec) runs with its module's globals
            src = f"<generated:{name}>"
        else:
            src = f"<external:{name.split('.')[0]}>"
    key = (src, _label(code))
    if len(_edges) < _MAX or key in _edges:
        _edges[key] = _edges.get(key, 0) + 1


def start():
    if not hasattr(sys, "monitoring"):
        return False
    sys.monitoring.use_tool_id(TOOL, "repo-forensics")
    sys.monitoring.register_callback(TOOL, sys.monitoring.events.PY_START, _on_start)
    sys.monitoring.set_events(TOOL, sys.monitoring.events.PY_START)
    return True


def stop_and_dump(path):
    if hasattr(sys, "monitoring"):
        try:
            sys.monitoring.set_events(TOOL, 0)
            sys.monitoring.free_tool_id(TOOL)
        except ValueError:
            pass
    loaded = sorted(
        {
            os.path.relpath(os.path.realpath(m.__file__), ROOT)
            for m in list(sys.modules.values())
            if getattr(m, "__file__", None) and _inside(m.__file__)
        }
    )
    data = {
        "edges": [[s, d, n] for (s, d), n in _edges.items()],
        "loaded_files": loaded,
        "truncated": len(_edges) >= _MAX,
        "python": sys.version.split()[0],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
