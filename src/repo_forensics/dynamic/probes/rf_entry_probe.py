"""Entry-point probe: import the entry module and call it with --help, under the call-graph monitor.

Usage: python rf_entry_probe.py OUT.json module[:function] [prog-name]
--help is the least side-effecting invocation most CLIs support; SystemExit is expected.
"""

import importlib
import sys

import rf_monitor

out, spec = sys.argv[1], sys.argv[2]
prog = sys.argv[3] if len(sys.argv) > 3 else spec
mod_name, _, func = spec.partition(":")
status = "ok"
rf_monitor.start()
try:
    mod = importlib.import_module(mod_name)
    if func:
        target = mod
        for part in func.split("."):
            target = getattr(target, part)
        sys.argv = [prog, "--help"]
        try:
            target()
        except SystemExit as e:
            status = f"exit:{e.code}"
except BaseException as e:  # noqa: BLE001 - the probe must report, never crash
    status = f"error:{type(e).__name__}: {str(e)[:200]}"
finally:
    rf_monitor.stop_and_dump(out)
    with open(out + ".status", "w", encoding="utf-8") as fh:
        fh.write(status)
