# -*- coding: utf-8 -*-
"""
guards.py — Debugger safety guards
===================================
ALL write operations in the plugin must call require_static_mode() first.
is_debugger_active() uses two-method IDA 9.0-compatible check.
PRESERVED VERBATIM FROM v4 — do not weaken these guards.
"""

_IN_IDA = False
try:
    import idaapi
    import ida_dbg
    _IN_IDA = True
except ImportError:
    pass


def is_debugger_active() -> bool:
    """
    Return True when IDA has a debugger attached and a process loaded.

    IDA 9.0 process states (dbg.hpp):
      DSTATE_NOTASK        = -1  no process
      DSTATE_IDD_DISABLED  =  0  plugin loaded, no process
      DSTATE_LOADED        =  1  process loaded, not running
      DSTATE_RUN           =  2  running
      DSTATE_SUSP          =  3  suspended / breakpoint
      DSTATE_SUSP_FOR_STEP =  4  single-step
      ...
    We block writes only when state >= 1 (process is present).
    """
    if not _IN_IDA:
        return False
    try:
        dbg_name = ida_dbg.get_debugger_name() or ""
        if not dbg_name:
            return False          # "No debugger" selected → safe
        state = ida_dbg.get_process_state()
        return state >= 1         # process loaded/running/suspended
    except Exception:
        return False              # graceful fallback → allow writes


def require_static_mode(op_name: str = "this operation") -> bool:
    """
    Gate for every write operation.
    Shows a warning dialog and returns False if debugger is active.
    """
    if not is_debugger_active():
        return True
    if _IN_IDA:
        idaapi.warning(
            "[GPT Renamer] WARNING: %s\n\n"
            "Cannot %s while a debugger session is active!\n\n"
            "Reason: Modifying the IDB (rename, comment) while the debugger\n"
            "is running can corrupt IDA's code cache and cause crashes.\n\n"
            "Please stop the debugger first (Debug > Detach / Stop)\n"
            "then retry." % (op_name, op_name)
        )
    return False
