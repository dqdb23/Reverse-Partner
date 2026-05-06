# -*- coding: utf-8 -*-
"""
logger.py — Plugin-wide logger
================================
All output goes to IDA's Output window (idaapi.msg).
Falls back to print() when running outside IDA (test harness).
"""

import time

_IN_IDA = False
try:
    import idaapi
    _IN_IDA = True
except ImportError:
    pass


class Logger:
    PREFIX = "[reverse_partner]"

    @staticmethod
    def _ts() -> str:
        return time.strftime("%H:%M:%S")

    @classmethod
    def _emit(cls, line: str):
        if _IN_IDA:
            idaapi.msg(line + "\n")
        else:
            print(line)

    @classmethod
    def info(cls, msg: str):
        cls._emit("%s [%s] %s" % (cls.PREFIX, cls._ts(), msg))

    @classmethod
    def ok(cls, msg: str):
        cls._emit("%s [%s] \u2713 %s" % (cls.PREFIX, cls._ts(), msg))

    @classmethod
    def warn(cls, msg: str):
        cls._emit("%s [%s] ! %s" % (cls.PREFIX, cls._ts(), msg))

    @classmethod
    def err(cls, msg: str):
        cls._emit("%s [%s] \u2717 %s" % (cls.PREFIX, cls._ts(), msg))

    @classmethod
    def sep(cls):
        cls._emit("%s %s" % (cls.PREFIX, "-" * 60))

    @classmethod
    def renamed(cls, old: str, new: str):
        cls._emit("%s [%s]   %-40s  ->  %s" % (cls.PREFIX, cls._ts(), old, new))

    @classmethod
    def progress(cls, bi, tb, proc, tq, ren, skip, fail, ki, kt, elapsed):
        pct    = int(proc * 100 / tq) if tq else 0
        filled = int(20 * proc / tq) if tq else 0
        bar    = "#" * filled + "." * (20 - filled)
        cls._emit(
            "%s [%s] [%s] %3d%% Batch %d/%d  Ham %d/%d\n"
            "%s          OK:%-5d Skip:%-5d Fail:%-5d Key:%d/%d %ds" % (
                cls.PREFIX, cls._ts(), bar, pct,
                bi + 1, tb, proc, tq,
                cls.PREFIX, ren, skip, fail, ki, kt, int(elapsed))
        )


log = Logger()
