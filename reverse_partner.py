# -*- coding: utf-8 -*-
import os
import sys
import traceback

import idaapi

PLUGIN_ROOT = os.path.dirname(__file__)

if PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, PLUGIN_ROOT)

try:
    # Case 1: package exports GPTRenamerPlugin in __init__.py
    from reverse_partner import GPTRenamerPlugin
except Exception:
    try:
        # Case 2: plugin class is inside plugin.py
        from reverse_partner.plugin import GPTRenamerPlugin
    except Exception:
        idaapi.msg("[GPT Renamer v5] Failed to import plugin:\n")
        idaapi.msg(traceback.format_exc() + "\n")
        GPTRenamerPlugin = None


def PLUGIN_ENTRY():
    if GPTRenamerPlugin is None:
        class BrokenPlugin(idaapi.plugin_t):
            flags = idaapi.PLUGIN_SKIP
            comment = "GPT Renamer v5 failed to import"
            help = ""
            wanted_name = "GPT Renamer v5 Import Failed"
            wanted_hotkey = ""

            def init(self):
                idaapi.msg("[GPT Renamer v5] Import failed. Check Output window.\n")
                return idaapi.PLUGIN_SKIP

            def run(self, arg):
                pass

            def term(self):
                pass

        return BrokenPlugin()

    return GPTRenamerPlugin()