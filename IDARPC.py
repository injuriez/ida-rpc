
import ida_idaapi
import ida_funcs
import ida_kernwin
import ida_nalt
from pypresence import Presence
import asyncio
import time
# most of the other rpcs i found didn't work so i just coded something tiny!
class rpcmod(ida_idaapi.plugmod_t):
    def __init__(self):
        self.rpc = None
        self.client_id = "1571951560378945646"
        self.last_status = None
        self.start = int(time.time())
        self.timer = ida_kernwin.register_timer(3000, self.update)
        self.update()

    def __del__(self):
        if self.timer is not None:
            ida_kernwin.unregister_timer(self.timer)

        if self.rpc is not None:
            try:
                self.rpc.close()
            except Exception:
                pass

        print("[idaRPC] KIL YOURSEF.")

    def update(self):
        try:
            if self.rpc is None:
                self.rpc = Presence(self.client_id, loop=asyncio.new_event_loop())
                self.rpc.connect()

            name = ida_funcs.get_func_name(ida_kernwin.get_screen_ea()) or "Unknown"
            filename = ida_nalt.get_root_filename() or "Unknown"

            widget = ida_kernwin.get_current_widget()
            view = ida_kernwin.get_widget_type(widget) if widget else None


            activity = {
                ida_kernwin.BWN_STRINGS: "Viewing strings",
                ida_kernwin.BWN_IMPORTS: "Viewing imports",
                ida_kernwin.BWN_EXPORTS: "Viewing exports",
                ida_kernwin.BWN_PSEUDOCODE: f"Decompiling {name}",
                ida_kernwin.BWN_DISASM: f"Viewing {name}",
                ida_kernwin.BWN_BPTS: "Viewing breakpoints",
                ida_kernwin.BWN_HEXVIEW: "Viewing hex",
                ida_kernwin.BWN_FUNCS: "Viewing functions",
                ida_kernwin.BWN_STKVIEW: "Viewing Stack view",
                ida_kernwin.BWN_ADDRWATCH: "Viewing Watch List",
                ida_kernwin.BWN_NAMES: "Viewing names",
                ida_kernwin.BWN_SEGS: "Viewing segments",
                ida_kernwin.BWN_XREFS: "Viewing xrefs",
                ida_kernwin.BWN_TILIST: "Viewing local types",
                ida_kernwin.BWN_FRAME: f"Viewing stack frame of {name}",
                ida_kernwin.BWN_SIGNS: "Viewing signatures",
                ida_kernwin.BWN_PROBS: "Viewing problems",
                ida_kernwin.BWN_NOTEPAD: "Writing notes",
                ida_kernwin.BWN_OUTPUT: "Reading output",
                ida_kernwin.BWN_CLI: "Typing in the console",
                ida_kernwin.BWN_CPUREGS: "Debugging registers",
                ida_kernwin.BWN_MODULES: "Debugging modules",
                ida_kernwin.BWN_THREADS: "Debugging threads",
                ida_kernwin.BWN_CALL_STACK: "Debugging call stack",
                ida_kernwin.BWN_LOCALS: "Debugging locals",
                ida_kernwin.BWN_WATCH: "Debugging watches",
            }.get(view, "") # btw this is a fall back you can change this idc

            status = (name, activity)

            if status != self.last_status:
                self.rpc.update(
                    state=activity[:128] or None,
                    details=f"{filename}",
                    large_image="main_image",
                    name=f"IDA Professional {ida_kernwin.get_kernel_version()}",
                    start=self.start,
                )

                self.last_status = status

        except Exception as e:
            print(f"[idaRPC] Error: {e}")
            if self.rpc is not None:
                try:
                    self.rpc.close()
                except Exception:
                    pass

            self.rpc = None
            self.last_status = None

        return 3000

    def run(self):
        self.update()
        return True


class rpc(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_MULTI | ida_idaapi.PLUGIN_FIX
    wanted_name = "idaRPC"
    comment = "tung tung"

    def init(self):
        print("[idaRPC] loaded")
        return rpcmod()


def PLUGIN_ENTRY():
    return rpc()




