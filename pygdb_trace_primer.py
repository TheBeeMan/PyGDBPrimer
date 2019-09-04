#
# This script needs to be run on startup
# emulator  -avd ${AVD_NAME}  -netdelay none -netspeed full -show-kernel -kernel ${PATH_TO_KERNEL}  -qemu -S -s
# and then go to kernel build output folder:
# gdb  -x pygdb_trace_primer.py

import gdb

x16_entry = 0
x16_exit = 0
tmp_hwpoint = None

def prRed(skk): print("\033[91m {}\033[00m" .format(skk))
def prBlue(skk): print("\033[0;49;34m {}\033[00m" .format(skk))
def prGreen(skk): print("\033[0;49;32m {}\033[00m" .format(skk))
def prYellow(skk): print("\033[93m {}\033[00m" .format(skk))
def prLightPurple(skk): print("\033[94m {}\033[00m" .format(skk))
def prPurple(skk): print("\033[95m {}\033[00m" .format(skk))
def prCyan(skk): print("\033[96m {}\033[00m" .format(skk))
def prLightGray(skk): print("\033[97m {}\033[00m" .format(skk))
def prBlack(skk): print("\033[98m {}\033[00m" .format(skk))

def init(msg):
    prGreen("[+] " + msg)
    gdb.execute("file vmlinux")
    gdb.execute("target remote :1234")
    # These are not very useful in scripts
    gdb.execute("set pagination off")

def resume():
    gdb.execute("c")

class CatchBreakpoint(gdb.Breakpoint):
    def __init__(self, sym_name):
        super(CatchBreakpoint, self).__init__(sym_name)
        self.sym, ok = gdb.lookup_symbol(sym_name)

    def stop(self):
        end_pc = gdb.parse_and_eval('$pc')
        prGreen("[+] CB: %s == %s" % (end_pc, self.sym.value()))

class WatchPoint(gdb.Breakpoint):
    "Setup sym and wp_str for given symbol or constant address"
    def __init__(self, sym_name, type):
        wp_str = self.get_wpstr(sym_name)
        super(WatchPoint, self).__init__(wp_str, gdb.BP_WATCHPOINT, type)

    def get_wpstr(self, sym_name):
        # determinate whether the given symbol is numberic formatted address or not
        if isinstance(sym_name, int) or isinstance(sym_name, long):
            self.wp_str = "*{}".format(sym_name)
        else:
            self.sym, ok = gdb.lookup_symbol(sym_name)
            wp_addr = gdb.parse_and_eval(sym_name).address
            self.wp_str = '*(%(type)s)(&%(address)s)' % dict(
                type = wp_addr.type, address = sym_name)
        return(self.wp_str)

    def stop(self):
        end_pc = gdb.parse_and_eval('$pc')
        prRed("[+] HIT WP @ %s" % (end_pc))
        return True

class TestBreakPoints(object):
    def run_test(self):
        "Run throught the tests one by one"

        prGreen("[+] Checking we can step the first few instructions")
        step_ok = 0
        for i in range(3):
            if self.check_step():
                step_ok += 1

        prGreen("[+] Checking HW breakpoint works")
        break_ok = self.check_hbreak("kernel_init")

        # Can't set this up until we are in the kernel proper
        # if we make it to run_init_process we've over-run and
        # one of the tests failed
        prGreen("[+] Setup catch-all for run_init_process")
        cbp = CatchBreakpoint("run_init_process")
        cpb2 = CatchBreakpoint("try_to_run_init_process")

        prGreen("[+] Checking Normal breakpoint works")
        break_ok = check_break("wait_for_completion")
        prGreen("[+] Checking watchpoint works")
        self.check_watches("system_state")

    def check_step():
        "Step an instruction, check it moved."
        start_pc = gdb.parse_and_eval('$pc')
        gdb.execute("si")
        end_pc = gdb.parse_and_eval('$pc')
        return not (start_pc == end_pc)

    def check_break(self, sym_name):
        "Setup breakpoint, continue and check we stopped."
        sym, ok = gdb.lookup_symbol(sym_name)
        bp = gdb.Breakpoint(sym_name)
        # It will be blocked here until breakpoint hits
        resume()
        # hopefully we came back
        end_pc = gdb.parse_and_eval('$pc')
        prGreen("[+] %s == %s %d" % (end_pc, sym.value(), bp.hit_count))
        bp.delete()
        # can we test we hit bp?
        return end_pc == sym.value()

    # We need to do hbreak manually as the python interface doesn't export it
    def check_hbreak(self, sym_name):
        "Setup hardware breakpoint, continue and check we stopped."
        sym, ok = gdb.lookup_symbol(sym_name)
        gdb.execute("hbreak %s" % (sym_name))
        resume()
        # hopefully we came back
        end_pc = gdb.parse_and_eval('$pc')
        prGreen("[+] %s == %s" % (end_pc, sym.value()))
        if end_pc == sym.value():
            gdb.execute("d 1")
            return True
        else:
            return False

    def do_one_watch(sym, wtype, text):
        wp = WatchPoint(sym, wtype)
        resume()
        if wp.hit_count > 0:
            wp.delete()

    def check_watches(sym_name):
        "Watch a symbol for any access."

        # Should hit for access
        self.do_one_watch(sym_name, gdb.WP_ACCESS, "awatch")

        # Again should hit for reads
        self.do_one_watch(sym_name, gdb.WP_READ, "rwatch")

        # Finally when it is written
        self.do_one_watch(sym_name, gdb.WP_WRITE, "watch")

class EntryReg16Tracer(gdb.Breakpoint):
    def stop(self):
        R16 = self.get_x16() 
        self.record(R16)
        if not R16: 
            prRed("[!] x16 is 0, at [ftrace_regs_caller entry], sp points to {}".format( \
                    gdb.parse_and_eval("$sp")))
            return True

        prBlue("===========================================================================================") 
        prGreen("[+] x16 is 0x{:x}, at [ftrace_regs_caller entry], sp points to {}".format( \
                    R16 if R16 >= 0 else 1<<64 + R16, gdb.parse_and_eval("$sp")))
        # We want to add written watchpoint once reaches here
        self.set_hwpoint(128)
        return False

    def record(self, curr):
        global x16_entry
        x16_entry = curr 

    def get_x16(self):
        long_int_t = gdb.lookup_type("unsigned long")
        x16_raw = gdb.parse_and_eval('$x16').cast(long_int_t)
        return int(x16_raw) & 0xffffffffffffffff

    def get_sp(self):
        long_int_t = gdb.lookup_type("unsigned long")
        sp_raw = gdb.parse_and_eval('$sp').cast(long_int_t)
        return int(sp_raw) & 0xffffffffffffffff

    def set_hwpoint(self, offset):
        curr_sp = self.get_sp()
        dest = curr_sp + offset
        global tmp_hwpoint
        # On certain situation, add watchpoint will trigger RuntimeError 
        try:
            tmp_hwpoint = WatchPoint(dest, gdb.WP_WRITE)
        except:
            # Ignore the error and keep going
            prYellow("[x] failed to add watchpoint")
            resume() 

class ExitReg16Tracer(gdb.Breakpoint):
    def stop(self):
        R16 = self.get_x16()
        self.record(R16)
        global x16_entry
        if not R16 and R16 != x16_entry: 
            prRed("[!] x16 is 0x{:x} while x16_entry is 0x{:x}, at [ftrace return exit], sp points to {}".format( \
                    R16 if R16 >= 0 else 1<<64 + R16, x16_entry, gdb.parse_and_eval("$sp")))
            return True
            #return False

        # Global written watchpoint is not hit and everything is ok
        prGreen("[+] watchpoint hit [{:d}] times, we will delete it".format(tmp_hwpoint.hit_count))
        tmp_hwpoint.delete()
        prGreen("[+] x16 keep unchanged and non-zero at [ftrace return exit], sp points to {}".format( \
                gdb.parse_and_eval("$sp")))
        return False

    def record(self, curr):
        global x16_exit
        x16_exit = curr 

    def get_x16(self):
        long_int_t = gdb.lookup_type("unsigned long")
        x16_raw = gdb.parse_and_eval('$x16').cast(long_int_t)
        return int(x16_raw) & 0xffffffffffffffff

#
# This runs as the script it sourced (via -x)
#

try:
    init("load kernel image, and connecting to emulator")    

    # Set up a breakpoint at the following address where assembly code seems like this:
    # "ffffff8008094ef4:    a90847f0    stp x16, x17, [sp, #128]"
    # "ffffff8008094ef8:    a9094ff2    stp x18, x19, [sp, #144]"
    ert1 = EntryReg16Tracer("*0xffffff8008094ef8")

    # Set up a breakpoint at the following address where assembly code seems like this:
    # "ffffff8008094da4:   a94847f0    ldp x16, x17, [sp, #128]"
    # "ffffff8008094da8:   9104c3ff    add sp, sp, #0x130"
    ExitReg16Tracer("*0xffffff8008094da8")
    resume()
except:
    prRed("[!] GDB Exception: %s" % (sys.exc_info()[0]))
    import code
    code.InteractiveConsole(locals=globals()).interact()
    raise
