if __name__ == '__main__':
    print("Please import this file from the interpreter")
    exit(-1)

from dobby import *

# load the PE
ctx = Dobby(0x4141410000)
pe = ctx.loadPE("./tester/tester.exe", 0x400000)
ctx.initState(0x4013AF, 0x4013B4, 0x64f000, 3)

# add in predefined API hooks
    
onexit = [x for x in ctx.hooks[0] if x.label.endswith("_onexit")]
if len(onexit) != 1:
    print(f"expected one onexit hook, found {len(onexit)}")
    exit(-1)
def onexitHook(hook, ctx, addr, sz, op):
    print("_onexit Called, with argument:")
    ctx.printReg(ctx.api.registers.rcx)
    return ctx.rethook(hook, ctx, addr, sz, op)
    
onexit[0].handler = onexitHook

# add a breakpoint
ctx.addHook(0x401574, 0x401575, "e", None, False, "Breakpoint1")
ctx.addHook(0x40166e, 0x40166f, "e", None, False, "Breakpoint2: check deref")
ctx.addHook(0x401640, 0x401641, "e", None, False, "Breakpoint3: check stack ret")

# setup argc argv
ctx.api.symbolizeRegister(ctx.api.registers.rcx, "ARGC")
ctx.api.symbolizeRegister(ctx.api.registers.rdx, "ARGV")

print("ctx prepped for tester.exe")
