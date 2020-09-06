if __name__ == '__main__':
    print("Please import this file from the interpreter")
    exit(-1)

from dobby import *

# load the PE
ctx = Dobby(0x4141410000)
pe = ctx.loadPE("./tester/tester.exe", 0x400000)
ctx.initState(0x4013AF, 0x4013B4, 0x64f000, 3)

# setup easy reg access
rax = ctx.api.registers.rax
rbx = ctx.api.registers.rbx
rcx = ctx.api.registers.rcx
rdx = ctx.api.registers.rdx
rdi = ctx.api.registers.rdi
rsi = ctx.api.registers.rsi
rbp = ctx.api.registers.rbp
rsp = ctx.api.registers.rsp
r8  = ctx.api.registers.r8
r9  = ctx.api.registers.r9
r10 = ctx.api.registers.r10
r11 = ctx.api.registers.r11
r12 = ctx.api.registers.r12
r13 = ctx.api.registers.r13
r14 = ctx.api.registers.r14
r15 = ctx.api.registers.r15
rip = ctx.api.registers.rip

# add in predefined API hooks    
onexit = [x for x in ctx.hooks[0] if x.label.endswith("_onexit")]
if len(onexit) != 1:
    print(f"expected one onexit hook, found {len(onexit)}")
    exit(-1)
def onexitHook(hook, ctx, addr, sz, op):
    print("_onexit Called, with argument:")
    ctx.printReg(rcx)
    return ctx.rethook(hook, ctx, addr, sz, op)
    
onexit[0].handler = onexitHook

# add a breakpoint
ctx.addHook(0x401574, 0x401575, "e", None, False, "Breakpoint1: check symbolic cmp")
ctx.addHook(0x401600, 0x401600, "e", None, False, "Breakpoint2: test_asm")

# setup argc argv
ctx.api.symbolizeRegister(rcx, "ARGC")
ctx.api.symbolizeRegister(rdx, "ARGV")
print("ctx prepped for tester.exe")
