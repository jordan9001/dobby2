if __name__ == '__main__':
    print("Please import this file from the interpreter")
    exit(-1)

from dobby import *

# load the PE
ctx = Dobby(0x4141410000)
pe = ctx.loadPE("./tester/Test2/x64/Release/Test2.exe", 0x140000000)
ctx.initState(0x140001A3F, 0x140001A44, 0, 3)

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

def putsHook(hook, ctx, addr, sz, op, isemu):
    fmtptr = ctx.getRegVal(rcx)
    fmt = ctx.getCStr(fmtptr, isemu) 

    print(f"Puts: {str(fmt, 'ascii')}")

    ctx.retzerohook(hook, ctx, addr, sz, op, isemu)

    #return HookRet.DONE_INS
    return HookRet.STOP_INS

ctx.setApiHandler("puts", putsHook, "ignore", True)

# setup argc argv
#ctx.api.symbolizeRegister(rcx, "ARGC")
#ctx.api.symbolizeRegister(rdx, "ARGV")
ctx.setRegVal(rcx, 2)
argv0 = b"Test2.exe\0"
argv1 = b"AAAA\0"
argv = ctx.alloc((8*3) + len(argv0) + len(argv1))
ctx.setu64(argv, argv + 0x18)
ctx.setu64(argv+8, argv + 0x18 + len(argv0))
ctx.setu64(argv+0x10, 0)
ctx.api.setConcreteMemoryAreaValue(argv + 0x18, argv0)
ctx.api.setConcreteMemoryAreaValue(argv + 0x18 + len(argv0), argv1)
ctx.api.setConcreteRegisterValue(rdx, argv)

ctx.copyStateToEmu()
ctx.startTrace(isemu="both")

print("ctx prepped for Test2.exe")
