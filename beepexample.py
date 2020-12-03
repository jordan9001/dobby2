if __name__ == '__main__':
    print("Please import this file from the interpreter")
    exit(-1)

from dobby import *
from dobby.winsys import *
from dobby import dobby_triton
from dobby import dobby_unicorn
import os
import time

# load the PE
base = 0xfffff80154a00000
entry = base + 0x602b
ctx = Dobby()
dobby_triton.DobbyTriton(ctx)
#dobby_unicorn.DobbyUnicorn(ctx)

# setup easy reg access
rax = DB_X86_R_RAX
rbx = DB_X86_R_RBX
rcx = DB_X86_R_RCX
rdx = DB_X86_R_RDX
rdi = DB_X86_R_RDI
rsi = DB_X86_R_RSI
rbp = DB_X86_R_RBP
rsp = DB_X86_R_RSP
r8  = DB_X86_R_R8
r9  = DB_X86_R_R9
r10 = DB_X86_R_R10
r11 = DB_X86_R_R11
r12 = DB_X86_R_R12
r13 = DB_X86_R_R13
r14 = DB_X86_R_R14
r15 = DB_X86_R_R15
rip = DB_X86_R_RIP
gs = DB_X86_R_GS

save = "beepstartstate"
savefile = save+".snap"
starttime = time.time()
if os.path.exists(savefile):
    # load from saved state
    print("Loading file")
    save = ctx.loadSnapFile(savefile)
    print("Restoring State")
    ctx.restoreSnap(save)
    if not ctx.active.getName() == "Triton":
        ctx.setRegVal(DB_X86_R_CR0, 0x10039) # turn off paging until we add that feature to our unicorn setup
    print("Restored")
else:
    print("No state file found, restarting from start")
    print("Loading Beep...")
    pe = ctx.loadPE("./beep.sys", base)

    print("Loaded")
    ctx.initState(entry, entry+5)
    # add in predefined API hooks
    initSys(ctx)

    # setup args
    if ctx.issym:
        ctx.symbolizeRegister(rdx, "RegistryPath")
    else:
        ctx.setRegVal(rdx, 0x3031323340414243)

    drvobj = createDrvObj(ctx, base, pe.virtual_size, entry, "\\??\\C:\\Windows\\System32\\drivers\\beep.sys", name="beep")
    regpath = createUnicodeStr(ctx, "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\BEEP")
    ctx.setRegVal(rcx, drvobj)
    ctx.setRegVal(rdx, regpath)

    # save state for quick loading next time
    ctx.takeSnap(save)
    ctx.saveSnapFile(save, savefile)

ctx.startTrace()

ctx.printIns = False

endtime = time.time()

print(f"ctx prepped for beep driver entry in {endtime-starttime} seconds")
