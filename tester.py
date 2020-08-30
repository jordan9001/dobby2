if __name__ == '__main__':
    print("Please import this file from the interpreter")

from dobby import *


# load the PE
ctx = Dobby(0x4141410000)
pe = ctx.loadPE("./tester/tester.exe", 0x400000)
ctx.initState(0x4013AF, 0x4013B4, 0x64f000, 3)

# setup argc argv
ctx.api.symbolizeRegister(ctx.api.registers.rcx, "ARGC")
ctx.api.symbolizeRegister(ctx.api.registers.rdx, "ARGV")

print("ctx prepped for tester.exe")
