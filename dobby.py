if __name__ == '__main__':
    print("Please import this file from the interpreter")
    exit(-1)

from triton import *
import lief
import sys
import collections
import struct
from enum import Enum

# ok so the plan
# instead of making our own cmdline interface, just use the python interpreter or ipython
# add our helper tools as helper functions in this library
# allow for iteration and reloading of this library as changes are added during runtime via importlib.reload
#
# must haves:
# - scriptable hooks
#       this is the real reason for moving away from a pure C++ codebase
#       While we had some limited scripting in the C++ code, here we can create functions with full access on the fly
# - save state to file
#       this is also more possible with python, as we can pickle created hooks
#       and easily serialize our saved sandbox changes
# - sandbox everything
#       the idea of dobby is to build the sandbox as the program runs, and be alerted to any side effects so we can build the env
# - sys file PE loading
# - (somewhat) quick emulation
#       it can't take more than a minute between sandbox prompts, otherwise it is unusable

#TODO current vague steps forward
#   0. test PE loading
#   1. emulation with callbacks
#   2. change tracking

#TODO other features
#   file symbol annotation
#   save/load state from file
#   per PE arch, instead of global hooks, annotations, etc

class Hook:
    def __init__(self, start, end, label="", handler=None):
        self.start = start
        self.end = end
        self.label = label
        self.handler = handler

    def __repr__(self):
        return f"Hook @ {hex(self.start)}:\"{self.label}\""

class Annotation:
    def __init__(self, start, end, mtype="UNK", label=""):
        self.start = start
        self.end = end
        self.mtype = mtype
        self.label = label

    def __repr__(self):
        return f"{hex(self.start)}-{hex(self.end)}=>\"{self.mtype}:{self.label}\""

class HookRet(Enum):
    CONT_INS = 0
    DONE_INS = 1
    STOP_INS = 2

class StepRet(Enum):
    ERR_IP_OOB = -2
    ERR = -1
    OK = 0
    HOOK_EXEC = 1
    HOOK_WRITE = 2
    HOOK_READ = 3
    PATH_FORKED = 4
    BAD_INS = 5
    DREF_SYMBOLIC = 6
    

class Dobby:
    def __init__(self, apihookarea=0xffff414100000000):
        print("Starting Dobby 🤘")
        
        self.api = TritonContext(ARCH.X86_64)
        self.api.enableSymbolicEngine(True)

        # setup hook stuff
        # hooks are for stopping execution, or running handlers
        self.hooks = [[],[],[]] # e, rw, w
        self.lasthook = None

        # setup annotation stuff
        # annotations are for noting things in memory that we track
        self.ann = []

        # setup bounds
        # bounds is for sandboxing areas we haven't setup yet
        self.bounds = []

        # add annotation for the API_FUNC area
        self.apihooks = self.addAnn(apihookarea, apihookarea, "API_HOOKS", False, "API HOOKS")

    def printBounds(self):
        for b in self.bounds:
            print(hex(b[0]),'-',hex(b[1]))

    def printReg(self, reg, simp=True):
        print(reg, end=" = ")
        s = self.api.getSymbolicRegister(reg)
        if s is not None:
            ast = s.getAst()
            if simp:
                ast = self.api.simplify(ast, True)
            print(ast)
        else:
            # concrete value
            print(hex(self.api.getConcreteRegisterValue(reg)))

    def printMem(self, addr, simp=True):
        #TODO
        pass
        

    def getu64(self, addr):
        return struct.unpack("Q", self.api.getConcreteMemoryAreaValue(addr, 8))[0]

    def setu64(self, addr, val):
        self.api.setConcreteMemoryAreaValue(addr, struct.pack("Q", val))

    def loadPE(self, path, base):
        pe = lief.parse(path)

        dif = base - pe.optional_header.imagebase

        # load concrete mem vals from image
        # we need to load in header as well
        rawhdr = b""
        with open(path, "rb") as fp:
            rawhdr = fp.read(pe.sizeof_headers)
        self.api.setConcreteMemoryAreaValue(base, rawhdr)
        self.addAnn(base, base+len(rawhdr), "MAPPED_PE_HDR", True, pe.name)

        for phdr in pe.sections:
            start = base + phdr.virtual_address
            end = start + len(phdr.content)
            self.api.setConcreteMemoryAreaValue(base + phdr.virtual_address, phdr.content)
            
            #annotate the memory region
            self.addAnn(start, end, "MAPPED_PE", True, pe.name + '(' + phdr.name + ')')

        # do reloactions
        for r in pe.relocations:
             for re in pe.relocations:
                if re.type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64:
                    a = re.address
                    val = self.getu64(base + a)

                    slid = val + dif

                    self.setu64(base + a, slid)
                else:
                    print(f"Warning: PE Loading: Unhandled relocation type {re.type}")

        # setup exception handlers
        #TODO

        # symbolize imports
        for i in pe.imports:
            for ie in i.entries:
                # extend the API HOOKS execution hook 
                hookaddr = self.apihooks.end
                self.apihooks.end += 8
                self.setu64(base + ie.iat_address, hookaddr)

                name = i.name + "::" + ie.name
                # create symbolic entry in the, if the address is used strangly
                # really this should be in the IAT, if the entry is a pointer to something bigger than 8 bytes
                #TODO
                # but for now, we just assume most of these are functions or pointers to something 8 or less bytes large
                self.api.symbolizeMemory(MemoryAccess(hookaddr, 8), "IAT val from " + pe.name + " for " + name)

                # create execution hook in hook are
                self.addHook(hookaddr, hookaddr+8, "e", None, False, "IAT entry from " + pe.name + " for " + name)

        self.updateBounds(self.apihooks.start, self.apihooks.end)
        
        # annotate symbols from image
        #TODO

        return pe

    def addHook(self, start, end, htype, handler=None, ub=False, label=""):
        # handler takes 3 args, (hook, addr, sz, op)
        # handler returns True to be a breakpoint, False to continue execution
        h = Hook(start, end, label, handler)
        added = False
        if 'e' in htype:
            added = True
            self.hooks[0].append(h)
        if 'r' in htype:
            added = True
            self.hooks[1].append(h)
        if 'w' in htype:
            added = True
            self.hooks[2].append(h)

        if not added:
            raise ValueError(f"Unknown Hook Type {htype}")
        elif ub:
            self.updateBounds(start, end)
        
        return h

    def rethook(handler, ctx, addr, sz, op):
        print("HOOK happened")
        sp = ctx.api.getConcreteRegisterValue(ctx.api.registers.rsp)
        retaddr = ctx.getu64(sp)
        ctx.api.setConcreteRegisterValue(ctx.api.registers.rip, retaddr)
        ctx.api.setConcreteRegisterValue(ctx.api.registers.rax, 0)
        return HookRet.DONE_INS

    def updateBounds(self, start, end):
        insi = 0
        si = -1
        ei = -1
        combine = False

        if start > end:
            raise ValueError(f"Invalid bounds {start} -> {end}")

        # see if it is already in bounds, or starts/ends in a region
        for bi in range(len(self.bounds)):
            b = self.bounds[bi]
            if b[1] < start:
                insi = bi+1
            if b[0] <= start <= b[1]:
                si = bi
            if b[0] <= end <= b[1]:
                ei = bi

        if si == -1 and ei == -1:
            # add a new bounds area
            self.bounds.insert(insi, [start, end])
        elif si == ei:
            # we are good already
            pass
        elif si == -1:
            # extend the ei one
            self.bounds[ei][0] = start
            combine = True
        elif ei == -1:
            # extend the si one
            self.bounds[si][1] = end
            combine = True
        else:
            # combine two or more entries
            self.bounds[si][1] = self.bounds[ei][1]
            combine = True

        if combine:
            while insi+1 < len(self.bounds) and self.bounds[insi+1][1] <= d[insi][1]:
                del self.bounds[insi+1]

    def inBounds(self, addr, sz=1):
        #TODO binary search
        for b in self.bounds:
            if b[1] < (addr+sz):
                continue
            if b[0] > addr:
                break
            return True
        return False

    def addAnn(self, start, end, mtype, ub=False, label=""):
        if ub:
            self.updateBounds(start, end)

        ann = Annotation(start, end, mtype, label)
        self.ann.append(ann)
        return ann

    def initState(self, start, end, stackbase=0xffffb9872000000, priv=0):
        # zero or symbolize all registers
        for r in self.api.getAllRegisters():
            n = r.getName()
            sym = False
            if n.startswith("cr") or n in ["gs", "fs"]:
                sym = True

            if sym:
                self.api.symbolizeRegister(r, "Inital " + n)
            else:
                self.api.setConcreteRegisterValue(r, 0)
        # setup rflags to be sane
        self.api.setConcreteRegisterValue(
            self.api.registers.eflags,
            (1 << 9) | # interrupts enabled
            (priv << 12) | # IOPL
            (1 << 21) # support cpuid
        )

        # setup sane control registers instead of symbolizing them all?
        #TODO

        # create stack
        stackstart = stackbase - (0x1000 * 16)
        stackann = self.addAnn(stackstart, stackbase, "STACK", True, "Inital Stack")
        # add guard hook
        def stack_guard_hook(hk, ctx, addr, sz, op):
            # grow the stack, if we can
            nonlocal stackann

            newstart = stackann.start - 0x1000
            if ctx.inBounds(newstart, 0x1000):
                # error, stack ran into something else
                print(f"Stack overflow! Stack with top at {stackann.start} could not grow")
                return True

            # grow annotation
            stackann.start = newstart
            # grow bounds
            ctx.updateBounds(newstart, stackann[1])
            # move the hook
            hk.start = newstart - 0x1000
            hk.end = newstart
            return False

        self.addHook(stackstart - (0x1000), stackstart, "w", stack_guard_hook, False, "Stack Guard")

        # create end hook
        self.addHook(end, end+1, "e", None, False, "End Hit")

        # create heap
        #TODO

        # set initial rip and rsp
        self.api.setConcreteRegisterValue(self.api.registers.rip, start)
        self.api.setConcreteRegisterValue(self.api.registers.rsp, stackbase - 0x100)

        return True

    def getNextIns(self):
        # rip should never be symbolic when this function is called
        if self.api.isRegisterSymbolized(self.api.registers.rip):
            raise ValueError("Tried to get instruction with symbolized rip")
        rip = self.api.getConcreteRegisterValue(self.api.registers.rip)
        insbytes = self.api.getConcreteMemoryAreaValue(rip, 15)
        inst = Instruction(rip, insbytes)
        self.api.disassembly(inst)
        return inst

#class StepRet(Enum):
#    ERR_IP_OOP = -2
#    ERR = -1
#    OK = 0
#    HOOK_EXEC = 1
#    HOOK_WRITE = 2
#    HOOK_READ = 3
#    PATH_FORKED = 4
#    BAD_INS = 5
#    DREF_SYMBOLIC = 6

    def stepi(self, ins, ignorehook=False):
        # do pre-step stuff
        self.lasthook = None

        # rip and rsp should always be a concrete value at the beginning of this function
        rspreg = self.api.registers.rsp
        ripreg = self.api.registers.rip
        rsp = self.api.getConcreteRegisterValue(rspreg)
        rip = self.api.getConcreteRegisterValue(ripreg)

        if not self.inBounds(rip):
            return StepRet.ERR_IP_OOB

        if not ignorehook:
            # check if rip is at a hooked execution location
            for eh in self.hooks[0]:
                if eh.start <= rip < eh.end:
                    # hooked
                    self.lasthook = eh

                    stop = True
                    if eh.handler is not None:
                        hret = eh.handler(self, rip, 1, "e")
                        if hret == STOP_INS:
                            return StepRet.HOOK_EXEC
                        elif hret == CONT_INS:
                            break
                        elif hret == DONE_INS:
                            return StepRet.OK

                    else:
                        return StepRet.HOOK_EXEC

            # check if we are about to do a memory deref of a symbolic value or a hooked location
            # we can't know beforehand if it is a write or not, so verify after the instruction
            #TODO

        # actually do a step
        if not self.api.processing(ins):
            return StepRet.BAD_INS

        # check if we forked rip
        if self.api.isRegisterSymbolized(ripreg):
            return StepReg.PATH_FORKED

        # check if we forked rsp
        #TODO

        # follow up on the write hooks
        #TODO

        return StepRet.OK

    def step(self, printIns=True, ignorehook=False):
        ins = self.getNextIns()
        print(ins)
        return self.stepi(ins, ignorehook)

    def cont(self, printIns=True):
        while True:
            ret = self.step(printIns)
            if ret != StepRet.OK:
                return ret

