if __name__ == '__main__':
    print("Please import this file from the interpreter")
    exit(-1)

from triton import *
import lief
import sys
import collections
import struct
import string
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
        return f"Hook @ {hex(self.start)}:\"{self.label}\"{' (no handler)' if self.handler is None else ''}"

class Annotation:
    def __init__(self, start, end, mtype="UNK", label=""):
        self.start = start
        self.end = end
        self.mtype = mtype
        self.label = label

    def __repr__(self):
        return f"{hex(self.start)}-{hex(self.end)}=>\"{self.mtype}:{self.label}\""

class HookRet(Enum):
    ERR = -1
    CONT_INS = 0
    DONE_INS = 1
    STOP_INS = 2
    FORCE_STOP_INS = 3 # unlike STOP_INS this one can not be ignored

class StepRet(Enum):
    ERR_STACK_OOB = -3
    ERR_IP_OOB = -2
    ERR = -1
    OK = 0
    HOOK_EXEC = 1
    HOOK_WRITE = 2
    HOOK_READ = 3
    HOOK_CB = 4
    HOOK_ERR = 5
    PATH_FORKED = 6
    STACK_FORKED = 7
    BAD_INS = 8
    DREF_SYMBOLIC = 9
    DREF_OOB = 10
    

class Dobby:
    def __init__(self, apihookarea=0xffff414100000000):
        print("🤘 Starting Dobby 🤘")
        
        self.api = TritonContext(ARCH.X86_64)
        self.api.enableSymbolicEngine(True)

        self.printIns = True
        self.lasthook = None
        self.lastins = None
        self.stepcb = None
        self.trace = None
        self.inscount = 0
        self.priv = True
        self.pes = []

        # id's of symbols we have set a value for
        self.defsyms = set()

        # setup hook stuff
        # hooks are for stopping execution, or running handlers
        self.hooks = [[],[],[]] # e, rw, w

        # setup annotation stuff
        # annotations are for noting things in memory that we track
        self.ann = []

        # setup bounds
        # bounds is for sandboxing areas we haven't setup yet
        self.bounds = []

        # save off types for checking later
        self.type_MemoryAccess = type(MemoryAccess(0,1))
        self.type_Register = type(self.api.registers.rax)

        # add annotation for the API_FUNC area
        self.apihooks = self.addAnn(apihookarea, apihookarea, "API_HOOKS", False, "API HOOKS")

    def printBounds(self):
        for b in self.bounds:
            print(hex(b[0]),'-',hex(b[1]))

    def printReg(self, reg, simp=True):
        print(reg, end=" = ")
        if self.api.isRegisterSymbolized(reg):
            s = self.api.getSymbolicRegister(reg)
            if s is not None:
                ast = s.getAst()
                if simp:
                    ast = self.api.simplify(ast, True)
                #TODO print ast with HEX and optional tabbing of args
                print(ast)
                return
        # concrete value
        print(hex(self.api.getConcreteRegisterValue(reg)))

    def ip(self):
        self.printReg(self.api.registers.rip)

    def printSymMem(self, addr, amt, stride, simp=True):
        if not self.inBounds(addr, amt):
            print("Warning, OOB memory")
        for i in range(0, amt, stride):
            memast = self.api.getMemoryAst(MemoryAccess(addr+i, stride))
            if simp:
                memast = self.api.simplify(memast, True)
            print(hex(addr+i)[2:].zfill(16), end=":  ")
            #TODO print ast with HEX and optional tabbing of args
            print(memast)

    def printMem(self, addr, amt=0x60, simp=True):
        if not self.inBounds(addr, amt):
            print("Warning, OOB memory")
        # read symbolic memory too
        hassym = False
        for i in range(0, amt):
            if self.api.isMemorySymbolized(MemoryAccess(addr+i, 1)):
                hassym = True
                break
        if hassym:
            print("Warning, contains symbolized memory")
            self.printSymMem(addr, amt, 8, simp)
            return
        mem = self.api.getConcreteMemoryAreaValue(addr, amt)
        hexdmp(mem, addr)

    def printRegMem(self, reg, amt=0x60, simp=True):
        # dref register, if not symbolic and call printMem
        if self.api.isRegisterSymbolized(reg):
            print("Symbolic Register")
            self.printReg(reg, simp)
        else:
            addr = self.api.getConcreteRegisterValue(reg)
            self.printMem(addr, amt, simp)

    def printStack(self, amt=0x60):
        self.printRegMem(self.api.registers.rsp, amt)

    def printMap(self):
        mp = [ x for x in self.ann if (x.end - x.start) != 0 ]
        mp.sort(key = lambda x: x.start)

        # add bounds areas not covered by ann
        for b in self.bounds:
            covered = False
            # if b is not contained by any annotation save it
            s = b[0]
            e = b[1]
            for m in mp:
                if m.end <= s:
                    continue
                if m.start >= e:
                    break
                # take out a chunk
                if m.start <= s < m.end:
                    s = m.end
                if m.start < e <= m.end:
                    e = m.start

                if e <= s:
                    covered = True
                    break

            if not covered:
                mp.append(Annotation(s, e, "UNK", "IN BOUNDS, NO ANN"))
        mp.sort(key = lambda x: x.start)

        print("\n".join([str(x) for x in mp]))
    

    def getfmt(self, addr, fmt, sz):
        return struct.unpack(fmt, self.api.getConcreteMemoryAreaValue(addr, sz))[0]

    def getu64(self, addr):
        return self.getfmt(addr, "<Q", 8)

    def getu32(self, addr):
        return self.getfmt(addr, "<I", 4)

    def getu16(self, addr):
        return self.getfmt(addr, "<H", 2)

    def getu8(self, addr):
        return self.getfmt(addr, "<B", 1)

    def geti64(self, addr):
        return self.getfmt(addr, "<q", 8)

    def geti32(self, addr):
        return self.getfmt(addr, "<i", 4)

    def geti16(self, addr):
        return self.getfmt(addr, "<h", 2)

    def geti8(self, addr):
        return self.getfmt(addr, "<b", 1)

    def setfmt(self, addr, val, fmt):
        self.api.setConcreteMemoryAreaValue(addr, struct.pack(fmt, val))

    def setu64(self, addr, val):
        self.setfmt(addr, val, "<Q")

    def setu32(self, addr, val):
        self.setfmt(addr, val, "<I")

    def setu16(self, addr, val):
        self.setfmt(addr, val, "<H")

    def setu8(self, addr, val):
        self.setfmt(addr, val, "<B")

    def seti64(self, addr, val):
        self.setfmt(addr, val, "<q")

    def seti32(self, addr, val):
        self.setfmt(addr, val, "<i")

    def seti16(self, addr, val):
        self.setfmt(addr, val, "<h")

    def seti8(self, addr, val):
        self.setfmt(addr, val, "<b")

    def getCStr(self, addr):
        mem = bytearray()
        while True:
            if not self.inBounds(addr, 1):
                raise MemoryError("Tried to read a CStr out of bounds")
            c = self.api.getConcreteMemoryValue(addr)
            if c == 0:
                break
            addr += 1

            mem.append(c)
        return bytes(mem)

    def getSymbol(self, symname):
        # use name to find symbol with that alias
        syms = self.api.getSymbolicVariables()
        for s in syms:
            if symname == syms[s].getAlias():
                return s
        raise KeyError(f"Unknown symbol {symname}")

    def setSymbol(self, sym, value, overwrite=False):
        # use setConcreteVariableValue to set the value
        # store the variable id in our list of set variables
        if sym in self.defsyms:
            if overwrite:
                print("Warning overwriting previously concretized symbol")
            else:
                raise KeyError(f"Attempted to concretize symbol {sym} which has already been set before")

        self.defsyms.add(sym)

        svar = self.api.getSymbolicVariable(sym)

        self.api.setConcreteVariableValue(svar, value)

    def hasUnsetSym(self, ast):
        # walk the ast and see if any of the symbols are not in our list
        #TODO
        pass

    def evalReg(self, reg):
        #TODO use hasUnsetSym to see if it is okay
        if self.api.isRegisterSymbolized(reg):
            val = self.api.getSymbolicRegisterValue(reg)
            self.api.setConcreteRegisterValue(reg, val)

    def evalMem(self, addr, size):
        #TODO use hasUnsetSym to see if it is okay
        mem = b""
        for i in range(size):
            mem += self.api.getSymbolicMemoryValue(MemoryAccess(addr+i, 1))
            self.api.setConcreteMemoryValue(addr+i, mem)

    def loadPE(self, path, base, again=False):
        pe = lief.parse(path)
        if pe is None:
            raise FileNotFoundError(f"Unable to parse file {path}")

        if not again and pe.name in [ x.name for x in self.pes ]:
            raise KeyError(f"PE with name {pe.name} already loaded")

        # get size, check base doesn't crush existing area
        end = base
        for phdr in pe.sections:
            e = base + phdr.virtual_address + phdr.virtual_size
            if e > end:
                end = e
        
        if self.inBounds(base, end - base):
            raise MemoryError(f"Could not load pe {pe.name} at {hex(base)}, because it would clobber existing memory")

        self.pes.append(pe)

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

            if (end - start) < phdr.virtual_size:
                end = start + phdr.virtual_size

            # round end up to page size
            end = (end + 0xfff) & (~0xfff)
            
            #annotate the memory region
            self.addAnn(start, end, "MAPPED_PE", True, pe.name + '(' + phdr.name + ')')

        # do reloactions
        for r in pe.relocations:
            lastabs = False
            for re in r.entries:
                if lastabs:
                    # huh, it wasn't the last one?
                    print(f"Warning, got a ABS relocation that wasn't the last one")
                if re.type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64:
                    a = re.address
                    val = self.getu64(base + a)

                    slid = val + dif

                    self.setu64(base + a, slid)
                elif re.type == lief.PE.RELOCATIONS_BASE_TYPES.ABSOLUTE:
                    # last one is one of these as a stop point
                    lastabs = True
                    #TODO handle this anyways?
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
        for sym in pe.exported_functions:
            if not sym.name:
                continue
            self.addAnn(sym.address + base, sym.address + base, "SYMBOL", False, pe.name + "::" + sym.name)

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

    #TODO
    # add a way to use read-only capabilities from a windows kernel debugger to apply real system info?
    
    def doRet(self, retval=0):
        self.api.setConcreteRegisterValue(self.api.registers.rax, retval)
        sp = self.api.getConcreteRegisterValue(self.api.registers.rsp)
        retaddr = self.getu64(sp)
        self.api.setConcreteRegisterValue(self.api.registers.rip, retaddr)
        self.api.setConcreteRegisterValue(self.api.registers.rsp, sp+8)

    @staticmethod
    def retzerohook(hook, ctx, addr, sz, op):
        ctx.doRet()
        return HookRet.DONE_INS

    def addVolatileSymHook(name, addr, sz, op, stops=False):
        if op != "r":
            raise TypeError("addVolatileSymHook only works with read hooks")
        
        ma = MemoryAccess(addr, sz)
        hit_count = 0
        def vshook(hook, ctx, addr, sz, op):
            nonlocal hit_count
            # create a new symbol for every hit
            ctx.api.symbolizeMemory(ma, name+hex(hit_count))
            hit_count += 1
            return HookRet.STOP_INS if stops else HookRet.CONT_INS

    def createThunkHook(self, symname, pename=""):
        symaddr = self.getSym(symname, pename)
        def dothunk(hook, ctx, addr, sz, op):
            ctx.api.setConcreteRegisterValue(ctx.api.registers.rip, symaddr)

            return HookRet.DONE_INS
        return dothunk

    def setApiHandler(self, name, handler, overwrite=False):
        found = [x for x in self.hooks[0] if x.label.endswith("::"+name)]
        if len(found) != 1:
            raise KeyError(f"Found {len(found)} hooks that match that name, unable to set handler")

        hk = found[0]
        if hk.handler is not None:
            if overwrite == "ignore":
                return
            if not overwrite:
                raise KeyError(f"Tried to set a handler for a API hook that already has a set handler")

        hk.handler = handler
        

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
            while insi+1 < len(self.bounds) and self.bounds[insi+1][1] <= self.bounds[insi][1]:
                del self.bounds[insi+1]

    def getFreeMem(self, start, amt):
        #TODO binary search
        
        prev = start
        for b in self.bounds:
            if (prev+amt) <= b[0]:
                # found spot
                return (prev, prev+amt)
            elif b[1] > prev:
                prev = b[1]
        return (prev, prev+amt)
            

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
        #TODO keep annotations sorted
        self.ann.append(ann)
        return ann

    def getSym(self, symname, pename=""):
        symname = pename + "::" + symname
        match = [ x for x in self.ann if x.mtype == "SYMBOL" and x.label.endswith(symname) ]

        if len(match) == 0:
            raise KeyError(f"Unable to find Symbol {symname}")
        if len(match) > 1:
            raise KeyError(f"Found multiple Symbols matching {symname}")

        return match[0].start

    def alloc(self, amt, start=0, label="", roundamt=True):
        if start == 0:
            start = 0xffff765400000000 if self.priv else 0x660000

        # round amt up to 0x10 boundry
        amt = (amt+0xf) & (~0xf)

        (start, end) = self.getFreeMem(start, amt)
        # if there is already an "ALLOC" annotation, extend it
        allocann = None
        for a in self.ann:
            if a.end == start and a.mtype == "ALLOC":
                allocann = a
                allocann.end = end
                if len(label) > 0:
                    allocann.label += "and " + label
                break;
            #TODO join to trailing ALLOC as well?
        if allocann is None:
            allocann = Annotation(start, end, "ALLOC", label)
            self.ann.append(allocann)
            #TODO keep annotations sorted

        self.updateBounds(start, end)
        return start

    def initState(self, start, end, stackbase=0, priv=0, symbolizeControl=True):
        self.priv = (priv == 0)
        if stackbase == 0:
            stackbase = 0xffffb98760000000 if self.priv else 0x64f000

        # zero or symbolize all registers
        for r in self.api.getAllRegisters():
            n = r.getName()
            sym = False
            if n.startswith("cr") or n in ["gs", "fs"]:
                sym = True

            if sym and symbolizeControl:
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

    def startTrace(self):
        if self.trace is None:
            self.trace = []

    def stopTrace(self):
        t = self.trace
        self.trace = None
        return t

    def getNextIns(self):
        # rip should never be symbolic when this function is called
        if self.api.isRegisterSymbolized(self.api.registers.rip):
            #TODO use hasUnsetSym to see if the symbols are already concretized
            # if so, evalReg rip
            raise ValueError("Tried to get instruction with symbolized rip")
        rip = self.api.getConcreteRegisterValue(self.api.registers.rip)
        insbytes = self.api.getConcreteMemoryAreaValue(rip, 15)
        inst = Instruction(rip, insbytes)
        self.api.disassembly(inst)
        return inst

    def stepi(self, ins, ignorehook=False):
        if self.stepcb is not None:
            ret = self.stepcb(self)
            if ret == HookRet.FORCE_STOP_INS:
                return StepRet.HOOK_CB
            elif ret == HookRet.STOP_INS and not ignorehook:
                return StepRet.HOOK_CB
            elif ret == HookRet.DONE_INS:
                return StepRet.OK

        # do pre-step stuff
        self.lasthook = None
        self.lastins = ins

        # rip and rsp should always be a concrete value at the beginning of this function
        rspreg = self.api.registers.rsp
        ripreg = self.api.registers.rip
        rsp = self.api.getConcreteRegisterValue(rspreg)
        rip = self.api.getConcreteRegisterValue(ripreg)

        #TODO add exception raising

        if not self.inBounds(rip, ins.getSize()):
            return StepRet.ERR_IP_OOB

        if not self.inBounds(rsp, 8):
            return StepRet.ERR_STACK_OOB

        # check if rip is at a hooked execution location
        for eh in self.hooks[0]:
            if eh.start <= rip < eh.end:
                # hooked
                self.lasthook = eh

                if eh.handler is not None:
                    hret = eh.handler(eh, self, rip, 1, "e")
                    if hret == HookRet.FORCE_STOP_INS:
                        return StepRet.HOOK_EXEC
                    elif hret == HookRet.STOP_INS:
                        if not ignorehook:
                            return StepRet.HOOK_EXEC
                        else:
                            break
                    elif hret == HookRet.CONT_INS:
                        break
                    elif hret == HookRet.DONE_INS:
                        return StepRet.OK
                    elif hret == HookRet.ERR:
                        return StepRet.HOOK_ERR
                    else:
                        raise TypeError(f"Unknown return from hook handler for hook {eh}")
                else:
                    # no ignoring API hooks
                    if (self.apihooks.start <= rip < self.apihooks.end) or (not ignorehook):
                        return StepRet.HOOK_EXEC
                    else:
                        break

        # check if we are about to do a memory deref of:
        #   a symbolic value
        #   a hooked location (if not ignorehook)
        #   an out of bounds location
        # we can't know beforehand if it is a write or not, so verify after the instruction
        #TODO how to automatically detect symbolic expressions that are evaluable based on variables we have set
        for o in ins.getOperands():
            #TODO check if non-register memory derefs are MemoryAccess as well
            if isinstance(o, self.type_MemoryAccess):
                lea = ins.getDisassembly().find("lea")
                nop = ins.getDisassembly().find("nop")
                if lea != -1 or nop != -1:
                    # get that fake crap out of here
                    continue
                # check base register isn't symbolic
                basereg = o.getBaseRegister()
                baseregid = basereg.getId()
                if baseregid != 0 and self.api.isRegisterSymbolized(basereg):
                    #TODO check if the register can be concretized here
                    return StepRet.DREF_SYMBOLIC

                # check index register isn't symbolic
                indexreg = o.getIndexRegister()
                indexregid = indexreg.getId()
                if indexregid != 0 and self.api.isRegisterSymbolized(indexreg):
                    #TODO check if the register can be concretized here
                    return StepRet.DREF_SYMBOLIC

                # check segment isn't symbolic
                segreg = o.getSegmentRegister()
                segregis = segreg.getId()
                if segreg.getId() != 0 and self.api.isRegisterSymbolized(segreg):
                    #TODO check if the register can be concretized here
                    return StepRet.DREF_SYMBOLIC

                # calculate the address with displacement and scale
                addr = 0
                if baseregid != 0:
                    addr += self.api.getConcreteRegisterValue(basereg)

                if indexregid != 0:
                    scale = o.getScale().getValue()
                    addr += (scale * self.api.getConcreteRegisterValue(indexreg))

                disp = o.getDisplacement().getValue()
                addr += disp
                size = o.getSize()

                # check access is in bounds
                if not self.inBounds(addr, size):
                    return StepRet.DREF_OOB

                # check if access is hooked
                for rh in self.hooks[1]:
                    if rh.start <= addr < rh.end:
                        # hooked
                        self.lasthook = rh

                        if rh.handler is not None:
                            hret = rh.handler(eh, self, addr, size, "r")
                            if hret == HookRet.FORCE_STOP_INS:
                                return StepRet.HOOK_EXEC
                            elif hret == HookRet.STOP_INS:
                                if not ignorehook:
                                    return StepRet.HOOK_READ
                                else:
                                    break
                            elif hret == HookRet.CONT_INS:
                                break
                            elif hret == HookRet.DONE_INS:
                                return StepRet.OK
                            elif hret == HookRet.ERR:
                                return StepRet.HOOK_ERR
                            else:
                                raise TypeError(f"Unknown return from hook handler for hook {rh}")
                        else:
                            if not ignorehook:
                                return StepRet.HOOK_READ
                            else:
                                break

                    #TODO check write hooks

        # actually do a step
        #TODO how do we detect exceptions like divide by zero?
        if not self.api.processing(ins):
            return StepRet.BAD_INS

        self.inscount += 1

        if self.trace is not None:
            self.trace.append(str(ins))

        # check if we forked rip
        if self.api.isRegisterSymbolized(ripreg):
            return StepRet.PATH_FORKED
            # find what symbols it depends on
            # and use setSymbol to give a concrete value for the var
            # then use evalReg(rip) to evaluate rip

        # check if we forked rsp
        if self.api.isRegisterSymbolized(ripreg):
            return StepRet.STACK_FORKED

        # follow up on the write hooks
        if ins.isMemoryWrite():
            #TODO
            # also what if they wrote to a hooked location on the stack with a push?
            #TODO
            pass

        return StepRet.OK

    def step(self, ignorehook=True):
        ins = self.getNextIns()
        if self.printIns:
            #TODO if in API hooks, print API hook instead
            print(ins)
        return self.stepi(ins, ignorehook)

    def cont(self, ignoreFirst=True):
        if ignoreFirst:
            ret = self.step(True)
            if ret != StepRet.OK:
                return ret
        while True:
            ret = self.step(False)
            if ret != StepRet.OK:
                return ret

    def until(self, addr, ignoreFirst=True):
        ret = StepRet.OK
        if ignoreFirst:
            ret = self.step(True)
            if ret != StepRet.OK:
                return ret

        while True:
            rip = self.api.getConcreteRegisterValue(ripreg)
            if rip == addr:
                break

            ret = self.step(False)
            if ret != StepRet.OK:
                break

        return ret
        
            
        

# util
def hexdmp(stuff, start=0):
    printable = string.digits + string.ascii_letters + string.punctuation + ' '
    rowlen = 0x10
    mid = (rowlen//2)-1
    for i in range(0, len(stuff), rowlen):
        # start of line
        print(hex(start + i)[2:].zfill(16), end=":  ")

        # bytes
        rowend = min(i+rowlen, len(stuff))
        for ci in range(i, rowend):
            print(stuff[ci:ci+1].hex(), end=(" " if ((ci & (rowlen-1)) != mid) else '-'))
            
        # padding
        empty = rowlen - (rowend - i)
        if empty != 0:
            # pad out
            print("   " * empty, end="")

        print(' ', end="")

        # ascii
        for c in stuff[i:rowend]:
            cs = chr(c)
            if cs in printable:
                print(cs, end="")
            else:
                print(".", end="")
        print()
