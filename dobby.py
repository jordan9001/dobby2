if __name__ == '__main__':
    print("Please import this file from the interpreter")
    exit(-1)

from triton import *
from unicorn import *
from unicorn.x86_const import *

import lief
import sys
import collections
import struct
import string
import copy
import zlib
from enum import Enum

#TODO add documentation when the api is stable
class Hook:
    def __init__(self, start, end, label="", handler=None, handler_emu=None):
        self.start = start
        self.end = end
        self.label = label
        self.handler = handler
        self.handler_emu = handler_emu

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
    INTR = 11

class SavedState:
    COMP_NONE = 0
    COMP_ZLIB = 1

    def __init__(self, name):
        self.name = name
        self.setup = False

    def save(self, ctx, isemu, doann=False, dohooks=False, dosyms=False):
        self.bounds = copy.deepcopy(ctx.bounds)

        self.hasann = doann
        self.hashooks = dohooks
        self.hassyms = dosyms
        
        self.ann = None
        if doann:
            self.ann = copy.deepcopy(ctx.ann)

        # are hooks common? do we want to save them all off?
        # do we want to save any of them off? or just keep them all
        if dohooks:
            raise NotImplementedError("TODO")

        self.mem = [] # (start_addr, uncompressed_size, compression_type, bytes)
        self.regs = [] # (regname, value)

        for r in ctx.regtrans:
            self.regs.append((r.getName(), ctx.getRegVal(r, isemu)))

        # save memory values
        for b in ctx.bounds:
            sz = b[1] - b[0]
            addr = b[0]
            val = ctx.getMemVal(addr, sz, isemu)
            cval = zlib.compress(val, 6)
            self.mem.append((addr, sz, self.COMP_ZLIB, cval))
            
        if dosyms:
            # How do we do this for emu?
            raise NotImplementedError("TODO")

        self.setup = True

    def load(self, ctx, isemu, doann=False, dohooks=False, dosyms=False):
        if not self.setup:
            raise ValueError("Tried to write a uninitialized state to file")

        if isemu:
            # reset emu mem
            ctx.emu = None
            ctx.emu = Uc(UC_ARCH_X86, UC_MODE_64)
        else:
            # delete all symbols?
            #TODO
            pass
        
        if self.hasann and doann:
            ctx.ann = copy.deepcopy(self.ann)
        elif doann:
            print("Warning, tried to load ann from a state without any ann")

        if self.hashooks and dohooks:
            raise NotImplementedError("TODO")
        elif doann:
            print("Warning, tried to load hooks from a state without any hooks")

        if self.hassyms and dosyms:
            raise NotImplementedError("TODO")
        elif dosyms:
            print("Warning, tried to load syms from a state without any syms")

        # Load bounds
        ctx.bounds = copy.deepcopy(self.bounds)
        lastaddr = 0
        if isemu:
            # map mem
            for b in self.bounds:
                # round to page boundries?
                start = b[0] & (~ (self.pgsz-1))
                if lastaddr > start:
                    start = lastaddr
                end = (b[1] + (self.pgsz-1)) & (~ (self.pgsz-1))
                lastaddr = end
                sz = end - start
                self.emu.mem_map(start, sz)

        # Load memory values 
        for m in self.mem:
            addr, sz, comptype, cval = m

            val = None
            if comptype == self.COMP_ZLIB:
                val = zlib.decompress(cval, bufsize=sz)
            elif comptype == self.COMP_NONE:
                val = cval
            else:
                raise TypeError("Unknown compression type")

            ctx.setMemVal(addr, val, isemu)

        # Load register values
        for r in self.regs:
            name, val = r
            ctx.setReg(ctx.nameToReg(name), val, isemu)

        # save memory values
        for b in ctx.bounds:
            sz = b[1] - b[0]
            addr = b[0]
            val = ctx.getMemVal(addr, sz, isemu)
            cval = zlib.compress(val, 6)
            mem.append((addr, sz, self.COMP_ZLIB, cval))
            
            

    def tofile(fname):
        if not self.setup:
            raise ValueError("Tried to write a uninitialized state to file")
        raise NotImplementedError("TODO")

    def fromfile(fname):
        raise NotImplementedError("TODO")
        self.setup = True

    def __repr__(self):
        return f"SaveState({self.name})" 


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
        self.pgsz = 0x1000
        self.pes = []

        # for unicorn emulator
        self.emu = None
        self.trace_emu = None
        self.inscount_emu = 0
        self.stepret_emu = StepRet.OK
        self.intrnum_emu = -1
        self.ignorehookaddr_emu = -1
        self.trystop_emu = False
        self.regtrans = {}
        for x in x64KeyRegs:
            self.regtrans[getattr(self.api.registers, x)] = getattr(unicorn.x86_const, 'UC_X86_REG_' + x.upper())

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

        # set modes appropriately
        self.api.setMode(MODE.ALIGNED_MEMORY, False)
        self.api.setMode(MODE.AST_OPTIMIZATIONS, True)
        self.api.setMode(MODE.CONCRETIZE_UNDEFINED_REGISTERS, False)
        self.api.setMode(MODE.CONSTANT_FOLDING, True)
        self.api.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
        self.api.setMode(MODE.ONLY_ON_TAINTED, False)
        self.api.setMode(MODE.PC_TRACKING_SYMBOLIC, False)
        self.api.setMode(MODE.SYMBOLIZE_INDEX_ROTATION, False)
        self.api.setMode(MODE.TAINT_THROUGH_POINTERS, False)

    def printBounds(self):
        for b in self.bounds:
            print(hex(b[0]),'-',hex(b[1]))

    def printAst(self, ast, tabbed=4):
        print(taboutast(str(ast)))

    def printReg(self, reg, isemu=False, simp=True):
        print(reg.getName(), end=" = ")

        if not isemu and self.api.isRegisterSymbolized(reg):
            s = self.api.getSymbolicRegister(reg)
            if s is not None:
                ast = s.getAst()
                if simp:
                    ast = self.api.simplify(ast, True)
                #TODO print ast with HEX and optional tabbing of args
                print(ast)
                return
        # concrete value
        print(hex(self.getRegVal(reg, isemu)))

    def ip(self, isemu=False):
        self.printReg(self.api.registers.rip, isemu)

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

    def printMem(self, addr, amt=0x60, isemu=False, simp=True):
        if not self.inBounds(addr, amt):
            print("Warning, OOB memory")
        # read symbolic memory too
        if not isemu:
            hassym = False
            for i in range(0, amt):
                if self.api.isMemorySymbolized(MemoryAccess(addr+i, 1)):
                    hassym = True
                    break
            if hassym:
                print("Warning, contains symbolized memory")
                self.printSymMem(addr, amt, 8, simp)
                return
        mem = self.getMemVal(addr, amt, isemu)
        hexdmp(mem, addr)

    def printRegMem(self, reg, amt=0x60, isemu=False, simp=True):
        # dref register, if not symbolic and call printMem
        if not isemu and self.api.isRegisterSymbolized(reg):
            print("Symbolic Register")
            self.printReg(reg, simp)
        else:
            addr = self.getRegVal(reg, isemu)
            self.printMem(addr, amt, isemu, simp)

    def printStack(self, amt=0x60, isemu=False):
        self.printRegMem(self.api.registers.rsp, amt, isemu)

    def printQMem(self, addr, amt=12, isemu=False):
        if not self.inBounds(addr, amt*8):
            print("Warning, OOB memory")
        for i in range(amt):
            a = addr + (8*i)
            v = self.getu64(a, isemu)
            print(hex(a)[2:]+':', hex(v)[2:])

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
    
    def printEmuMap(self):
        reg_i = self.emu.mem_regions()
        for r_beg, r_end, _ in reg_i:
            print(hex(r_beg) +'-'+ hex(r_end))
    
    def nameToReg(name):
        return getattr(self.ctx.registers, name)

    def getfmt(self, addr, fmt, sz, isemu=False):
        return struct.unpack(fmt, self.getMemVal(addr, sz, isemu))[0]

    def getu64(self, addr, isemu=False):
        return self.getfmt(addr, "<Q", 8, isemu)

    def getu32(self, addr, isemu=False):
        return self.getfmt(addr, "<I", 4, isemu)

    def getu16(self, addr, isemu=False):
        return self.getfmt(addr, "<H", 2, isemu)

    def getu8(self, addr, isemu=False):
        return self.getfmt(addr, "<B", 1, isemu)

    def geti64(self, addr, isemu=False):
        return self.getfmt(addr, "<q", 8, isemu)

    def geti32(self, addr, isemu=False):
        return self.getfmt(addr, "<i", 4, isemu)

    def geti16(self, addr, isemu=False):
        return self.getfmt(addr, "<h", 2, isemu)

    def geti8(self, addr, isemu=False):
        return self.getfmt(addr, "<b", 1, isemu)

    def setfmt(self, addr, val, fmt, isemu=False):
        self.setMemVal(addr, struct.pack(fmt, val), isemu)

    def setu64(self, addr, val, isemu=False):
        self.setfmt(addr, val, "<Q", isemu)

    def setu32(self, addr, val, isemu=False):
        self.setfmt(addr, val, "<I", isemu)

    def setu16(self, addr, val, isemu=False):
        self.setfmt(addr, val, "<H", isemu)

    def setu8(self, addr, val, isemu=False):
        self.setfmt(addr, val, "<B", isemu)

    def seti64(self, addr, val, isemu=False):
        self.setfmt(addr, val, "<q", isemu)

    def seti32(self, addr, val, isemu=False):
        self.setfmt(addr, val, "<i", isemu)

    def seti16(self, addr, val, isemu=False):
        self.setfmt(addr, val, "<h", isemu)

    def seti8(self, addr, val, isemu=False):
        self.setfmt(addr, val, "<b", isemu)

    def getCStr(self, addr, isemu=False):
        mem = bytearray()
        while True:
            if not self.inBounds(addr, 1):
                raise MemoryError("Tried to read a CStr out of bounds")
            c = self.getMemVal(addr, 1, isemu)[0]
            if c == 0:
                break
            addr += 1

            mem.append(c)
        return bytes(mem)

    def getCWStr(self, addr, isemu=False):
        mem = bytearray()
        while True:
            if not self.inBounds(addr, 2):
                raise MemoryError("Tried to read a CWStr out of bounds")
            c = self.getMemVal(addr, 2, isemu)
            if c == b'\x00\x00':
                break
            addr += 2

            mem.append(c)
        return bytes(mem)

    def disass(self, addr=-1, count=16, isemu=False):
        if addr == -1:
            addr = self.getRegVal(self.api.registers.rip, isemu)
        #TODO
        raise NotImplementedError("TODO")

    def getRegVal(self, reg, isemu=False):
        if isemu:
            return self.emu.reg_read(self.regtrans[reg])
        else:
            return self.api.getConcreteRegisterValue(reg)

    def setRegVal(self, reg, val, isemu=False):
        if isemu:
            self.emu.reg_write(self.regtrans[reg], val)
        else:
            self.api.setConcreteRegisterValue(reg, val)

    def getMemVal(self, addr, amt, isemu=False):
        if isemu:
            return self.emu.mem_read(addr, amt)
        else:
            return self.api.getConcreteMemoryAreaValue(addr, amt)

    def getRegMemVal(self, reg, amt, isemu=False):
        addr = self.getRegVal(reg, isemu)
        return self.getMemVal(addr, amt, isemu)

    def setMemVal(self, addr, val, isemu=False):
        if isemu:
            self.emu.mem_write(addr, bytes(val))
        else:
            self.api.setConcreteMemoryAreaValue(addr, val)

    def setRegMemVal(self, reg, amt, isemu=False):
        addr = self.getRegVal(reg, isemu)
        self.setMemVal(addr, val, isemu)

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
        # Use after using setSymbol
        #TODO use hasUnsetSym to see if it is okay
        if self.api.isRegisterSymbolized(reg):
            val = self.api.getSymbolicRegisterValue(reg)
            self.api.setConcreteRegisterValue(reg, val)

    def evalMem(self, addr, size):
        # Use after using setSymbol
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
                else:
                    print(f"Warning: PE Loading: Unhandled relocation type {re.type}")

        # setup exception handlers
        # actually, we check exception handlers at runtime, in case they change under us

        # symbolize imports
        for i in pe.imports:
            for ie in i.entries:
                # extend the API HOOKS execution hook 
                hookaddr = self.apihooks.end
                self.apihooks.end += 8
                self.setu64(base + ie.iat_address, hookaddr)

                name = i.name + "::" + ie.name
                # create symbolic entry in the, if the address is used strangly
                # really this hook should be in the IAT, if the entry is a pointer to something bigger than 8 bytes
                #TODO
                # but for now, we just assume most of these are functions or pointers to something 8 or less bytes large?
                self.api.symbolizeMemory(MemoryAccess(hookaddr, 8), "IAT val from " + pe.name + " for " + name)

                # create execution hook in hook are
                self.addHook(hookaddr, hookaddr+8, "e", None, False, "IAT entry from " + pe.name + " for " + name, True)

        self.updateBounds(self.apihooks.start, self.apihooks.end)
        
        # annotate symbols from image
        for sym in pe.exported_functions:
            if not sym.name:
                continue
            self.addAnn(sym.address + base, sym.address + base, "SYMBOL", False, pe.name + "::" + sym.name)

        return pe

    def getPEExeHandlers(self, addr):
        # should return a generator that will walk back over exception handlers
        # generator each time returns (filteraddr, handleraddr)
        #TODO
        raise NotImplementedError("Lot to do here")

        # also create an API to setup args for filter/handler, do state save, etc
        #TODO

    def addHook(self, start, end, htype, handler=None, ub=False, label="", andemu=False):
        # handler takes 4 args, (hook, addr, sz, op, isemu)
        # handler returns True to be a breakpoint, False to continue execution
        emuhandler = None
        if andemu == True:
            emuhandler = handler
        elif andemu == "only":
            emuhandler = handler
            handler = None
        if andemu == "nop":
            emuhandler = self.noopemuhook
        h = Hook(start, end, label, handler, emuhandler)
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
    
    def doRet(self, retval=0, isemu=False):
        self.setRegVal(self.api.registers.rax, retval, isemu)
        sp = self.getRegVal(self.api.registers.rsp, isemu)
        retaddr = self.getu64(sp, isemu)
        self.setRegVal(self.api.registers.rip, retaddr, isemu)
        self.setRegVal(self.api.registers.rsp, sp+8, isemu)

    @staticmethod
    def noopemuhook(hook, ctx, addr, sz, op, isemu):
        return HookRet.CONT_INS

    @staticmethod
    def retzerohook(hook, ctx, addr, sz, op, isemu):
        ctx.doRet(0, isemu)
        return HookRet.DONE_INS

    def addVolatileSymHook(name, addr, sz, op, stops=False):
        if op != "r":
            raise TypeError("addVolatileSymHook only works with read hooks")
        
        ma = MemoryAccess(addr, sz)
        hit_count = 0
        def vshook(hook, ctx, addr, sz, op, isemu):
            if isemu:
                return HookRet.STOP_INS if stops else HookRet.CONT_INS
            
            nonlocal hit_count
            # create a new symbol for every hit
            ctx.api.symbolizeMemory(ma, name+hex(hit_count))
            hit_count += 1
            return HookRet.STOP_INS if stops else HookRet.CONT_INS
        
        self.addHook(addr, addr+sz, op, vshook, False, name + "_VolHook", True)

    def createThunkHook(self, symname, pename="", dostop=False):
        symaddr = self.getSym(symname, pename)
        def dothunk(hook, ctx, addr, sz, op, isemu):
            ctx.setRegVal(ctx.api.registers.rip, symaddr, isemu)

            return HookRet.DONE_INS if not dostop else HookRet.STOP_INS
        return dothunk

    def stopNextHook(self, hook, isemu=False):
        oldhandler = hook.handler if not isemu else hook.handler_emu
        def stoponce(hook, ctx, addr, sz, op, isemu):
            if isemu:
                hook.handler_emu = oldhandler
            else:
                hook.handler = oldhandler
            return HookRet.FORCE_STOP_INS
        if isemu:
            hook.handler_emu = stoponce
        else:
            hook.handler = stoponce

    def setApiHandler(self, name, handler, overwrite=False, andemu=False):
        found = [x for x in self.hooks[0] if x.label.endswith("::"+name)]
        if len(found) != 1:
            raise KeyError(f"Found {len(found)} hooks that match that name, unable to set handler")

        hk = found[0]

        doh = True
        if hk.handler is not None:
            if overwrite == "ignore":
                doh = False
            if not overwrite:
                raise KeyError(f"Tried to set a handler for a API hook that already has a set handler")

        if andemu and hk.handler_emu is not None:
            if overwrite == "ignore":
                andemu = False
            if not overwrite:
                raise KeyError(f"Tried to set a handler for a API hook that already has a set handler for em for emu")
                
        if doh:
            hk.handler = handler
        if andemu:
            hk.handler_emu = handler

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
        #TODO keep annotations sorted?
        self.ann.append(ann)
        return ann

    def getSym(self, symname, pename=""):
        # not to be confused with getSymbol, which works on symbolic symbols
        # this works on annotations of type SYMBOL
        symname = pename + "::" + symname
        match = [ x for x in self.ann if x.mtype == "SYMBOL" and x.label.endswith(symname) ]

        if len(match) == 0:
            raise KeyError(f"Unable to find Symbol {symname}")
        if len(match) > 1:
            raise KeyError(f"Found multiple Symbols matching {symname}")

        return match[0].start

    def alloc(self, amt, start=0, label="", roundamt=True, isemu=False):
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

        if isemu:
            # allocate the memory, needs to be rounded
            mapstart = start & (~ (self.pgsz-1))
            mapend = (end + (self.pgsz-1)) & (~ (self.pgsz-1))

            #TODO slow to ask for all regions here?
            reg_i = self.emu.mem_regions()
            for r_beg, r_end, _ in reg_i:
                if mapend < r_beg:
                    break

                if r_beg <= mapstart <= r_end:
                    mapstart = (r_end+1)
                if r_beg < mapend < r_end:
                    mapend = r_beg

            if mapend > mapstart:
                print(hex(start), hex(end), hex(mapstart), hex(mapend))
                self.emu.mem_map(mapstart, mapend-mapstart)

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
        def stack_guard_hook(hk, ctx, addr, sz, op, isemu):
            if isemu:
                #TODO
                raise NotImplementedError("Unimplemented stack growth for emu")
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

        self.addHook(stackstart - (0x1000), stackstart, "w", stack_guard_hook, False, "Stack Guard", True)

        # create end hook
        self.addHook(end, end+1, "e", None, False, "End Hit", True)

        # set initial rip and rsp
        self.api.setConcreteRegisterValue(self.api.registers.rip, start)
        self.api.setConcreteRegisterValue(self.api.registers.rsp, stackbase - 0x100)

        return True

    def startTrace(self, isemu=False):
        if isemu:
            if self.trace_emu is None:
                self.trace_emu = []
        if isemu == "both" or not isemu:
            if self.trace is None:
                self.trace = []

    def stopTrace(self, isemu=False):
        if isemu == "both":
            t = (self.trace_emu, self.trace)
            self.trace_emu = None
            self.trace = None
        elif isemu:
            t = self.trace_emu
            self.trace_emu = None
        else:
            t = self.trace
            self.trace = None

        return t

    def cmpTraces(self):
        # looks like trying to stop execution with ^C can make the trace skip?
        if len(self.trace_emu) != len(self.trace):
            print("Traces len differ. Emu:", len(self.trace_emu), "Symb:", len(self.trace))

        l = min(len(self.trace_emu), len(self.trace))

        differ = False
        for i in range(l):
            emu = self.trace_emu[i]
            symb = self.trace[i]
            if (emu[0] != symb[0]):
                differ = True
                print(f"Traces diverge after {i} instructions (emu @ {hex(emu[0])}, symb @ {hex(symb[0])})")
                break
        if not differ:
            print("Traces match")

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

    def handle_hook(self, hk, addr, sz, op, ignorehook, isemu):
        self.lasthook = hk

        handler = hk.handler
        if isemu:
            handler = hk.handler_emu

        stopret = StepRet.HOOK_EXEC
        if op == "r":
            stopret = StepRet.HOOK_READ
        elif op == "w":
            stopret = StepRet.HOOK_WRITE
        elif op != "e":
            raise TypeError(f"Unknown op to handler hook \"{op}\"")

        if handler is not None:
            hret = handler(hk, self, addr, sz, op, isemu)
            if hret == HookRet.FORCE_STOP_INS:
                return (True, stopret)
            elif hret == HookRet.STOP_INS:
                if not ignorehook:
                    return (True, stopret)
                else:
                    return (False, stopret)
            elif hret == HookRet.CONT_INS:
                return (False, StepRet.OK)
            elif hret == HookRet.DONE_INS:
                # only applies to exec type hooks
                if op != "e":
                    raise TypeError(f"Hook \"{str(hk)}\" returned done, even though the op type is \"{op}\"")
                return (True, StepRet.OK)
            elif hret == HookRet.ERR:
                return (True, StepRet.HOOK_ERR)
            else:
                raise TypeError(f"Unknown return from hook handler for hook {eh}")
        else:
            # no ignoring API hooks with no handler
            if (self.apihooks.start <= addr < self.apihooks.end) or (not ignorehook):
                return (True, stopret)
            else:
                return (False, StepRet.OK)

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

        #TODO add exception raising after possible first_chance stop?

        #TODO enforce page permissions
        if not self.inBounds(rip, ins.getSize()):
            return StepRet.ERR_IP_OOB

        if not self.inBounds(rsp, 8):
            return StepRet.ERR_STACK_OOB

        # check if rip is at a hooked execution location
        for eh in self.hooks[0]:
            if eh.start <= rip < eh.end:
                # hooked
                #TODO multiple hooks at the same location?
                stop, sret = self.handle_hook(eh, rip, 1, "e", ignorehook, False)
                if not stop:
                    break
                return sret

        #TODO handle special instructions that Triton might not capture the way we want
        #TODO rdtsc?

        # check if we are about to do a memory deref of:
        #   a symbolic value
        #   a hooked location (if not ignorehook)
        #   an out of bounds location
        # we can't know beforehand if it is a write or not, so verify after the instruction
        #TODO automatically detect symbolic expressions that are evaluable based on variables we have set
        #TODO enforce page permissions
        for o in ins.getOperands():
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
                    addr &= 0xffffffffffffffff

                if indexregid != 0:
                    scale = o.getScale().getValue()
                    addr += (scale * self.api.getConcreteRegisterValue(indexreg))
                    addr &= 0xffffffffffffffff

                disp = o.getDisplacement().getValue()
                addr += disp
                addr &= 0xffffffffffffffff
                size = o.getSize()

                # check access is in bounds
                if not self.inBounds(addr, size):
                    print("DEBUG: oob dref at", hex(addr))
                    return StepRet.DREF_OOB

                # check if access is hooked
                for rh in self.hooks[1]:
                    if rh.start <= addr < rh.end:
                        # hooked
                        #TODO multiple hooks at the same location?
                        stop, sret = self.handle_hook(rh, addr, size, "r", ignorehook, False)
                        if not stop:
                            break
                        return sret
                    #TODO check write hooks

        #TODO check ins.isSymbolized?

        # actually do a step
        #TODO how do we detect exceptions like divide by zero?
        # triton just lets divide by zero through
        if not self.api.processing(ins):
            return StepRet.BAD_INS

        self.inscount += 1

        if self.trace is not None:
            addr = ins.getAddress()
            if len(self.trace) == 0 or self.trace[-1][0] != addr:
                self.trace.append((addr, ins.getDisassembly()))

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
        #TODO undo write if need to?
        if ins.isMemoryWrite():
            #TODO enforce page permissions
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

    def cont(self, ignoreFirst=True, n=0):
        n -= 1
        if ignoreFirst:
            ret = self.step(True)
            if ret != StepRet.OK:
                return ret
            n -= 1
        while n != 0:
            ret = self.step(False)
            if ret != StepRet.OK:
                return ret
            n -= 1

    def until(self, addr, ignoreFirst=True):
        ret = StepRet.OK
        if ignoreFirst:
            ret = self.step(True)
            if ret != StepRet.OK:
                return ret

        while True:
            ripreg = self.api.registers.rip
            rip = self.api.getConcreteRegisterValue(ripreg)
            if rip == addr:
                break

            ret = self.step(False)
            if ret != StepRet.OK:
                break

        return ret
    
    def next(self, ignoreFirst=True):
        # this is just an until next ins if cur ins is call
        i = self.getNextIns()
        if i.getDisassembly().startswith("call "):
            na = i.getNextAddress()
            return self.until(na, ignoreFirst)

        return self.step(ignoreFirst)

    def emu_insHook(self, emu, addr, sz, user_data):
        if self.printIns:
            print('@', hex(addr))

        if self.trystop_emu:
            print("In instruction hook when we wanted to stop!")
            emu.emu_stop()

        # this hook could happen even if we are not about to execute this instruction
        # it happens before we are stopped
        ignorehook = (addr == self.ignorehookaddr_emu)
        try:
            for eh in self.hooks[0]:
                if eh.start <= addr < eh.end:
                    # hooked
                    stop, sret = self.handle_hook(eh, addr, 1, "e", ignorehook, True)
                    if not stop:
                        break
                    if sret == StepRet.OK:
                        return
                    self.stepret_emu = sret
                    emu.emu_stop()
                    self.trystop_emu = True
                    return
        except Exception as e:
            print("Stopping emulation, exception occured during insHook:", e)
            self.stepret_emu = StepRet.ERR
            emu.emu_stop()
            self.trystop_emu = True
            raise e

        if self.trace_emu is not None:
            if len(self.trace_emu) == 0 or self.trace_emu[-1][0] != addr:
                self.trace_emu.append((addr,))

        #TODO this will go up too much because we get called to much, can we fix that?
        self.inscount_emu += 1

    def emu_rwHook(self, emu, access, addr, sz, val, user_data):
        if self.trystop_emu:
            print("In memory hook when we wanted to stop!")
            emu.emu_stop()

        #TODO why can't I read registers from here?
        try:
            # handle read / write hooks
            op = "r"
            if access == UC_MEM_WRITE:
                op = "w"
            
            if op == "r":
                for rh in self.hooks[1]:
                    if rh.start <= addr < rh.end:
                        # hooked
                        stop, sret = self.handle_hook(rh, addr, sz, "r", False, True)
                        if not stop:
                            break
                        self.stepret_emu = sret
                        emu.emu_stop()
                        self.trystop_emu = True
                        return
            elif op == "w":
                for wh in self.hooks[2]:
                    if wh.start <= addr < wh.end:
                        # hooked
                        stop, sret = self.handle_hook(wh, addr, sz, "w", False, True)
                        if not stop:
                            break
                        self.stepret_emu = sret
                        emu.emu_stop()
                        self.trystop_emu = True
                        return
        except Exception as e:
            print("Stopping emulation, exception occured during rwHook:", e)
            self.stepret_emu = StepRet.ERR
            emu.emu_stop()
            self.trystop_emu = True
            raise e

    def emu_invalMemHook(self, emu, access, addr, sz, val, user_data):
        if self.trystop_emu:
            print("In invalid memory hook when we wanted to stop!")
            emu.emu_stop()
        ret = False
        #TODO why can't I read registers from here?
        try: 
            # handle read / write hooks
            op = "r"
            if access == UC_MEM_WRITE:
                op = "w"
            
            if op == "r":
                for rh in self.hooks[1]:
                    if rh.start <= addr < rh.end:
                        # hooked
                        stop, sret = self.handle_hook(rh, addr, sz, "r", False, True)
                        if not stop:
                            ret = True
                            break
                        self.stepret_emu = sret
                        emu.emu_stop()
                        self.trystop_emu = True
                        return ret
            elif op == "w":
                for wh in self.hooks[2]:
                    if wh.start <= addr < wh.end:
                        # hooked
                        stop, sret = self.handle_hook(wh, addr, sz, "w", False, True)
                        if not stop:
                            ret = True
                            break
                        self.stepret_emu = sret
                        emu.emu_stop()
                        self.trystop_emu = True
                        return ret

            # if no hooks handle it
            self.stepret_emu = StepRet.DREF_OOB
        except Exception as e:
            print("Stopping emulation, exception occured during invalMemHook:", e)
            self.stepret_emu = StepRet.ERR
            ret = False
        return ret

    def emu_invalInsHook(self, emu, user_data):
        self.stepret_emu = StepRet.BAD_INS
        return False

    def emu_intrHook(self, emu, intno, user_data):
        self.stepret_emu = StepRet.INTR
        self.intrnum_emu = intno
        emu.emu_stop()
        self.trystop_emu = True
    
    def copyRegToEmu(self):
        # use self.regemu dictionary
        for k in self.regtrans:
            val = self.api.getConcreteRegisterValue(k)
            self.emu.reg_write(self.regtrans[k], val)

    def copyStateToEmu(self):
        self.emu = None
        self.emu = Uc(UC_ARCH_X86, UC_MODE_64)

        # copy over memory
        lastaddr = 0
        for b in self.bounds:
            # round to page boundries?
            start = b[0] & (~ (self.pgsz-1))
            if lastaddr > start:
                start = lastaddr
            end = (b[1] + (self.pgsz-1)) & (~ (self.pgsz-1))
            lastaddr = end
            sz = end - start
            self.emu.mem_map(start, sz)

            mem = self.api.getConcreteMemoryAreaValue(b[0], b[1]-b[0])
            self.emu.mem_write(b[0], mem)

        # set memory permissions
        #TODO

        # copy over registers
        self.copyRegToEmu()
        
        # set up for hooks
        # hook every instruction
        self.emu.hook_add(UC_HOOK_CODE, self.emu_insHook, None, 0, 0xffffffffffffffff)
        # hook read/write
        self.emu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.emu_rwHook, None)
        # hook invalid stuff
        self.emu.hook_add(UC_HOOK_MEM_INVALID, self.emu_invalMemHook, None)
        self.emu.hook_add(UC_HOOK_INSN_INVALID, self.emu_invalInsHook, None)
        self.emu.hook_add(UC_HOOK_INTR, self.emu_intrHook, None)

    def step_emu(self, ignoreFirst=True):
        if self.emu == None:
            print("Emu is not initalized")
            return

        self.stepret_emu = StepRet.OK
        stat = None
        self.trystop_emu = False

        addr = self.emu.reg_read(UC_X86_REG_RIP)

        self.ignorehookaddr_emu = -1
        if ignoreFirst:
            self.ignorehookaddr_emu = addr

        try:
            self.emu.emu_start(addr, 0xffffffffffffffff, 0, 1)
        except UcError as e:
            stat = e

        return (self.stepret_emu, stat)

    def cont_emu(self, ignoreFirst=True, n=0):
        if self.emu == None:
            print("Emu is not initalized")
            return

        self.stepret_emu = StepRet.OK
        addr = self.emu.reg_read(UC_X86_REG_RIP)
        stat = None
        self.trystop_emu = False

        self.ignorehookaddr_emu = -1
        if ignoreFirst:
            self.ignorehookaddr_emu = addr

        try:
            self.emu.emu_start(addr, 0xffffffffffffffff, 0, n)
        except UcError as e:
            stat = e

        return (self.stepret_emu, stat)

    def until_emu(self, until, ignoreFirst=True):
        if self.emu == None:
            print("Emu is not initalized")
            return

        self.stepret_emu = StepRet.OK
        stat = None
        self.trystop_emu = False

        addr = self.emu.reg_read(UC_X86_REG_RIP)

        self.ignorehookaddr_emu = -1
        if ignoreFirst:
            self.ignorehookaddr_emu = addr

        try:
            self.emu.emu_start(addr, until, 0, 0)
        except UcError as e:
            stat = e

        return (self.stepret_emu, stat)

    def next_emu(self, ignoreFirst=True):
        if self.emu == None:
            print("Emu is not initalized")
            return

        self.stepret_emu = StepRet.OK
        stat = None
        self.trystop_emu = False

        addr = self.emu.reg_read(UC_X86_REG_RIP)

        self.ignorehookaddr_emu = -1
        if ignoreFirst:
            self.ignorehookaddr_emu = addr

        raise NotImplementedError("TODO")


# utility helper functions and stuff

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

def taboutast(h, ta=2, hexify=True, maxline=90):
    if hexify:
        h = ' '.join(['bv'+hex(int(x[2:])) if x.startswith('bv') else x for x in h.split()])

    out = ""
    tc = ' '
    tb = tc * ta
    tl = 0
    i = 0
    while i < len(h):
        assert tl >= 0
        c = h[i]
        if c == '(':
            tl += 1
            assert i+1 < len(h)
            cn = h[i+1]
            end = -1
            # first check if the () of this one will fit in this line
            
            depth = 0
            ii = i+1
            didline = False
            while True:
                cl = h.find(')', ii)
                op = h.find('(', ii)

                assert cl != -1

                if (cl - i) > maxline:
                    break
                
                if op == -1 or cl < op:
                    if depth <= 0:
                        # at end
                        end = cl
                        break
                    else:
                        depth -= 1
                        ii = cl+1
                else:
                    depth += 1
                    ii = op+1

            #DEBUG
            #end = -1

            if end != -1:
                tl -= 1
 
            # otherwise if it starts with a (_ grab that as the op
            elif cn == '(':
                assert h[i+2] == '_'
                # print all of this (group) before newline
                end = h.find(')', i)
                assert end != -1
                check = h.find('(', i+2)
                assert check == -1 or check > end
            # otherwise grab the op
            else:
                end = h.find(' ', i)
                assert end != -1
                end = end-1

            out += h[i:end+1]
            i = end
            
            out += '\n' + (tb * tl)
            while (i+1) < len(h) and h[i+1] == ' ':
                i += 1
        elif c == ')':
            tl -= 1
            if len(out) > 0 and out[-1] != tc:
                out += '\n' + (tb * tl)
            else:
                # they tabbed us too much
                out = out[:0 - len(tb)]
            out += c
            out += '\n' + (tb * tl)
            while (i+1) < len(h) and h[i+1] == ' ':
                i += 1
        elif c == ' ':
            out += '\n' + (tb * tl)
            while (i+1) < len(h) and h[i+1] == ' ':
                i += 1
        else:
            out += c
        
        i += 1

    return out


x64KeyRegs = [
    'cr0',
    'cr1',
    'cr10',
    'cr11',
    'cr12',
    'cr13',
    'cr14',
    'cr15',
    'cr2',
    'cr3',
    'cr4',
    'cr5',
    'cr6',
    'cr7',
    'cr8',
    'cr9',
    'cs',
    'dr0',
    'dr1',
    'dr2',
    'dr3',
    'dr6',
    'dr7',
    'ds',
    'eflags',
    'es',
    'fs',
    'gs',
    'mm0',
    'mm1',
    'mm2',
    'mm3',
    'mm4',
    'mm5',
    'mm6',
    'mm7',
    'mxcsr',
    'r10',
    'r11',
    'r12',
    'r13',
    'r14',
    'r15',
    'r8',
    'r9',
    'rax',
    'rbp',
    'rbx',
    'rcx',
    'rdi',
    'rdx',
    'rip',
    'rsi',
    'rsp',
    'ss',
    'zmm0',
    'zmm1',
    'zmm10',
    'zmm11',
    'zmm12',
    'zmm13',
    'zmm14',
    'zmm15',
    'zmm16',
    'zmm17',
    'zmm18',
    'zmm19',
    'zmm2',
    'zmm20',
    'zmm21',
    'zmm22',
    'zmm23',
    'zmm24',
    'zmm25',
    'zmm26',
    'zmm27',
    'zmm28',
    'zmm29',
    'zmm3',
    'zmm30',
    'zmm31',
    'zmm4',
    'zmm5',
    'zmm6',
    'zmm7',
    'zmm8',
    'zmm9',
]
