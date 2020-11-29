from .dobby_const import *
from .dobby_types import *
import os
import lief
import json
import struct
import string
import pickle

class Dobby:
    """
    This Dobby class holds only global state
    All real state is held by the providers themselves
    And transfered in snapshots
    """
    def __init__(self):
        print("🤘 Starting Dobby 🤘")
        self.systemtimestart = 0x1d68ce74d7e4519
        self.IPC = 16 # instructions / Cycle
        self.CPN = 3.2  # GigaCycles / Second == Cycles / Nanosecond
        self.IPN = self.IPC * self.CPN * 100 # instructions per 100nanosecond
        self.printIns = True

        # setup values for active providers
        self.isemu = False
        self.issym = False
        self.isreg = False
        self.ismem = False
        self.issnp = False
        self.active = None
        self.providers = []

        self.snapshots = {}

        # for now just support x86
        self.spreg = DB_X86_R_RSP
        self.ipreg = DB_X86_R_RIP
        self.pgshft = DB_X86_PGSHFT
        self.pgsz = DB_X86_PGSZ
        self.name2reg = x86name2reg
        self.reg2name = x86reg2name

        #TODO automatically register providers here?

    def registerProvider(self, provider, name, activate):
        if provider in self.providers:
            print(f"Provider {name} is already registered")
            return
        print(f"Registering provider {name}")
        self.providers.append(provider)
        
        if activate:
            if self.active is not None:
                print("Warning, deactivating previous provider")
                self.deactivateProvider()
            self.activateProvider(provider)

    def activateProvider(self, provider):
        if self.active == provider:
            return
        if self.active is not None:
            self.deactivateProvider()
        self.active = provider
        self.isemu = provider.isEmuProvider
        self.issym = provider.isSymProvider
        self.isreg = provider.isRegContextProvider
        self.ismem = provider.isMemoryProvider
        self.issnp = provider.isSnapshotProvider

        self.active.activated()

    def deactivateProvider(self):
        if self.active is not None:
            self.active.deactivated()

        self.active = None
        self.isemu = False
        self.issym = False
        self.isreg = False
        self.ismem = False
        self.issnp = False

    def removeProvider(self, provider):
        if self.active == provider:
            deactivateProvider()

        self.providers.remove(provider)

        provider.removed()

    def getProvider(self, nameprefix):
        found = None
        for p in self.providers:
            if p.getName().lower().startswith(nameprefix.lower()):
                if found is not None:
                    raise KeyError(f"Multiple providers start with \"{nameprefix}\"")
                found = p
        if found is not None:
            return found
        raise KeyError(f"No active provider that starts with \"{nameprefix}\"")

    def setProvider(self, nameprefix):
        p = self.getProvider(nameprefix)
        self.activateProvider(p)

    def delProvider(self, nameprefix):
        p = self.getProvider(nameprefix)
        removeProvider(p)

    def perm2Str(self, p):
        s = ""
        if p & MEM_READ:
            s += "r"
        if p & MEM_WRITE:
            s += "w"
        if p & MEM_EXECUTE:
            s += "x"
        return s

    def printBounds(self):
        for b in self.getBoundsRegions(True):
            print(hex(b[0])[2:].zfill(16), '-', hex(b[1])[2:].zfill(16), self.perm2Str(b[2]))

    def printAst(self, ast):
        if not self.issym:
            raise RuntimeError("No symbolic providers are active")
        self.active.printAst(ast)

    def printReg(self, reg):
        print(self.getRegName(reg), end=" = ")

        if self.issym and self.isSymbolizedRegister(reg):
            ast = self.getRegisterAst(reg)
            self.printAst(ast)
        else:
            # concrete value
            print(hex(self.getRegVal(reg)))

    def ip(self):
        self.getRegVal(self.ipreg)

    def printSymMem(self, addr, amt, stride):
        if not self.issym:
            raise RuntimeError("No symbolic providers are active")
        if not self.inBounds(addr, amt, MEM_NONE):
            print("Warning, OOB memory")
        for i in range(0, amt, stride):
            memast = self.getMemoryAst(addr+i, stride)
            print(hex(addr+i)[2:].zfill(16), end=":  ")
            self.printAst(memast)

    def printMem(self, addr, amt=0x60):
        if not self.inBounds(addr, amt, MEM_NONE):
            print("Warning, OOB memory")
        # read symbolic memory too
        if self.issym and self.isSymbolizedMemory(addr, amt):
            print("Warning, contains symbolized memory")
            self.printSymMem(addr, amt, 8, simp)
        else:
            mem = self.getMemVal(addr, amt)
            hexdmp(mem, addr)

    def printRegMem(self, reg, amt=0x60):
        # dref register, if not symbolic and call printMem
        if self.issym and self.isSymbolizedRegister(reg):
            print("Symbolic Register")
            self.printReg(reg)
        else:
            addr = self.getRegVal(reg)
            self.printMem(addr, amt)

    def printStack(self, amt=0x60):
        self.printRegMem(self.spreg, amt)

    def printQMem(self, addr, amt=12):
        if not self.inBounds(addr, amt*8, MEM_NONE):
            print("Warning, OOB memory")
        for i in range(amt):
            a = addr + (8*i)
            v = self.getu64(a)
            print(hex(a)[2:]+':', hex(v)[2:])

    def printMap(self):
        mp = [ x for x in self.active.ann if (x.end - x.start) != 0 ]
        mp.sort(key = lambda x: x.start)

        # add bounds areas not covered by ann
        for p in self.active.bounds:
            covered = False
            # if b is not contained by any annotation save it
            s = p << self.pgshft
            e = s + self.pgsz
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
        return struct.unpack(fmt, self.getMemVal(addr, sz))[0]

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
        self.setMemVal(addr, struct.pack(fmt, val))

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
            if not self.inBounds(addr, 1, MEM_READ):
                raise MemoryError("Tried to read a CStr out of bounds")
            c = self.getMemVal(addr, 1)[0]
            if c == 0:
                break
            addr += 1

            mem.append(c)
        return bytes(mem)

    def getCWStr(self, addr):
        mem = bytearray()
        while True:
            if not self.inBounds(addr, 2, MEM_READ):
                raise MemoryError("Tried to read a CWStr out of bounds")
            c = self.getMemVal(addr, 2)
            if c == b'\x00\x00':
                break
            addr += 2
            mem += c
        return str(bytes(mem), "UTF_16_LE")

    def disass(self, addr=-1, count=16):
        if not self.ismem:
            raise RuntimeError("No memory providers are active")
        return self.active.disass(addr, count)

    def getInsLen(self, addr=-1):
        if not self.ismem:
            raise RuntimeError("No memory providers are active")
        return self.active.getInsLen(addr)

    def nameToReg(self, name):
        name = name.lower()
        if name not in self.name2reg:
            raise KeyError(f"{name} is not a valid register name")
        return self.name2reg[name]

    def getRegName(self, reg):
        return self.reg2name[reg]

    def getAllReg(self):
        if not self.isreg:
            raise RuntimeError("No Register providers are active")
        return self.active.getAllRegisters()

    def getRegVal(self, reg, *, allowsymb=False):
        if not self.isreg:
            raise RuntimeError("No register providers are active")

        if self.issym and not allowsymb and self.isSymbolizedRegister(reg):
            raise ValueError("Tried to get concrete value for a symbolic register")

        return self.active.getRegVal(reg)

    def setRegVal(self, reg, val):
        if not self.isreg:
            raise RuntimeError("No register providers are active")

        self.active.setRegVal(reg, val)

    def getMemVal(self, addr, amt, *, allowsymb=False):
        if not self.ismem:
            raise RuntimeError("No memory providers are active")

        if self.issym and not allowsymb and self.isSymbolizedMemory(addr, amt):
            raise ValueError("Tried to get concrete value for a symbolic region of memory")

        return self.active.getMemVal(addr, amt)

    def getRegMemVal(self, reg, amt):
        addr = self.getRegVal(reg)
        return self.getMemVal(addr, amt)

    def setMemVal(self, addr, val):
        if not self.ismem:
            raise RuntimeError("No memory providers are active")

        self.active.setMemVal(addr, val)

    def setRegMemVal(self, reg, amt):
        addr = self.getRegVal(reg)
        self.setMemVal(addr, val)

    def getInsCount(self):
        if not self.isemu:
            raise RuntimeError("No emulation providers are active")

        return self.active.getInsCount()

    def getCycles(self):
        # returns number of cycles like rdtsc would
        return int(self.getInsCount() // self.IPC)

    def getTicks(self):
        # turns cycles into 100ns ticks
        return int(self.getCycles() // self.IPN)

    def getTime(self):
        # uses getTicks and base time to get a timestamp
        # 100ns res (/ 10000 to get milliseconds)
        return self.getTicks() + self.systemtimestart

    def trySymbolizeRegister(self, reg, name):
        if self.issym:
            self.symbolizeRegister(reg, name)

    def symbolizeRegister(self, reg, name):
        if not self.issym:
            raise RuntimeError("No symbolic providers are active")
        self.active.symbolizeRegister(reg, name)

    def trySymbolizeMemory(self, addr, size, name):
        if self.issym:
            self.symbolizeMemory(addr, size, name)

    def symbolizeMemory(self, addr, size, name):
        if not self.issym:
            raise RuntimeError("No symbolic providers are active")
        self.active.symbolizeMemory(addr, size, name)

    def isSymbolizedRegister(self, reg):
        if not self.issym:
            raise RuntimeError("No symbolic providers are active")
        return self.active.isSymbolizedRegister(reg)

    def isSymbolizedMemory(self, addr, size):
        if not self.issym:
            raise RuntimeError("No symbolic providers are active")
        return self.active.isSymbolizedMemory(addr, size)

    def getSymbol(self, symname):
        if not self.issym:
            raise RuntimeError("No symbolic providers are active")
        return self.active.getSymbol(symname)

    def setSymbolVal(self, sym, value, overwrite=False):
        if not self.issym:
            raise RuntimeError("No symbolic providers are active")
        return self.active.setSymbolVal(syn, value, overwrite)

    def getRegUnsetSym(self, reg, single=True, allSym=False):
        ast = self.getRegisterAst(reg)
        return self.getUnsetSym(ast, single, allSym)

    def getUnsetSym(self, ast, single=True, allSym=False, followRef=True):
        if not self.issym:
            raise RuntimeError("No symbolic providers are active")
        return self.active.getUnsetSym(ast, single, allSym, followRef)

    def getUnsetCount(self):
        if not self.issym:
            raise RuntimeError("No symbolic providers are active")
        return self.active.getUnsetCount()

    def printUnsetCount(self):
        print(self.getUnsetCount())

    def evalReg(self, reg, checkUnset=True):
        if not self.issym:
            raise RuntimeError("No symbolic providers are active")
        return self.active.evalReg(reg, checkUnset)

    def evalMem(self, addr, size, checkUnset=True):
        if not self.issym:
            raise RuntimeError("No symbolic providers are active")
        return self.active.evalMem(addr, size, checkUnset)

    def loadPE(self, path, base, again=False, failwarn=True):
        pe = lief.parse(path)
        if pe is None:
            raise FileNotFoundError(f"Unable to parse file {path}")

        if not again and pe.name in [ x.name for x in self.active.modules ]:
            raise KeyError(f"PE with name {pe.name} already loaded")

        # get size, check base doesn't crush existing area
        end = base
        for phdr in pe.sections:
            e = base + phdr.virtual_address + phdr.virtual_size
            if e > end:
                end = e

        if self.inBounds(base, end - base, MEM_NONE):
            raise MemoryError(f"Could not load pe {pe.name} at {hex(base)}, because it would clobber existing memory")

        self.active.modules.append(pe)

        dif = base - pe.optional_header.imagebase

        # load concrete mem vals from image
        # we need to load in header as well
        rawhdr = b""
        with open(path, "rb") as fp:
            rawhdr = fp.read(pe.sizeof_headers)
        roundedlen = (len(rawhdr) + (self.pgsz-1)) & (~(self.pgsz-1))

        self.updateBounds(base, base+roundedlen, MEM_READ, False)
        self.setMemVal(base, rawhdr)

        self.addAnn(base, base+len(rawhdr), "MAPPED_PE_HDR", pe.name)

        for phdr in pe.sections:
            start = base + phdr.virtual_address
            end = start + len(phdr.content)

            if (end - start) < phdr.virtual_size:
                end = start + phdr.virtual_size

            # round end up to page size
            end = (end + 0xfff) & (~0xfff)

            #annotate the memory region
            self.addAnn(start, end, "MAPPED_PE", pe.name + '(' + phdr.name + ')')
            perm = MEM_NONE
            if phdr.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
                perm |= MEM_EXECUTE
            if phdr.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_READ):
                perm |= MEM_READ
            if phdr.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):
                perm |= MEM_WRITE

            self.updateBounds(start, end, perm, False)
            self.setMemVal(start, phdr.content)

        # do reloactions
        for r in pe.relocations:
            lastabs = False
            for re in r.entries:
                if lastabs:
                    # huh, it wasn't the last one?
                    print(f"Warning, got a ABS relocation that wasn't the last one")
                    if failwarn:
                        raise ReferenceError("Bad relocation")
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
                    if failwarn:
                        raise ReferenceError("Bad relocation")

        # setup exception handlers
        # actually, we check exception handlers at runtime, in case they change under us

        # symbolize imports
        for i in pe.imports:
            for ie in i.entries:
                # extend the API HOOKS execution hook 
                hookaddr = self.active.apihooks.end
                self.active.apihooks.end += 8
                self.setu64(base + ie.iat_address, hookaddr)

                name = i.name + "::" + ie.name
                # create symbolic entry in the, if the address is used strangly
                # really this hook should be in the IAT, if the entry is a pointer to something bigger than 8 bytes
                #TODO
                # but for now, we just assume most of these are functions or pointers to something 8 or less bytes large?
                if self.issym:
                    self.symbolizeMemory(hookaddr, 8, "IAT val from " + pe.name + " for " + name)

                # create execution hook in hook are
                h = self.addHook(hookaddr, hookaddr+8, MEM_EXECUTE, None, "IAT entry from " + pe.name + " for " + name)
                h.isApiHook = True

        self.updateBounds(self.active.apihooks.start, self.active.apihooks.end, MEM_ALL, False)

        # annotate symbols from image
        for sym in pe.exported_functions:
            if not sym.name:
                continue
            self.addAnn(sym.address + base, sym.address + base, "SYMBOL", pe.name + "::" + sym.name)

        return pe

    def getExceptionHandlers(self, addr):
        # should return a generator that will walk back over exception handlers
        # generator each time returns (filteraddr, handleraddr)
        #TODO
        raise NotImplementedError("Lot to do here")

        # also create an API to setup args for filter/handler, do state save, etc
        #TODO

    def addHook(self, start, end, htype, handler=None, label=""):
        # handler takes 4 args, (hook, addr, sz, op, provider)
        # handler returns a HookRet code that determines how to procede
        if (htype & MEM_ALL) == 0:
            raise ValueError("Hook didn't specify a proper type")

        h = Hook(start, end, htype, label, handler)

        added = False
        if (htype & MEM_ALL) == 0:
            raise ValueError(f"Unknown Hook Type {htype}")

        if (htype & MEM_EXECUTE) != 0:
            added = True
            self.active.hooks[0].append(h)
        if (htype & MEM_READ) != 0:
            added = True
            self.active.hooks[1].append(h)
        if (htype & MEM_WRITE) != 0:
            added = True
            self.active.hooks[2].append(h)

        if self.isemu:
            self.active.insertHook(h)
        else:
            print("Warning, added a hook without a emulation provider active")

        return h

    def bp(self, addr):
        self.addHook(addr, addr+1, MEM_EXECUTE, None, "breakpoint")

    def delHook(self, hook, htype=MEM_ALL):
        if self.isemu:
            self.active.removeHook(hook)

        if (htype & MEM_EXECUTE) != 0 and hook in self.active.hooks[0]:
            self.active.hooks[0].remove(hook)
        if (htype & MEM_READ) != 0 and hook in self.active.hooks[1]:
            self.active.hooks[1].remove(hook)
        if (htype & MEM_WRITE) != 0 and hook in self.active.hooks[2]:
            self.active.hooks[2].remove(hook)

    def doRet(self, retval=0):
        self.setRegVal(DB_X86_R_RAX, retval)
        sp = self.getRegVal(self.spreg)
        retaddr = self.getu64(sp)
        self.setRegVal(self.ipreg, retaddr)
        self.setRegVal(self.spreg, sp+8)

    @staticmethod
    def noopemuhook(hook, ctx, addr, sz, op, provider):
        return HookRet.CONT_INS

    @staticmethod
    def retzerohook(hook, ctx, addr, sz, op, provider):
        ctx.doRet(0)
        return HookRet.DONE_INS

    @staticmethod
    def stack_guard_hook(hk, ctx, addr, sz, op, provider):
        if ctx.active.stackann is None:
            raise RuntimeError("No stack was initalized")
        # grow the stack, if we can
        newstart = ctx.stackann.start - 0x1000
        if ctx.inBounds(newstart, 0x1000, MEM_NONE):
            # error, stack ran into something else
            print(f"Stack overflow! Stack with top at {stackann.start} could not grow")
            return True

        # grow annotation
        ctx.stackann.start = newstart
        # grow bounds
        ctx.updateBounds(newstart, ctx.stackann[1], MEM_READ | MEM_WRITE, provider)
        # move the hook
        hk.start = newstart - 0x1000
        hk.end = newstart
        return False


    def addVolatileSymHook(name, addr, sz, op, stops=False):
        if op != MEM_READ:
            raise TypeError("addVolatileSymHook only works with read hooks")

        if not self.issym:
            raise RuntimeError("No symbolic providers are active")

        hit_count = 0
        def vshook(hook, ctx, addr, sz, op, provider):
            nonlocal hit_count
            # create a new symbol for every hit
            ctx.symbolizeMemory(addr, sz, name+hex(hit_count))
            hit_count += 1
            return HookRet.OP_CONT_INS

        self.addHook(addr, addr+sz, op, vshook, name + "_VolHook")

    def createThunkHook(self, symname, pename="", dostop=False):
        symaddr = self.getImageSymbol(symname, pename)
        def dothunk(hook, ctx, addr, sz, op, provider):
            ctx.setRegVal(ctx.ipreg, symaddr)
            return HookRet.OP_DONE_INS
        return dothunk

    def stopNextHook(self, hook, count=1):
        oldhandler = hook.handler
        def stoponce(hook, ctx, addr, sz, op, provider):
            nonlocal count
            if count <= 1:
                hook.handler = oldhandler
                return HookRet.FORCE_STOP_INS
            else:
                count -= 1
                return oldhandler(hook, ctx, addr, sz, op, provider)
        hook.handler = stoponce

    def setApiHandler(self, name, handler, overwrite=False):
        if not self.isemu:
            raise RuntimeError("No emulation providers are active")

        found = [x for x in self.active.hooks[0] if x.isApiHook and x.label.endswith("::"+name) and 0 != (x.htype & MEM_EXECUTE)]

        if len(found) != 1:
            raise KeyError(f"Found {len(found)} hooks that match that name, unable to set handler")

        hk = found[0]

        doh = True
        if hk.handler is not None and not overwrite:
            raise KeyError(f"Tried to set a handler for a API hook that already has a set handler")

        hk.handler = handler

    @staticmethod
    def rdtscHook(ctx, addr, provider):
        cycles = ctx.getCycles()
        newrip = ctx.getRegVal(ctx.ipreg) + 2
        ctx.setRegVal(ctx.ipreg, newrip)
        aval = cycles & 0xffffffff
        dval = (cycles >> 32) & 0xffffffff
        ctx.setRegVal(DB_X86_R_RAX, aval)
        ctx.setRegVal(DB_X86_R_RDX, dval)
        return HookRet.DONE_INS

    def updateBounds(self, start, end, permissions, overrule=False):
        if end <= start:
            raise ValueError("Tried to UpdateBounds with end <= start")

        startshft = start >> self.pgshft
        startcountshft = startshft
        endshft = (end + (self.pgsz-1)) >> self.pgshft
        while startshft < endshft:
            if startshft not in self.active.bounds:
                self.active.bounds[startshft] = permissions
            else:
                existingperm = self.active.bounds[startshft]
                if not overrule and permissions != existingperm:
                    raise MemoryError(f"Tried to update bounds with permissions {permissions} when they were already {self.active.bounds[start]}")
                elif permissions == existingperm and startcountshft == startshft:
                    startcountshft += 1
            startshft += 1

        # call the providers
        if self.ismem and startcountshft != endshft:
            rndstart = startcountshft << self.pgshft
            rndend = endshft << self.pgshft
            self.active.updateBounds(rndstart, rndend, permissions)

    def inBounds(self, addr, sz, access):
        start = addr >> self.pgshft
        sz = (sz + (self.pgsz-1)) >> self.pgshft
        end = (start + sz)

        while start < end:
            if start not in self.active.bounds:
                return False
            if access != (access & self.active.bounds[start]):
                print("DEBUG Violated Memory Permissions?")
                return False
            start += 1
        return True

    def getBoundsRegions(self, withPerm=False):
        out = []
        curp = MEM_NONE
        start = 0
        last = -1
        for p in sorted(self.active.bounds):
            if last == -1:
                start = p
                curp = self.active.bounds[p]
            elif p > (last+1) or (withPerm and curp != self.active.bounds[p]):
                if withPerm:
                    out.append((start << self.pgshft, (last+1) << self.pgshft, curp))
                else:
                    out.append((start << self.pgshft, (last+1) << self.pgshft))
                start = p
                curp = self.active.bounds[p]
            last = p

        if start <= last:
            if withPerm:
                out.append((start << self.pgshft, (last+1) << self.pgshft, curp))
            else:
                out.append((start << self.pgshft, (last+1) << self.pgshft))

        return out

    def getNextFreePage(self, addr):
        start = addr >> self.pgshft
        while start in self.active.bounds:
            start += 1

        return start << self.pgshft

    def addAnn(self, start, end, mtype, label=""):
        ann = Annotation(start, end, mtype, label)
        self.active.ann.append(ann)
        return ann

    def getImageSymbol(self, symname, pename=""):
        # not to be confused with getSymbol, which works on symbolic symbols
        # this works on annotations of type SYMBOL
        symname = pename + "::" + symname
        match = [ x for x in self.active.ann if x.mtype == "SYMBOL" and x.label.endswith(symname) ]

        if len(match) == 0:
            raise KeyError(f"Unable to find Symbol {symname}")
        if len(match) > 1:
            raise KeyError(f"Found multiple Symbols matching {symname}")

        return match[0].start

    def alloc(self, amt):
        if self.active.nextalloc == 0:
            self.active.nextalloc = 0xffff765400000000 if self.active.priv else 0x660000

        start = self.active.nextalloc

        # round amt up to 0x10 boundry
        amt = (amt+0xf) & (~0xf)

        end = start + amt
        self.active.nextalloc = end

        # if there is already an "ALLOC" annotation, extend it
        allocann = None
        for a in self.active.ann:
            if a.end == start and a.mtype == "ALLOC":
                allocann = a
                allocann.end = end
                break;
        if allocann is None:
            allocann = Annotation(start, end, "ALLOC", "allocations")
            self.active.ann.append(allocann)

        self.updateBounds(start, end, MEM_READ | MEM_WRITE)

        return start

    def initState(self, start, end, stackbase=0, priv=0):
        #TODO be able to initalize/track multiple contexts
        #TODO work in emu mode
        self.active.priv = (priv == 0)
        if stackbase == 0:
            stackbase = 0xffffb98760000000 if self.active.priv else 0x64f000

        # zero or symbolize all registers
        for r in self.getAllReg():
            n = self.getRegName(r)
            sym = False
            if n in ["cr8", "cr0"]:
                sym=False
            elif n.startswith("cr") or n in ["gs", "fs"]:
                sym = True

            self.setRegVal(r, 0)
            if self.issym and sym:
                self.symbolizeRegister(r, "Inital " + n)

        # setup rflags to be sane
        self.setRegVal(
            DB_X86_R_EFLAGS,
            (1 << 9) | # interrupts enabled
            (priv << 12) | # IOPL
            (1 << 21) # support cpuid
        )

        # setup sane control registers
        self.setRegVal(DB_X86_R_CR8, 0) # IRQL of 0 (PASSIVE_LEVEL)

        cr0val = 0
        cr0val |= 1 << 0 # Protected Mode
        cr0val |= 0 << 1 # Monitor Coprocessor
        cr0val |= 0 << 2 # Emulation Mode
        cr0val |= 1 << 3 # Task Switched ?
        cr0val |= 1 << 4 # Extension Type ?
        cr0val |= 1 << 5 # Numeric Error
        cr0val |= 1 << 16 # Write Protect
        cr0val |= 0 << 18 # Alignment Mask
        cr0val |= 0 << 29 # Not Write-through
        cr0val |= 0 << 30 # Cache Disable
        if self.active.providerName == "Triton":
            cr0val |= 1 << 31 # Paging Enabled
        else:
            # we can't get away with this without actually supporting this in things like unicorn
            #TODO
            cr0val |= 0 << 31 # Paging Enabled

        self.setRegVal(DB_X86_R_CR0, cr0val)
        #TODO set cr4 as well

        # create stack
        if self.active.stackann is None:
            stackstart = stackbase - (0x1000 * 16)
            self.active.stackann = self.addAnn(stackstart, stackbase, "STACK", "Inital Stack")
            self.updateBounds(stackstart, stackbase, MEM_READ | MEM_WRITE, False)
            self.addHook(stackstart - (0x1000), stackstart, MEM_WRITE, self.stack_guard_hook, "Stack Guard")

        # create end hook
        self.addHook(end, end+1, MEM_EXECUTE, None, "End Hit")

        # set initial rip and rsp
        self.setRegVal(self.ipreg, start)
        self.setRegVal(self.spreg, stackbase - 0x100)

        return True

    def startTrace(self, getaddrs=False):
        if not self.isemu:
            raise RuntimeError("No emulation providers are active")

        return self.active.startTrace(getaddrs)

    def getTrace(self):
        if not self.isemu:
            raise RuntimeError("No emulation providers are active")

        return self.active.getTrace()

    def stopTrace(self):
        if not self.isemu:
            raise RuntimeError("No emulation providers are active")
        
        return self.active.stopTrace()

    def printTrace(self, prev=42):
        t = self.getTrace()[-prev:]
        for e in t:
            out = hex(e[0])[2:]
            if len(e) >= 2:
                out += ", " + e[1]
            print(out)

    def cmpTraceAddrs(self, t1, t2):
        # looks like trying to stop execution with ^C can make the trace skip?
        if len(t1) != len(t2):
            print("Traces len differ ", len(t1), len(t2))

        l = min(len(t1), len(t2))

        differ = False
        for i in range(l):
            t1i = t1[i]
            t2i = t2[i]
            if (t1i[0] != t2i[0]):
                differ = True
                print(f"Traces diverge after {i} instructions ( @ {hex(t1[0])}, @ {hex(t2[0])})")
                break
        if not differ:
            print("Traces match")

    def saveTrace(self, trace, filepath):
        with open(filepath, "w") as fp:
            for te in trace:
                fp.write(json.dumps(te) + '\n')

    def loadTrace(self, filepath):
        trace = []
        with open(filepath, "r") as fp:
            while True:
                l = fp.readline()
                if l == "":
                    break
                trace.append(json.loads(l))
        return trace
    
    #TODO move to EMU interface?
    def handle_hook(self, hk, addr, sz, op, ignorehook):
        self.active.lasthook = hk

        handler = hk.handler

        stopret = StepRet.HOOK_EXEC
        if op == MEM_READ:
            stopret = StepRet.HOOK_READ
        elif op == MEM_WRITE:
            stopret = StepRet.HOOK_WRITE
        elif op != MEM_EXECUTE:
            raise TypeError(f"Unknown op to handler hook \"{op}\"")

        if handler is not None:
            hret = handler(hk, self, addr, sz, op, self.active)
            
            if hret == HookRet.FORCE_STOP_INS:
                return (True, stopret)
            elif hret == HookRet.OP_CONT_INS:
                if self.active.opstop:
                    hret = HookRet.STOP_INS
                else:
                    hret = HookRet.CONT_INS
            elif hret == HookRet.OP_DONE_INS:
                if self.active.opstop:
                    hret = HookRet.STOP_INS
                else:
                    hret = HookRet.DONE_INS

            if hret == HookRet.STOP_INS:
                if not ignorehook:
                    return (True, stopret)
                else:
                    return (False, stopret)
            elif hret == HookRet.CONT_INS:
                return (False, StepRet.OK)
            elif hret == HookRet.DONE_INS:
                # only applies to exec type hooks
                if op != MEM_EXECUTE:
                    raise TypeError(f"Hook \"{str(hk)}\" returned done, even though the op type is \"{op}\"")
                return (True, StepRet.OK)
            elif hret == HookRet.ERR:
                return (True, StepRet.HOOK_ERR)
            else:
                raise TypeError(f"Unknown return from hook handler for hook {eh}")
        else:
            # no ignoring API hooks with no handler
            if (self.active.apihooks.start <= addr < self.active.apihooks.end) or (not ignorehook):
                return (True, stopret)
            else:
                return (False, StepRet.OK)

    def step(self, ignorehook=True):
        if not self.isemu:
            raise RuntimeError("No emulation providers are active")

        return self.active.step(ignorehook, self.printIns)

    def cont(self, ignorehook=True, n=0):
        if not self.isemu:
            raise RuntimeError("No emulation providers are active")

        return self.active.cont(ignorehook, self.printIns)

    def until(self, addr, ignorehook=True):
        if not self.isemu:
            raise RuntimeError("No emulation providers are active")

        return self.active.until(addr, ignorehook, self.printIns)

    def next(self, ignorehook=True):
        if not self.isemu:
            raise RuntimeError("No emulation providers are active")

        return self.active.next(ignorehook, self.printIns)

    def takeSnap(self, name):
        if not self.issnp:
            raise RuntimeError("No emulation providers are active")

        if name in self.snapshots:
            raise KeyError(f"Snapshot named {name} already exists")

        snap = Snapshot(name)

        snap.take(self)

        self.active.takeSnapshot(snap)

        self.snapshots[name] = snap

    def restoreSnap(self, name):
        if not self.issnp:
            raise RuntimeError("No emulation providers are active")

        if name not in self.snapshots:
            raise KeyError(f"No snapshot named {name}")

        snap = self.snapshots[name]

        snap.restore(self)

        self.active.restoreSnapshot(snap)

    def removeSnap(self, name):
        if name not in self.snapshots:
            raise KeyError(f"No snapshot named {name}")

        del self.snapshots[name]

    def saveSnapFile(self, name, filename=None):

        if name not in self.snapshots:
            raise KeyError(f"No snapshot named {name}")

        if filename is None:
            filename = "./"+name+".snap"

        snap = self.snapshots[name]
        try:
            with open(filename, "wb") as fp:
                    pickle.dump(snap, fp)
        except Exception as e:
            os.unlink(filename)
            raise e

    def loadSnapFile(self, filename):
        snap = None
        with open(filename, "rb") as fp:
            snap = pickle.load(fp)

        name = snap.name

        if name in self.snapshots:
            print(f"Snapshot named {name} already exists, appending a number")
            i = 0
            while name+str(i) in self.snapshots:
                i += 1
            name = name+str(i)

        self.snapshots[name] = snap

        return name

    def takeSnapToFile(self, name="_quicksave", filename=None):
        takeSnap(name)
        saveSnapFile(name, filename)
        removeSnap(name)

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
