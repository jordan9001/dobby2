from triton import *

from .interface import *
from .dobby import *

class DobbyTriton(DobbyProvider, DobbyEmu, DobbySym, DobbyRegContext, DobbyMem, DobbySnapshot):
    """
    Dobby provider using Triton DSE
    """

    def __init__(self, ctx):
        super().__init__(ctx, "Triton")
        self.ctx = ctx
        self.ctx.triton = self
        
        # setup Triton API
        self.api = TritonContext(ARCH.X86_64)
        self.api.enableSymbolicEngine(True)
        #TODO add a dobby interface for taint and hook up triton's 

        # set modes appropriately
        self.api.setMode(MODE.ALIGNED_MEMORY, False)
        self.api.setMode(MODE.AST_OPTIMIZATIONS, True)
        self.api.setMode(MODE.CONCRETIZE_UNDEFINED_REGISTERS, False)
        self.api.setMode(MODE.CONSTANT_FOLDING, True)
        # remove this if you want to backslice
        self.api.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
        self.api.setMode(MODE.ONLY_ON_TAINTED, False)
        self.api.setMode(MODE.PC_TRACKING_SYMBOLIC, False)
        self.api.setMode(MODE.SYMBOLIZE_INDEX_ROTATION, False)
        self.api.setMode(MODE.TAINT_THROUGH_POINTERS, False)

        # register callbacks
        self.addrswritten = []
        self.addrsread = []
        self.callbackson = False
        self.api.addCallback(CALLBACK.GET_CONCRETE_MEMORY_VALUE, self.getMemCallback)
        self.api.addCallback(CALLBACK.SET_CONCRETE_MEMORY_VALUE, self.setMemCallback)

        # save off types for checking later
        self.type_MemoryAccess = type(MemoryAccess(0,1))
        self.type_Register = type(self.api.registers.rax)

        self.inscount = 0
        self.trace = None
        self.tracefull = False
        self.defsyms = set()
        self.lastins = None

        self.db2tri = {}
        self.tri2db = {}

        self.triton_inshooks = {
            "smsw": self.smswHook,
        }

        for dbreg in x86allreg:
            regname = x86reg2name[dbreg]
            try:
                trireg = getattr(self.api.registers, regname)
                self.db2tri[dbreg] = trireg
                self.tri2db[trireg] = dbreg
            except AttributeError:
                pass

    #EMU INTERFACE

    def getInsCount(self):
        return self.inscount

    def insertHook(self, hook):
        pass

    def removeHook(self, hook):
        pass

    def insertInstructionHook(self, insname, handler):
        pass

    def removeInstructionHook(self, insname, handler):
        pass

    def startTrace(self, getdrefs=False):
        if self.trace is not None:
            raise ValueError("Tried to start trace when there is already a trace being collected")
        self.trace = []
        if getdrefs:
            self.tracefull = True

    def getTrace(self):
        return self.trace

    def stopTrace(self):
        t = self.trace
        self.trace = None
        return t

    def step(self, ignorehook, printIns):
        ins = self.getNextIns()
        if printIns:
            if (self.ctx.apihooks.start <= ins.getAddress() < self.ctx.apihooks.end):
                #TODO print API hook label
                print("API hook")
            else:
                print(ins)
        return self.stepi(ins, ignorehook)

    def cont(self, ignorehook, printInst):
        if ignorehook:
            ret = self.step(True, printInst)
            if ret != StepRet.OK:
                return ret
        while True:
            ret = self.step(False, printInst)
            if ret != StepRet.OK:
                return ret

    def until(self, addr, ignorehook, printInst):
        ret = StepRet.OK
        if ignorehook:
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

    def next(self, ignorehook, printInst):
        # this is just an until next ins if cur ins is call
        i = self.getNextIns()
        if i.getDisassembly().startswith("call"):
            na = i.getNextAddress()
            return self.until(na, ignorehook)

        return self.step(ignorehook)

    # EMU HELPERS

    def getNextIns(self):
        # rip should never be symbolic when this function is called
        # Is this check worth it? Slows us down, when we do it after each step anyways
        if self.api.isRegisterSymbolized(self.api.registers.rip):
            #TODO use hasUnsetSym to see if the symbols are already concretized
            # if so, evalReg rip
            raise ValueError("Tried to get instruction with symbolized rip")
        rip = self.api.getConcreteRegisterValue(self.api.registers.rip)
        insbytes = self.api.getConcreteMemoryAreaValue(rip, 15)
        inst = Instruction(rip, insbytes)
        self.api.disassembly(inst)
        return inst

    def setMemCallback(self, trictx, mem, val):
        if not self.callbackson:
            return

        addr = mem.getAddress()
        size = mem.getSize()

        self.addrswritten.append((mem.getAddress(), mem.getSize()))

    def getMemCallback(self, trictx, mem):
        if not self.callbackson:
            return

        addr = mem.getAddress()
        size = mem.getSize()

        self.addrsread.append((mem.getAddress(), mem.getSize()))

    def stepi(self, ins, ignorehook=False):
        # do pre-step stuff
        self.ctx.lasthook = None
        self.addrswritten = []
        self.addrsread = []
        self.lastins = ins

        # rip and rsp should always be a concrete value at the beginning of this function
        rspreg = self.api.registers.rsp
        ripreg = self.api.registers.rip
        rsp = self.api.getConcreteRegisterValue(rspreg)
        rip = self.api.getConcreteRegisterValue(ripreg)

        #TODO add exception raising after possible first_chance stop?

        # enforce page permissions
        if not self.ctx.inBounds(rip, ins.getSize(), MEM_EXECUTE):
            return StepRet.ERR_IP_OOB

        # check if rip is at a hooked execution location
        for eh in self.ctx.hooks[0]: #TODO be able to search quicker here
            if eh.start <= rip < eh.end:
                # hooked
                #TODO multiple hooks at the same location?
                stop, sret = self.ctx.handle_hook(eh, rip, 1, MEM_EXECUTE, ignorehook)
                if not stop:
                    break
                return sret

        # check if we are about to do a memory deref of:
        #   a symbolic value
        #   a hooked location (if not ignorehook)
        #   an out of bounds location
        # we can't know beforehand if it is a write or not, so verify after the instruction
        #TODO automatically detect symbolic expressions that are evaluable based on variables we have set
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

        #TODO check ins.isSymbolized?

        self.inscount += 1

        insaddr = ins.getAddress()
        if self.trace is not None:
            if len(self.trace) == 0 or self.trace[-1][0] != insaddr:
                item = None
                if self.tracefull:
                    item = (insaddr, ins.getDisassembly(), [[],[]])
                else:
                    item = (insaddr, ins.getDisassembly())
                self.trace.append(item)

        # every X thousand instructions, check for inf looping ?
        #if (self.inscount & 0xffff) == 0:
            #TODO
            # check for current rip addr in past X instructions
            # for each of those, backward, check if same loop reaches start of lopp
            # enforce some minimum loop count required? Over 9000?

        # check inshooks
        ins_name = ins.getDisassembly().split()[0]
        ihret = None
        if ins_name in self.triton_inshooks:
            ihret = self.triton_inshooks[ins_name](self.ctx, insaddr, ins, self)
        elif ins_name in self.ctx.inshooks:
            ihret = self.ctx.inshooks[ins_name](self.ctx, insaddr, self)

        if ihret is not None:
            if ihret == HookRet.OP_CONT_INS:
                if self.ctx.opstop:
                    ihret = HookRet.STOP_INS
                else:
                    ihret = HookRet.CONT_INS
            if ihret == HookRet.OP_DONE_INS:
                if self.ctx.opstop:
                    ihret = HookRet.STOP_INS
                else:
                    ihret = HookRet.DONE_INS

            if ihret == HookRet.ERR:
                return StepRet.HOOK_ERR
            elif ihret == HookRet.CONT_INS:
                pass
            elif ihret == HookRet.DONE_INS:
                return StepRet.OK
            elif ihret == HookRet.STOP_INS and not ignorehook:
                return StepRet.HOOK_INS
            elif ihret == HookRet.FORCE_STOP_INS:
                return StepRet.HOOK_INS
            else:
                raise ValueError("Unknown return from instruction hook")

        self.callbackson = True

        # actually do a step
        #TODO how do we detect exceptions like divide by zero?
        # triton just lets divide by zero through
        if not self.api.processing(ins):
            return StepRet.BAD_INS

        self.callbackson = False

        if self.trace is not None and self.tracefull:
            self.trace[-1][2][0] += self.addrsread
            self.trace[-1][2][1] += self.addrswritten

        #TODO we are doing bounds checks after they already happen
        # this is a problem if we want to be able to handle exceptions properly

        # Read and Write hooks
        for addr, size in self.addrsread:
            # check access is in bounds
            if not self.ctx.inBounds(addr, size, MEM_READ):
                print("DEBUG: oob read at", hex(addr))
                return StepRet.DREF_OOB

            # check if access is hooked
            for rh in self.ctx.hooks[1]:
                if (rh.start - size) < addr < rh.end:
                    # hooked
                    #TODO multiple hooks at the same location?
                    stop, sret = self.ctx.handle_hook(rh, addr, size, MEM_READ, ignorehook)
                    if not stop:
                        break
                    return sret

        for addr, size in self.addrswritten:
            # check access is in bounds
            if not self.ctx.inBounds(addr, size, MEM_READ):
                print("DEBUG: oob write at", hex(addr))
                return StepRet.DREF_OOB

            # check if access is hooked
            for wh in self.ctx.hooks[2]:
                if (wh.start - size) < addr < wh.end:
                    # hooked
                    #TODO multiple hooks at the same location?
                    stop, sret = self.ctx.handle_hook(rh, addr, size, MEM_WRITE, ignorehook)
                    if not stop:
                        break
                    return sret

        # check if we forked rip
        if self.api.isRegisterSymbolized(ripreg):
            return StepRet.PATH_FORKED
            # find what symbols it depends on
            # and use setSymbol to give a concrete value for the var
            # then use evalReg(rip) to evaluate rip

        # check if we forked rsp
        if self.api.isRegisterSymbolized(ripreg):
            return StepRet.STACK_FORKED

        return StepRet.OK

    @staticmethod
    def smswHook(ctx, addr, ins, trictx):
        cr0val = ctx.getRegVal(DB_X86_R_CR0)

        newrip = ctx.getRegVal(DB_X86_R_RIP) + ins.getSize()
        ctx.setRegVal(DB_X86_R_RIP, newrip)

        op = ins.getOperands()[0]
        if isinstance(op, trictx.type_Register):
            ctx.setRegVal(op, cr0val)
        else:
            raise NotImplementedError("TODO")

        return HookRet.DONE_INS

    # SYMBOLIC INTERFACE

    def isSymbolizedRegister(self, reg):
        trireg = self.db2tri[reg]
        return self.api.isRegisterSymbolized(trireg)

    def isSymbolizedMemory(self, addr, size):
        #TODO do smart sizing to not do a ton of memory access things here
        for i in range(size):
            if self.api.isMemorySymbolized(addr+i):
                return True
        return False
    
    def symbolizeRegister(self, reg, name):
        trireg = self.db2tri[reg]
        return self.api.symbolizeRegister(trireg, name)

    def symbolizeMemory(self, addr, size, name):
        #TODO be smart about this with as large of aligned memory access as we can get away with
        for i in range(size):
            self.api.symbolizeMemory(MemoryAccess(addr + i, 1), name +"+"+hex(i)[2:])

    def getSymbol(self, name):
        # use name to find symbol with that alias
        syms = self.api.getSymbolicVariables()
        for s in syms:
            if symname == syms[s].getAlias():
                return s
        raise KeyError(f"Unknown symbol {symname}")

    def setSymbolVal(self, sym, value, overwrite=False):
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

    def getRegisterAst(self, reg):
        trireg = self.db2tri[reg]
        return self.api.getRegisterAst(trireg)

    def getMemoryAst(self, addr, size):
        #TODO do a smart memory access. This will fail on unaligned size/addr
        return self.api.getMemoryAst(MemoryAccess(addr, size))

    def printAst(self, ast):
        ast = self.api.simplify(ast, True)
        print(self.taboutast(str(ast)))

    def getUnsetSym(self, ast, single=True, allSym=False, followRef=True):
        # walk the ast and see if any of the symbols are not in our list
        # depth first search, stop when we hit the first one
        symlist = set()
        path = [ast]
        while len(path) > 0:
            cur, path = path[-1], path[:-1]
            nt = cur.getType()
            if nt == AST_NODE.VARIABLE:
                # Found one!
                symvar = cur.getSymbolicVariable()
                sym = symvar.getId()
                if not allSym and sym in self.defsyms:
                    continue

                if single:
                    return sym
                else:
                    symlist.add(symvar.getId())
            elif nt == AST_NODE.REFERENCE:
                # get symexp and continue
                if followRef:
                    path.append(cur.getSymbolicExpression().getAst())
            else:
                path += cur.getChildren()


        if single:
            return None
        else:
            return list(symlist)

    def getUnsetCount(self):
        varcount = {}
        ses = self.api.getSymbolicExpressions()
        for k in ses:
            ast = ses[k].getAst()

            # note, this will only count each variable in this se once
            unsetvars = self.getUnsetSym(ast, single=False, followRef=False)
            for uv in unsetvars:
                if uv not in varcount:
                    varcount[uv] = 1
                else:
                    varcount[uv] += 1

        return varcount

    def evalReg(self, reg, checkUnset=True):
        trireg = self.db2tri[reg]
        # Use after using setSymbol
        if self.api.isRegisterSymbolized(trireg):
            if checkUnset:
                ast = self.api.getRegisterAst(trireg)
                unsetsym = self.getUnsetSym(ast, True, False)
                if unsetsym is not None:
                    print(f"Unable to eval register, relies on unset symbol {unsetsym}")
                    return False

            val = self.api.getSymbolicRegisterValue(trireg)
            self.api.setConcreteRegisterValue(trireg, val)
            return True
        else:
            print("Unable to eval register, is not symbolized")
            return False

    def evalMem(self, addr, size, checkUnset=True):
        # Use after using setSymbol
        for i in range(size):
            if checkUnset:
                # doing this for every byte seems like a lot
                # should probably use bigger getMemoryAst, but that has to be aligned
                ast = self.api.getMemoryAst(MemoryAccess(addr+i, 1))
                unsetsym = self.getUnsetSym(ast, True, False)
                if unsetsym is not None:
                    print(f"Unable to eval memory at {hex(addr+i)[2:]}, relies on unset symbol {unsetsym}")
                    return False
            mem = self.api.getSymbolicMemoryValue(MemoryAccess(addr+i, 1))
            self.api.setConcreteMemoryValue(addr+i, mem)
        return True

    # SYMBOLIC HELPERS

    def taboutast(self, h, ta=2, hexify=True, maxline=90):
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

    # REG INTERFACE

    def getRegVal(self, reg): 
        trireg = self.db2tri[reg]
        return self.api.getConcreteRegisterValue(trireg)

    def setRegVal(self, reg, val):
        trireg = self.db2tri[reg]
        self.api.setConcreteRegisterValue(trireg, val)

    def getAllRegisters(self):
        return list(self.db2tri.keys())

    # REG HELPERS

    def db2Tri(self, reg):
        return self.db2tri[reg]

    def tri2Db(self, trireg):
        return self.tri2db[trireg]

    # MEM INTERFACE

    def disass(self, addr=-1, count=16):
        if addr == -1:
            addr = self.getConcreteRegisterValue(self.api.registers.rip)
        lines = []
        for i in range(count):
            insbytes = self.api.getConcreteMemoryAreaValue(addr, 15)
            inst = Instruction(addr, insbytes)
            self.api.disassembly(inst)
            lines.append((addr, inst.getDisassembly()))
            addr = inst.getNextAddress()
        
        return lines

    def getInsLen(self, addr=-1):
        if addr == -1:
            addr = self.getConcreteRegisterValue(self.api.registers.rip)
        insbytes = self.api.getConcreteMemoryAreaValue(addr, 15)
        inst = Instruction(addr, insbytes)
        self.api.disassembly(inst)
        return inst.getNextAddress() - addr

    def getMemVal(self, addr, amt):
        return self.api.getConcreteMemoryAreaValue(addr, amt)

    def setMemVal(self, addr, val):
        self.api.setConcreteMemoryAreaValue(addr, val)

    def updateBounds(self, start, end, permissions):
        pass # not needed in this provider
