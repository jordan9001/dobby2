from unicorn import *
from unicorn.x86_const import *

from .interface import *
from .dobby import *

class DobbyUnicorn(DobbyProvider, DobbyEmu, DobbyRegContext, DobbyMem, DobbySnapshot):
    """
    Dobby provider using Triton DSE
    """

    def __init__(self, ctx):
        self.ctx = ctx
        super().__init__(ctx, "Unicorn")

        self.emu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.ctx.unicorn = self
        self.trace = None
        self.tracefull = False
        self.inscount = 0
        self.stepret = StepRet.OK
        self.intrnum = -1
        self.ignorehookaddr = -1
        self.trystop = False
        self.regtrans = {}
        self.lasterr = None
        self.printIns = False

        # hook every instruction
        self.emu.hook_add(UC_HOOK_CODE, self.insHook, None, 0, 0xffffffffffffffff)
        # hook read/write
        self.emu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.rwHook, None)
        # hook invalid stuff
        self.emu.hook_add(UC_HOOK_MEM_INVALID, self.invalMemHook, None)

        #older versions of unicorn don't have this
        try:
            self.emu.hook_add(UC_HOOK_INSN_INVALID, self.invalInsHook, None)
        except:
            print("Unable to install emulation invalid instruction hook")

        self.emu.hook_add(UC_HOOK_INTR, self.intrHook, None)

        self.db2uc = {}
        self.uc2db = {}

        for dbreg in x86allreg:
            regname = x86reg2name[dbreg]
            ucregname = "UC_X86_REG_" + regname.upper()
            #TODO support Floating point and tr stuff
            if regname.startswith("fp") or regname.endswith("tr") or regname in ["msr"]:
                continue
            try:
                ucreg = getattr(unicorn.x86_const, ucregname)
                self.db2uc[dbreg] = ucreg
                self.uc2db[ucreg] = dbreg
            except AttributeError:
                pass

    # EMU INTERFACE

    def getInsCount(self):
        return self.inscount

    def insertHook(self, hook):
        if hook.htype == MEM_EXECUTE:
            #TODO 
            # write in breakpoint instructions for execution hooks
            pass

    def removeHook(self, hook):
        #TODO handle removing any saved breakpoint instructions
        pass

    def insertInstructionHook(self, insname, handler):
        pass

    def removeInstructionHook(self, insname, handler):
        pass

    def startTrace(self, getdrefs=False):
        if self.trace is not None:
            raise ValueError("Tried to start trace when there is already a trace being collected")
        self.trace = []
        self.tracefull = getdrefs

    def getTrace(self):
        return self.trace

    def stopTrace(self):
        t = self.trace
        self.trace = None
        return t

    def step(self, ignorehook, printIns):
        self.printIns = printIns
        self.stepret = StepRet.OK
        self.lasterr = None
        self.trystop = False

        addr = self.emu.reg_read(UC_X86_REG_RIP)

        self.ignorehookaddr = -1
        if ignorehook:
            self.ignorehookaddr = addr

        try:
            self.emu.emu_start(addr, 0xffffffffffffffff, 0, 1)
        except UcError as e:
            self.lasterr = e

        # we go over because the ins hook is called even when we don't execute the final instruction
        self.inscount -= 1

        return self.stepret

    def cont(self, ignorehook, printIns, n=0):
        self.printIns = printIns
        self.stepret = StepRet.OK
        addr = self.emu.reg_read(UC_X86_REG_RIP)
        self.lasterr = None
        self.trystop = False

        self.ignorehookaddr = -1
        if ignorehook:
            self.ignorehookaddr = addr

        try:
            self.emu.emu_start(addr, 0xffffffffffffffff, 0, n)
        except UcError as e:
            self.lasterr = e

        # we go over because the ins hook is called even when we don't execute the final instruction
        self.inscount -= 1

        return self.stepret

    def contn(self, ignorehook, printIns, n):
        return self.cont(ignorehook, printInt, n)

    def until(self, addr, ignorehook, printIns):
        self.printIns = printIns
        self.stepret = StepRet.OK
        self.lasterr = None
        self.trystop = False

        addr = self.emu.reg_read(UC_X86_REG_RIP)

        self.ignorehookaddr = -1
        if ignorehook:
            self.ignorehookaddr = addr

        try:
            self.emu.emu_start(addr, until, 0, 0)
        except UcError as e:
            self.lasterr = e

        # we go over because the ins hook is called even when we don't execute the final instruction
        self.inscount -= 1

        return self.stepret

    def next(self, ignorehook, printIns):
        raise NotImplementedError(f"TODO") 

    # EMU HELPERS

    def insHook(self, emu, addr, sz, user_data):
        if self.printIns:
            print('@', hex(addr))

        if self.trystop:
            print("In instruction hook when we wanted to stop!")
            emu.emu_stop()

        # this hook could happen even if we are not about to execute this instruction
        # it happens before we are stopped
        ignorehook = (addr == self.ignorehookaddr)
        try:
            for eh in self.hooks[0]:
                if eh.start <= addr < eh.end:
                    # hooked
                    stop, sret = self.ctx.handle_hook(eh, addr, 1, MEM_EXECUTE, ignorehook)
                    if not stop:
                        break
                    if sret == StepRet.OK:
                        return
                    self.stepret = sret
                    emu.emu_stop()
                    self.trystop = True
                    return
        except Exception as e:
            print("Stopping emulation, exception occured during insHook:", e)
            self.stepret = StepRet.ERR
            emu.emu_stop()
            self.trystop = True
            raise e

        if self.trace is not None:
            if len(self.trace) == 0 or self.trace[-1][0] != addr:
                item = None
                if self.tracefull:
                    item = (addr, None, [[],[]])
                else:
                    item = (addr, )
                self.trace.append(item)

        #TODO this will go up too much because we get called to much, can we fix that?
        self.inscount += 1

        #TODO do inshooks here

    def rwHook(self, emu, access, addr, sz, val, user_data):
        if self.trystop:
            #TODO better way to stop?
            print("In memory hook when we wanted to stop!")
            emu.emu_stop()

        if not self.trystop and self.tracefull and self.trace is not None:
            if access == UC_MEM_WRITE:
                self.trace[-1][2][1].append((addr, sz))
            else:
                self.trace[-1][2][0].append((addr, sz))

        #TODO why can't I read registers from here?
        try:
            # handle read / write hooks
            if access == UC_MEM_WRITE:
                for wh in self.hooks[2]:
                    if wh.start <= addr < wh.end:
                        # hooked
                        #TODO should ignorehook if on that address?
                        stop, sret = self.ctx.handle_hook(wh, addr, sz, MEM_WRITE, False)
                        if not stop:
                            break
                        self.stepret = sret
                        emu.emu_stop()
                        self.trystop = True
                        return
            else:
                for rh in self.hooks[1]:
                    if rh.start <= addr < rh.end:
                        # hooked
                        #TODO should ignorehook if on that address?
                        stop, sret = self.ctx.handle_hook(rh, addr, sz, MEM_READ, False)
                        if not stop:
                            break
                        self.stepret = sret
                        emu.emu_stop()
                        self.trystop = True
                        return
        except Exception as e:
            print("Stopping emulation, exception occured during rwHook:", e)
            self.stepret = StepRet.ERR
            emu.emu_stop()
            self.trystop = True
            raise e

    def invalMemHook(self, emu, access, addr, sz, val, user_data):
        if self.trystop:
            print("In invalid memory hook when we wanted to stop!")
            emu.emu_stop()
        ret = False
        #TODO why can't I read registers from here?
        try:
            # handle read / write hooks
            if access == UC_MEM_WRITE:
                for wh in self.hooks[2]:
                    if wh.start <= addr < wh.end:
                        # hooked
                        #TODO return True/False?
                        #TODO should ignorehook if on that address?
                        stop, sret = self.ctx.handle_hook(wh, addr, sz, MEM_WRITE, False)
                        if not stop:
                            break
                        self.stepret = sret
                        emu.emu_stop()
                        self.trystop = True
                        return ret
            else:
                for rh in self.hooks[1]:
                    if rh.start <= addr < rh.end:
                        # hooked
                        #TODO return True/False?
                        #TODO should ignorehook if on that address?
                        stop, sret = self.ctx.handle_hook(rh, addr, sz, MEM_READ, False)
                        if not stop:
                            break
                        self.stepret = sret
                        emu.emu_stop()
                        self.trystop = True
                        return ret
            # if no hooks handle it
            self.stepret = StepRet.DREF_OOB
        except Exception as e:
            print("Stopping emulation, exception occured during invalMemHook:", e)
            self.stepret = StepRet.ERR
            ret = False
        return ret

    def invalInsHook(self, emu, user_data):
        print(f"DEBUG Invalid ins")
        return False

    def intrHook(self, emu, intno, user_data):
        self.stepret = StepRet.INTR
        self.intrnum = intno
        emu.emu_stop()
        self.trystop = True

    # REG INTERFACE

    def getRegVal(self, reg): 
        ucreg = self.db2uc[reg]
        return self.emu.reg_read(ucreg)

    def setRegVal(self, reg, val):
        ucreg = self.db2uc[reg]
        self.emu.reg_write(ucreg, val)

    def getAllRegisters(self):
        return list(self.db2uc.keys())

    # MEM INTERFACE

    def disass(self, addr=-1, count=16):
        #TODO use capstone I guess
        raise NotImplementedError(f"Unicorn disassembly not implemented yet")

    def getInsLen(self, addr=-1):
        raise NotImplementedError(f"Unicorn length disassembly not implemented yet")

    def getMemVal(self, addr, amt):
        return self.emu.mem_read(addr, amt)

    def setMemVal(self, addr, val):
        self.emu.mem_write(addr, bytes(val))

    def updateBounds(self, start, end, permissions):
        try:
            self.emu.mem_map(start, end - start, permissions)
        except UcError as e:
            # probably already mapped, find pages to map
            #TODO
            raise e

    # MEM Helper

    def printUcMap(self):
        reg_i = self.emu.mem_regions()
        for r_beg, r_end, _ in reg_i:
            print(hex(r_beg) +'-'+ hex(r_end))
