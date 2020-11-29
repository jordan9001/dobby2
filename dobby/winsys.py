if __name__ == '__main__':
    print("Please import this file from a dobby script")
    exit(-1)

import struct
from .dobby import *
from .dobby_const import *

# windows kernel helper functions
def createIrq(ctx, irqtype, inbuf):
    raise NotImplementedError("TODO")

def createDrvObj(ctx, start, size, entry, path, name="DriverObj"):
    dobjsz = 0x150
    d = ctx.alloc(dobjsz)
    dex = ctx.alloc(0x50)
    dte = ctx.alloc(0x120)

    # initialize driver object
    # type = 0x4
    ctx.setu16(d + 0x00, 0x4)
    # size = 0x150
    ctx.setu16(d + 0x02, dobjsz)
    # DeviceObject = 0
    ctx.setu64(d + 0x08, 0x0)

    # flags = ??
    #TODO
    ctx.trySymbolizeMemory(d+0x10, 8, name+".Flags")

    # DriverStart = start
    ctx.setu64(d + 0x18, start)
    # DriverSize = size
    ctx.setu32(d + 0x20, size)

    # DriverSection = LDR_DATA_TABLE_ENTRY
    # not sure what most of these fields are, so we will see what is used
    # set up DriverSection
    ctx.trySymbolizeMemory(dte+0x0, 0x10, name + ".DriverSection.InLoadOrderLinks")
    ctx.trySymbolizeMemory(dte+0x10, 0x10, name + ".DriverSection.InMemoryOrderLinks")
    ctx.trySymbolizeMemory(dte+0x20, 0x10, name + ".DriverSection.InInitializationOrderLinks")
    ctx.setu64(dte+0x30, start)
    ctx.setu64(dte+0x38, entry)
    ctx.setu64(dte+0x40, size)
    initUnicodeStr(ctx, dte+0x48, path)
    initUnicodeStr(ctx, dte+0x58, path.split('\\')[-1])
    ctx.trySymbolizeMemory(dte+0x68, 0x8, name + ".DriverSection.Flags")
    ctx.trySymbolizeMemory(dte+0x70, 0x10, name + ".DriverSection.HashLinks")
    ctx.setu64(dte+0x80, 0) # TimeDateStamp
    ctx.trySymbolizeMemory(dte+0x88, 0x8, name + ".DriverSection.EntryPointActivationContext")
    ctx.setu64(dte+0x90, 0) # Lock
    ctx.trySymbolizeMemory(dte+0x98, 0x8, name + ".DriverSection.DdagNode")
    ctx.trySymbolizeMemory(dte+0xa0, 0x10, name + ".DriverSection.NodeModuleLink")
    ctx.trySymbolizeMemory(dte+0xb0, 0x8, name + ".DriverSection.LoadContext")
    ctx.trySymbolizeMemory(dte+0xb8, 0x8, name + ".DriverSection.ParentDllBase")
    ctx.trySymbolizeMemory(dte+0xc0, 0x8, name + ".DriverSection.SwitchBackContext")
    ctx.trySymbolizeMemory(dte+0xc8, 0x20, name + ".DriverSection.IndexNodeStuff")
    ctx.trySymbolizeMemory(dte+0xf8, 0x8, name + ".DriverSection.OriginalBase")
    ctx.trySymbolizeMemory(dte+0x100, 0x8, name + ".DriverSection.LoadTime")
    ctx.setu32(dte+0x108, 0) # BaseNameHashValue
    ctx.setu32(dte+0x10c, 0) # LoadReasonStaticDependency
    ctx.trySymbolizeMemory(dte+0x110, 4, name + ".DriverSection.ImplicitPathOptions")
    ctx.setu32(dte+0x118, 0) # DependentLoadFlags
    ctx.setu32(dte+0x11c, 0) # SigningLevel

    #ctx.trySymbolizeMemory(d+0x28, 8, name+".DriverSection")
    ctx.setu64(d+0x28, dte)

    # DriverExtension = dex
    ctx.setu64(d + 0x30, dex)
    # DriverName
    initUnicodeStr(ctx, d+0x38, "\\Driver\\" + name)

    # HardwareDatabase = ptr str
    hd = createUnicodeStr(ctx, "\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM")
    ctx.setu64(d + 0x48, hd)

    # FastIoDispatch = 0
    ctx.setu64(d + 0x50, 0x0)
    # DriverInit = DriverEntry
    ctx.setu64(d + 0x58, entry)
    # DriverStartIO = 0
    ctx.setu64(d + 0x60, 0x0)
    # DriverUnload = 0
    ctx.setu64(d + 0x68, 0x0)
    # MajorFunctions = 0
    ctx.setMemVal(d + 0x70, b"\x00" * 8 * 28)

    # initialize driver extension
    # ext.DriverObject = d
    ctx.setu64(dex + 0x00, d)
    # ext.AddDevice = 0
    ctx.setu64(dex + 0x08, 0)
    # ext.Count = 0
    ctx.setu64(dex + 0x10, 0)
    # ext.ServiceKeyName
    initUnicodeStr(ctx, dex+0x18, name)
    # ext.ClientDriverExtension = 0
    ctx.setu64(dex + 0x28, 0)
    # ext.FsFilterCallbacks = 0
    ctx.setu64(dex + 0x30, 0)
    # ext.KseCallbacks = 0
    ctx.setu64(dex + 0x38, 0)
    # ext.DvCallbacks = 0
    ctx.setu64(dex + 0x40, 0)
    # ext.VerifierContext = 0
    ctx.setu64(dex + 0x48, 0)

    return d

def createUnicodeStr(ctx, s):
    ustr = ctx.alloc(0x10)
    initUnicodeStr(ctx, ustr, s)
    return ustr

def initUnicodeStr(ctx, addr, s):
    us = s.encode("UTF-16-LE")
    buf = ctx.alloc(len(us))
    ctx.setMemVal(buf, us)

    ctx.setu16(addr + 0, len(us))
    ctx.setu16(addr + 2, len(us))
    ctx.setu64(addr + 0x8, buf)

def readUnicodeStr(ctx, addr):
    l = ctx.getu16(addr)
    ptr = ctx.getu64(addr+0x8)
    if ctx.issym and ctx.isSymbolizedMemory(addr+8, 8):
        print("Tried to read from a symbolized buffer in a unicode string")
        return ""
    b = ctx.getMemVal(ptr, l)
    return str(b, "UTF_16_LE")

def setIRQL(ctx, newlevel):
    oldirql = ctx.getRegVal(DB_X86_R_CR8)
    #TODO save old one at offset from gs see KeRaiseIrqlToDpcLevel
    ctx.setRegVal(DB_X86_R_CR8, newlevel)
    return oldirql

#TODO more helper stuff

#TODO add windows kernel api hooks here
# this file can be reimported as we continue to fill it out

# API to emulate first
# with this you can probably figue out the original target...
"""
BCryptDestroyHash
BCryptCloseAlgorithmProvider
__C_specific_handler
ZwReadFile
KeInitializeApc
KeInsertQueueApc
KeBugCheckEx
"""

poolAllocations = [] # see ExAllocatePoolWithTag
handles = {} # number : (object,)
nexthandle = 1

def ExAllocatePoolWithTag_hook(hook, ctx, addr, sz, op, provider):
    #TODO actually have an allocator? Hope they don't do this a lot
    #TODO memory permissions based on pool
    pool = ctx.getRegVal(DB_X86_R_RCX)
    amt = ctx.getRegVal(DB_X86_R_RDX)
    tag = struct.pack("<I", ctx.getRegVal(DB_X86_R_R8))

    area = ctx.alloc(amt)

    poolAllocations.append((pool, amt, tag, area))

    print("ExAllocatePoolWithTag", hex(amt), tag, '=', hex(area))

    ctx.doRet(area)
    return HookRet.OP_DONE_INS

def ExFreePoolWithTag_hook(hook, ctx, addr, sz, op, provider):
    #TODO actually do this?

    area = ctx.getRegVal(DB_X86_R_RCX)

    print("ExFreePoolWithTag", hex(area))

    ctx.doRet(area)
    return HookRet.OP_DONE_INS

def RtlDuplicateUnicodeString_hook(hook, ctx, addr, sz, op, provider):
    add_nul = ctx.getRegVal(DB_X86_R_RCX)
    src = ctx.getRegVal(DB_X86_R_RDX)
    dst = ctx.getRegVal(DB_X86_R_R8)

    # check bounds
    if not ctx.inBounds(src, 0x10, MEM_READ):
        print("RtlDuplicateUnicodeString: src oob")
        return HookRet.STOP_INS
    if not ctx.inBounds(dst, 0x10, MEM_WRITE):
        print("RtlDuplicateUnicodeString: dst oob")
        return HookRet.STOP_INS

    numbytes = ctx.getu16(src)
    srcbuf = ctx.getu64(src+8)

    srcval = b""

    if numbytes != 0:
        # check buffers
        if not ctx.inBounds(srcbuf, numbytes, MEM_READ):
            print("RtlDuplicateUnicodeString: src.buf oob")
            return HookRet.STOP_INS

        for i in range(numbytes):
            if ctx.issym and ctx.isSymbolizedMemory(srcbuf+i, 1):
                print("RtlDuplicateUnicodeString: symbolized in src.buf")
                return HookRet.STOP_INS

        srcval = ctx.getMemVal(srcbuf, numbytes)

    if add_nul > 1 or (add_nul == 1 and numbytes != 0):
        srcval += b"\x00\x00"

    if len(srcval) == 0:
        # null buffer, 0 len
        ctx.setu16(dst + 0x0, 0)
        ctx.setu16(dst + 0x2, 0)
        ctx.setu64(dst + 0x8, 0)
    else:
        dstbuf = ctx.alloc(len(srcval))
        ctx.setMemVal(dstbuf, srcval)
        ctx.setu16(dst + 0x0, numbytes)
        ctx.setu16(dst + 0x2, numbytes)
        ctx.setu64(dst + 0x8, dstbuf)

    s = str(srcval, "UTF_16_LE")

    ctx.doRet(0)

    print(f"RtlDuplicateUnicodeString : \"{s}\"")
    return HookRet.OP_DONE_INS

def IoCreateFileEx_hook(hook, ctx, addr, sz, op, provider):
    global nexthandle
    h = nexthandle
    nexthandle += 1

    phandle = ctx.getRegVal(DB_X86_R_RCX)
    oa = ctx.getRegVal(DB_X86_R_R8)
    iosb = ctx.getRegVal(DB_X86_R_R9)
    sp = ctx.getRegVal(DB_X86_R_RSP)
    disp = ctx.getu32(sp + 0x28 + (3 * 8))
    driverctx = ctx.getu64(sp + 0x28 + (10 * 8))

    if ctx.issym and ctx.isSymbolizedMemory(oa+0x10, 8):
        print("Unicode string in object attributes is symbolized")
        return HookRet.FORCE_STOP_INS
    namep = ctx.getu64(oa+0x10)
    name = readUnicodeStr(ctx, namep)

    ctx.setu64(phandle, h)

    # set up iosb
    info = 0
    disp_str = ""
    if disp == 0:
        disp_str = "FILE_SUPERSEDE"
        info = 0 # FILE_SUPERSEDED
    elif disp == 1:
        disp_str = "FILE_OPEN"
        info = 1 # FILE_OPENED
    elif disp == 2:
        disp_str = "FILE_CREATE"
        info = 2 # FILE_CREATED
    elif disp == 3:
        disp_str = "FILE_OPEN_IF"
        info = 2 # FILE_CREATED
    elif disp == 4:
        disp_str = "FILE_OVERWRITE_IF"
        info = 3 # FILE_OVERWRITTEN
    elif disp == 5:
        disp_str = "FILE_OVERWRITE_IF"
        info = 2 # FILE_CREATED
    ctx.setu64(iosb, 0)
    ctx.setu64(iosb+8, info)

    objinfo = (h, name, disp, driverctx, provider)
    handles[h] = objinfo

    ctx.doRet(0)

    print(f"IoCreateFileEx: \"{name}\" {disp_str} = {h}")

    return HookRet.STOP_INS

def ZwClose_hook(hook, ctx, addr, sz, op, provider):
    h = ctx.getRegVal(DB_X86_R_RCX)
    name = handles[h][1]
    del handles[h]
    print(f"Closed File {h} ({name})")
    ctx.doRet(0)
    return HookRet.OP_DONE_INS

def ZwWriteFile_hook(hook, ctx, addr, sz, op, provider):
    h = ctx.getRegVal(DB_X86_R_RCX)
    evt = ctx.getRegVal(DB_X86_R_RDX)
    apcrou = ctx.getRegVal(DB_X86_R_R8)
    apcctx = ctx.getRegVal(DB_X86_R_R9)
    sp = ctx.getRegVal(DB_X86_R_RSP)
    iosb = ctx.getu64(sp + 0x28 + (0 * 8))
    buf = ctx.getu64(sp + 0x28 + (1 * 8))
    blen = ctx.getu32(sp + 0x28 + (2 * 8))
    poff = ctx.getu64(sp + 0x28 + (3 * 8))

    if apcrou != 0:
        print("ZwWriteFile with apcroutine!")
        return HookRet.FORCE_STOP_INS

    name = handles[h][1]

    off = 0
    if poff != 0:
        off = ctx.getu64(poff)

    ctx.setu64(iosb, 0)
    ctx.setu64(iosb+8, blen)
    ctx.doRet(0)

    print(f"ZwWriteFile: {h}({name})) {hex(blen)} bytes{(' at offset ' + hex(off)) if poff != 0 else ''}")
    ctx.printMem(buf, blen)

    return HookRet.OP_DONE_INS

def ZwReadFile_hook(hook, ctx, addr, sz, op, provider):
    h = ctx.getRegVal(DB_X86_R_RCX)
    sp = ctx.getRegVal(DB_X86_R_RSP)
    iosb = ctx.getu64(sp + 0x28 + (0 * 8))
    buf = ctx.getu64(sp + 0x28 + (1 * 8))
    blen = ctx.getu32(sp + 0x28 + (2 * 8))
    poff = ctx.getu64(sp + 0x28 + (3 * 8))
    print(f"ZwReadFile: {h}({name}) {hex(blen)} into {hex(buf)}")
    if poff:
        offval = ctx.getu64(poff)
        print(f"Read is at offset {hex(offval)}")
    
    ctx.doRet(0)
    return HookRet.FORCE_STOP_INS

def ZwFlushBuffersFile_hook(hook, ctx, addr, sz, op, provider):
    h = ctx.getRegVal(DB_X86_R_RCX)
    iosb = ctx.getRegVal(DB_X86_R_RDX)
    ctx.setu64(iosb, 0)
    ctx.setu64(iosb+8, 0)

    print(f"ZwFlushBuffersFile {h}")
    ctx.doRet(0)

    return HookRet.DONE_INS

def KeAreAllApcsDisabled_hook(hook, ctx, addr, sz, op, provider):
    # checks:
    # currentthread.SpecialAcpDisable
    # KeAreInterruptsEnabled (IF in rflags)
    # cr8 == 0
    #TODO do all the above checks
    cr8val = ctx.getRegVal(DB_X86_R_CR8)
    ie = ((ctx.getRegVal(DB_X86_R_EFLAGS) >> 9) & 1)

    ret = 0 if cr8val == 0 and ie == 1 else 1
    print(f"KeAreAllApcsDisabled : {ret}")
    ctx.doRet(ret)
    return HookRet.DONE_INS

def KeIpiGenericCall_hook(hook, ctx, addr, sz, op, provider):
    fcn = ctx.getRegVal(DB_X86_R_RCX)
    arg = ctx.getRegVal(DB_X86_R_RDX)
    # set IRQL to IPI_LEVEL
    old_level = setIRQL(ctx, 0xe)
    # do IpiGeneric Call
    ctx.setRegVal(DB_X86_R_RCX, arg)
    ctx.setRegVal(DB_X86_R_RIP, fcn)

    # set hook for when we finish
    def finish_KeIpiGenericCall_hook(hook, ctx, addr, sz, op, provider):
        # remove self
        ctx.delHook(hook)

        setIRQL(ctx, old_level)

        rval = ctx.getRegVal(DB_X86_R_RAX)
        print(f"KeIpiGenericCall returned {hex(rval)}")

        return HookRet.OP_CONT_INS

    curstack = ctx.getRegVal(DB_X86_R_RSP)
    retaddr = ctx.getu64(curstack)

    ctx.addHook(retaddr, retaddr+1, MEM_EXECUTE, handler=finish_KeIpiGenericCall_hook, label="")
    print(f"KeIpiGenericCall {hex(fcn)} ({hex(arg)})")
    return HookRet.OP_DONE_INS

def ZwQuerySystemInformation_hook(hook, ctx, addr, sz, op, provider):
    infoclass = ctx.getRegVal(DB_X86_R_RCX)
    buf = ctx.getRegVal(DB_X86_R_RDX)
    buflen = ctx.getRegVal(DB_X86_R_R8)
    retlenptr = ctx.getRegVal(DB_X86_R_R9)

    if infoclass == 0x0b: #SystemModuleInformation
        # buffer should contain RTL_PROCESS_MODULES structure
        raise NotImplementedError(f"Unimplemented infoclass SystemModuleInformation in ZwQuerySystemInformation")
    elif infoclass == 0x4d: #SystemModuleInformationEx
        # buffer should contain RTL_PROCESS_MODULE_INFORMATION_EX
        # has to include the module we are emulating
        # just copy over a good buffer from the computer?
        # if they actually use the info we are in trouble
        # actually load in a bunch of modules? :(
        # might have to support paging in/out if that needs to happen
        # for now just try a good value
        # see side_utils for doing this from python to get example output
        # TODO provide a good output, but symbolize any real addresses
        raise NotImplementedError(f"Unimplemented infoclass SystemModuleInformationEx in ZwQuerySystemInformation")
    else:
        raise NotImplementedError(f"Unimplemented infoclass in ZwQuerySystemInformation : {hex(infoclass)}")

_thunk_symaddr0 = -1
def ExSystemTimeToLocalTime_hook(hook, ctx, addr, sz, op, provider):
    ctx.setRegVal(DB_X86_R_RIP, _thunk_symaddr0)
    print("ExSystemTimeToLocalTime")
    return HookRet.DONE_INS

_thunk_symaddr1 = -1
def RtlTimeToTimeFields_hook(hook, ctx, addr, sz, op, provider):
    ctx.setRegVal(DB_X86_R_RIP, _thunk_symaddr1)
    print("RtlTimeToTimeFields")
    return HookRet.DONE_INS

_thunk_symaddr2 = -1
def _stricmp_hook(hook, ctx, addr, sz, op, provider):
    ctx.setRegVal(DB_X86_R_RIP, _thunk_symaddr2)
    s1addr = ctx.getRegVal(DB_X86_R_RCX)
    s2addr = ctx.getRegVal(DB_X86_R_RDX)
    s1 = ctx.getCStr(s1addr)
    s2 = ctx.getCStr(s2addr)
    print(f"_stricmp \"{s1}\" vs \"{s2}\"")
    return HookRet.OP_DONE_INS

_thunk_symaddr3 = -1
def wcscat_s_hook(hook, ctx, addr, sz, op, provider):
    ctx.setRegVal(DB_X86_R_RIP, _thunk_symaddr3)
    s1addr = ctx.getRegVal(DB_X86_R_RCX)
    s2addr = ctx.getRegVal(DB_X86_R_R8)
    num = ctx.getRegVal(DB_X86_R_RDX)
    s1 = ctx.getCWStr(s1addr)
    s2 = ctx.getCWStr(s2addr)
    print(f"wcscat_s ({num}) \"{s1}\" += \"{s2}\"")
    return HookRet.OP_DONE_INS

_thunk_symaddr4 = -1
def wcscpy_s_hook(hook, ctx, addr, sz, op, provider):
    ctx.setRegVal(DB_X86_R_RIP, _thunk_symaddr4)
    dst = ctx.getRegVal(DB_X86_R_RCX)
    src = ctx.getRegVal(DB_X86_R_R8)
    num = ctx.getRegVal(DB_X86_R_RDX)
    s = ctx.getCWStr(src)
    print(f"wcscpy_s {hex(dst)[2:]}({num}) <= \"{s}\"")
    return HookRet.OP_DONE_INS

_thunk_symaddr5 = -1
def RtlInitUnicodeString_hook(hook, ctx, addr, sz, op, provider):
    ctx.setRegVal(DB_X86_R_RIP, _thunk_symaddr5)
    src = ctx.getRegVal(DB_X86_R_RDX)
    s = ctx.getCWStr(src)
    print(f"RtlInitUnicodeString \"{s}\"")
    return HookRet.OP_DONE_INS

_thunk_symaddr6 = -1
def swprintf_s_hook(hook, ctx, addr, sz, op, provider):
    ctx.setRegVal(DB_X86_R_RIP, _thunk_symaddr6)
    buf = ctx.getRegVal(DB_X86_R_RCX)
    fmt = ctx.getRegVal(DB_X86_R_R8)
    fmts = ctx.getCWStr(fmt)
    # set hook for after return
    sp = ctx.getRegVal(DB_X86_R_RSP)
    retaddr = ctx.getu64(sp)
    def finish_swprintf_s_hook(hook, ctx, addr, sz, op, provider):
        # remove self
        ctx.delHook(hook)
        s = ctx.getCWStr(buf)
        print(f"Finished swprintf_s: \"{s}\" from \"{fmts}\"")
        return HookRet.OP_CONT_INS
    ctx.addHook(retaddr, retaddr+1, MEM_EXECUTE, handler=finish_swprintf_s_hook, label="")
    return HookRet.OP_DONE_INS

_thunk_symaddr7 = -1
def vswprintf_s_hook(hook, ctx, addr, sz, op, provider):
    ctx.setRegVal(DB_X86_R_RIP, _thunk_symaddr7)
    buf = ctx.getRegVal(DB_X86_R_RCX)
    fmt = ctx.getRegVal(DB_X86_R_R8)
    fmts = ctx.getCWStr(fmt)
    # set hook for after return
    sp = ctx.getRegVal(DB_X86_R_RSP)
    retaddr = ctx.getu64(sp)
    def finish_vswprintf_s_hook(hook, ctx, addr, sz, op, provider):
        # remove self
        ctx.delHook(hook)
        s = ctx.getCWStr(buf)
        print(f"Finished vswprintf_s: \"{s}\" from \"{fmts}\"")
        return HookRet.OP_CONT_INS
    ctx.addHook(retaddr, retaddr+1, MEM_EXECUTE, handler=finish_vswprintf_s_hook, label="")
    return HookRet.OP_DONE_INS

_thunk_symaddr8 = -1
def _vsnwprintf_hook(hook, ctx, addr, sz, op, provider):
    ctx.setRegVal(DB_X86_R_RIP, _thunk_symaddr8)
    buf = ctx.getRegVal(DB_X86_R_RCX)
    fmt = ctx.getRegVal(DB_X86_R_R8)
    fmts = ctx.getCWStr(fmt)
    # set hook for after return
    sp = ctx.getRegVal(DB_X86_R_RSP)
    retaddr = ctx.getu64(sp)
    def finish__vsnwprintf_s_hook(hook, ctx, addr, sz, op, provider):
        # remove self
        ctx.delHook(hook)
        s = ctx.getCWStr(buf)
        print(f"Finished _vsnwprintf_s: \"{s}\" from \"{fmts}\"")
        return HookRet.OP_CONT_INS
    ctx.addHook(retaddr, retaddr+1, MEM_EXECUTE, handler=finish__vsnwprintf_s_hook, label="")
    return HookRet.OP_DONE_INS

def createThunkHooks(ctx):
    # have to be in higher scope for pickling the hooks
    global _thunk_symaddr0
    global _thunk_symaddr1
    global _thunk_symaddr2
    global _thunk_symaddr3
    global _thunk_symaddr4
    global _thunk_symaddr5
    global _thunk_symaddr6
    global _thunk_symaddr7
    global _thunk_symaddr8

    name = "ExSystemTimeToLocalTime"
    _thunk_symaddr0 = ctx.getImageSymbol(name, "ntoskrnl.exe")
    ctx.setApiHandler(name, ExSystemTimeToLocalTime_hook, "ignore")

    name = "RtlTimeToTimeFields"
    _thunk_symaddr1 = ctx.getImageSymbol(name, "ntoskrnl.exe")
    ctx.setApiHandler(name, RtlTimeToTimeFields_hook, "ignore")

    name = "_stricmp"
    _thunk_symaddr2 = ctx.getImageSymbol(name, "ntoskrnl.exe")
    ctx.setApiHandler(name, _stricmp_hook, "ignore")

    name = "wcscat_s"
    _thunk_symaddr3 = ctx.getImageSymbol(name, "ntoskrnl.exe")
    ctx.setApiHandler(name, wcscat_s_hook, "ignore")

    name = "wcscpy_s"
    _thunk_symaddr4 = ctx.getImageSymbol(name, "ntoskrnl.exe")
    ctx.setApiHandler(name, wcscpy_s_hook, "ignore")

    name = "RtlInitUnicodeString"
    _thunk_symaddr5 = ctx.getImageSymbol(name, "ntoskrnl.exe")
    ctx.setApiHandler(name, RtlInitUnicodeString_hook, "ignore")

    name = "swprintf_s"
    _thunk_symaddr6 = ctx.getImageSymbol(name, "ntoskrnl.exe")
    ctx.setApiHandler(name, swprintf_s_hook, "ignore")

    name = "vswprintf_s"
    _thunk_symaddr7 = ctx.getImageSymbol(name, "ntoskrnl.exe")
    ctx.setApiHandler(name, vswprintf_s_hook, "ignore")

    name = "_vsnwprintf"
    _thunk_symaddr8 = ctx.getImageSymbol(name, "ntoskrnl.exe")
    ctx.setApiHandler(name, _vsnwprintf_hook, "ignore")


def setNtosThunkHook(ctx, name, dostop):
    ctx.setApiHandler(name, ctx.createThunkHook(name, "ntoskrnl.exe", dostop), "ignore")

def registerWinHooks(ctx):
    ctx.setApiHandler("RtlDuplicateUnicodeString", RtlDuplicateUnicodeString_hook, "ignore")
    ctx.setApiHandler("ExAllocatePoolWithTag", ExAllocatePoolWithTag_hook, "ignore")
    ctx.setApiHandler("ExFreePoolWithTag", ExFreePoolWithTag_hook, "ignore")
    ctx.setApiHandler("IoCreateFileEx", IoCreateFileEx_hook, "ignore")
    ctx.setApiHandler("ZwClose", ZwClose_hook, "ignore")
    ctx.setApiHandler("ZwWriteFile", ZwWriteFile_hook, "ignore")
    ctx.setApiHandler("ZwFlushBuffersFile", ZwFlushBuffersFile_hook, "ignore")
    ctx.setApiHandler("KeAreAllApcsDisabled", KeAreAllApcsDisabled_hook, "ignore")
    ctx.setApiHandler("KeIpiGenericCall", KeIpiGenericCall_hook, "ignore")

    createThunkHooks(ctx)

def loadNtos(ctx, base=0xfffff8026be00000):
    # NOTE just because we load ntos doesn't mean it is initialized at all
    # Make sure you initalize the components you intend to use
    print("Loading nt...")
    ctx.loadPE("ntoskrnl.exe", base)
    print("Loaded!")

def kuser_time_hook(hk, ctx, addr, sz, op, provider):
    # InterruptTime is 100ns scale time since start
    it = ctx.getTicks()
    # SystemTime is 100ns scale, as timestamp
    st = ctx.getTime()
    # TickCount is 1ms scale, as ticks update as if interrupts have maximum period?
    # TODO adjust this?
    tc = int(it // 10000)

    # write the values back
    bts = struct.pack("<QI", tc, tc>>32)
    ctx.setMemVal(shared_data_addr + 0x320, bts)
    bts = struct.pack("<QIQI", it, it>>32, st, st>>32)
    ctx.setMemVal(shared_data_addr + 0x8, bts)

    if shared_data_addr + 0x8 <= addr < shared_data_addr + 0x14:
        print("Read from InterruptTime")
    if shared_data_addr + 0x14 <= addr < shared_data_addr + 0x20:
        print("Read from SystemTime")
    if shared_data_addr + 0x320 <= addr < shared_data_addr + 0x330:
        print("Read from TickCount")
    return HookRet.CONT_INS

def initSys(ctx):
    loadNtos(ctx)
    registerWinHooks(ctx)

    # setup KUSER_SHARED_DATA at 0xFFFFF78000000000
    shared_data_addr = 0xfffff78000000000
    shared_data_sz = 0x720
    ctx.addAnn(shared_data_addr, shared_data_addr + shared_data_sz, "GLOBAL", "_KUSER_SHARED_DATA")
    ctx.updateBounds(shared_data_addr, shared_data_addr + shared_data_sz, MEM_READ, False)

    #TODO verify tick count/time works how you think
    # time is # of 100-nanosecond intervals
    # these numbers aren't actually any good because we hook out a looot of functionality?
    # but eh, if things don't work then use a volatile symbol hook here

    ctx.addHook(shared_data_addr + 0x8, shared_data_addr+0x20, MEM_READ, kuser_time_hook, "Interrupt and System Time hook")
    ctx.addHook(shared_data_addr + 0x320, shared_data_addr+0x32c, MEM_READ, kuser_time_hook, "Tick Time hook")

    ctx.setMemVal(
        shared_data_addr + 0x0,
        b'\x00\x00\x00\x00' +  # +0x0 .TickCountLowDeprecated
        b'\x00\x00\xa0\x0f' +  # +0x4 .TickCountMultiplier
        # HOOK THIS and use instruction count to add to it
        b'O\xcaW[\xd8\x05\x00\x00\xd8\x05\x00\x00' +  # +0x8 .InterruptTime
        # HOOK THIS and use instruction count to add to it
        b'\x19E~M\xe7\x8c\xd6\x01\xe7\x8c\xd6\x01' +  # +0x14 .SystemTime
        b'\x00\xa0\x11\x87!\x00\x00\x00!\x00\x00\x00' +  # +0x20 .TimeZoneBias
        b'd\x86' +  # +0x2c .ImageNumberLow
        b'd\x86' +  # +0x2e .ImageNumberHigh
        b'C\x00:\x00\\\x00W\x00I\x00N\x00D\x00O\x00' +  # +0x30 .NtSystemRoot
        b'W\x00S\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00' +  # +0x238 .MaxStackTraceDepth
        b'\x00\x00\x00\x00' +  # +0x23c .CryptoExponent
        b'\x02\x00\x00\x00' +  # +0x240 .TimeZoneId
        b'\x00\x00 \x00' +  # +0x244 .LargePageMinimum
        b'\x00\x00\x00\x00' +  # +0x248 .AitSamplingValue
        b'\x00\x00\x00\x00' +  # +0x24c .AppCompatFlag
        b'I\x00\x00\x00\x00\x00\x00\x00' +  # +0x250 .RNGSeedVersion
        b'\x00\x00\x00\x00' +  # +0x258 .GlobalValidationRunlevel
        b'\x1c\x00\x00\x00' +  # +0x25c .TimeZoneBiasStamp
        b'aJ\x00\x00' +  # +0x260 .NtBuildNumber
        b'\x01\x00\x00\x00' +  # +0x264 .NtProductType
        b'\x01' +  # +0x268 .ProductTypeIsValid
        b'\x00' +  # +0x269 .Reserved0
        b'\t\x00' +  # +0x26a .NativeProcessorArchitecture
        b'\n\x00\x00\x00' +  # +0x26c .NtMajorVersion
        b'\x00\x00\x00\x00' +  # +0x270 .NtMinorVersion
    #ctx.symbolizeMemory(MemoryAccess(shared_data_addr + 0x274, 0x4), "kuser_shared_data.ProcessorFeature[0:4]")
    #ctx.symbolizeMemory(MemoryAccess(shared_data_addr + 0x278, 0x8), "kuser_shared_data.ProcessorFeature[4:c]")
    #ctx.symbolizeMemory(MemoryAccess(shared_data_addr + 0x280, 0x20), "kuser_shared_data.ProcessorFeature[c:2c]")
    #ctx.symbolizeMemory(MemoryAccess(shared_data_addr + 0x2a0, 0x10), "kuser_shared_data.ProcessorFeature[2c:3c]")
    #ctx.symbolizeMemory(MemoryAccess(shared_data_addr + 0x2b0, 0x8), "kuser_shared_data.ProcessorFeature[3c:44]")
    #ctx.symbolizeMemory(MemoryAccess(shared_data_addr + 0x2b8, 0x4), "kuser_shared_data.reserved3")
        b'\x00\x00\x01\x01\x00\x00\x01\x00\x01\x01\x01\x00\x01\x01\x01\x00' +  # +0x274 .ProcessorFeatures
        b'\x00\x01\x00\x00\x00\x01\x01\x01\x00\x00\x00\x00\x01\x00\x00\x00' +
        b'\x01\x01\x00\x00\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\xff\xff\xfe\x7f' +  # +0x2b4 .Reserved1
        b'\x00\x00\x00\x80' +  # +0x2b8 .Reserved3
        b'\x00\x00\x00\x00' +  # +0x2bc .TimeSlip
        b'\x00\x00\x00\x00' +  # +0x2c0 .AlternativeArchitecture
        b' \x00\x00\x00' +  # +0x2c4 .BootId
        b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # +0x2c8 .SystemExpirationDate
        b'\x10\x03\x00\x00' +  # +0x2d0 .SuiteMask
        # Yeah, go ahead and keep this one a 0
        b'\x00' +  # +0x2d4 .KdDebuggerEnabled # Yeah, go ahead and keep this one a 0
        b'\n' +  # +0x2d5 .Reserved
        b'<\x00' +  # +0x2d6 .CyclesPerYield
        b'\x01\x00\x00\x00' +  # +0x2d8 .ActiveConsoleId
        b'\x04\x00\x00\x00' +  # +0x2dc .DismountCount
        b'\x01\x00\x00\x00'    # +0x2e0 .ComPlusPackage
    )
    #TODO hook this properly
    ctx.trySymbolizeMemory(shared_data_addr + 0x2e4, 0x4, "kuser_shared_data.LastSystemRITEventTickCount")
        #b'\xc9\x85N&' +  # +0x2e4 .LastSystemRITEventTickCount

    ctx.setMemVal(
        shared_data_addr + 0x2e8,
        b'\x94\xbb?\x00' +  # +0x2e8 .NumberOfPhysicalPages
        b'\x00' +  # +0x2ec .SafeBootMode
        b'\x01' +  # +0x2ed .VirtualizationFlags #TODO worth symbolizing?
        b'\x00\x00' +  # +0x2ee .Reserved12
        #TODO should any of these be changed?
        #   ULONG DbgErrorPortPresent       : 1;
        #   ULONG DbgElevationEnabled       : 1; // second bit 
        #   ULONG DbgVirtEnabled            : 1; // third bit
        #   ULONG DbgInstallerDetectEnabled : 1; // fourth bit
        #   ULONG DbgSystemDllRelocated     : 1;
        #   ULONG DbgDynProcessorEnabled    : 1;
        #   ULONG DbgSEHValidationEnabled   : 1;
        #   ULONG SpareBits                 : 25;
        b'\x0e\x01\x00\x00' +  # +0x2f0 .SpareBits
        b'\x00\x00\x00\x00' +  # +0x2f4 .DataFlagsPad
        b'\xc3\x00\x00\x00\x00\x00\x00\x00' +  # +0x2f8 .TestRetInstruction
        b'\x80\x96\x98\x00\x00\x00\x00\x00' +  # +0x300 .QpcFrequency
        b'\x00\x00\x00\x00' +  # +0x308 .SystemCall
        b'\x00\x00\x00\x00' +  # +0x30c .UserCetAvailableEnvironments
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +  # +0x310 .SystemCallPad
        # HOOK THIS and use instruction count to add to it
        b'\x17\x9es\x02\x00\x00\x00\x00\x00\x00\x00\x00' +  # +0x320 .ReservedTickCountOverlay
        b'\x00\x00\x00\x00' +  # +0x32c .TickCountPad
        b'\xd3PB\x1b' +  # +0x330 .Cookie
        b'\x00\x00\x00\x00' +  # +0x334 .CookiePad
        b'\xbc\x1d\x00\x00\x00\x00\x00\x00' +  # +0x338 .ConsoleSessionForegroundProcessId
        #TODO hook this?
        b'\xa2{H\x1a\x00\x00\x00\x00' +  # +0x340 .TimeUpdateLock
        b'-\x83\x87[\xd8\x05\x00\x00' +  # +0x348 .BaselineSystemTimeQpc
        b'-\x83\x87[\xd8\x05\x00\x00' +  # +0x350 .BaselineInterruptTimeQpc
        b'\x00\x00\x00\x00\x00\x00\x00\x80' +  # +0x358 .QpcSystemTimeIncrement
        b'\x00\x00\x00\x00\x00\x00\x00\x80' +  # +0x360 .QpcInterruptTimeIncrement
        b'\x01' +  # +0x368 .QpcSystemTimeIncrementShift
        b'\x01' +  # +0x369 .QpcInterruptTimeIncrementShift
        b'\x18\x00' +  # +0x36a .UnparkedProcessorCount
        b'\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +  # +0x36c .EnclaveFeatureMask
        b'\x03\x00\x00\x00' +  # +0x37c .TelemetryCoverageRound
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +  # +0x380 .UserModeGlobalLogger
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00' +  # +0x3a0 .ImageFileExecutionOptions
        b'\x01\x00\x00\x00' +  # +0x3a4 .LangGenerationCount
        b'\x00\x00\x00\x00\x00\x00\x00\x00' +  # +0x3a8 .Reserved4
        b'\x17\xfc\x9eU\xd8\x03\x00\x00' +  # +0x3b0 .InterruptTimeBias
        b'\xcd"\x15G\xd8\x03\x00\x00' +  # +0x3b8 .QpcBias
        b'\x18\x00\x00\x00' +  # +0x3c0 .ActiveProcessorCount
        b'\x01' +  # +0x3c4 .ActiveGroupCount
        b'\x00' +  # +0x3c5 .Reserved9
        b'\x83' +  # +0x3c6 .QpcBypassEnabled
        b'\x00' +  # +0x3c7 .QpcShift
        b'\x9a,\x17\xcdq\x8c\xd6\x01' +  # +0x3c8 .TimeZoneBiasEffectiveStart
        b'\x000\x9d;\x14\xb0\xd6\x01' +  # +0x3d0 .TimeZoneBiasEffectiveEnd
        b'\x07\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00' +  # +0x3d8 .XState
        b'@\x03\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\xa0\x00\x00\x00' +
        b'\xa0\x00\x00\x00\x00\x01\x00\x00@\x02\x00\x00\x00\x01\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00@\x03\x00\x00\xa0\x00\x00\x00' +
        b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x00\x00\x00\x00\x00\x00\x00\x00' +
        b'\x12\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' +  # +0x710 .FeatureConfigurationChangeStamp
        b'\x00\x00\x00\x00'    # +0x71c .Spare
    )

    # setup KPCR and KPRCB
    #TODO



