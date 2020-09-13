if __name__ == '__main__':
    print("Please import this file from a dobby script")
    exit(-1)

import struct
from dobby import *
from triton import *

# windows kernel helper functions
def createDrvObj(ctx, start, size, entry, name="DriverObj"):
    dobjsz = 0x150
    d = ctx.alloc(dobjsz)
    dex = ctx.alloc(0x50)

    # initialize driver object
    # type = 0x4
    ctx.api.setConcreteMemoryAreaValue(d + 0x00, struct.pack("<H", 0x4))
    # size = 0x150
    ctx.api.setConcreteMemoryAreaValue(d + 0x02, struct.pack("<H", dobjsz))
    # DeviceObject = 0
    ctx.api.setConcreteMemoryAreaValue(d + 0x08, struct.pack("<Q", 0x0))
    
    # flags = ??
    #TODO
    ctx.api.symbolizeMemory(MemoryAccess(d+0x10, 8), name+".Flags")

    # DriverStart = start
    ctx.api.setConcreteMemoryAreaValue(d + 0x18, struct.pack("<Q", start))
    # DriverSize = size
    ctx.api.setConcreteMemoryAreaValue(d + 0x20, struct.pack("<I", size))
    
    # DriverSection = ??
    #TODO
    ctx.api.symbolizeMemory(MemoryAccess(d+0x28, 8), name+".DriverSection")
 
    # DriverExtension = dex
    ctx.api.setConcreteMemoryAreaValue(d + 0x30, struct.pack("<Q", dex))
    # DriverName
    initUnicodeStr(ctx, d+0x38, "\\Driver\\" + name)

    # HardwareDatabase = ptr str
    hd = createUnicodeStr(ctx, "\\REGISTRY\\MACHINE\\HARDWARE\\DESCRIPTION\\SYSTEM")
    ctx.api.setConcreteMemoryAreaValue(d + 0x48, struct.pack("<Q", hd))

    # FastIoDispatch = 0
    ctx.api.setConcreteMemoryAreaValue(d + 0x50, struct.pack("<Q", 0x0))
    # DriverInit = DriverEntry
    ctx.api.setConcreteMemoryAreaValue(d + 0x58, struct.pack("<Q", entry))
    # DriverStartIO = 0
    ctx.api.setConcreteMemoryAreaValue(d + 0x60, struct.pack("<Q", 0x0))
    # DriverUnload = 0
    ctx.api.setConcreteMemoryAreaValue(d + 0x68, struct.pack("<Q", 0x0))
    # MajorFunctions = 0
    ctx.api.setConcreteMemoryAreaValue(d + 0x70, b"\x00" * 8 * 28)

    # initialize driver extension
    # ext.DriverObject = d
    ctx.api.setConcreteMemoryAreaValue(dex + 0x00, struct.pack("<Q", d))
    # ext.AddDevice = 0
    ctx.api.setConcreteMemoryAreaValue(dex + 0x08, struct.pack("<Q", 0))
    # ext.Count = 0
    ctx.api.setConcreteMemoryAreaValue(dex + 0x10, struct.pack("<Q", 0))
    # ext.ServiceKeyName
    initUnicodeStr(ctx, dex+0x18, name)
    # ext.ClientDriverExtension = 0
    ctx.api.setConcreteMemoryAreaValue(dex + 0x28, struct.pack("<Q", 0))
    # ext.FsFilterCallbacks = 0
    ctx.api.setConcreteMemoryAreaValue(dex + 0x30, struct.pack("<Q", 0))
    # ext.KseCallbacks = 0
    ctx.api.setConcreteMemoryAreaValue(dex + 0x38, struct.pack("<Q", 0))
    # ext.DvCallbacks = 0
    ctx.api.setConcreteMemoryAreaValue(dex + 0x40, struct.pack("<Q", 0))
    # ext.VerifierContext = 0
    ctx.api.setConcreteMemoryAreaValue(dex + 0x48, struct.pack("<Q", 0))

    return d

def createUnicodeStr(ctx, s):
    ustr = ctx.alloc(0x10)
    initUnicodeStr(ctx, ustr, s)
    return ustr

def initUnicodeStr(ctx, addr, s):
    us = s.encode("UTF-16-LE")
    buf = ctx.alloc(len(us))
    ctx.api.setConcreteMemoryAreaValue(buf, us)

    ctx.api.setConcreteMemoryAreaValue(addr + 0, struct.pack("<H", len(us)))
    ctx.api.setConcreteMemoryAreaValue(addr + 2, struct.pack("<H", len(us)))
    ctx.api.setConcreteMemoryAreaValue(addr + 0x8, struct.pack("<Q", buf))


#TODO more helper stuff

#TODO add windows kernel api hooks here
# this file can be reimported as we continue to fill it out

# API to emulate first
# with this you can probably figue out the original target...
"""
BCryptDestroyHash
BCryptCloseAlgorithmProvider
KeIpiGenericCall
__C_specific_handler
ExFreePoolWithTag
ZwClose
_stricmp
RtlDuplicateUnicodeString
wcscat_s
wcscpy_s
RtlInitUnicodeString
ZwReadFile
ZwWriteFile
IoCreateFileEx
ZwFlushBuffersFile
ZwQuerySystemInformation
RtlTimeToTimeFields
KeAreAllApcsDisabled
ExSystemTimeToLocalTime
swprintf_s
vswprintf_s
_vsnwprintf
KeInitializeApc
KeInsertQueueApc
ExAllocatePoolWithTag
KeBugCheckEx
"""


def RtlDuplicateUnicodeString_hook(hook, ctx, addr, sz, op):
    # check nothing is symbolized
    if ctx.api.isRegisterSymbolized(ctx.api.registers.rcx):
        print("RtlDuplicateUnicodeString: rcx symbolized")
        return HookRet.STOP_INS
    if ctx.api.isRegisterSymbolized(ctx.api.registers.rdx):
        print("RtlDuplicateUnicodeString: rdx symbolized")
        return HookRet.STOP_INS
    if ctx.api.isRegisterSymbolized(ctx.api.registers.r8):
        print("RtlDuplicateUnicodeString: r8 symbolized")
        return HookRet.STOP_INS

    add_nul = ctx.api.getConcreteRegisterValue(ctx.api.registers.rcx)
    src = ctx.api.getConcreteRegisterValue(ctx.api.registers.rdx)
    dst = ctx.api.getConcreteRegisterValue(ctx.api.registers.r8)

    # check bounds
    if not ctx.inBounds(src, 0x10):
        print("RtlDuplicateUnicodeString: src oob")
        return HookRet.STOP_INS
    if not ctx.inBounds(dst, 0x10):
        print("RtlDuplicateUnicodeString: dst oob")
        return HookRet.STOP_INS

    numbytes = ctx.getu16(src)
    srcbuf = ctx.getu64(src+8)

    srcval = b""

    if numbytes != 0:
        # check buffers
        if not ctx.inBounds(srcbuf, numbytes):
            print("RtlDuplicateUnicodeString: src.buf oob")
            return HookRet.STOP_INS

        for i in range(numbytes):
            if ctx.api.isMemorySymbolized(MemoryAccess(srcbuf+i, 1)):
                print("RtlDuplicateUnicodeString: symbolized in src.buf")
                return HookRet.STOP_INS
            
        srcval = ctx.api.getConcreteMemoryAreaValue(srcbuf, numbytes)

    if add_nul > 1 or (add_nul == 1 and numbytes != 0):
        srcval += b"\x00\x00"

    if len(srcval) == 0:
        # null buffer, 0 len
        ctx.setu16(dst + 0x0, 0)
        ctx.setu16(dst + 0x2, 0)
        ctx.setu64(dst + 0x8, 0)
    else:
        dstbuf = ctx.alloc(len(srcval))
        ctx.api.setConcreteMemoryAreaValue(dstbuf, srcval)
        ctx.setu16(dst + 0x0, numbytes)
        ctx.setu16(dst + 0x2, numbytes)
        ctx.setu64(dst + 0x8, dstbuf)

    ctx.doRet(0)

    return HookRet.DONE_INS
    #print("DEBUG: Did RtlDuplicateUnicodeString")
    #return HookRet.STOP_INS

def registerWinHooks(ctx):
    ctx.setApiHandler("RtlDuplicateUnicodeString", RtlDuplicateUnicodeString_hook, "ignore")


def initSys(ctx):
    registerWinHooks(ctx)

    # setup KUSER_SHARED_DATA
    #TODO

    # setup KPCR and KPRCB
    #TODO
