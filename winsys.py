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

def ExSystemTimeToLocalTime_hook(hook, ctx, addr, sz, op):
    #TODO
    print("Hook creation in progress")
    return HookRet.FORCE_STOP_INS

def registerWinHooks(ctx):
    ctx.setApiHandler("RtlDuplicateUnicodeString", RtlDuplicateUnicodeString_hook, "ignore")
    ctx.setApiHandler("ExSystemTimeToLocalTime", ctx.createThunkHook("ExSystemTimeToLocalTime", "ntoskrnl.exe"), "ignore") 

def loadNtos(ctx, base=0xfffff8026be00000):
    # NOTE just because we load ntos doesn't mean it is initialized at all
    # Make sure you initalize the components you intend to use
    print("Loading nt...")
    ctx.loadPE("ntoskrnl.exe", base)
    print("Loaded!")

def initSys(ctx):
    loadNtos(ctx)
    registerWinHooks(ctx)

    # setup KUSER_SHARED_DATA at 0xFFFFF78000000000
    shared_data_addr = 0xfffff78000000000
    shared_data_sz = 0x720
    ctx.addAnn(shared_data_addr, shared_data_addr + shared_data_sz, "GLOBAL", True, "_KUSER_SHARED_DATA.Timers")

    last_inscnt = ctx.inscount
    nrover = 0
    mrover = 0
    
    IPC = 16 # instructions / Cycle
    F = 3.2  # GigaCycles / Second == Cycles / Nanosecond
    IPN = IPC * F * 100 # instructions per 100nanosecond
    IPM = IPN * 10000   # instructions per millisecond
    NPI = 1.0/IPN
    TPI = 1.0/IPM
    #TODO verify tick count/time works how you think
    # time is # of 100-nanosecond intervals
    # these numbers aren't actually any good because we hook out a looot of functionality?
    # but eh, if things don't work then use a volatile symbol hook here

    def kuser_time_hook(hk, ctx, addr, sz, op):
        nonlocal last_inscnt
        nonlocal nrover
        nonlocal mrover
        dif = ctx.inscount - last_inscnt 
        last_inscnt = ctx.inscount

        nrover += dif
        mrover += dif

        if op != "r":
            print(f"Attempted {op} on kuser timer")
            return HookRet.STOP_INS

        # get timers at 0x8, 0x14
        bts = ctx.api.getConcreteMemoryAreaValue(shared_data_addr + 0x8, 0x18)
        it, _, st, _ = struct.unpack("<QIQI", bts)
        # get tick count at 0x320
        bts = ctx.api.getConcreteMemoryAreaValue(shared_data_addr + 0x320, 0xc)
        tc, _ = struct.unpack("<QI", bts)

        #TODO update timers based on dif
        # timers are in 100-ns intervals
        # tick is in millisecond intervals
        # ticks account for sleep and hibernation

        ndif = int(nrover * NPI)
        mdif = int(mrover * TPI)
        nrover -= ndif * IPN
        mrover -= mdif * IPM
        
        it += ndif
        st += ndif
        tc += mdif

        # write the values back
        bts = struct.pack("<QI", tc, tc>>32)
        ctx.api.setConcreteMemoryAreaValue(shared_data_addr + 0x320, bts)
        bts = struct.pack("<QIQI", it, it>>32, st, st>>32)
        ctx.api.setConcreteMemoryAreaValue(shared_data_addr + 0x8, bts)

        #DEBUG
        print("Read from a shared timer")
        #return HookRet.STOP_INS #DEBUG
        return HookRet.CONT_INS

    ctx.addHook(shared_data_addr + 0x8, shared_data_addr+0x20, "r", kuser_time_hook, False, "Interrupt and System Time hook")
    ctx.addHook(shared_data_addr + 0x320, shared_data_addr+0x32c, "r", kuser_time_hook, False, "Tick Time hook")

    ctx.api.setConcreteMemoryAreaValue(
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
    ctx.api.symbolizeMemory(MemoryAccess(shared_data_addr + 0x2e4, 0x4), "kuser_shared_data.LastSystemRITEventTickCount")
        #b'\xc9\x85N&' +  # +0x2e4 .LastSystemRITEventTickCount

    ctx.api.setConcreteMemoryAreaValue(
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



