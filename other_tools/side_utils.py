
# windbg helper scripts

# needs to handle unions and multi level pieces
def parse_dt(dtstr):
    out = []
    last_lvl = [0]
    #TODO handle unions when we handle nested types
    for l in dtstr.split('\n'):
        if not l.strip().startswith("+0x"):
            #TODO
            continue
        if not l.startswith('   '):
            print("line =", l)
            #TODO
            raise NotImplementedError("Need to implement nested type dt parsing")
        ll = l.split()
        if ll[0].startswith('+0x'):
            out.append((int(ll[0][3:],16), ll[1]))

    if out[0][0] != 0:
        raise TypeError("dtstr does not have a type that starts at zero?")
    return out

def parse_db(dbstr):
    out = b""
    for l in dbstr.split('\n'):
        out += bytes.fromhex(l.split("  ")[1].replace('-', ''))
    return out

def gen_sym_type(dtstr, typesize, addr, name):
    #TODO allow addr to be a variable name
    dt = parse_dt(dtstr)
    out = ""
    for i in range(len(dt)):
        e = typesize
        if i != (len(dt)-1):
            e = dt[i+1][0]
        sz = e - dt[i][0]
        # hopefully it fits in a MemoryAccess size
        out += f"ctx.symbolizeMemory(MemoryAccess( {hex(addr + dt[i][0])} , {hex(sz)} ), \"{name + '.' + dt[i][1]}\")\n"
    return out

def gen_mem_init(dtstr, dbstr, addr, name=""):
    #TODO allow addr to be a variable name
    dt = parse_dt(dtstr)
    db = parse_db(dbstr)
    typesize = len(db)

    out = ""
    for i in range(len(dt)):
        e = typesize
        if i != (len(dt)-1):
            e = dt[i+1][0]
        s = dt[i][0]
    
        out +=  "ctx.api.setConcreteMemoryAreaValue(\n"
        out += f"    {hex(addr + dt[i][0])}, # {name + '.' + dt[i][1]}\n"
        out += f"    bytes.fromhex(\"{db[s:e].hex()}\")\n"
        out +=  ")\n"

    return out

def gen_commented_memdmp(dtstr, dbstr):
    dt = parse_dt(dtstr)
    db = parse_db(dbstr)

    # cut up where we have
    out = ""
    for d in dt[::-1]:
        b = db[d[0]:]
        bl = [ b[i:i+0x10] for i in range(0x0, len(b), 0x10) ]
        first = True
        line = ""
        for bi in bl:
            line += str(bi)
            line += " + "
            if first:
                line += " # +" + hex(d[0]) + " ." + d[1]
            line += "\n"
            first = False

        db = db[:d[0]]
        out = line + out

    out += "b\"\"\n"
    return out


import ctypes
import struct

def QuerySysInfo(infoclass=0x4d):
    retsz = ctypes.c_ulong(0)
    retszptr = ctypes.pointer(retsz)
    ctypes.windll.ntdll.NtQuerySystemInformation(infoclass, 0, 0, retszptr)
    buf = (ctypes.c_byte * retsz.value)()
    ctypes.windll.ntdll.NtQuerySystemInformation(infoclass, buf, len(buf), retszptr)
    return bytes(buf)

def quickhex(chunk):
    spced = ' '.join([chunk[i:i+1].hex() for i in range(len(chunk))])
    fourd = '  '.join([spced[i:i+(4*3)] for i in range(0, len(spced), (4*3))])
    sxtnd = '\n'.join([fourd[i:i+(((4*3)+2)*4)] for i in range(0, len(fourd), (((4*3)+2)*4))])
    print(sxtnd)

def parseModInfoEx(infobuf):
    #TODO
    fmt = "<HHIQQQIIHHHH256sIIQ"
    off = 0
    modinfo = []
    while True:
        nextoff = struct.unpack("<H", infobuf[off:off+2])[0]
        if nextoff == 0:
            break
        vals = struct.unpack(fmt, infobuf[off:off+struct.calcsize(fmt)])
        (
            nextoff,
            pad, pad,
            section,
            mapbase,
            imgbase,
            imgsz,
            flags,
            loadorder,
            initorder,
            loadcount,
            nameoff,
            pathname,
            chksum,
            timedate,
            defbase,
        ) = vals
        pend = pathname.find(b'\x00')
        if pend != -1:
            pathname = pathname[:pend]
        name = pathname[nameoff:]
        modinfo.append({
            "Section": section,
            "MappedBase": mapbase,
            "ImageBase": imgbase,
            "ImageSize": imgsz,
            "Flags": flags,
            "LoadOrderIndex": loadorder,
            "InitOrderIndex": initorder,
            "LoadCount": loadcount,
            "Name": name,
            "Path": pathname,
            "ImageChecksum": chksum,
            "TimeDataStamp": timedate,
            "DefaultBase": defbase,
        })
        off += nextoff
    return modinfo
