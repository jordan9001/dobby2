
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
