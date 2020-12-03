import pyvex
import archinfo

def getRegInOut(ctx, address, inslen=15, arch=None, oneins=True, ignorereg=[]):
    b = ctx.getMemVal(address, inslen)
    if arch is None:
        arch = archinfo.ArchAMD64()
    irsb = pyvex.lift(b, address, arch)

    out = [[],[]] # [[regin][regout]]

    for s in irsb.statements[1:]:
        if isinstance(s, pyvex.IRStmt.IMark):
            if oneins:
                #bad inslen, grab again, otherwise we miss things
                #unless we really have the full block
                return getRegInOut(ctx, address, s.addr - address, arch, oneins, ignorereg)
        elif isinstance(s, pyvex.IRStmt.Put):
            roff = s.offset
            rsz = s.data.result_size(irsb.tyenv)//8
            for i in range(rsz):
                r = roff + i
                if r not in ignorereg:
                    out[1].append(r)

        for e in s.expressions:
            if isinstance(e, pyvex.IRStmt.Get):
                roff = e.offset
                rsz = e.result_size(irsb.tyenv)//8
                for i in range(rsz):
                    r = roff + i
                    if r not in ignorereg:
                        out[0].append(r)

    # if there is an option for changing RIP here, we need to report RIP as an output
    #if not isinstance(irsb.next, pyvex.expr.Const):
    #    out[1].append("rip")

    return out

def revtainttrace(ctx, trace, intaintedaddrs, intaintedregs, outputtrace=None, printinfo=False):
    # tainted addrs is a set of addresses, for each byte tainted
    # tainted regs is a set of register, currently string names
    # convert registers to offsets in pyvex arch style
    taintedregs = set()
    taintedaddrs = set()

    arch = archinfo.ArchAMD64()
    for r in intaintedregs:
        rname = r
        if not isinstance(r, str):
            rname = r.getName()
        roff, rsz = arch.registers[rname]
        for i in range(rsz):
            taintedregs.add(roff + i)

    for addr, sz in intaintedaddrs:
        for i in range(sz):
            taintedaddrs.append(addr+i)

    #DEBUG
    ignorereg = []
    for r in arch.registers:
        # cc is too broad of a register, taints too much
        # sp is also misused by VEX in some of the instructions?
        # so this isn't 100% accurate, but still gives me some good answers
        if r.startswith("cc_") or r.endswith("sp"):
            roff, rsz = arch.registers[r]
            for i in range(rsz):
                ignorereg.append(roff+i)

    taintedins = 1

    for i in range(len(trace)-1, -1, -1):
        if not printinfo and (i & 0xfff == 0):
            print(f"{i:x}\t{taintedins/len(trace):.2%} tainted\tTaintedRegs: {strVexRegSet(arch, taintedregs)}, num adders = {len(taintedaddrs)}")
        te = trace[i]
        if te[0] == -1:
            # Got an api area!
            # if rax is tainted, we issue a stop here
            # if any volatile register is tainted, issue a stop here
            #TODO
            continue
        if len(te) < 3:
            raise ValueError("Need drefs in trace for reverse taint analysis")
        l = 15 if len(te) < 4 else te[3]
        regs = getRegInOut(ctx, te[0], l, arch, True, ignorereg)
        # if one of the output registers or addresses was in our tainted list:
        # remove registers output this last instruction
        # add registers input
        # remove memory written
        # add memory read
        spreads = False
        for r in regs[1]:
            if r in taintedregs:
                spreads = True
                break
        # check written addresses
        for addr, sz in te[2][1]:
            for i in range(sz):
                if addr+i in taintedaddrs:
                    spreads = True

        if printinfo:
            print(f"@{te[0]:x} : {te[1]} : {strVexRegSet(arch, regs[0])} : {strVexRegSet(arch, regs[1])}")

        if spreads:
            taintedins += 1
            # remove outputs we were tracking that got written out
            for r in regs[1]:
                if r in taintedregs:
                    taintedregs.remove(r)
            for addr, sz in te[2][1]:
                for i in range(sz):
                    if addr+i in taintedaddrs:
                        taintedaddrs.remove(addr+i)
            # add inputs
            for r in regs[0]:
                taintedregs.add(r)
            for addr, sz in te[2][0]:
                for i in range(sz):
                    taintedaddrs.add(addr+i)
            if printinfo:
                print(f"\tTaintedRegs: {strVexRegSet(arch, taintedregs)}, num adders = {len(taintedaddrs)}")

            if outputtrace is not None:
                # will be in reverse order
                outputtrace.append(trace[i])

    print(f"{taintedins}/{len(trace)} = {taintedins/len(trace):.2%} tainted")

    #change vex offsets back to real registers
    return (taintedaddrs, strVexRegSet(arch,taintedregs))

def strVexRegSet(arch, regs):
    offs = arch.register_names
    out = set()
    for r in regs:
        if r in offs:
            out.add(arch.register_names[r])
    return ','.join(out)
