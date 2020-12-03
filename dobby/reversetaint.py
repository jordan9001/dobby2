import pyvex
import archinfo

def getRegInOut(ctx, address, inslen=15, oneins=True):
    b = ctx.getMemVal(address, inslen)
    irsb = pyvex.lift(b, address, archinfo.ArchAMD64())

    out = [[],[]] # [[regin][regout]]

    for s in irsb.statements[1:]:
        s.pp()
        if isinstance(s, pyvex.IRStmt.IMark):
            if oneins:
                #bad inslen, grab again, otherwise we miss things
                #unless we really have the full block
                return getRegInOut(ctx, address, s.addr - address)
        elif isinstance(s, pyvex.IRStmt.Put):
            roff = s.offset
            out[1].append(irsb.arch.register_names[roff])
        for e in s.expressions:
            if isinstance(e, pyvex.IRStmt.Get):
                roff = e.offset
                out[0].append(irsb.arch.register_names[roff])

    return out

def revtainttrace(ctx, trace, taintedaddrs, taintedregs, outputtrace=None):
    # tainted addrs is a set of addresses, for each byte tainted
    # tainted regs is a set of register, currently string names
    #TODO use DB reg constants, not strings
    for te in trace[:-45:-1]:
        if te[0] == -1:
            # Got an api area!
            # if rax is tainted, we issue a stop here
            # if any volatile register is tainted, issue a stop here
            #TODO
            continue
        if len(te) < 3:
            raise ValueError("Need drefs in trace for reverse taint analysis")
        l = 15 if len(te) < 4 else te[3]
        regs = getRegInOut(ctx, te[0], l)
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

        if spreads:
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
                    taintedaddr.add(addr+i)
        print(f"@{te[0]:x} : {te[1]} : {regs}")

    return (taintedaddrs, taintedregs)
