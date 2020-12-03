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

def revtainttrace(ctx, trace, taintedaddrs, taintedregs):
    #DEBUG
    for te in trace[:-45:-1]:
        if len(te) < 3:
            raise ValueError("Need drefs in trace for reverse taint analysis")
        l = 15 if len(te) < 4 else te[3]
        regs = getRegInOut(ctx, te[0], l)
        print(f"@{te[0]:x} : {te[1]} : {regs}")
