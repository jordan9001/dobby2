import copy
import zlib

class Hook:
    """
    Hook handlers should have the signature (hook, addr, sz, op, provider) -> None
    """
    def __init__(self, start, end, htype, label="", handler=None):
        self.start = start
        self.end = end
        self.label = label
        self.handler = handler
        self.htype = htype
        self.isApiHook=False

    def __repr__(self):
        return f"Hook @ {hex(self.start)}:\"{self.label}\"{' (no handler)' if self.handler is None else ''}"

class Annotation:
    def __init__(self, start, end, mtype="UNK", label=""):
        self.start = start
        self.end = end
        self.mtype = mtype
        self.label = label

    def __repr__(self):
        return f"{hex(self.start)}-{hex(self.end)}=>\"{self.mtype}:{self.label}\""

class Snapshot:
    COMP_NONE = 0
    COMP_ZLIB = 1

    def __init__(self, name):
        self.name = name
        self.setup = False
        self.extradata = None
        self.hasemu = False
        self.hassym = False
        self.hasreg = False
        self.hasmem = False

    def take(self, ctx):
        if ctx.active is None:
            raise RuntimeError("Tried to take snapshot with no active provider")

        # interface independant stuff

        self.priv = ctx.active.priv
        #TODO self.modules = copy.deepcopy(ctx.active.modules)
        self.nextalloc = ctx.active.nextalloc
        self.hooks = copy.deepcopy(ctx.active.hooks)
        self.inshooks = copy.deepcopy(ctx.active.inshooks)
        self.ann = copy.deepcopy(ctx.active.ann)
        self.bounds = copy.deepcopy(ctx.active.bounds)
        self.apihooks = copy.deepcopy(ctx.active.apihooks)
        self.stackann = copy.deepcopy(ctx.active.stackann)

        if ctx.isemu:
            self.hasemu = True
            # nothing else to save here

        if ctx.issym:
            print("WARNING, saving symbolic state is not yet implemented")

        if ctx.isreg:
            self.hasreg = True
            # save off register state
            self.rstate = {}
            for r in ctx.active.getAllRegisters():
                rv = ctx.active.getRegVal(r)
                self.rstate[r] = rv

        if ctx.ismem:
            self.hasmem = True
            # save off memory state
            self.mem = []
            for start, end in ctx.getBoundsRegions(False):
                sz = end - start
                val = ctx.getMemVal(start, sz, allowsymb=True)
                cval = zlib.compress(val, 6)
                self.mem.append((start, sz, self.COMP_ZLIB, cval))

        self.setup = True

    def restore(self, ctx):
        if ctx.active is None:
            raise RuntimeError("Tried to take snapshot with no active provider")

        if not self.setup:
            raise RuntimeError("Tried to restore a snapshot that isn't set up")

        # interface independant stuff

        ctx.active.priv = self.priv
        #TODO ctx.active.modules = copy.deepcopy(self.modules)
        ctx.active.nextalloc = self.nextalloc
        ctx.active.hooks = copy.deepcopy(self.hooks)
        ctx.active.inshooks = copy.deepcopy(self.inshooks)
        ctx.active.ann = copy.deepcopy(self.ann)
        ctx.active.bounds = copy.deepcopy(self.bounds)
        ctx.active.apihooks = copy.deepcopy(self.apihooks)
        ctx.active.stackann = copy.deepcopy(self.stackann)

        if ctx.isemu:
            if not self.hasemu:
                print("Warning: loading state from a provider without Emulation")
            else:
                # nothing to load here
                pass

        if ctx.issym:
            if not self.hassym:
                print("Warning: loading state from a provider without Symbolism")
            else:
                print("Warning: symbolic loading not implemented")
                #TODO

        if ctx.isreg:
            if not self.hasreg:
                print("Warning: loading state from a provider without Emulation")
            else:
                # restore register state
                allreg = ctx.active.getAllRegisters()
                for r,rv in self.rstate.items():
                    if r not in allreg:
                        if rv != 0:
                            print(f"Warning: Did not load unsupported register {ctx.getRegName(r)}!")
                    else:
                        ctx.active.setRegVal(r, rv)

        if ctx.ismem:
            if not self.hasmem:
                print("Warning: loading state from a provider without Emulation")
            else:
                #TODO Copy On Write memory mapped files?
                # update bounds
                #TODO do this in groups, not once per page
                for start, end, perm in ctx.getBoundsRegions(True):
                    ctx.active.updateBounds(start, end, perm)

                # update memory contents
                for m in self.mem:
                    addr, sz, comptype, cval = m

                    val = None
                    if comptype == self.COMP_ZLIB:
                        val = zlib.decompress(cval, bufsize=sz)
                    elif comptype == self.COMP_NONE:
                        val = cval
                    else:
                        raise TypeError("Unknown compression type")

                    ctx.setMemVal(addr, val)

    def __repr__(self):
        return f"SaveState({self.name})" 
