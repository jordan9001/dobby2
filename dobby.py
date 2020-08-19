
from triton import *
import lief
import sys
import collections
import struct

# ok so the plan
# instead of making our own cmdline interface, just use the python interpreter or ipython
# add our helper tools as helper functions in this library
# allow for iteration and reloading of this library as changes are added during runtime via importlib.reload
#
# must haves:
# - scriptable hooks
#       this is the real reason for moving away from a pure C++ codebase
#       While we had some limited scripting in the C++ code, here we can create functions with full access on the fly
# - save state to file
#       this is also more possible with python, as we can pickle created hooks
#       and easily serialize our saved sandbox changes
# - sandbox everything
#       the idea of dobby is to build the sandbox as the program runs, and be alerted to any side effects so we can build the env
# - sys file PE loading
# - (somewhat) quick emulation
#       it can't take more than a minute between sandbox prompts, otherwise it is unusable

#TODO current vague steps forward
#   0. test PE loading
#   1. emulation with callbacks
#   2. change tracking

def getu64(ctx, addr):
    return struct.unpack("Q", ctx.api.getConcreteMemoryAreaValue(addr, 8))[0]

def setu64(ctx, addr, val):
    ctx.api.setConcreteMemoryAreaValue(addr, struct.pack("Q", val))

def init(apihookarea=0xffff414100000000):
    ctx_t = collections.namedtuple("CTX", ['api', 'hooks', 'ann', 'bounds'])
    
    api = TritonContext(ARCH.X86_64)

    # setup hook stuff
    # hooks are for stopping execution, or running handlers
    hooks = [[],[],[]] # e, rw, w

    # setup annotation stuff
    # annotations are for noting things in memory that we track
    ann = []

    # setup bounds
    # bounds is for sandboxing areas we haven't setup yet
    bounds = []

    ctx = ctx_t(api, hooks, ann, bounds)

    # add hooks for the API_FUNC area
    addHook(ctx, apihookarea, apihookarea, 'e', None, "API HOOKS")
    return ctx

def setupEmu(entry, end, stackbase):
    #TODO

def loadPE(ctx, path, base):
    pe = lief.parse(path)

    dif = base - pe.optional_header.imagebase

    # load concrete mem vals from image
    # we need to load in header as well
    rawhdr = b""
    with open(path, "rb") as fp:
        rawhdr = fp.read(pe.sizeof_headers)
    ctx.api.setConcreteMemoryAreaValue(base, rawhrd)
    addAnn(ctx, base, base+len(rawhdr), "MAPPED_PE_HDR", True, pe.name)

    for phdr in pe.sections:
        start = base + phdr.virtual_address
        end = start + len(phdr.content)
        ctx.api.setConcreteMemoryAreaValue(base + phdr.virtual_address, phdr.content)
        
        #annotate the memory region
        addAnn(ctx, start, end, "MAPPED_PE", True, pe.name + '(' + phdr.name = ')')

    # do reloactions
    for r in pe.relocations:
         for re in pe.relocations:
            if re.type == lief.PE.RELOCATIONS_BASE_TYPES.DIR64:
                a = re.address
                val = getu64(ctx, base + a)

                slid = val + dif

                setu64(ctx, base + a, slid)
            else:
                print(f"Unhandled relocation type {re.type}")
    
    # setup exception handlers
    #TODO

    # symbolize imports
    for i in pe.imports:
        for ie in i.entries:
            # extend the API HOOKS execution hook 
            hookaddr = ctx.hooks[0][0]

    # annotate symbols from image
    #TODO

def addHook(ctx, start, end, htype, handler=None, label=""):
    h = [start, end, label, handler]
    if htype == 'e':
        ctx.hooks[0].append(h)
    elif htype == 'r':
        ctx.hooks[1].append(h)
    elif htype == 'w':
        ctx.hooks[2].append(h)
    else:
        print("Unknown hook type")
        return False
    
    return True

def updateBounds(ctx, start, end):
    insi = 0
    si = -1
    ei = -1
    combine = False

    if start > end:
        print("Bad bounds")
        return False

    # see if it is already in bounds, or starts/ends in a region
    for bi in range(len(ctx.bounds)):
        b = ctx.bounds[bi]
        if b[1] < start:
            insi = bi+1
        if b[0] <= start <= b[1]:
            si = bi
        if b[0] <= end <= b[1]:
            ei = bi

    if si == -1 and ei == -1:
        # add a new bounds area
        ctx.bounds.insert(insi, [start, end])
    elif si == ei:
        # we are good already
        pass
    elif si == -1:
        # extend the ei one
        ctx.bounds[ei][0] = start
        combine = True
    elif ei == -1:
        # extend the si one
        ctx.bounds[si][1] = end
        combine = True
    else:
        # combine two or more entries
        ctx.bounds[si][1] = ctx.bounds[ei][1]
        combine = True

    if combine:
        while insi+1 < len(ctx.bounds) and ctx.bounds[insi+1][1] <= d[insi][1]:
            del ctx.bounds[insi+1]

    return True 
        

def addAnn(ctx, start, end, mtype, updatebounds=False, label=""):
    if updatebounds:
        updateBounds(ctx, start, end)

    ctx.ann.append((start, end, mtype, label))
    return True

def stepi(ctx):
    #TODO

if __name__ == '__main__':
    print("Please import this file from the interpreter")

