from .dobby_const import *

class Dobby:
    def __init__(self, apihookarea=0xffff414100000000):
        self.systemtimestart = 0x1d68ce74d7e4519
        self.IPC = 16 # instructions / Cycle
        self.CPN = 3.2  # GigaCycles / Second == Cycles / Nanosecond
        self.IPN = self.IPC * self.CPN * 100 # instructions per 100nanosecond
        self.printIns = True
        self.priv = True
        self.modules = []

        # heap stuff
        self.nextalloc = 0

        # inshooks are handlers of the form func(ctx, addr, provider)
        self.inshooks = {
            "rdtsc" : self.rdtscHook,
            "smsw": self.smswHook,
        }

        # setup annotation stuff
        # annotations are for noting things in memory that we track
        self.ann = []

        # setup bounds
        # bounds is for sandboxing areas we haven't setup yet and tracking permissions
        self.bounds = {}

        # add annotation for the API_FUNC area
        self.apihooks = self.addAnn(apihookarea, apihookarea, "API_HOOKS", "API HOOKS")

    #TODO

class Hook:
    """
    Hook handlers should have the signature (hook, addr, sz, op, provider)
    """
    def __init__(self, start, end, label="", handler=None):
        self.start = start
        self.end = end
        self.label = label
        self.handler = handler

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

class HookRet(Enum):
    ERR = -1
    CONT_INS = 0
    DONE_INS = 1
    STOP_INS = 2
    FORCE_STOP_INS = 3 # unlike STOP_INS this one can not be ignored

# Matches Unicorn's permissions values
MEM_NONE = 0
MEM_READ = 1
MEM_WRITE = 2
MEM_EXECUTE = 4
MEM_ALL = 7

class StepRet(Enum):
    ERR_STACK_OOB = -3
    ERR_IP_OOB = -2
    ERR = -1
    OK = 0
    HOOK_EXEC = 1
    HOOK_WRITE = 2
    HOOK_READ = 3
    HOOK_INS = 4
    HOOK_CB = 5
    HOOK_ERR = 6
    PATH_FORKED = 7
    STACK_FORKED = 8
    BAD_INS = 9
    DREF_SYMBOLIC = 10
    DREF_OOB = 11
    INTR = 12
