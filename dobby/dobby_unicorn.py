from unicorn import *
from unicorn.x86_const import *

from .interface import *
from .dobby import *

class DobbyUnicorn(DobbyProvider, DobbyEmu, DobbyRegContext, DobbyMem, DobbySnapshot):
    """
    Dobby provider using Triton DSE
    """

    def __init__(self, ctx):
        self.ctx = ctx
        super().__init__(ctx, "Unicorn")

        self.emu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.trace = None
        self.inscount = 0
        self.stepret = StepRet.OK
        self.intrnum = -1
        self.ignorehookaddr = -1
        self.trystop = False
        self.regtrans = {}
        #TODO

    #TODO
