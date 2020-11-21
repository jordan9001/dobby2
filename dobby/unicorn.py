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
        #TODO

    #TODO
