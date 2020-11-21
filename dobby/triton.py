from triton import *

from .interface import *
from .dobby import *

class DobbyTriton(DobbypProvider, DobbyEmu, DobbySym, DobbyRegContext, DobbyMem, DobbySnapshot):
    """
    Dobby provider using Triton DSE
    """

    def __init__(self, ctx):
        self.ctx = ctx
        super().__init__(ctx, "Triton")
        #TODO

