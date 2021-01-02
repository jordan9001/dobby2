from triton import *

from .interface import *
from .dobby import *


#TODO this will be a interface for any remote providers
# I plan to use this with my hypervisor as a really fast provider
class DobbyRemote(DobbyProvider, DobbyEmu, DobbySym, DobbyRegContext, DobbyMem, DobbySnapshot, DobbyFuzzer):
    """
    Dobby provider using Triton DSE
    """

    def __init__(self, ctx, remotename):
        super().__init__(ctx, remotename)
        
        #TODO
        raise NotImplementedError(f"TODO") 
