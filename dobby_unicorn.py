from unicorn import *
from unicorn.x86_const import *

class Dobby_Unicorn(Dobby_Emu, Dobby_RegContext, Dobby_Mem, Dobby_Snapshot):
    """
    Dobby provider using Triton DSE
    """

    def __init__(self, ctx):
        self.ctx = ctx
        #TODO

    #TODO
