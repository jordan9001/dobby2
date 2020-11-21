from triton import *

class Dobby_Triton(Dobby_Emu, Dobby_Sym, Dobby_RegContext, Dobby_Mem, Dobby_Snapshot):
    """
    Dobby provider using Triton DSE
    """

    def __init__(self, ctx):
        self.ctx = ctx
        #TODO

    #TODO
