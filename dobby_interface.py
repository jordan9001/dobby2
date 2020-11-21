from dobby_const import *

"""
These are the interfaces that providers can fill out to work with the Dobby system
"""

class Dobby_Emu:
    """
    Emulation interface for providers to fill out
    """ 

    def getInsCount(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def insertHook(self, hook, htype):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def removeHook(self, hook, htype):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def updateHookHandler(self, labelglob, newhandler):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def startTrace(self, getdrefs=False):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def getTrace(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def stopTrace(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def step(self, ignoreCurrentHook=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def cont(self, ignoreCurrentHook=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def until(self, ignoreCurrentHook=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def next(self, ignoreCurrentHook=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 
         

class Dobby_Sym:
    """
    Symbolic interface for providers to fill out
    """

    def symbolizeRegister(self, reg, name):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def symbolizeMemory(self, addr, size, name):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def getSymbol(self, name):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def setSymbolVal(self, sym, value, overwrite=False):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")
    
    def getRegisterAst(self, reg):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def getMemoryAst(self, reg):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def getUnsetSym(self, ast, single=True, allSym=False, followRef=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def getUnsetCount(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def evalReg(self, reg, checkUnset=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def evalMem(self, addr, size, checkUnset=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

class Dobby_RegContext:
    """
    Register Read interface for providers to fill out
    """

    def getRegVal(self, reg): 
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def setRegVal(self, reg, val):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

class Dobby_Mem:
    """
    Memory Read interface for providers to fill out
    """

    def disass(self, addr=-1, count=16):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def getMemVal(self, addr, amt):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def setMemVal(self, addr, val):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

class Dobby_Snapshot:
    """
    State saving and restoring for providers to fill out
    """

    def saveSnapshot(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")
        
    def loadSnapshot(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")
