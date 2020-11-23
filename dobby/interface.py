from enum import Enum

"""
This is the class that all providers must inherit from
"""
class DobbyProvider:
    """
    This should be the first class inherited from, with the interfaces following in order after
    """
    def __init__(self, ctx, name):
        self.ctx = ctx
        self.providerName = name

        self.isEmuProvider = issubclass(type(self), DobbyEmu)
        self.isSymProvider = issubclass(type(self), DobbySym)
        self.isRegContextProvider = issubclass(type(self), DobbyRegContext)
        self.isMemoryProvider = issubclass(type(self), DobbyMem)
        self.isSnapshotProvider = issubclass(type(self), DobbySnapshot)

        ctx.registerProvider(self, name, True)

    def __repr__(self):
        return f"Dobby Provider {self.providerName}"

"""
These are the interfaces that providers can fill out to work with the Dobby system
"""

class DobbyEmu:
    """
    Emulation interface for providers to fill out
    """ 

    def getInsCount(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def insertHook(self, hook, htype):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def removeHook(self, hook, htype):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def getHooks(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def insertInstructionHook(self, insname, handler):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def lastHook(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def startTrace(self, getdrefs=False):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def getTrace(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def stopTrace(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def step(self, ignoreCurrentHook=True, printIns=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def cont(self, ignoreCurrentHook=True, printInst=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def until(self, ignoreCurrentHook=True, printInst=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 

    def next(self, ignoreCurrentHook=True, printInst=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function") 
         

class DobbySym:
    """
    Symbolic interface for providers to fill out
    """

    def isSymbolizedRegister(self, reg):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def isSymbolizedMemory(self, addr, size):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")
    
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

    def printAst(self, ast):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def getUnsetSym(self, ast, single=True, allSym=False, followRef=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def getUnsetCount(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def evalReg(self, reg, checkUnset=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def evalMem(self, addr, size, checkUnset=True):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

class DobbyRegContext:
    """
    Register Read interface for providers to fill out
    """

    def getRegVal(self, reg): 
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def setRegVal(self, reg, val):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

class DobbyMem:
    """
    Memory Read interface for providers to fill out
    """

    def disass(self, addr=-1, count=16):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def getMemVal(self, addr, amt):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def setMemVal(self, addr, val):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

    def updateBounds(self, start, end, permissions):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")

class DobbySnapshot:
    """
    State saving and restoring for providers to fill out
    """

    def saveSnapshot(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")
        
    def loadSnapshot(self):
        raise NotImplementedError(f"{str(type(self))} does not implement this function")
