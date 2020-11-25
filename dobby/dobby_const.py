from .x86const import *
from enum import Enum

class HookRet(Enum):
    ERR = -1
    CONT_INS = 0
    DONE_INS = 1
    STOP_INS = 2
    FORCE_STOP_INS = 3 # unlike STOP_INS this one can not be ignored
    OP_CONT_INST = 4 # This one can optionally be a stop or a continue, depending on ctx.opstop
    OP_DONE_INST = 4 # This one can optionally be a stop or a done, depending on ctx.opstop

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

# Matches Unicorn's permissions values
MEM_NONE = 0
MEM_READ = 1
MEM_WRITE = 2
MEM_EXECUTE = 4
MEM_ALL = 7
