
class Hook:
    """
    Hook handlers should have the signature (hook, addr, sz, op, provider)
    """
    def __init__(self, start, end, htype, label="", handler=None):
        self.start = start
        self.end = end
        self.label = label
        self.handler = handler
        self.htype = htype
        self.isApiHook=False

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

