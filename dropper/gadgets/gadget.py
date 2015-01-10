from barf.analysis.gadget import RawGadget
from barf.analysis.gadget import TypedGadget



class DrRawGadget(RawGadget):
    """ Dummy class used for allow dynamic attribute insertion in RawGadget object.
    """

    def __init__(self, raw_gadget):
        for a in dir(raw_gadget):
            setattr(self, a, getattr())


class DrTypedGadget(TypedGadget):
    """ Dummy class used for allow dynamic attribute insertion in TypedGadget object.
    """

    pass
        
