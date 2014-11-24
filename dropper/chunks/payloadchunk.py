import struct
import pdb

class PayloadChunk():

    def __init__ (self, pl, arch_info, address, next_ret_at_end = True, next_ret_offset = None, chunk_list = None):
        self.next_ret_at_end = next_ret_at_end
        self.next_ret_offset = next_ret_offset
        self.arch_info = arch_info
        self.address = address
        self.pl = pl
        self.chunk_list = chunk_list


    def get_payload(self):
        return self.pl

    @staticmethod
    def get_general_chunk(chunk_list):
        address_size = chunk_list[0].arch_info.architecture_size
        fmt = "<I"
        if chunk_list[0].arch_info.architecture_size == 64:
            fmt = "<Q"

        next_ret_offset = 0
        pl = ""
        for i, c in enumerate(chunk_list):
            if i != 0:
                pl = pl[:next_ret_offset] + struct.pack(fmt, c.address) + pl[next_ret_offset:]

            curr = len(pl)
            pl += c.get_payload()

            next_ret_at_end = c.next_ret_at_end

            if c.next_ret_at_end:
                next_ret_offset = len(pl)
            else:
                next_ret_offset = curr + c.next_ret_offset
                if i == 0:
                    next_ret_offset -= chunk_list[0].arch_info.address_size

        #only for debug
        flat_chunk_list = []
        for c in chunk_list:
            if hasattr(c, 'chunk_list') and c.chunk_list != None:
                flat_chunk_list += c.chunk_list
            else:
                flat_chunk_list.append(c)

        return PayloadChunk(pl, chunk_list[0].arch_info, chunk_list[0].address, next_ret_at_end,  next_ret_offset, flat_chunk_list)

    @staticmethod
    def chain(chunk_list):
        address_size = chunk_list[0].arch_info.architecture_size
        fmt = "<I"
        if chunk_list[0].arch_info.architecture_size == 64:
            fmt = "<Q"

        return struct.pack(fmt,chunk_list[0].address) + PayloadChunk.get_general_chunk(chunk_list).get_payload()


class RegSetChunk(PayloadChunk):
    def __init__(self, g, arch_info, values, padding='\x00'):
        self.g = g
        self.address = g.address
        self.padding = padding
        self.values = values
        self.arch_info = arch_info

        self.next_ret_at_end = True
        self.offset_next_ret = None

    def set_value(self, reg, value):
        if reg in self.g._stack_indexes:
            self.values[reg] = value
            return

        reg_mapper = self.arch_info.register_access_mapper()
        r, mask, shift = reg_mapper.get(self.reg)

        if r not in self.g._stack_indexes:
            raise BaseException("Try to pop on reg %s but %s(from register mapper) isn't in the regs popped by this gadgets, IMPLEMENT" % (self.reg, r))

        self.values[r] = value << shift


    def get_payload(self):
        fmt = "<I"
        if self.arch_info.architecture_size == 64:
            fmt = "<Q"

        ptr = 0
        pl = ""
        bsidx = sorted(self.g._stack_indexes, key = lambda x: self.g._stack_indexes[x])
        for r in bsidx:
            off = self.g._stack_indexes[r]
            pl += self.padding * (off - ptr)
            if r in self.values:
                pl += struct.pack(fmt, self.values[r])
            else:
                pl += self.padding * (self.arch_info.address_size / 8)

            ptr = len(pl)

        pl += self.padding * (self.g._stack_offset - ptr)

        return pl

class ArithmeticMemSetChunk(PayloadChunk):
    def __init__(self, g, esp_at_end, arch_info, padding='\x00'):
        self.g = g
        self.address = g.address
        self.arch_info = arch_info
        self.padding = padding

        self.next_ret_at_end = True
        self.offset_next_ret = None

        self.esp_at_end = esp_at_end

    def get_payload(self):
        pl = self.padding * self.esp_at_end
        return pl

class StackSlideChunk(PayloadChunk):
    def __init__(self, address, arch_info, wanted_slide, slide, padding=0x00):
        self.address = address
        self.arch_info = arch_info

        self.wanted_slide = wanted_slide
        self.slide = slide
        self.padding = padding

        self.next_ret_at_end = True
        self.next_ret_offset = None


    def get_payload(self):
        address_size = self.arch_info.architecture_size
        fmt = "<I"
        if self.arch_info.architecture_size == 64:
            fmt = "<Q"

        pl = ""
        for _ in xrange(self.slide - self.wanted_slide):
            pl += struct.pack(fmt, self.padding)

        return pl


class MemSetLibcRead32(PayloadChunk):
    def __init__(self, location, fd, size, address, arch_info):
        self.location = location
        self.address = address
        self.size = size
        self.fd = fd
        self.arch_info = arch_info

        self.next_ret_at_end = False
        self.next_ret_offset = 4


    def get_payload(self):

        pl = struct.pack("<I", self.fd)
        pl += struct.pack("<I", self.location)
        pl += struct.pack("<I", self.size)

        return pl



class CCFlagChunk():
    def __init__ (self, g, arch_info):
        self.next_ret_at_end = True
        self.arch_info = arch_info
        self.address = g.address
        self.net_ret_offset = None
        self.g = g


    def get_payload(self):
        pl = ""
        pl += "N" * self.g._stack_offset

        return pl
