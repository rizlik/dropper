import random
import struct
import dropper.utils as utils
from dropper.chunks.payloadchunk import PayloadChunk
from dropper.chunks.payloadchunk import ArithmeticMemSetChunk


class MemoryStore():
    def __init__(self, gts):
        self.gts = gts

    def add(self, gs):
        self.by_addr = {}
        for g in gs:
            self._verify(g)

    def _verify(self, g):
        #we don't want push {something} like gadgets here
        if g.destination[0].name == 'rsp' or g.destination[0].name == 'esp':
            return False

        #we don't want mov[rip] like gadgets here
        if g.destination[0].name == 'rip' or g.destination[0].name == 'eip':
            return False

        for r in [g.destination[0], g.sources[0]]:
            if not self.gts.regset.can_control_reg(r.name):
                return False


        location = random.randint(0, 2 ** self.gts.arch_info.address_size - 1)
        value = random.randint(0, 2 ** self.gts.arch_info.register_size[g.sources[0].name])

        valid, src, dst = self._get_params(g, location, value)

        if valid == False:
            return False

        valid = self._is_valid(g, src, dst, location, value)
        if valid == False:
            return False

        size = self.gts.arch_info.register_size[g.sources[0].name]
        mem_side_effects, stack_at_end = self._side_effects(g,
                                                            src,
                                                            dst,
                                                            location,
                                                            size)
        if len(mem_side_effects) > 0:
            return False

        g._stack_offset = stack_at_end
        self.by_addr[g.address] = g
        return True
        
    def _get_params(self, g, location, value):
        self.gts.code_analyzer.reset(full=True)
        for ir in g.get_ir_instrs():
            self.gts.code_analyzer.add_instruction(ir)

        size = self.gts.arch_info.register_size[g.sources[0].name]

        stack_reg = 'esp'
        if (self.gts.arch_info.architecture_size == 64):
            stack_reg = 'rsp'


        src_reg = self.gts.code_analyzer.get_register_expr(g.sources[0].name, mode='pre')
        dst_reg = self.gts.code_analyzer.get_register_expr(g.destination[0].name, mode='pre')
        stack = self.gts.code_analyzer.get_register_expr(stack_reg, mode='pre')
        mem_pre = self.gts.code_analyzer.get_memory_expr(location, size/8, mode='pre')
        mem_post = self.gts.code_analyzer.get_memory_expr(location, size/8, mode='post')

        ac = self.gts.code_analyzer.get_immediate_expr(value & (2**size-1), size)
        rv = random.randint(0, 2**size-1)
        random_value = self.gts.code_analyzer.get_immediate_expr(rv, size)

        rv = random.randint(0, 2 ** self.gts.arch_info.address_size -1)
        random_stack = self.gts.code_analyzer.get_immediate_expr(rv, self.gts.arch_info.address_size)

        constrs = []
        constrs.append(mem_pre == random_value)
        constrs.append(mem_post == ac)
        constrs.append(stack == random_stack)

        self.gts.code_analyzer.set_preconditions(constrs)
        if self.gts.code_analyzer.check() == 'sat':
            src = self.gts.code_analyzer.get_expr_value(src_reg)
            dst = self.gts.code_analyzer.get_expr_value(dst_reg)
            return True, src, dst

        return False, 0, 0

    def _is_valid(self, g, src, dst, location, value):
        self.gts.code_analyzer.reset(full=True)
        for ir in g.get_ir_instrs():
            self.gts.code_analyzer.add_instruction(ir)

        size = self.gts.arch_info.register_size[g.sources[0].name]
        src_reg = self.gts.code_analyzer.get_register_expr(g.sources[0].name, mode='pre')
        dst_reg = self.gts.code_analyzer.get_register_expr(g.destination[0].name, mode='pre')

        mem_post = self.gts.code_analyzer.get_memory_expr(location, size/8, mode='post')
        ac = self.gts.code_analyzer.get_immediate_expr(value & (2**size-1), size)

        constrs = []
        constrs.append(src_reg == src)
        constrs.append(dst_reg == dst)
        constrs.append(mem_post != ac)

        if self.gts.code_analyzer.check_constraints(constrs) != 'unsat':
            return False

        return True

    def _side_effects(self, g, src, dst, location, size):
        self.gts.emulator.reset()
        regs_init = utils.make_random_regs_context(self.gts.arch_info)
        regs_init[g.destination[0].name] = dst
        regs_init[g.sources[0].name] = src

        mem_side_effects, stack_at_end = self.gts.check_mem_side_effects_and_stack_end(g,
                                                                                   regs_init,
                                                                                   location,
                                                                                   size)

        return mem_side_effects, stack_at_end

    def get_chunk(self, location, raw_value):
        """ Return a chunk for writing raw_value in location
        """

        #TODO choose the best gadget
        keys = self.by_addr.keys()
        keys.sort()

        if len(keys) == 0:
            raise BaseException("Trying to build a memory write chain without memory write gadget")
            return

        ms_g = self.by_addr[keys[0]]
        size = len(raw_value)
        op_size = self.gts.arch_info.register_size[ms_g.sources[0].name]
        op_size_bytes = op_size / 8


        n_iter = size / op_size_bytes

        #TODO search for memory gadget that make len(raw_value) 0 module op_size
        if size % op_size_bytes != 0:
            n_iter += 1

        curr = 0
        #TODO add 8 and 16
        if op_size == 32:
            fmt = "<I"
        if op_size == 64:
            fmt = "<Q"

        params = []

        for i in xrange(n_iter):
            value = raw_value[curr : curr + op_size_bytes]

            if len(value) < op_size_bytes:
                padding = op_size_bytes - len(value)
                value += "\x00" * padding

            value = struct.unpack(fmt, value)[0]
            valid, src, dst = self._get_params(ms_g, location, value)

            curr += op_size / 8
            location += op_size / 8
            if not valid:
                return

            params.append((src, dst))

        msg_chunk = ArithmeticMemSetChunk(ms_g, ms_g._stack_offset, self.gts.arch_info)

        for i, param in enumerate(params):
            c = self.gts.regset.get_chunk({ms_g.sources[0].name : param[0],
                                           ms_g.destination[0].name : param[1]})
            if i == 0:
                pl = PayloadChunk.get_general_chunk([c, msg_chunk])
            else:
                pl = PayloadChunk.get_general_chunk([pl, c, msg_chunk])

        return pl
