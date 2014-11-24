from barf.arch.x86.x86base import X86RegisterOperand
from dropper.chunks.payloadchunk import RegSetChunk
from dropper.chunks.payloadchunk import PayloadChunk
from dropper.chunks.payloadchunk import StackSlideChunk
import dropper.utils as utils


class RegSet():
    def __init__ (self, gts):
        self.gts = gts
        self.by_addr = {}
        self.by_reg = {}
        pass

    def add(self, gadgets):
        for g in gadgets:
            self._analyze_gadget(g)

    def _analyze_gadget(self, g):
        self.gts.emulator.reset()

        regs = utils.make_parent_regs_random(self.gts.arch_info)
        stack_base = 0x80

        stack_reg = 'esp'
        if (self.gts.arch_info.architecture_size == 64):
            stack_reg = 'rsp'

        regs[stack_reg] = stack_base
        stack = stack_base
        g._stack_indexes = {}
        address = []

        for i, d_instr in enumerate(g.instrs):
            asm_instr = d_instr.asm_instr
            if asm_instr.mnemonic == 'pop':
                # not considering popping/pushing to mememory. TODO
                if not isinstance(asm_instr.operands[0],  X86RegisterOperand):
                    return False

                reg = asm_instr.operands[0].name
                g._stack_indexes[reg] = stack - stack_base

            try:
                cregs, cmem = self.gts.emulator.execute_lite(d_instr.ir_instrs, regs)
            except:
                return False, 0, 0

            if asm_instr.mnemonic == 'pop':
                address += cmem.get_addresses()
            else:
                for addr in cmem.get_addresses():
                    if addr not in address:
                        return False

            regs = cregs
            stack = regs[stack_reg]

        if len(g._stack_indexes) > 0:
            g._stack_offset = stack - stack_base
            self.by_addr[g.address] = g
            for r in g._stack_indexes:
                if not r in self.by_reg:
                    self.by_reg[r] = []
                self.by_reg[r].append(g)


    def can_control_reg(self, reg):
        ret, _ = self.reg_in(reg, self.by_reg)
        return ret


    def reg_in(self, reg, regs):
        if reg in regs:
            return True, reg

        rm = self.gts.arch_info.register_access_mapper()
        if reg in rm:
            if rm[reg][0] in regs:
                return True, rm[reg][0]

        # ok this is shit : in 64bit we've to check if we haxe e*x and *x in _by_reg
        if len(reg) == 2 and reg[1] in ['l','h']:
            mm = reg[0] + 'x'
            if mm in regs:
                return True, mm
            mm = 'e' + mm
            if mm in regs:
                return True, mm

        return False, None

    def _sort_by_instr_length(self, gadgets):
        return sorted(gadgets, key = lambda x : len(x.instrs))

    def get_chunk(self, reg, value):
        pass


    def get_clobber_free_chunk(self, regs_values):

        #naive greedy TODO implement better searching (planning? smt?)
        selected = []
        regs_covered = set()
        for r, v in regs_values.iteritems():
            control, reg = self.reg_in(r, self.by_reg)
            if not control:
                raise BaseException("Can't control reg %s" % r)

            if reg in regs_covered:
                continue

            shortest = self._sort_by_stack_offset(self.by_reg[reg])
            shortest = self._sort_by_instr_length(shortest)[0]

            for i, g in enumerate(selected):
                mism = [reg for reg in g._stack_indexes if reg in regs_values and reg not in shortest._stack_indexes]
                if len(mism) == 0:
                    selected.pop(i)

            selected.append(shortest)
            for k in shortest._stack_indexes.keys():
                regs_covered.add(k)



        chunks = []

        for g in selected:
            values = {}
            for r, v in regs_values.iteritems():
                is_in, reg =  self.reg_in(r, g._stack_indexes)
                if not is_in:
                    continue

                if r in g._stack_indexes:
                    values[r] = v
                else:
                    values[reg] = self._get_parent_value(v, r)

            c = RegSetChunk(g, self.gts.arch_info, values)
            chunks.append(c)

        return PayloadChunk.get_general_chunk(chunks)


    def _get_parent_value(self, value, reg):
        reg_mapper = self.gts.arch_info.register_access_mapper()
        r, mask, shift = reg_mapper.get(reg)
        return value << shift

    def _sort_by_stack_offset(self, gs):
        return sorted(gs, key = lambda x : x._stack_offset)


    def get_slide_stack_chunk(self, slide):
        gs = self._sort_by_stack_offset(self.by_addr.values())
        for g in gs:
            so = g._stack_offset
            if so >= slide:
                return StackSlideChunk(g.address, self.gts.arch_info, slide, so)
