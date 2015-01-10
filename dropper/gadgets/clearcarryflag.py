from dropper.chunks.payloadchunk import CCFlagChunk
import dropper.utils as utils
import copy

class CCFlag():
    def __init__(self, gts):
        self.gts = gts

    def add(self, gs):
        self.by_addr = {}
        self.by_stack_offset = {}

        for g in gs:
            self._analyze(g)
    
    def get_ccf_chunk(self, regs):
        by_stack = sorted(self.by_addr.values(), key = lambda x : x._stack_offset)
        for g in by_stack:
            clobs = [r for r in g._regs_written if r in regs]
            if len(clobs) > 0:
                continue

            return CCFlagChunk(g, self.gts.arch_info)

        return None
            

    def _analyze(self, g):
        self.gts.code_analyzer.reset(full=True)
        ir_instrs = [ir for i in g.instrs for ir in self.gts.reil_translator.translate(i.asm_instr)] 
        for ir in ir_instrs:
            self.gts.code_analyzer.add_instruction(ir)

        zero = self.gts.code_analyzer.get_immediate_expr(0, 1)
        uno = self.gts.code_analyzer.get_immediate_expr(1, 1)

        cf = self.gts.code_analyzer.get_register_expr('cf', mode='pre')
        cf_post = self.gts.code_analyzer.get_register_expr('cf', mode='post')
        
        self.gts.code_analyzer.set_postconditions([(cf == 1),
                                                   (cf_post != 0)])

        if self.gts.code_analyzer.check() != 'unsat':
            return 

        if self._has_side_effects(g):
            return

        self.by_addr[g.address] = g
        
        if g._stack_offset not in self.by_stack_offset:
            self.by_stack_offset[g._stack_offset] = []

        self.by_stack_offset[g._stack_offset].append(g)


    def _has_side_effects(self, g):
        self.gts.emulator.reset()
        regs_init = utils.make_random_regs_context(self.gts.arch_info)
        mem_side_effects, stack_at_end = self.gts.check_mem_side_effects_and_stack_end(g, regs_init, 0, 0)

        if len(mem_side_effects) > 0:
            return True

        g._regs_written = copy.deepcopy(self.gts.emulator.written_registers)
        g._stack_offset = stack_at_end
                

