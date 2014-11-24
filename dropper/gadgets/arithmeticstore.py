import dropper.utils as utils
from dropper.chunks.payloadchunk import PayloadChunk
from dropper.chunks.payloadchunk import ArithmeticMemSetChunk

class ArithmeticStore:
    def __init__(self, gts):
        self.gts = gts

    def add(self, gs):
        self.by_addr = {}
        self.adcs = []

        for g in gs:
            self._analyze(g)

    def _analyze(self, g):
        for r in [g.sources[0], g.sources[2], g.destination[0]]:
            if not self.gts.regset.can_control_reg(r.name):
                return 

        size = g.operation_size

        location = 0x808080
        pattern = 0xac

        success, dst_0, src_0, src_2, cf = self._get_params(g, size, location, pattern)
        if not success:
            return 

        if not self._is_valid(g, dst_0, src_0, src_2, size, location, pattern):
            return 

        mem_writes = self._side_effects(g, dst_0, src_0, src_2, location, size)

        if len (mem_writes) > 0:
            return False

        self.by_addr[g.address] = g
        if g._is_adc:
            self.adcs.append(g)

    def _is_valid(self, g, dst0, src0, src2, size, location, pattern):
        self.gts.code_analyzer.reset(full=True)

        for ir in g.get_ir_instrs():
            self.gts.code_analyzer.add_instruction(ir)

        mem_pre = self.gts.code_analyzer.get_memory_expr(location, size/8, mode='pre')
        mem_post = self.gts.code_analyzer.get_memory_expr(location, size/8, mode='post')

        ac = self.gts.code_analyzer.get_immediate_expr(pattern & (2**size-1), size)

        dest = self.gts.code_analyzer.get_register_expr(g.destination[0].name, mode='pre')
        source_0 = self.gts.code_analyzer.get_register_expr(g.sources[0].name, mode='pre')
        source_2 = self.gts.code_analyzer.get_register_expr(g.sources[2].name, mode='pre')

        constr = []
        constr.append(mem_pre == 0)
        constr.append(dest == dst0)
        constr.append(source_0 == src0)
        constr.append(source_2 == src2)
        constr.append(mem_post != ac)

        # we assume we can control or easily take account of carry flag
        if self.gts.read_carrier_flag(g):
            flag_cf = self.gts.code_analyzer.get_register_expr('cf', mode='pre')
            constr.append(flag_cf == 0)

        valid = True
        if self.gts.code_analyzer.check_constraints(constr) != 'unsat':
            return False


        g._is_adc = False
        if self.gts.read_carrier_flag(g) and g.operation == '+':
            self.gts.code_analyzer.reset(full=True)
            ir_instrs = []
            self.gts.reil_translator.reset()
            for i in g.instrs:
                ir_instrs += self.gts.reil_translator.translate(i.asm_instr)

            for ir in ir_instrs:
                self.gts.code_analyzer.add_instruction(ir)

            flag_cf = self.gts.code_analyzer.get_register_expr('cf', mode='pre')
            flag_cf_p = self.gts.code_analyzer.get_register_expr('cf', mode='post')
            constr.append(flag_cf == 0)

            zero = self.gts.code_analyzer.get_immediate_expr(0, size)
            one = self.gts.code_analyzer.get_immediate_expr(1, size)
            two = self.gts.code_analyzer.get_immediate_expr(2, size)

            self.gts.code_analyzer._solver.push()
            self.gts.code_analyzer.set_postconditions([(mem_pre == zero),
                                                   (flag_cf == zero),
                                                   (mem_post == one)])

            # should be always sat, no?

            if self.gts.code_analyzer.check() != 'sat':
                return False

            dst_expr = self.gts.code_analyzer.get_expr_value(dest)
            source_0_expr = self.gts.code_analyzer.get_expr_value(source_0)
            source_2_expr = self.gts.code_analyzer.get_expr_value(source_2)

            self.gts.code_analyzer._solver.pop()
            self.gts.code_analyzer._solver.push()
            self.gts.code_analyzer.set_postconditions([(dest == dst_expr),
                                                   (source_0 == source_0_expr),
                                                   (source_2 == source_2_expr),
                                                   (mem_pre == zero),
                                                   (flag_cf == one),
                                                   (mem_post != two)])

            if self.gts.code_analyzer.check() != 'unsat':
                g_is_adc = False
            else:
                self.gts.code_analyzer._solver.pop()

                a = (flag_cf == one)
                b = (flag_cf == zero)
                c = (flag_cf <= one)
                self.gts.code_analyzer.set_postconditions([(dest == dst_expr),
                                                       (source_0 == source_0_expr),
                                                       (source_2 == 0xff),
                                                       (mem_pre == 0xff),
                                                       (flag_cf <= one),
                                                       (flag_cf >= zero),
                                                       (flag_cf_p != one)])

                if self.gts.code_analyzer.check() == 'unsat':
                    g._is_adc = True

        return valid

    def _side_effects(self, g, dst0, src0, src2, location, size):
        self.gts.emulator.reset()
        regs_init = utils.make_random_regs_context(self.gts.arch_info)

        regs_init[g.destination[0].name] = dst0
        regs_init[g.sources[0].name] = src0
        regs_init[g.sources[2].name] = src2

        mem_side_effects, stack_at_end = self.gts.check_mem_side_effects_and_stack_end(g,
                                                                                       regs_init,
                                                                                       location,
                                                                                       size)

        g._stack_offset = stack_at_end
        return mem_side_effects

    def _get_params(self, g, size, location=0x808080, pattern=0xac, cf=0, mem_pre_value=0x0):
    # smt sources operand values for writing at arbitrary location in memory
    # here symbolic execution should be used instead
        self.gts.code_analyzer.reset(full=True)
        for ir in g.get_ir_instrs():
            self.gts.code_analyzer.add_instruction(ir)

        mem_pre = self.gts.code_analyzer.get_memory_expr(location, size/8, mode='pre')
        mem_post = self.gts.code_analyzer.get_memory_expr(location, size/8, mode='post')

        ac = self.gts.code_analyzer.get_immediate_expr(pattern & (2**size-1), size)
        cf_value = self.gts.code_analyzer.get_immediate_expr(cf, self.gts.arch_info.register_size['cf'])

        dest = self.gts.code_analyzer.get_register_expr(g.destination[0].name, mode='pre')
        source_0 = self.gts.code_analyzer.get_register_expr(g.sources[0].name, mode='pre')
        source_2 = self.gts.code_analyzer.get_register_expr(g.sources[2].name, mode='pre')

        constr = []
        constr.append(mem_pre == mem_pre_value)
        constr.append(mem_post == ac)

        flag_cf = self.gts.code_analyzer.get_register_expr('cf', mode='pre')

        # we assume we can control or easily take account of carry flag
        if self.gts.read_carrier_flag(g):
            constr.append(flag_cf == cf_value)


        success = False
        dst_expr = 0
        source_0_expr = 0
        source_2_expr = 0
        flag_cf_expr = 0


        self.gts.code_analyzer.set_postconditions(constr)
        if self.gts.code_analyzer.check() == 'sat':
            dst_expr = self.gts.code_analyzer.get_expr_value(dest)
            source_0_expr = self.gts.code_analyzer.get_expr_value(source_0)
            source_2_expr = self.gts.code_analyzer.get_expr_value(source_2)
            flag_cf_expr = self.gts.code_analyzer.get_expr_value(flag_cf)
            success = True

        return [success, dst_expr, source_0_expr, source_2_expr, flag_cf_expr]

    def _for_stack_offset(self, gs):
        return sorted(gs, key = lambda x : x._stack_offset)

    def _for_operation_size(self, gs):
        return sorted(gs, key = lambda x : x.operation_size)

    def _for_min_payload(self, gs, size):
        return sorted(gs, key = lambda x : size / x.operation_size * x._stack_offset)

    def _get_chunk(self, location, value, size, mem_pre, cf = 0):
        candidates = []
        bits_size = size * 8
        best = None
        s = filter(lambda x : x.operation_size > bits_size, self.by_addr.values())
        candidates += s
        if len(candidates) > 0:
            best = self._for_min_payload(candidates, bits_size)[0]

        if not best:
            candidates += self.adcs
            if len(candidates) > 0:
                best = self._for_min_payload(candidates, bits_size)[0]

        if not best:
            best = self._for_min_payload(self.by_addr.values(), bits_size)[0]

        if not best:
            raise BaseException('No arithmetic store for build mem write')

        ams_g = best
        esp_at_end = best._stack_offset

        if ams_g.operation != '+':
            raise BaseException('Arithmetic store gadgets is not an addition. Not supported yet!')

        chunk_len = ams_g.operation_size / 8
        n_iter = size / chunk_len

        params = []
        fix_plus_one = False
        for i in xrange(n_iter):
            cvalue = ((value >> i * ams_g.operation_size) & 2 ** ams_g.operation_size-1)
            cmem_pre = ((mem_pre >> i * ams_g.operation_size) & 2 ** ams_g.operation_size-1)

            #we have to force a change to get right parameters (whe should also verify)
            if cmem_pre == cvalue:
                cvalue = cmem_pre + 1
                fix_plus_one = True
                continue

            cparams = self._get_params(ams_g,
                                       ams_g.operation_size,
                                       location + (chunk_len * i),
                                       cvalue,
                                       cf,
                                       cmem_pre)

            if fix_plus_one:
                cparams[3] -= 1


            params.append(cparams)

        #we make a last add with for overflow
        if ams_g._is_adc:
            cmem_pre = 0
            cvalue = 1
            cparams = self._get_params(ams_g,
                                       ams_g.operation_size,
                                       location + (chunk_len * n_iter),
                                       cvalue,
                                       0,
                                       cmem_pre)
            cparams[3] -= 1
            params.append(cparams)


        if (ams_g.destination[0].name != ams_g.sources[0].name):
            return

        ams_chunk = ArithmeticMemSetChunk(ams_g, esp_at_end, self.gts.arch_info)
        pl = None
        for i, param in enumerate(params):
            c = self.gts.regset.get_clobber_free_chunk({ams_g.destination[0].name : param[1],
                                                    ams_g.sources[2].name: param[3]
                                            })
            if i == 0:
                pl = PayloadChunk.get_general_chunk([c, ams_chunk])
            else:
                pl = PayloadChunk.get_general_chunk([pl, c, ams_chunk])


        if not ams_g._is_adc:
            return pl

        # Add a chunk for clearing the zero carry flag at the begging if we have one
        ccf = self.gts.ccf.get_ccf_chunk({})
        if ccf == None:
            print "Warning, assuming cf will be zero when adding offset"
            return pl

        pl = PayloadChunk.get_general_chunk([ccf, pl])
        return pl

    def get_memory_add_chunk(self, location, offset, size, mem_pre = None):
        # If we've bigger add (so carry is not a problem) or an adc gadget we set mem_pre = 0 and value to offset
        bits_size = size * 8
        s = filter(lambda x : x.operation_size >= (bits_size + 8), self.by_addr.values())
        if len(s) > 0 or len(self.adcs) > 0:
            mem_pre = 0
            value = offset
            return self._get_chunk(location, value, size, mem_pre)


        if not mem_pre:
            mem_pre = random.randint(0, (2 ** (size * 8)) -1)

        print "Warning no adc or adding with opearnd size less than address size (suppling good mempre value can be enough to get right got pathed value) "
        #Otherwise we've make a guess based on "fixed" bytes of the function used as base address
        mem_pre = mem_pre
        value = mem_pre + offset

        #We have a carry
        if value >> bits_size != 0:
            size += 1

        return self._get_chunk(location, value, size, mem_pre)
