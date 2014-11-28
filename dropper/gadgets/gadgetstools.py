from elftools.elf import elffile

from barf.arch.x86.x86base import X86RegisterOperand
from barf.analysis.gadget import GadgetFinder
from barf.analysis.gadget import GadgetType
from barf.arch.x86.x86disassembler import X86Disassembler
from barf.arch.x86.x86translator import FULL_TRANSLATION
from barf.arch.x86.x86translator import X86Translator
from barf.arch.x86.x86base import X86ArchitectureInformation
from barf.arch import ARCH_X86_MODE_32
from barf.arch import ARCH_X86_MODE_64
from barf.core.reil import ReilEmulator
from barf.core.bi import Memory
from barf.analysis.gadget.gadgetclassifier import GadgetClassifier
from barf.core.smt.smtlibv2 import Z3Solver as SmtSolver
from barf.core.smt.smttranslator import SmtTranslator
from barf.analysis.codeanalyzer import CodeAnalyzer

from dropper.chunks.payloadchunk import RegSetChunk
from dropper.chunks.payloadchunk import ArithmeticMemSetChunk
from dropper.chunks.payloadchunk import PayloadChunk
from dropper.chunks.payloadchunk import RetToAddress32
from dropper.chunks.payloadchunk import StackSlideChunk

from dropper.gadgets.regset import RegSet
from dropper.gadgets.arithmeticstore import ArithmeticStore
from dropper.gadgets.clearcarryflag import CCFlag
from dropper.gadgets.memorystore import MemoryStore

import dropper.utils as utils
import logging
import random
import struct
import pdb

class GadgetTools():
    def __init__ (self, binary):
        self.elf = elffile.ELFFile(binary)

        if self.elf.elfclass == 32:
            self.arch_info = X86ArchitectureInformation(ARCH_X86_MODE_32)
        if self.elf.elfclass == 64:
            self.arch_info = X86ArchitectureInformation(ARCH_X86_MODE_64)

        self.emulator = ReilEmulator(self.arch_info.address_size)
        self.emulator.set_arch_registers(self.arch_info.registers_gp)
        self.emulator.set_arch_registers_size(self.arch_info.register_size)
        self.emulator.set_reg_access_mapper(self.arch_info.register_access_mapper())

        self.classifier = GadgetClassifier(self.emulator, self.arch_info)

        self.smt_solver = SmtSolver()
        self.smt_translator = SmtTranslator(self.smt_solver, self.arch_info.address_size)

        self.smt_translator.set_reg_access_mapper(self.arch_info.register_access_mapper())
        self.smt_translator.set_arch_registers_size(self.arch_info.register_size)

        self.code_analyzer = CodeAnalyzer(self.smt_solver, self.smt_translator)

        self.gadgets = {}
        self.classified_gadgets = {}

        self.regset = RegSet(self)
        self.ccf = CCFlag(self)
        self.ams = ArithmeticStore(self)
        self.memstr = MemoryStore(self)

        self.reil_translator = X86Translator(architecture_mode=self.arch_info.architecture_mode,
                                                  translation_mode=FULL_TRANSLATION)




    def find_gadgets(self, max_instr=10, max_bytes=15):
        logging.info('searching gadgets in binary..')
        for s in self.elf.iter_sections():
            if (s.header.sh_type == 'SHT_PROGBITS') and (s.header.sh_flags & 0x4):
                sz = s.header.sh_size
                base = s.header.sh_addr
                mem = Memory(lambda x, y : s.data()[x - base], None)
                gfinder = GadgetFinder(X86Disassembler(architecture_mode=self.arch_info.architecture_mode),
                                    mem,
                                    self.reil_translator)

                logging.info("searching gadgets in section " + s.name + "...")

                for g in gfinder.find(base, base + sz - 1, max_instr, max_bytes):
                    self.gadgets[g.address] = g

                logging.info("found {0} gadgets".format(len(self.gadgets)))

    def classify_gadgets(self):
        #setting 0 to cf flags to avoid impossible random value invalidates results
        self.classifier.set_reg_init({'cf': 0})

        for g in self.gadgets.itervalues():
            tgs = self.classifier.classify(g)
            for tg in tgs:
                if tg.type not in self.classified_gadgets:
                    self.classified_gadgets[tg.type] = []

                self.classified_gadgets[tg.type].append(tg)



    def find_reg_set_gadgets(self):
        self.regset.add(self.gadgets.itervalues())


    def read_carrier_flag(self, g):
        self.emulator.reset()
        regs_init = utils.make_random_regs_context(self.arch_info)

        self.emulator.execute_lite(g.get_ir_instrs(), regs_init)

        return 'cf' in self.emulator.registers


    def find_arithmetic_mem_set_gadgets(self):
        self.ams.add(self.classified_gadgets[GadgetType.ArithmeticStore])

    def get_stack_slide_chunk(self, slide):
        #TODO not use only pop gadgets and chain more slide if we wan't longer slide
        return self.regset.get_slide_stack_chunk(slide)


    def get_ret_func_chunk(self, args, address):
        """Return a chainable chunk that return to address and set up args or registers as if a function was called with args.

        Args:

        args (list): the list of args to setup as function arguments
        address (int): the address where to return

        """
        if self.arch_info.architecture_size == 64:
            if len(args) > 6:
                raise BaseException("chunk for calling a function whit more of six args isn't implemented")

            args_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
            regs_values = {args_regs[i] : a for i, a in enumerate(args)}
            regs_c = self.regset.get_chunk(regs_values)
            ret_c = PayloadChunk("", self.arch_info, address)
            return PayloadChunk.get_general_chunk([regs_c, ret_c])

        if self.arch_info.architecture_size == 32:
            slide_c = self.regset.get_slide_stack_chunk(len(args) * 4)
            ret_c = RetToAddress32(args, address, self.arch_info)
            return PayloadChunk.get_general_chunk([ret_c, slide_c])

    def get_mem_set_libc_read_chunk(self, location, fd, size, read_address):
        if self.arch_info.architecture_size == 64:
            print "TO IMPLEMENT"
            return


        if self.arch_info.architecture_size == 32:
            slide_chunk = self.regset.get_slide_stack_chunk(4 * 3)
            pl_chunk = MemSetLibcRead32(location,
                                        fd,
                                        size,
                                        read_address,
                                        self.arch_info)


        return PayloadChunk.get_general_chunk([pl_chunk, slide_chunk])

    def build_mem_add(self, location, offset, size, mem_pre = None):
        return self.ams.get_memory_add_chunk(location, offset, size, mem_pre)


    def check_mem_side_effects_and_stack_end(self, g, regs_init, location, size):
        stack_reg = 'esp'
        if (self.arch_info.architecture_size == 64):
            stack_reg = 'rsp'

        stack_base = 0x50
        regs_init[stack_reg] = stack_base

        cregs, mem_final = self.emulator.execute_lite(g.get_ir_instrs(), regs_init)
        mem_side_effects = []

        for addr in mem_final.get_addresses():
            if addr in [location + i for i in xrange(size/8)]:
                continue

            sp, vp = mem_final.try_read_prev(addr, 8)
            sn, vn = mem_final.try_read(addr, 8)

            #quick fix. We should disting between reading from stack and read side effetcs
            if sn and not sp and (addr >= stack_base - abs(stack_base - cregs[stack_reg]) and addr <= stack_base + abs(stack_base - cregs[stack_reg])):
                continue

            if (sp and sn and vp != vn) or (sn and not sp) :
                mem_side_effects.append(addr)

        return mem_side_effects, cregs[stack_reg] - stack_base

    def find_memory_store(self):
        self.mem_set_gadgets = {}

        if not GadgetType.StoreMemory in self.classified_gadgets:
            return

        self.memstr.add(self.classified_gadgets[GadgetType.StoreMemory])

    def find_ccfs(self):
        self.ccf.add(self.gadgets.values())

