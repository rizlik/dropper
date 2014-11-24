import random


def make_parent_regs_random(arch_info):
    regs_init = {r: random.randint(0, 2**arch_info.register_size[r] - 1) for r in arch_info.registers_gp_parent}
    return regs_init

def full_regs_set(_regs, arch_info):
    regs = _regs.copy()
    rm = arch_info.register_access_mapper()
    for r in arch_info.registers_gp:
        if r in regs:
            continue

        pr, mask, shift = rm[r]
        regs[r] = (regs[pr] & mask) >> shift

    return regs


def make_zero_regs_context(arch_info):
    regs_init = { r: 0 for r in arch_info.registers_gp_parent}

    reg_mapper = arch_info.register_access_mapper()
    for r in arch_info.registers_gp:
        if r in regs_init:
            continue

        reg, mask, shift = reg_mapper.get(r)
        regs_init[r] = (regs_init[reg] & mask) >> shift

    return regs_init
    
def make_random_regs_context(arch_info):
    regs_init = { r: random.randint(0, (2 ** arch_info.register_size[r]) - 1) for r in arch_info.registers_gp_parent}

    reg_mapper = arch_info.register_access_mapper()
    for r in arch_info.registers_gp:
        if r in regs_init:
            continue

        reg, mask, shift = reg_mapper.get(r)
        regs_init[r] = (regs_init[reg] & mask) >> shift

    return regs_init

def print_gadget(g):
    asm_instrs = [i.asm_instr for i in g.instrs]
    s =  "0x%x : " % g.address
    si = "; ".join([str(a) for a in asm_instrs])
    
    print s + si
