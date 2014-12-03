from dropper import dropper
from dropper import planner

if __name__ == "__main__":
    dr = dropper.dropper('ls')
    cache = open('ls.cache', 'rb')
    dr.restore_state_from_file(cache)
    cache.close()
    pl = planner.Planner(dr.gts.arch_info, dr.gts)
    domain = open('/home/garulf/rop/pddl/ls_domain.pddl', 'wb')

    #    domain.write(pl.translate_domain(regset_gadgets=dr.gts.regset.by_addr.values()))
    memstr = [dr.gts.memstr.by_addr[0x40ea2c]]
    regset = [dr.gts.regset.by_addr[0x412052], dr.gts.regset.by_addr[0x412050]]
    domain.write(pl.translate_domain(regset_gadgets=dr.gts.regset.by_addr.values(), memstr=dr.gts.memstr.by_addr.values()))
    domain.close()

    problem = open('/home/garulf/rop/pddl/ls_rs.pddl', 'wb')
    problem.write(pl.get_regset_problem({'rsi': 2, 'rdi': 7}))
    problem.close()

    problem = open('/home/garulf/rop/pddl/ls_ms.pddl', 'wb')
    problem.write(pl.get_memset_problem({0x8080: 2, 0x8181: 3}))
    problem.close()
    
