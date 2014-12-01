class Planner():
    def __init__(self, arch_info, gts):
        self.arch_info = arch_info
        self.gts = gts

    def get_parent_reg(self, r):
        """ Return the parent register of r.
        """
        if r in self.arch_info.registers_base:
            return r

        rm = self.arch_info.register_access_mapper()
        if r in rm:
            return rm[r][0]
        else:
            raise BaseException("Can't find parent reg for %s" % r)
        

    def translate_memory_store(self, g):
        """Translate a mem[reg] <- reg type gadget in a PDDL action.
        """
        name = "memstr_%x" % g.address

        effect = "(and (forall (?a -imm) \n"
        effect += "      (when (= (val ?a) (reg %s))" % self.get_parent_reg(g.destination[0].name)
        effect += "          (assign (mem ?a) (reg %s))))" % self.get_parent_reg(g.sources[0].name)
        effect += "    (increase (stack-length) %d))" % g._stack_offset

        action = "(:action %s\n" % name
        action += "  :parameters ()\n"
        action += "  :precondition (and)\n"
        action += "  :effect %s" % effect
        action += ")\n"

        return action
        
    def translate_regset(self, g):
        """Translate a registers settings gadget in an PDDL action.
        """
        name = "regset_%x" % g.address

        parameters = " ".join(["?v%s" % self.get_parent_reg(d) for d in g._stack_indexes])

        effects = " ".join(["        (assign (reg %s) (val ?v%s))\n" % (self.get_parent_reg(r),self.get_parent_reg(r))
                            for r in g._stack_indexes])

        effects += "     (increase (stack-length) %d)" % g._stack_offset
        
        
        ret = "(:action %s\n" % name
        ret += "   :parameters (%s - imm)\n" % parameters
        ret += "   :precondition (and)\n"
        ret += "   :effect (and %s)" % effects
        ret += ")\n"

        return ret
    
    def translate_domain(self, name='dropper', regset_gadgets=None, memstr=None):
        """Build the domain representation associated with the examined file.
        """

        domain = "(define (domain %s )\n" % name
        req = "(:requirements :typing :fluents :conditional-effects)\n"
        types = "(:types imm register)\n"
        
        constants = "(:constants "
        constants += " ".join(["%s" %r for r in self.arch_info.registers_base])
        constants += " - register)\n"
        
        functions = "(:functions \n"
        functions += "(val ?x -imm)\n"
        functions += "(reg ?r - register)\n"
        functions += "(stack-length)\n"
        functions += "(mem ?addres - imm))\n"
        
        actions = ""
        if regset_gadgets:
            for g in regset_gadgets:
                actions += self.translate_regset(g)
        if memstr:
            for g in memstr:
                actions += self.translate_memory_store(g)

        domain += req
        domain += types
        domain += constants
        domain += functions
        domain += actions
        domain += ")\n"

        return domain

    def get_memset_problem(self, mem_values, domain_name = 'dropper'):
        objects = " ".join(["v_%d v_%d" % (a,v) for a,v in mem_values.iteritems()])
        objects = "(:objects %s - imm)\n" % objects

        values = "\n".join(["(= (val v_%d) %d)" % (r,r) for r in mem_values])
        values += "\n".join(["(= (val v_%d) %d)" % (r,r) for r in mem_values.values()])
        regs = "\n".join(["(= (reg %s) 0)" % r for r in self.arch_info.registers_base])
        mem = "\n".join(["(= (mem v_%d) 0)" % a for a in mem_values])
        
        init = "(:init\n"
        init += values + '\n'
        init += regs +'\n'
        init += mem + '\n'
        init += '(= (stack-length) 0))'

        goals = "\n".join(["(= (mem v_%d) %d)" % (r,v) for r,v in mem_values.iteritems()])
        goals = "\n(:goal (and %s))\n" % goals

        metric = "(:metric minimize (stack-length))\n"

        problem = "(define (problem regset)\n"
        problem += "(:domain %s)\n" % domain_name
        problem += objects
        problem += init
        problem += goals
        problem += metric
        problem += ")"

        
        return problem
        

    def get_regset_problem(self, regs_values, domain_name='dropper'):

        objects = " ".join(["v_%s" % s for s in regs_values])
        objects = "(:objects %s - imm)\n" % objects

        values = "\n".join(["(= (val v_%s) %d)" % (r,v) for r,v in regs_values.iteritems()])
        regs = "\n".join(["(= (reg %s) 0)" % r for r in regs_values])
        
        init = "(:init\n"
        init += values + '\n'
        init += regs +'\n'
        init += '(= (stack-length) 0))'

        goals = "\n".join(["(= (reg %s) %d)" % (r,v) for r,v in regs_values.iteritems()])
        goals = "\n(:goal (and %s))\n" % goals

        metric = "(:metric minimize (stack-length))\n"

        problem = "(define (problem regset)\n"
        problem += "(:domain %s)\n" % domain_name
        problem += objects
        problem += init
        problem += goals
        problem += metric
        problem += ")"

        
        return problem
        

