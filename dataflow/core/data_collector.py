#!/usr/bin/env python


from collections import defaultdict
from .parse_ast import *
from dataflow.core.data_process import ICALL_SOURCES

tainted_command_locs = []
tainted_length_locs = defaultdict(list)

weaks_copy = defaultdict(list)
weaks_copy_length = defaultdict(list)
weaks_only_length = defaultdict(list)
weaks_loop = defaultdict(list)
weaks_command_exec = defaultdict(list)
parameter_constraints = {}


MUSTALIAS, MAYALIAS, NOALIAS = 1, 2, 3


class Collector(object):
    """
    Collect all data generate in data flow analysis and analyze them.
    """

    def __init__(self, proj):

        self.support_data_types = ['Vptr', 'Iptr', 'Fptr', 'uArg', 'dArg', 'Aptr', 'Ret', 'Rptr', 'uData', 'sDef', 'Tdata', 'Dptr', 'Cons','tmp']

        self.proj = proj
        self.main_obj = self.proj.loader.main_object

        self.datas = {}
        self.constraints = defaultdict(list)

        self.icall_targets = {}
        self.switch_targets = {}

        self.analyzed_functions = set()

        self.state = self.proj.factory.blank_state()
        self.size_bytes = self.proj.arch.bytes
        self.endness = self.proj.arch.memory_endness

        self._initial_datas()


    def _initial_datas(self):

        for data_type in self.support_data_types:
            self.datas[data_type] = defaultdict(list)

    def _is_alias(self, datas1, datas2):
        # print(datas1, datas2)
        d1_hashs = [data.expr.ast.__hash__() for data in datas1]
        d2_hashs = [data.expr.ast.__hash__() for data in datas2]
        d1_hashs = set(d1_hashs)
        d2_hashs = set(d2_hashs)

        same_hashs = set()
        for d1 in d1_hashs:
            if d1 in d2_hashs:
                same_hashs.add(d1)

        if len(same_hashs) == len(d1_hashs) and len(same_hashs) == len(d2_hashs):
            return MUSTALIAS
        elif len(same_hashs):
            return MAYALIAS
        else:
            return NOALIAS

    def read_value(self, addr):
        # pe = get_mem_permission(addr)
        # if pe == 'ro' or pe == 'rw':
        # print("read-memory:%x" % (addr))
        if readable_address(addr):
            value_ast = self.state.memory.load(addr, self.size_bytes, endness=self.endness)
            if value_ast.op == 'BVV':
                return value_ast.args[0]

    def alias_check(self):
        from dataflow.core.data_process import ALIAS_SOURCES, ALL_SOURCES
        # print(ALIAS_SOURCES)

        alias_info = {}
        for funcea, datas in self.datas['uData'].items():
            for data in datas:
                aid = data.expr.alias_id
                if aid not in alias_info:
                    alias_info[aid] = []
                alias_info[aid].append(data)

                for sid in data.expr.contain_alias:
                    if sid not in alias_info:
                        alias_info[sid] = []
                    alias_info[sid].append(data)

        for as1, as2 in ALIAS_SOURCES:
            datas1 = alias_info.get(as1)
            datas2 = alias_info.get(as2)

            if datas1 and datas2:
                resalias = self._is_alias(datas1, datas2)
                if resalias == MUSTALIAS:
                    print("(%s %s) is MUSTALIAS" % (ALL_SOURCES[as1], ALL_SOURCES[as2]))

                elif resalias == MAYALIAS:
                    print("(%s %s) is MAYALIAS" % (ALL_SOURCES[as1], ALL_SOURCES[as2]))

                else:
                    print("(%s %s) is NOALIAS" % (ALL_SOURCES[as1], ALL_SOURCES[as2]))

            else:
                print("(%s %s) is NOALIAS" % (ALL_SOURCES[as1], ALL_SOURCES[as2]))

    def parse_function_ptr(self):

        print("\n Start-parse-icall-v1:\n")
        global_fptr_info = {}
        iptr_info = self.datas['Iptr']
        fptr_info = self.datas['Fptr']

        for funcea, fptr_exprs in fptr_info.items():
            for fptr_expr in fptr_exprs:
                base = fptr_expr.expr.base_ptr
                if type(base) is int:
                    if base not in global_fptr_info:
                        global_fptr_info[base] = []

                    global_fptr_info[base].append(fptr_expr)

        for funcea, iptr_exprs in iptr_info.items():
            for iptr_expr in iptr_exprs:
                base = iptr_expr.expr.base_ptr
                if type(base) is int and base in global_fptr_info:
                    fptr_exprs = global_fptr_info[base]
                    self._find_global_icall_target(iptr_expr, fptr_exprs)

                elif type(base) is str:
                    fptr_exprs = fptr_info.get(funcea)
                    if fptr_exprs:
                        self._find_symbol_icall_target(iptr_expr, fptr_exprs)

                # print("icall -> %s" % (iptr_expr))

        for funcea, icall_info in self.icall_targets.items():
            if len(icall_info):
                print("ICALL %x -> %s" % (funcea, icall_info))

            else:
                print("Unlucky, not found icall %x" % (funcea))

    def _find_global_icall_target(self, iptr_expr, fptr_exprs):
        iptr_struct_id = calculate_ast_struct_id(iptr_expr.expr.ast)
        funcea, iptr_src = ICALL_SOURCES.get(iptr_expr.expr.invariant_loc)
        if iptr_src is None:
            print("The iptr %s not in ICALL_SOURCES!" % (iptr_expr))
            return

        for fptr_expr in fptr_exprs:
            # print(" Icall- %s\n Fptr- %s" % (iptr_expr, fptr_expr))
            struct_id = calculate_ast_struct_id(fptr_expr.expr.ast)
            # print("Struct-ID: %s %s" % (iptr_struct_id, struct_id))
            if struct_id == iptr_struct_id:
                # print("Lucky, found icall %s -> %s" % (iptr_src, fptr_expr.expr.value))
                value_ast = fptr_expr.expr.value
                if value_ast.op == 'BVV':
                    value = value_ast.args[0]
                    self.add_icall_target(funcea, iptr_src, value)

    def _find_symbol_icall_target(self, iptr_expr, fptr_exprs):
        pass

    def parse_simple_function_ptr(self, proj):

        iptr_info = self.datas['Iptr']
        state = proj.factory.blank_state()
        size_bytes = proj.arch.bytes
        endness = proj.arch.memory_endness

        for funcea, iptr_exprs in iptr_info.items():
            for iptr_expr in iptr_exprs:
                base_ptr = iptr_expr.expr.base_ptr
                ast = iptr_expr.expr.ast

                funcea, iptr_src = ICALL_SOURCES.get(iptr_expr.expr.invariant_loc)
                # print("   -source: %x %x" % (funcea, iptr_src))

                if iptr_src in [0x2120c, 0x2115c]:
                    iptr_expr.constraints.append(0xa590c)

                # if ast.op == 'BVV' or type(base_ptr) is int and get_mem_permission(base_ptr) in ['ro', 'rw']:
                if ast.op == 'BVV' or type(base_ptr) is int and readable_address(base_ptr):
                    targets = self.read_data_by_expr(iptr_expr, state, size_bytes, endness, mode='icall')
                    for target in targets:
                        func_name = self.get_extern_function_name(target)
                        if func_name:
                            self.add_icall_target(funcea, iptr_src, func_name)
                        else:
                            self.add_icall_target(funcea, iptr_src, target)

        for funcea, icall_info in self.icall_targets.items():
            if len(icall_info):
                print("ICALL %x -> %s" % (funcea, icall_info))

    def parse_switch_targets(self, call_graph, proj):
        """
        Resolve the switch targets.
        """
        iptr_info = self.datas['Iptr']
        state = proj.factory.blank_state()
        size_bytes = proj.arch.bytes
        endness = proj.arch.memory_endness

        for funcea, iptr_exprs in iptr_info.items():
            function = call_graph.get_function_by_addr(funcea)
            if function is None:
                # print("The function %x not in call graph." % (funcea))
                continue

            for iptr_expr in iptr_exprs:
                print("Switch-jmp: %x has %s, with %s" % (funcea, iptr_expr, iptr_expr.constraints))
                base_ptr = iptr_expr.expr.base_ptr
                ast = iptr_expr.expr.ast

                funcea, iptr_src = ICALL_SOURCES.get(iptr_expr.expr.invariant_loc)
                print("   -source: %x %x" % (funcea, iptr_src))

                if ast.op == 'BVV' or type(base_ptr) is int:
                    targets = self.read_data_by_expr(iptr_expr, state, size_bytes, endness, mode='switch')
                    for target in targets:
                        if target in function.cfg._nodes:
                            self.add_switch_target(funcea, iptr_src, target)

        for funcea, switch_info in self.switch_targets.items():
            for bb_addr, targets in switch_info.items():
                for target in targets:
                    print("Switch %x : %x -> %x" % (funcea, bb_addr, target))

    def read_data_by_expr(self, trace_expr, state, size_bytes, endness, mode=None):

        def get_sim_action_info(trace_expr):
            sim_action_info = {}
            sim_actions = trace_expr.expr.sim_actions
            for i, sim_action in sim_actions.items():
                # print("degu- %s %s" % (sim_action, sim_action.action_data.__hash__()))
                action_id = sim_action.action_data.__hash__()
                sim_action_info[action_id] = sim_action.var_type
            return sim_action_info

        # print(" ...start parse icall-expr")
        data_ast = trace_expr.expr.ast
        if data_ast.op == 'BVV' and data_ast.args[0]:
            read_values = set()
            read_values.add(data_ast.args[0])

        # elif mode == 'icall' and data_ast.op == 'Load':
        elif mode == 'icall':
            constraints = trace_expr.constraints
            sim_action_info = get_sim_action_info(trace_expr)
            read_values = read_data_with_load(state, data_ast, size_bytes, endness, constraints, sim_action_info)

        elif mode == 'switch':
            constraints = trace_expr.constraints
            sim_action_info = get_sim_action_info(trace_expr)
            read_values = calculate_switch_targets(state, data_ast, size_bytes, endness, constraints, sim_action_info)

        else:
            read_values = set()

        # print("read_values: %s" % (read_values))
        # for value in read_values:
        #     print("i -> 0x%x" % (value))
        return read_values

    def add_icall_target(self, funcea, loc, target):
        if funcea not in self.icall_targets:
            self.icall_targets[funcea] = {}

        if loc not in self.icall_targets[funcea]:
            self.icall_targets[funcea][loc] = []

        if target not in self.icall_targets[funcea][loc]:
            self.icall_targets[funcea][loc].append(target)

    def add_switch_target(self, funcea, loc, target):
        if funcea not in self.switch_targets:
            self.switch_targets[funcea] = {}

        if loc not in self.switch_targets[funcea]:
            self.switch_targets[funcea][loc] = []

        if target not in self.switch_targets[funcea][loc]:
            self.switch_targets[funcea][loc].append(target)

    def collect_weaks(self, block, taint_expr):
        """
        Check taint security and collect some vulnerabilities.
        """
        taint_ast = taint_expr.expr.ast
        taint_loc = taint_expr.expr.taint_loc
        constraints = taint_expr.constraints

        if (taint_ast.op == 'BVV' and
                get_scope(taint_ast.args[0]) == 'stack' and taint_loc):
            # print("collect-weak: %s %x" % (taint_expr, taint_expr.expr.flag))
            taint_expr.expr.taint_loc = None
            # if taint_expr.expr.flag & 0x10000000:
            #     if taint_expr not in weaks_loop[block.addr]:
            #         print("Add-weak-loop-copy: bb-0x%x 0x%x %s (%s) %s" % (block.addr, taint_loc, taint_expr, id(taint_expr), taint_expr.constraints))
            #         copy_expr = taint_expr.deep_copy()
            #         weaks_loop[block.addr].append(copy_expr)
            if taint_expr.expr.flag & 0x1000:
                if taint_expr not in weaks_copy_length[taint_loc]:
                    print("Add-weak-copy-and-length: 0x%x %s (%s) %s" % (taint_loc, taint_expr, id(taint_expr), taint_expr.constraints))
                    weaks_copy_length[taint_loc].append(taint_expr)

            elif taint_expr not in weaks_copy[taint_loc]:
                print("Add-weak-copy: 0x%x %s (%s) %s" % (taint_loc, taint_expr, id(taint_expr), taint_expr.constraints))
                weaks_copy[taint_loc].append(taint_expr)

    def collect_heap_weaks(self, taint_expr):
        """
        Check taint security and collect some vulnerabilities.
        """
        taint_ast = taint_expr.expr.ast
        taint_loc = taint_expr.expr.taint_loc
        sim_actions = taint_expr.expr.sim_actions
        constraints = taint_expr.constraints

        taint_expr.expr.taint_loc = None
        if taint_expr.expr.flag & 0x1000:
            if len(sim_actions) == 0 and taint_expr not in weaks_copy_length[taint_loc]:
                print("Add-weak-heap-copy(len): 0x%x %s (%s) %s" % (taint_loc, taint_expr, id(taint_expr), taint_expr.constraints))
                weaks_copy_length[taint_loc].append(taint_expr)
        elif len(sim_actions) == 0 and taint_expr not in weaks_copy[taint_loc]:
            weaks_copy[taint_loc].append(taint_expr)
            print("Add-weak-heap-copy: 0x%x %s (%s) %s" % (taint_loc, taint_expr, id(taint_expr), taint_expr.constraints))

    def get_lib_func_name(self, addr):
        if self.main_obj.plt:
            for name, v_addr in self.main_obj.plt.items():
                if addr == v_addr:
                    return name

    def get_extern_function_name(self, addr):
        """
        Get extern lib function name.
        """
        if self.proj.is_hooked(addr):
            proc = self.proj._sim_procedures[addr]
            name = proc.display_name
            # print("%x with %s" % (addr, name))
            return name

        elif is_plt_region(addr):
            return self.get_lib_func_name(addr)

    def get_sim_action_info(self, trace_expr):
        sim_action_info = {}
        sim_actions = trace_expr.expr.sim_actions
        for i, sim_action in sim_actions.items():
            action_id = sim_action.action_data.__hash__()
            sim_action_info[action_id] = sim_action.var_type
        return sim_action_info

    def parse_icall_targets_v1(self):
        """
        Parse icall_expr and calculate its call target.
        """
        iptr_info = self.datas['Iptr']

        stores_info = defaultdict(list)
        similar_stores_info = defaultdict(list)
        self.get_stores_info(stores_info, 'Vptr')
        self.get_stores_info(stores_info, 'Fptr')
        self.get_similar_stores_info(similar_stores_info, 'Fptr')

        # for store_id, values in stores_info.items():
        #     print("store-info: %s %s" % (store_id, values))

        for addr, iptr_exprs in iptr_info.items():
            # print("\n %x has %s\n" % (addr, iptr_exprs))
            for iptr_expr in iptr_exprs:
                print("\nIcall: %x has %s, with %s" % (addr, iptr_expr, iptr_expr.constraints))
                data_ast = iptr_expr.expr.ast
                trace_sims = iptr_expr.expr.sims
                funcea, iptr_src = ICALL_SOURCES.get(iptr_expr.expr.invariant_loc)
                print("   -source: %x %x" % (funcea, iptr_src))

                sim_action_info = self.get_sim_action_info(iptr_expr)
                base_ptr = iptr_expr.expr.base_ptr
                constraints = iptr_expr.constraints

                new_iptrs = self.replace_alias_concret_ptr(data_ast, base_ptr, stores_info)
                new_asts = []
                for new_iptr in new_iptrs:
                    tmp_datas = self.replace_load_value(new_iptr, stores_info, sim_action_info, constraints=constraints)
                    new_asts.extend(tmp_datas)
                print("simplify_load get: %s" % (new_asts))
                for new_ast in new_asts:
                    calculate_ast_struct_similar_id(new_ast, trace_sims)

                if iptr_src in [0x2120c, 0x2115c]:
                    iptr_expr.constraints.append(0xa590c)

                targets = set()
                for iptr in new_asts:
                    targets |= self.calculate_icall_targets(iptr, sim_action_info, constraints)

                if len(targets) == 0 and iptr_expr.contain_special_symbol('o'):
                    targets = self.guess_icall_targets(iptr_expr, stores_info, sim_action_info)

                # if len(targets) == 0:
                #     print("Start Similar Match...")
                #     targets = self.match_icall_targets(iptr_expr, similar_stores_info)

                for target in targets:
                    func_name = self.get_extern_function_name(target)
                    print("   i -> 0x%x %s" % (target, func_name))
                    if func_name:
                        self.add_icall_target(funcea, iptr_src, func_name)
                    else:
                        self.add_icall_target(funcea, iptr_src, target)

    def calculate_icall_targets(self, iptr, sim_action_info, constraints, end_flag=None):
        values = set()

        if iptr.op == 'BVV':
            value = iptr.args[0]
            # if is_code_region(value) or is_extern_region(value):
            if maybe_function(value):
                values.add(value)

        elif iptr.op == 'Load':
            addr = iptr.args[0]
            if addr.op == 'BVV':
                addr_value = addr.args[0]
                value = self.read_value(addr_value)
                # if value and (is_code_region(value) or is_extern_region(value)):
                if value and maybe_function(value):
                    values.add(value)

            elif addr.op in offset_ops and not_contain_ls(addr):
                if 'i' in addr.variables:
                    read_values = self.read_recursive_data(addr, constraints=constraints, end_flag=end_flag, read_type='func')
                    if read_values:
                        values |= read_values

                else:
                    new_addr = claripy.simplify(addr)
                    if new_addr.op == 'BVV':
                        addr_value = new_addr.args[0]
                        value = self.read_value(addr_value)
                        # if value and is_code_region(value) or is_extern_region(value):
                        if value and maybe_function(value):
                            values.add(value)

        return values

    def get_stores_info(self, stores_info, data_type):
        """
        Get the pointer sotre info, e.g. store(bss_addr) == dptr
        """
        dptr_info = self.datas[data_type]
        for funcea, dptr_exprs in dptr_info.items():
            for dptr_expr in dptr_exprs:
                print("Sotre-func-ptr: %s" % (dptr_expr))
                if dptr_expr.expr.scope == 'stack':
                    continue
                data_ast = dptr_expr.expr.ast
                value = dptr_expr.expr.value
                if data_ast.op == 'Store':
                    struct_id = calculate_ast_struct_id(data_ast)
                    stores_info[struct_id].append(value)
                    new_store_addrs = self.simplify_store_addr(data_ast)
                    for new_addr in new_store_addrs:
                        struct_id = calculate_ast_struct_id(new_addr)
                        stores_info[struct_id].append(value)
                        print("Fnew-addr %s" % (new_addr))
                elif data_ast.op == 'BVV':
                    struct_id = data_ast.args[0]
                    stores_info[struct_id].append(value)

    def get_similar_stores_info(self, similar_stores_info, data_type):
        """
        Calculate the similar struct ID and get stores info.
        """
        dptr_info = self.datas[data_type]
        for funcea, dptr_exprs in dptr_info.items():
            for dptr_expr in dptr_exprs:
                # print("Cal-similar-sotre-func-ptr: %s" % (dptr_expr))
                data_ast = dptr_expr.expr.ast
                trace_sims = dptr_expr.expr.sims
                value = dptr_expr.expr.value
                if data_ast.op == 'Store':
                    struct_id = calculate_ast_struct_similar_id(data_ast, trace_sims)
                    if struct_id == 0:
                        continue
                    similar_stores_info[struct_id].append(value)
                    new_store_addrs = self.simplify_store_addr(data_ast)
                    for new_addr in new_store_addrs:
                        struct_id = calculate_ast_struct_similar_id(new_addr, trace_sims)
                        similar_stores_info[struct_id].append(value)

    def simplify_store_addr(self, data_ast):
        """
        Simplify store addr with concrete load value.
        """
        new_asts = []
        data_worklist = [data_ast]
        while data_worklist:
            data_ast = data_worklist.pop()
            tmp_asts = self.replace_concret_load_value(data_ast)
            if tmp_asts:
                data_worklist.extend(tmp_asts)

            else:
                new_asts.append(data_ast)

        return new_asts

    def replace_concret_load_value(self, data_ast):
        """
        Simplify store addr with concrete load value.
        """
        new_datas = []
        for child_ast in data_ast.recursive_children_asts:
            if child_ast.op != 'Load':
                continue

            ld_addr = child_ast.args[0]
            if ld_addr.op == 'BVV' and readable_address(ld_addr.args[0]):
                addr = ld_addr.args[0]
                value = self.state.memory.load(addr, self.size_bytes, endness=self.endness)
                if value.op == 'BVV' and value.args[0] and value.size() == child_ast.size():
                    new_data = data_ast.replace(child_ast, value)
                    new_datas.append(new_data)
                    return new_datas
        return new_datas

    def replace_one_load_value(self, data_ast, stores_info, sim_action_info, constraints=None):

        new_datas = []
        if data_ast.op == 'Load':
            ld_id = calculate_ast_struct_id(data_ast)
            if ld_id in stores_info:
                for value in stores_info[ld_id]:
                    # value_ast = BVV(value, data_ast.size())
                    new_data = data_ast.replace(data_ast, value)
                    new_datas.append(new_data)
                return new_datas

        for child_ast in data_ast.recursive_children_asts:
            if child_ast.op != 'Load':
                continue

            ld_addr = child_ast.args[0]
            ld_id = calculate_ast_struct_id(child_ast)

            # print("Load-addr: %s" % (ld_addr))

            if ld_id in stores_info:
                for value in stores_info[ld_id]:
                    # value_ast = BVV(value, child_ast.size())
                    print("-->find store: %s %s %s" % (data_ast, child_ast, value))
                    new_data = data_ast.replace(child_ast, value)
                    new_datas.append(new_data)
                return new_datas

            # elif ld_addr.op == 'BVV' and get_mem_permission(ld_addr.args[0]) in ['ro', 'rw']:
            elif ld_addr.op == 'BVV' and readable_address(ld_addr.args[0]):
                addr = ld_addr.args[0]
                value = self.state.memory.load(addr, self.size_bytes, endness=self.endness)
                if value.op == 'BVV' and value.args[0] and value.size() == child_ast.size():
                    new_data = data_ast.replace(child_ast, value)
                    new_datas.append(new_data)
                    return new_datas

            elif ld_addr.op in offset_ops and not_contain_ls(ld_addr) and 'i' in ld_addr.variables:
                child_ast_id = child_ast.__hash__()
                if child_ast_id in sim_action_info:
                    child_var_type = sim_action_info[child_ast_id]
                else:
                    child_var_type = get_no_ls_ast_type(ld_addr)
                read_values = self.read_recursive_data(ld_addr, constraints=constraints, read_type='data', end_flag=0, var_type=child_var_type)
                for value in read_values:
                    value_ast = BVV(value, child_ast.size())
                    new_data = data_ast.replace(child_ast, value_ast)
                    new_datas.append(new_data)
                return new_datas

        return new_datas

    def replace_load_value(self, data_ast, stores_info, sim_action_info, constraints=None):
        """
        Simplify the data/rodata/bss load expr with value.
        """
        new_asts = []
        data_worklist = [data_ast]
        while data_worklist:
            data_ast = data_worklist.pop()
            tmp_asts = self.replace_one_load_value(data_ast, stores_info, sim_action_info, constraints=constraints)
            if tmp_asts:
                data_worklist.extend(tmp_asts)

            else:
                new_asts.append(data_ast)

        return new_asts

    def get_max_cons(self, constraints):
        concret_cons = [c for c in constraints if type(c) is int and c != 0 and c != 1]
        return max(concret_cons) if len(concret_cons) else 0

    def read_recursive_data(self, addr, constraints=None, read_type=None, end_flag=None, var_type=None):
        """
        Recurisive parse load data by replace the symbol 'i'.
        """
        read_values = set()
        i = BVS('i')
        # max_value = constraints[0] if constraints else None
        # print("read-recurisive: %s %s" % (addr, constraints))

        max_index, max_addr = 0, 0
        max_cons = self.get_max_cons(constraints) if constraints else 0
        if max_cons:
            pe = get_mem_permission(max_cons)
            if pe == 'imm':
                max_index = max_cons
            else:
                max_addr = max_cons
        # print("max-index: %d, max-addr: %x" % (max_index, max_addr))
        max_index = max_index if max_index else Max_i

        for o in range(max_index):
            offset = BVV(o)
            new_addr = addr.replace(i, offset)
            new_addr = claripy.simplify(new_addr)
            # if new_addr.op == 'BVV' and get_mem_permission(new_addr.args[0]) in ['rw', 'ro']:
            if new_addr.op == 'BVV' and readable_address(new_addr.args[0]):
                addr_value = new_addr.args[0]
                if max_addr and addr_value > max_addr:
                    break

                value_ast = self.state.memory.load(addr_value, self.size_bytes, endness=self.endness)
                # print("read_recursive: addr %s, value: %s" % (new_addr, value_ast))
                if value_ast.op != 'BVV':
                    break
                    # continue

                value = value_ast.args[0]
                if value and value > 0:
                    if read_type == 'func' and is_code_region(value):
                        read_values.add(value)
                        print("  -- %x : %x" % (addr_value, value))

                    elif read_type == 'data' and is_data_region(value):
                        read_values.add(value)
                        # print("  -- %x : %x" % (addr_value, value))

                    else:
                        break

                elif value is None or value == end_flag:
                    break

                # elif value == 0:
                #     print("  -- %x : %x" % (addr_value, value))

            elif var_type and var_type != 'ptr':
                read_values.add(o)

            else:
                break

        return read_values

    def replace_alias_concret_ptr(self, data_ast, base_ptr, stores_info):
        new_datas = []
        if type(base_ptr) is int and base_ptr in stores_info:
            for value in stores_info[base_ptr]:
                sub_data = BVV(base_ptr, data_ast.size())
                # print("xxxx %s %s %s" % (data_ast, sub_data, value))
                new_data = data_ast.replace(sub_data, value)
                new_datas.append(new_data)
        if len(new_datas) == 0:
            new_datas.append(data_ast)
        return new_datas

    def guess_icall_targets(self, iptr_expr, stores_info, sim_action_info):
        """
        Guess icall targets, maybe not correct.
        """
        data_ast = iptr_expr.expr.ast
        un_syms = []
        for leaf_ast in data_ast.recursive_leaf_asts:
            if leaf_ast.op == 'BVS' and 'o' in leaf_ast.args[0]:
                un_syms.append(leaf_ast)

        for unsym_ast in un_syms:
            zero = BVV(0, unsym_ast.size())
            data_ast = data_ast.replace(unsym_ast, zero)
        constraints = iptr_expr.constraints

        tmp_datas = self.replace_load_value(data_ast, stores_info, sim_action_info)
        print("simplify_load get(2): %s" % (tmp_datas))

        targets = set()
        for iptr in tmp_datas:
            targets |= self.calculate_icall_targets(iptr, sim_action_info, constraints, end_flag=0)
        return targets

    def match_icall_targets(self, iptr_expr, similar_stores_info):
        """
        Match icall target and function pointer by similar struct.
        """
        targets = set()
        # for sim_id, values in similar_stores_info.items():
        #     print(sim_id, values)
        iptr_ast = iptr_expr.expr.ast
        trace_sims = iptr_expr.expr.sims
        struct_id = calculate_ast_struct_similar_id(iptr_ast, trace_sims)
        # print("--> %s with-id %s" % (iptr_expr, struct_id))

        values = similar_stores_info.get(struct_id)

        if values:
            # print("-->Good-find %s" % (values))
            for value in values:
                if value.op == 'BVV':
                    targets.add(value.args[0])
        return targets

    def save_collect_parameter_constraints(self):
        for addr, info in parameter_constraints.items():
            print('%x' % addr, info)
