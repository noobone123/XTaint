#!/usr/bin/env python

import pyvex
import claripy
import networkx
import itertools
from collections import defaultdict
from .variable_expression import VarExpr, TraceExpr, RecursiveExpr, SimAction, Sim, construct_trace_expr
# from .vex.statements import translate_stmt
from .code_location import CodeLocation
from .vex_process import EngineVEX

from .parse_ast import *
from .variable_type import *
from ..global_config import basic_types


import logging
logger = logging.getLogger("accurate_data_flow")
logger.setLevel('INFO')

#DEBUG
APTR_MAX_LS = 5
APTR_MAX_Load = 5
MAX_VALUE = 0x7fffffff
max_ast_lenght = 400
max_trace_exprs = 400
icall_check = True
# icall_check = False
# taint_check = True
taint_check = False

Taint_Offset = 0x64
symbolic_count = itertools.count(1)

choose_register = True
do_forward_store_redefine = True
do_forward_concrete_load = False

loop_inc_tmps_record = defaultdict(int)
loop_inc_locations = defaultdict(set)

backward_tmp_exprs = defaultdict(list)
function_store_defs = defaultdict(dict)
record_backward_exprs = defaultdict(list)
record_redef_exprs = defaultdict(list)
record_remaining_exprs = defaultdict(list)
record_redef_labels = set()

record_binop_symbols = {}


class AccurateDataFlow(EngineVEX):
    def __init__(self, project, call_graph, config, icall_check=False, taint_check=False, alias_check=False):

        super(AccurateDataFlow, self).__init__(project)

        self.call_graph = call_graph
        self.config = config

        self.icall_check = icall_check
        self.taint_check = taint_check
        self.alias_check = alias_check

        self.backward_store_records = set()

    # Kai code!
    def _initialize_execute_variable2(self, sym, sym_type, expr):
        """
        Initialize the variable while executing irsb
        :param sym: a sym name of tmp or register
        :param sym_type: a symbol t (tmp) or r (register)
        :param expr: a variable expression
        """
        if sym_type == 't':
            sym_offset = int(sym[1:])
            self.state.scratch.store_tmp(sym_offset, expr.expr.value)

        elif sym_type == 'r':
            sym_offset = int(sym[1:])
            self.state.registers.store(sym_offset, expr.expr.value)


    def create_recursive_expr(self, trace_expr, base_ast, offset_ast):
        recursive_expr = RecursiveExpr(trace_expr.expr.copy(),
                                        index=trace_expr.index,
                                        base=base_ast,
                                        offset=offset_ast)

        position = recursive_expr.get_recursive_base_positon()
        recursive_expr.position = position

        recursive_expr.forward_path = trace_expr.forward_path.copy()
        recursive_expr.backward_path = trace_expr.backward_path.copy()
        recursive_expr.cycle_locs = trace_expr.cycle_locs
        recursive_expr.guard = trace_expr.guard
        recursive_expr.constraints = trace_expr.constraints.copy()
        recursive_expr.cons_ids = trace_expr.cons_ids.copy()

        recursive_expr.loop_num = trace_expr.loop_num
        recursive_expr.inter_funcs = trace_expr.inter_funcs.copy()
        recursive_expr.inter_icall_level = trace_expr.inter_icall_level
        recursive_expr.taint_propagaton_level = trace_expr.taint_propagaton_level

        # print("Recursive: %s" % (recursive_expr))
        return recursive_expr

    def _check_sim_action(self, action, trace_expr):
        """
        Active or kill sim_action's live by the trace_dir and def location.
        """
        trace_dir = trace_expr.expr.trace_dir
        action_type, code_location = action.action_type, action.code_location

        if action_type == 's' and trace_dir == 'B':
            trace_expr.expr.kill_store_action_by_loc(code_location)

        elif action_type == 'wl' and trace_dir == 'F':
            trace_expr.expr.kill_load_action_by_loc(code_location)

    def _kill_exprs(self, block_exprs, trace_exprs, killed_exprs):
        for kill_expr in killed_exprs:
            if len(trace_exprs):
                try:
                    trace_exprs.remove(kill_expr)
                except ValueError:
                    pass
            if len(block_exprs):
                try:
                    block_exprs.remove(kill_expr)
                except ValueError:
                    pass

    def _kill_exprs_v2(self, block_exprs, killed_exprs):
        for kill_expr in killed_exprs:
            try:
                block_exprs.remove(kill_expr)
            except ValueError:
                pass

    def kill_all_alias_exprs(self, input_exprs, killed_exprs):
        """
        Kill all alias exprs that have same memory address
        (with same ptr_id)
        """
        ptr_ids = set()
        remove_exprs = []
        # print("killed-exprs: %s" % (killed_exprs))
        for kill_expr in killed_exprs:
            ptr_ids.add(kill_expr.expr.ptr_id)

        # print("ptr_ids: %s" % (ptr_ids))
        for trace_expr in input_exprs:
            if (trace_expr.expr.var_type == 'ptr' and
                    trace_expr.expr.ptr_id in ptr_ids):
                remove_exprs.append(trace_expr)

        for remove_expr in remove_exprs:
            input_exprs.remove(remove_expr)

    # Kai code!
    def _update_store_addr_with_alias(self, st_addr, st_addr_exprs, code_location, trace_exprs):

        new_exprs = []
        for trace_expr in trace_exprs:
            for st_addr_expr in st_addr_exprs:
                new_expr = trace_expr.replace(st_addr, st_addr_expr.expr.ast, st_addr_expr.expr.sim_actions)
                new_expr.expr.location = code_location
                new_expr.index = code_location.stmt_idx
                new_expr.expr.trace_dir = 'F'
                new_exprs.append(new_expr)
        return new_exprs

    def _create_constraint_expr(self, block, c, stmt_idx=0, index=0):
        """
        Create a constraint expr and use backward trace to find the constraint value.
        """
        data_ast = BVS(c)
        cons_expr = construct_trace_expr(data_ast,
                                    value=None,
                                    pattern='OB',
                                    data_type='Cons',
                                    trace_dir='B',
                                    block_addr=block.addr,
                                    stmt_idx=stmt_idx,
                                    index=index,
                                    var_type=basic_types[data_ast.size()])

        return cons_expr

    def _contraint_is_tained(self, block, cons_var):
        for trace_expr in block.forward_exprs:
            data_type = trace_expr.expr.data_type
            trace_ast = trace_expr.expr.ast
            trace_sims = trace_expr.expr.sims

            if data_type == 'Tdata' and trace_ast.op == 'BVS' and cons_var in trace_sims:
                return True
        return False

    def _find_taint_constraint(self, block, wr_info, code_location, trace_expr):
        """
        Find taint constraint.
        """
        def get_guard_info(src, dst):
            info = None
            src_addr = src.addr
            if src_addr in dst.guard:
                jmp_guard = dst.guard[src_addr]
                # print("jmp_guard: %s" % (jmp_guard))
                if (len(jmp_guard.args) == 2):
                    opnd0, opnd1 = jmp_guard.args
                    if ((opnd0.op == 'BVS' or opnd0.op == 'BVV') and
                            (opnd1.op == 'BVS' or opnd1.op == 'BVV')):
                        info = (jmp_guard.op, opnd0.args[0], opnd1.args[0])
            return info

        def get_cmp_binop(guard_var, cmpop, opnd0, opnd1):
            if '_' in cmpop:
                op = cmpop[2:4]
            else:
                op = self.get_claripy_operation(cmpop)

            if not op:
                return None

            if guard_var == opnd0:
                return op
            elif guard_var == opnd1:
                return self.reverse_cmp_binop(op)

        # block.irsb.pp()
        # print("F-cons: %s %s %s" % (code_location, trace_expr, str(wr_info)))
        sims = trace_expr.expr.sims
        opnds = wr_info[1]
        if opnds[0] in sims:
            guard_var = opnds[0]
            cmp_var = opnds[1]

        elif opnds[1] in sims:
            guard_var = opnds[1]
            cmp_var = opnds[0]

        else:
            return None

        if type(cmp_var) is str:
            cmp_value = get_value(block, cmp_var)
            if cmp_value is not None:
                cmp_var = cmp_value
            # print(block.live_defs[cmp_var])
            # print("xpx: %s" % (cmp_value))

        cons_type = trace_expr.expr.cons_type
        var_type = trace_expr.expr.var_type
        if cmp_var != 0 and cons_type == 0 and var_type == 'ptr':
            return None

        ptr_id = trace_expr.expr.ptr_id
        if ptr_id in block.taint_constraints:
            return None

        # print("Get-cons (%d): %x %s and %s" % (cons_type, ptr_id, guard_var, cmp_var))
        cons_expr = None
        # if (type(cmp_var) is str and cons_type == 3):
        #     cons_expr = self._create_constraint_expr(block, cmp_var, code_location.stmt_idx, code_location.stmt_idx)
        #     print("Found-strlen-cons: %s" % (cons_expr))

        succ_blocks = list(block.successors)
        # print(succ_blocks)
        # if len(succ_blocks) == 1:
        #     cmpop = self.get_claripy_operation(wr_info[0])
        #     # print("Sure-add-cons: %s %s %s" % (cmpop, guard_var, cmp_var))
        #     if cons_expr is not None:
        #         alias_id = cons_expr.expr.alias_id
        #         cons_info = (cons_type, cmpop, alias_id)
        #     else:
        #         cons_info = (cons_type, cmpop, cmp_var)
        #     block.taint_constraints[ptr_id] = {0: cons_info}
        #     # print(block.taint_constraints)
        #     return cons_expr

        for succ_block in succ_blocks:
            guard_info = get_guard_info(block, succ_block)
            # print("guard: %s" % (str(guard_info)))
            if guard_info is None:
                return cons_expr
            cmpop, opnd0, opnd1 = guard_info
            if ptr_id not in block.taint_constraints:
                block.taint_constraints[ptr_id] = {}

            cmp_op = get_cmp_binop(guard_var, cmpop, opnd0, opnd1)
            # print("guard-info: %s %s %s %s" % (succ_block, cmp_op, guard_var, cmp_var))

            if cmp_op:
                if cons_type == 5:
                    if 'g' in cmp_op:
                        # print("Skip-cons (strlen >) to %s %s %s" % (succ_block, cmp_op, cmp_var))
                        continue
                    else:
                        if type(cmp_var) is int or not self._contraint_is_tained(block, cmp_var):
                            cons_info = (cons_type, cmp_op, cmp_var)
                            block.taint_constraints[ptr_id][succ_block.addr] = cons_info
                            # print("Append-cons(strlen) to %s %s %s" % (succ_block, cmp_op, cmp_var))

                else:
                    # print("Append-cons to %s %s %s" % (succ_block, cmp_op, cmp_var))
                    cons_info = (cons_type, cmp_op, cmp_var)
                    block.taint_constraints[ptr_id][succ_block.addr] = cons_info

        # print("taint-cons: %s" % block.taint_constraints)
        # return cons_expr

    def _find_loop_constraint(self, block, wr_info, code_location, trace_expr):
        """
        Find loop copy's length constriant.
        """
        def get_guard_info(src, dst):
            info = None
            src_addr = src.addr
            if src_addr in dst.guard:
                jmp_guard = dst.guard[src_addr]
                # print("jmp_guard: %s" % (jmp_guard))
                if (len(jmp_guard.args) == 2):
                    opnd0, opnd1 = jmp_guard.args
                    if ((opnd0.op == 'BVS' or opnd0.op == 'BVV') and
                            (opnd1.op == 'BVS' or opnd1.op == 'BVV')):
                        info = (jmp_guard.op, opnd0.args[0], opnd1.args[0])
            return info

        def get_cmp_binop(guard_var, cmpop, opnd0, opnd1):
            if '_' in cmpop:
                op = cmpop[2:4]
            else:
                op = self.get_claripy_operation(cmpop)

            if not op:
                return None

            if guard_var == opnd0:
                return op
            elif guard_var == opnd1:
                return self.reverse_cmp_binop(op)

        # block.irsb.pp()
        # print("B-loop-cons: %s %s %s" % (code_location, trace_expr, str(wr_info)))
        sims = trace_expr.expr.sims
        opnd0, opnd1 = wr_info[1]
        if opnd0 in sims:
            guard_var = opnd0
            cmp_var = opnd1
            guard_type = sims[opnd0].var_type

        elif opnd1 in sims:
            guard_var = opnd1
            cmp_var = opnd0
            guard_type = sims[opnd1].var_type

        else:
            return None

        if guard_type not in ['int', 'long', 'llong']:
            return None

        if type(cmp_var) is str:
            cmp_value = get_value(block, cmp_var)
            if cmp_value is not None:
                cmp_var = cmp_value

        succ_blocks = list(block.successors)
        for succ_block in succ_blocks:
            guard_info = get_guard_info(block, succ_block)
            # print("guard: %s" % (str(guard_info)))
            if guard_info is None:
                continue
            cmpop, opnd0, opnd1 = guard_info
            cmp_op = get_cmp_binop(guard_var, cmpop, opnd0, opnd1)
            # print("guard-info: %s %s %s %s" % (succ_block, cmp_op, guard_var, cmp_var))

            if cmp_op and 'g' in cmp_op and not succ_block.is_loop:
                print("ooh, found loop copy length constriant: %s" % (cmp_var))
                if type(cmp_var) is str:
                    cons_expr = self._create_constraint_expr(block, cmp_var, code_location.stmt_idx, code_location.stmt_idx)
                    cons_expr.expr.cons_type = 3
                    trace_expr.cons_ids.append(cons_expr.expr.alias_id)
                    # print("Found-strlen-cons: %s" % (cons_expr))
                    return cons_expr

    def _find_loop_constraint_v2(self, block, wr_info, code_location, trace_expr):
        """
        Find loop copy's length constriant.
        """
        def get_guard_info(src, dst):
            info = None
            src_addr = src.addr
            if src_addr in dst.guard:
                jmp_guard = dst.guard[src_addr]
                # print("jmp_guard: %s" % (jmp_guard))
                if (len(jmp_guard.args) == 2):
                    opnd0, opnd1 = jmp_guard.args
                    if ((opnd0.op == 'BVS' or opnd0.op == 'BVV') and
                            (opnd1.op == 'BVS' or opnd1.op == 'BVV')):
                        info = (jmp_guard.op, opnd0.args[0], opnd1.args[0])
            return info

        def get_cmp_binop(guard_var, cmpop, opnd0, opnd1):
            if '_' in cmpop:
                op = cmpop[2:4]
            else:
                op = self.get_claripy_operation(cmpop)

            if not op:
                return None

            if guard_var == opnd0:
                return op
            elif guard_var == opnd1:
                return self.reverse_cmp_binop(op)

        # block.irsb.pp()
        # print("B-loop-cons: %s %s %s" % (code_location, trace_expr, str(wr_info)))
        sims = trace_expr.expr.sims
        guard_var, cmp_var = wr_info[1]
        opnd0_type, opnd1_type = wr_info[3]
        if opnd0_type not in ['int', 'long', 'llong']:
            return None

        for succ_block in block.successors:
            guard_info = get_guard_info(block, succ_block)
            # print("guard: %s" % (str(guard_info)))
            if guard_info is None:
                continue
            cmpop, opnd0, opnd1 = guard_info
            cmp_op = get_cmp_binop(guard_var, cmpop, opnd0, opnd1)
            # print("guard-info: %s %s %s %s" % (succ_block, cmp_op, guard_var, cmp_var))

            if cmp_op and ('g' in cmp_op or cmp_op == 'eq') and not succ_block.is_loop:
                print("ooh, found loop copy length constriant(A): %s" % (cmp_var))
                if type(cmp_var) is str:
                    cons_expr = self._create_constraint_expr(block, cmp_var, code_location.stmt_idx, code_location.stmt_idx)
                    cons_expr.expr.cons_type = 3
                    trace_expr.cons_ids.append(cons_expr.expr.alias_id)
                    # print("Found-strlen-cons: %s" % (cons_expr))
                    return cons_expr

    def _get_link_action_ast(self, action, sim_types):
        ld_data, link_base, link_offset = None, None, None
        ld_size = action.var_size
        addr_type = action.addr_type
        ld_addr = action.src_alias if action.src_alias else action.src

        if type(ld_addr) is str:
            ld_data = claripy.Load(BVS(ld_addr), ld_size)
            sim_types[ld_addr] = 'ptr'
            link_base = ld_data
            link_offset = BVV(0)

        elif type(ld_addr) is tuple:
            if ld_addr[0] in ['+', '-']:
                addr_ast = self._calculate_simple_binop_v3(ld_addr)
                ld_data = claripy.Load(addr_ast, ld_size)
                # sim_types = self._get_sim_type_v1(ld_addr, block.live_defs)
                sim_types = {ld_addr[1][0]: 'ptr'}
                if type(ld_addr[1][1]) is str:
                    sim_types[ld_addr[1][1]] = basic_types['default']
                link_base = addr_ast.args[0]
                link_offset = addr_ast.args[1]

        else:
            raise Exception("Unknow ld_addr type %s" % (str(ld_addr)))

        if ld_data is None:
            raise Exception("Could not found load ast in %s" % (action))

        return ld_data, link_base, link_offset

    def _get_chain_action_ast(self, action, sim_types):
        """
        """
        ld_data, link_base, link_offset = None, None, None
        ld_size = action.var_size
        addr_type = action.addr_type
        ld_addr = action.src_alias if action.src_alias else action.src

        if type(ld_addr) is str:
            sim_types[ld_addr] = 'ptr'
            link_base = BVS(ld_addr)
            link_offset = BVV(0)
            ld_data = claripy.Load(link_base, ld_size)

        elif type(ld_addr) is tuple and ld_addr[0] == '+':
            addr_ast = self._calculate_simple_binop_v3(ld_addr)
            ld_data = claripy.Load(addr_ast, ld_size)
            sim_types = {ld_addr[1][0]: 'ptr'}
            link_base = addr_ast.args[0]
            link_offset = addr_ast.args[1]

        else:
            raise Exception("Unknow ld_addr type %s" % (str(ld_addr)))

        if ld_data is None:
            raise Exception("Could not found load ast in %s" % (action))

        return ld_data, link_base, link_offset

    def _get_load_action_ast(self, action, block, sim_types, trace_ast, is_loop=False, data_type=None):
        ld_data = None
        ld_size = action.var_size
        addr_type = action.addr_type
        ld_addr = action.src_alias if type(action.src_alias) is str else action.src

        if data_type == 'Iptr' and trace_ast.op == 'BVS' and trace_ast.size() != ld_size:
            ld_size = trace_ast.size()

        if type(action.src) is int:
            ld_data = claripy.Load(BVV(action.src), ld_size)
            sim_types[action.src] = 'ptr'

        elif is_loop and addr_type != 'S' and type(ld_addr) is str:
            ld_data = claripy.Load(BVS(ld_addr), ld_size)
            sim_types[ld_addr] = 'ptr'

        else:
            # if type(action.value) is int:
            #     ld_data = BVV(action.value, ld_size)

            if (type(action.addr_value) is int and (addr_type == 'S' or
                    block.special_flag & 0x1)):
                ld_data = claripy.Load(BVV(action.addr_value), ld_size)
                sim_types[action.addr_value] = 'ptr'
                if addr_type == 'S':
                    arg_sym = self.judge_stack_argument(action.addr_value)
                    if arg_sym:
                        ld_data = BVS(arg_sym, ld_size)
                        sim_types[arg_sym] = 'ptr'

            elif type(ld_addr) is str:
                ld_data = claripy.Load(BVS(ld_addr), ld_size)
                sim_types[ld_addr] = 'ptr'

            # elif type(ld_addr) is tuple:
            #     addr_ast = self._calculate_simple_binop_v3(ld_addr)
            #     wr_data = claripy.Load(addr_ast, ld_size)
            #     sim_types = self._get_sim_type_v1(ld_addr, block.live_defs)

            else:
                raise Exception("Unknow ld_addr type %s" % (str(ld_addr)))

        if ld_data is None:
            raise Exception("Could not found load ast in %s" % (action))

        return ld_data

    def _get_loadg_action_ast(self, action, sim_types):
        ld_data = None
        ld_size = action.var_size
        opnds, opnds_alias = action.src[0], action.src_alias[0]
        ld_addr = opnds_alias[1] if type(opnds_alias[1]) is str else opnds[1]
        if type(action.value) is int:
            ld_data = BVV(action.value, ld_size)

        elif type(action.addr_value) is int:
            ld_data = claripy.Load(BVV(action.addr_value), ld_size)
            if action.addr_type == 'S':
                arg_sym = self.judge_stack_argument(action.addr_value)
                if arg_sym:
                    ld_data = BVS(arg_sym, ld_size)

        elif type(ld_addr) is str:
            ld_data = claripy.Load(BVS(ld_addr), ld_size)
            sim_types[ld_addr] = 'ptr'

        else:
            raise Exception("Unknow ld_addr type %s" % (str(ld_addr)))

        if ld_data is None:
            raise Exception("Could not found load ast in %s" % (action))

        return ld_data

    def _get_binop_action_ast(self, action, var_type, data_type, trace_flag=0):

        base_ast, offset_ast = None, None
        data_info = action.src_alias if action.src_alias else action.src
        vex_op, opnds = data_info[0], data_info[1]
        if action.inc_flag:
            binop_data, base_ast, offset_ast = self._get_increment_ast(action)

        else:
            if data_type in ['Vptr', 'Iptr', 'tmp'] and 'hl' in vex_op:
                binop_data = self._get_binop_ast(action)

            elif data_type != 'Cons' and var_type and var_type != 'ptr':
                binop_data = self.get_binop_symbol(action.code_location)

            elif (data_type == 'Tdata' and trace_flag & 0x200 == 0 and
                    (type(opnds[1]) is int and (opnds[1] >= 0x8000 or opnds[1]%2 != 0))):
                binop_data = None

            elif type(action.value) is int:
                binop_data = BVV(action.value, action.var_size)

            else:
                binop_data = self._get_binop_ast(action)

        return binop_data, base_ast, offset_ast

    def _get_binop_ast(self, action, data_type=None):

        data_info = action.src_alias if action.src_alias else action.src
        binop = data_info[0]

        if binop in self.ignore_binops:
            binop_data = self.insignificant_symbol
            # print('6: %s' % (binop_data))
            return binop_data

        binop_data = self.calculate_binop_stmt_v2(data_info)

        if binop_data.op in self.shift_ops:
            binop_data= self.convert_shift_operators(binop_data, data_type)
            # print('7: %s' % (binop_data))

        # print("get-binop: %s" % (binop_data))
        return binop_data

    def _get_increment_ast(self, action):
        """
        In loop, some variable with increment.
        """
        base_ast, offset_ast = None, None
        op = action.src_alias[0]
        if action.inc_flag == 1 and op in ['+', '-']:
            base, offset = action.inc_base[1], action.inc_offset[1]
            base_ast = BVS(base)
            if type(offset) is int:
                offset_ast = BVV(offset)
            else:
                offset_ast = self.get_binop_symbol(action.code_location)

            if op == '+':
                inc_data = base_ast + BVS('i') * offset_ast

            elif op == '-':
                inc_data = base_ast - BVS('i') * offset_ast

        else:
            inc_data = self._get_binop_ast(action)
            base_ast = inc_data

        return inc_data, base_ast, offset_ast

    def get_binop_symbol(self, code_location):
        """
        Get binop symbol ast from record_binop_symbols.
        """
        return self.insignificant_symbol
        # if code_location in record_binop_symbols:
        #     return record_binop_symbols[code_location]
        # else:
        #     sym = BVS("o%d" % (next(symbolic_count)))
        #     # print("unsym-data(1): %s %s" % (code_location, sym))
        #     record_binop_symbols[code_location] = sym
        #     return sym

    def _generate_tmp_expr(self, block, code_location, trace_exprs):
        """
        For the Vptr or Dptr, if the value is not 'BVS' or 'BVV', should trace the value in backward.
        """
        # print("Test-update-save-value: %s" % (code_location))
        update_vars = set()
        for trace_expr in trace_exprs:
            value = trace_expr.expr.value

            if value is not None and value.op not in ['BVV', 'BVS']:
                update_vars |= get_trace_symbols(value)

        if len(update_vars) == 0:
            return []

        new_exprs = []
        trace_expr = trace_exprs[0]
        for var in update_vars:
            ast = trace_expr.expr.ast
            var_type = get_sim_type(block, var)
            new_expr = trace_expr.replace(ast, var, rep_type=var_type, base_ptr=var)
            new_expr.expr.value = BVS(var, ast.size())
            new_expr.expr.data_type = 'tmp'
            new_expr.expr.trace_dir = 'B'
            new_expr.expr.pattern = 'OB'
            new_expr.expr.source = code_location
            new_expr.expr.alias_id = code_location.__hash__()
            new_expr.expr.flag = 0x400
            new_expr.index = 0 if 'r' in var else code_location.stmt_idx
            # print("should backward-update: %s\n get-new: %s" % (var, new_expr))
            new_exprs.append(new_expr)

        return new_exprs

    # Kai code!
    def _find_store_use2(self, st_addr, st_data, st_size, code_location, trace_expr):
        """
        For the IR "STle(t19) = t9", the tmp t9 is used, could be replaced with 'Store(t19)'
        """

        # TODO for the embedded store instructions.
        if code_location in trace_expr.expr.store_location:
            return []

        if type(st_addr) is int:
            addr_ast = claripy.BVV(st_addr, self.arch_bits)

        elif type(st_addr) is str:
            addr_ast = claripy.BVS(st_addr, self.arch_bits, explicit_name=True)

        elif type(st_addr) is tuple:
            addr_ast = self._calculate_simple_binop_v1(st_addr[1])
            # addr_ast = claripy.BVS(st_addr[0], self.arch_bits, explicit_name=True)
            # offset = claripy.BVV(st_addr[1], self.arch_bits)
            # addr_ast = ptr + offset

        else:
            return []

        dst_data = claripy.Store(addr_ast, st_size)
        sim_action = self.create_sim_action(dst_data, code_location)
        re_sim_actions = {0: sim_action}
        new_expr = trace_expr.replace(st_data, dst_data, re_sim_actions=re_sim_actions)
        new_expr.expr.store_location.append(code_location)
        new_expr.expr.location = code_location
        # new_expr.expr.trace_dir = 'F'
        new_expr.index = code_location.stmt_idx

        return [new_expr]

    def _find_store_use_v1(self, action, data, trace_expr):

        code_location = action.code_location
        data_type = trace_expr.expr.data_type
        value = trace_expr.expr.value

        if code_location in trace_expr.expr.store_location:
            return []
        elif data_type == 'Aptr' and value is not None and sim_action_len(value) > 2:
            return []

        sim = trace_expr.expr.sims[data]
        var_type = sim.var_type if sim.var_type else action.var_type

        if (not sim.live or (var_type and var_type != 'ptr' and data_type != 'Cons')):
            return []

        addr_value = action.addr_value

        sim_types = None
        if type(addr_value) is int:
            addr_ast = BVV(addr_value)
            sim_types = {addr_value: 'ptr'}

        elif type(action.dst) is str:
            s_addr = action.dst_alias if type(action.dst_alias) is str else action.dst
            addr_ast = BVS(s_addr)
            sim_types = {s_addr: 'ptr'}

        else:
            return []

        dst_data = claripy.Store(addr_ast, action.var_size)
        sim_action = self.create_sim_action(dst_data, code_location, var_type=var_type)
        re_sim_actions = {0: sim_action}
        if type(data) is int:
            data = BVV(data)
        new_expr = trace_expr.replace(data, dst_data, re_sim_actions=re_sim_actions, rep_info=sim_types)
        new_expr.expr.store_location.append(code_location)
        # new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx

        if action.addr_type == 'S':
            new_expr.expr.trace_dir = 'F'

        # Check. cs_tests/cs5.c, the gobal should be forward analyzed continue
        # TODO in taint analysis
        elif action.addr_type == 'G' and trace_expr.expr.data_type == 'Aptr' and not self.alias_check:
            new_expr.expr.trace_dir = 'B'

        return [new_expr]

    def _find_store_use_v3(self, block, action, data_alias, trace_expr):

        code_location = action.code_location
        if code_location in trace_expr.expr.store_location:
            return []

        var_type = action.var_type if action.var_type else get_type_with_binop(block, data_alias)
        if var_type and var_type != 'ptr':
            return []

        s_data, offset = self._find_binop_data_in_sim_actions(trace_expr.expr.sim_actions, data_alias)
        if s_data is None:
            return []

        addr_value = action.addr_value
        sim_types = None
        if type(addr_value) is int:
            addr_ast = BVV(addr_value)
            sim_types = {addr_value: 'ptr'}

        elif type(action.dst) is str:
            s_addr = action.dst_alias if type(action.dst_alias) is str else action.dst
            addr_ast = BVS(s_addr)
            sim_types = {s_addr: 'ptr'}

        else:
            return []

        dst_data = claripy.Store(addr_ast, action.var_size)
        sim_action = self.create_sim_action(dst_data, code_location, var_type=var_type)
        re_sim_actions = {0: sim_action}
        dst_data = dst_data + offset if offset else dst_data
        new_expr = trace_expr.replace(s_data, dst_data, re_sim_actions=re_sim_actions, rep_info=sim_types)
        new_expr.expr.store_location.append(code_location)
        # new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx

        if action.addr_type == 'S':
            new_expr.expr.trace_dir = 'F'

        return [new_expr]

    def _find_store_use_v4(self, action, addr_alias, value, trace_expr, live_defs):

        addr_value = action.addr_value
        code_location = action.code_location
        # print("use-v4: %s %s" % (trace_expr, trace_expr.expr.store_location))

        # TODO for the embedded store instructions.
        if code_location in trace_expr.expr.store_location:
            return []

        sim_types = None
        if type(addr_value) is int:
            addr_ast = BVV(addr_value)

        elif type(addr_alias) is str:
            addr_ast = BVS(addr_alias)
            sim_types = {addr_alias: 'ptr'}

        elif type(addr_alias) is tuple and addr_alias[0] in ['+', '-']:
            addr_ast = self._calculate_simple_binop_v3(addr_alias)
            sim_types = self._get_sim_type_v1(addr_alias, live_defs)

        else:
            return []

        sub_ast = BVV(value)

        dst_data = claripy.Store(addr_ast, action.var_size)
        sim_action = self.create_sim_action(dst_data, code_location, var_type='ptr')
        re_sim_actions = {0: sim_action}
        new_expr = trace_expr.replace(sub_ast, dst_data, re_sim_actions=re_sim_actions, rep_info=sim_types)
        new_expr.expr.store_location.append(code_location)
        new_expr.index = code_location.stmt_idx

        # TODO check whether stack-save only be forward.
        # if action.addr_type == 'S':
        #     new_expr.expr.trace_dir = 'F'

        return [new_expr]

    def _find_store_use_v5(self, action, addr_alias, value, trace_expr, live_defs):
        """
        For the Load(base_ptr) or store(base_ptr), while find 'store xxx, value',
        and the 'off = base_ptr - value' is less than 32, then replace base_ptr
        whieh 'store(xxx) + off'.
        """
        addr_value = action.addr_value
        code_location = action.code_location

        # TODO for the embedded store instructions.
        if code_location in trace_expr.expr.store_location:
            return []

        sim_types = None
        if type(addr_value) is int:
            addr_ast = BVV(addr_value)

        elif type(addr_alias) is str:
            addr_ast = BVS(addr_alias)
            sim_types = {addr_alias: 'ptr'}

        elif type(addr_alias) is tuple and addr_alias[0] in ['+', '-']:
            addr_ast = self._calculate_simple_binop_v3(addr_alias)
            sim_types = self._get_sim_type_v1(addr_alias, live_defs)

        else:
            return []

        base_ptr = trace_expr.expr.base_ptr
        offset = base_ptr - value
        sub_ast = BVV(base_ptr)
        dst_data = claripy.Store(addr_ast, action.var_size)

        sim_action = self.create_sim_action(dst_data, code_location, var_type='ptr')
        re_sim_actions = {0: sim_action}
        dst_data = dst_data + offset

        new_expr = trace_expr.replace(sub_ast, dst_data, re_sim_actions=re_sim_actions, rep_info=sim_types)
        new_expr.expr.store_location.append(code_location)
        new_expr.index = code_location.stmt_idx

        # TODO check whether stack-save only be forward.
        # if action.addr_type == 'S':
        #     new_expr.expr.trace_dir = 'F'

        return [new_expr]

    def _find_char_store(self, block, action, s_data, code_location, trace_expr):
        """
        In forward, the taint char store in memory. If the store addr has increment, there is a string copy.
        """
        new_exprs = []
        def simplify_inc_ast(inc_base, ast, block):
            var_type = get_sim_type(block, inc_base)
            # print("xx-type: %s" % (var_type))
            if var_type and var_type != 'ptr':
                inc_ast = BVS(inc_base)
                zero = BVV(0)
                new_ast = ast.replace(inc_ast, zero)
                return new_ast
            else:
                return ast

        flag = False
        trace_ast = trace_expr.expr.ast
        trace_dir = None
        s_addr = action.dst

        if type(s_addr) is int:
            return []

        if action.addr_type == 'S' and type(action.addr_value) is int and trace_expr.expr.var_type == 'char':
            addr_value = action.addr_value
            addr_ast = BVV(addr_value)
            sim_types = {addr_value: 'ptr'}
            dst_data = claripy.Store(addr_ast, action.var_size)
            sim_action = self.create_sim_action(dst_data, code_location, var_type='char')
            re_sim_actions = {0: sim_action}
            new_expr = trace_expr.deep_copy()
            new_expr.expr.ast = dst_data
            new_expr.expr.sims = {}
            new_expr.expr.sim_actions = re_sim_actions
            new_expr.expr.initial_sims(var_type='ptr')
            new_expr.expr.base_ptr = addr_value
            new_expr.expr.pattern = 'OF'
            new_expr.index = code_location.stmt_idx
            new_exprs.append(new_expr)

        if not block.is_loop:
            flag = self.find_increment_addr_no_loop(block, s_addr)
            if not flag:
                return new_exprs
            addr_at = block.live_defs[action.dst]
            if addr_at.action_type == 'wo':
                opnd_info = addr_at.src_alias if addr_at.src_alias else addr_at.src
                dst = opnd_info[1][0]
            else:
                dst = action.dst
            addr_ast = self._generate_ast(dst)

        else:
            inc_base, addr_ast = self.find_increment_addr_loop(block, s_addr)
            # print("Y- %s %s" % (inc_base, addr_ast))
            if inc_base:
                flag = True
                addr_ast = simplify_inc_ast(inc_base, addr_ast, block)
            else:
                dst_var = action.dst_alias if type(action.dst_alias) is str else action.dst
                addr_ast = self._generate_ast(dst_var)

        # print("find increment : %s" % (flag))
        new_expr = trace_expr.replace(trace_ast, addr_ast, rep_type='ptr')
        new_expr.expr.var_type = 'ptr'
        new_expr.expr.pattern = 'LBF'
        new_expr.expr.ptr_id = block.addr
        new_expr.index = code_location.stmt_idx

        # 0x200 lable the trace_expr is taint with char but not string copy.
        if not flag:
            new_expr.expr.flag |= 0x200
            new_expr.expr.trace_dir = 'B'
        else:
            print("Found loop copy(1): %s %s" % (code_location, new_expr))
            new_expr.loop_num += 1
        new_exprs.append(new_expr)

        return new_exprs

    def _find_binop_data_in_sim_actions(self, sim_actions, binop_opnds):
        # print("find-store-binop: ")
        op, opnds = binop_opnds[0], binop_opnds[1]
        for sim_action in sim_actions.values():
            name = sim_action.name
            if sim_action.binop == op and sim_action.live:
                if name == opnds:
                    return sim_action.action_data.args[0], 0

                elif name[0] == opnds[0] and type(name[1]) is int and type(opnds[1]) is int and (name[1]-opnds[1]) == 0x4:
                    return sim_action.action_data.args[0], name[1]-opnds[1]
        return None, None

    # Kai code!
    def _find_constant_store_use(self):
        return []

    def _find_argument_ptr_def_v1(self, addr_var, data_alias, var_type, var_size, code_location, trace_expr):
        new_exprs = []
        trace_ast = trace_expr.expr.ast
        var = trace_ast.args[0]

        if var == addr_var and code_location not in trace_expr.expr.store_location:
            store_ast = self._generate_ast_by_store(addr_var, var_size)
            data_ast = self._generate_ast(data_alias, var_size)
            new_expr = trace_expr.replace(trace_ast, data_ast, rep_type=var_type)

            value = store_ast.replace(trace_ast, trace_expr.expr.value)
            new_expr.expr.value = value
            new_expr.index = code_location.stmt_idx
            if code_location not in new_expr.expr.store_location:
                new_expr.expr.store_location.append(code_location)
            new_expr.store_loc = code_location
            new_exprs.append(new_expr)

        return new_exprs

    def _find_argument_ptr_def_v2(self, addr_info, data_alias, var_type, var_size, code_location, trace_expr):
        new_exprs = []
        trace_ast = trace_expr.expr.ast
        var = trace_ast.args[0]
        opnds = addr_info[1]

        if var in opnds and code_location not in trace_expr.expr.store_location:
            store_ast = self._generate_ast_by_store(addr_info, var_size)
            data_ast = self._generate_ast(data_alias, var_size)
            new_expr = trace_expr.replace(trace_ast, data_ast, rep_type=var_type)

            value = store_ast.replace(trace_ast, trace_expr.expr.value)
            new_expr.expr.value = value
            # new_expr.expr.trace_dir = 'B'
            if code_location not in new_expr.expr.store_location:
                new_expr.expr.store_location.append(code_location)
            new_expr.index = code_location.stmt_idx
            new_expr.store_loc = code_location
            new_exprs.append(new_expr)

        return new_exprs

    def _find_global_ptr_def_v1(self, addr_value, data_alias, var_type, var_size, code_location, trace_expr):
        """
        Find the global pointer definitions. e.g., Store(0x442880) = xxx.
        """
        new_exprs = []
        trace_ast = trace_expr.expr.ast
        gptr = trace_ast.args[0]

        # print(gptr, addr_value, code_location, trace_expr.expr.store_location)
        if gptr == addr_value and code_location not in trace_expr.expr.store_location:
            store_ast = self._generate_ast_by_store(addr_value, var_size)
            data_ast = self._generate_ast(data_alias, var_size)
            new_expr = trace_expr.replace(trace_ast, data_ast, rep_type=var_type)

            value = store_ast.replace(trace_ast, trace_expr.expr.value)
            new_expr.expr.value = value
            if code_location not in new_expr.expr.store_location:
                new_expr.expr.store_location.append(code_location)
            new_expr.index = code_location.stmt_idx
            new_expr.store_loc = code_location
            new_exprs.append(new_expr)

        return new_exprs

    # Kai code!
    def _find_pointer_field_define(self, st_addr, st_data, st_size, code_location, trace_expr):

        value = trace_expr.expr.value

        # ignore store int
        if value is None or type(st_data) is int:
            return []

        new_expr = trace_expr.replace(st_addr, st_data)
        new_value = claripy.Store(value, st_size)
        new_expr.expr.value = new_value
        new_expr.expr.trace_dir = 'B'
        new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx
        new_expr.expr.pattern = 'OB'

        return [new_expr]

    # Kai code!
    def _find_store_redefine_v1(self, addr_value, code_location, trace_expr):
        sim_actions = trace_expr.expr.sim_actions
        for i, sim_action in sim_actions.items():
            if sim_action.re_store_def(addr_value, 0, code_location):
                return True

    # Kai code!
    def _find_store_redefine_v2(self, addr_values, trace_expr):
        pass

    # Kai code!
    def _find_store_redefine_v3(self, addr, code_location, trace_expr):
        sim_actions = trace_expr.expr.sim_actions
        for i, sim_action in sim_actions.items():
            if sim_action.re_store_def(addr, 0, code_location):
                return True

    # Kai code!
    def _find_store_redefine_v4(self, addr_info, code_location, trace_expr):
        sim_actions = trace_expr.expr.sim_actions
        for i, sim_action in sim_actions.items():
            base, offset = addr_info[1]
            binop = addr_info[0]
            if sim_action.re_store_def(base, offset, code_location, binop=binop):
                return True

    # Kai code!
    def _find_put_use2(self, reg_name, put_data, code_location, trace_expr, trace_dir=None):

        op, opnds = put_data[0], put_data[1]
        opnd0, opnd1 = opnds
        opnd0_sim = trace_expr.expr.sims[opnd0]
        opnd0_type = opnd0_sim.var_type
        if opnd0_type != 'ptr' or (opnd0_sim.index is not None and code_location.stmt_idx > opnd0_sim.index):
            return

        sim_actions = trace_expr.expr.sim_actions
        trace_ast = trace_expr.expr.ast
        rep_data = None
        if trace_ast.op in ['Store', 'Load'] and len(sim_actions) == 1:
            sim_action = sim_actions[0]
            name = sim_action.name
            if name is None:
                return
            sub_data = sim_action.action_data.args[0]
            if name[0] != opnd0:
                return
            if name[1] == opnd1:
                rep_data = BVS(reg_name)

            elif (type(opnd1) is int and type(name[1]) is int and
                    0 < (name[1]-opnd1) <= 32 and
                    self.config.do_offset_update()):
                offset = name[1] - opnd1
                rep_data = BVS(reg_name) + offset
        elif trace_ast.op == '__add__': #TODO
            pass

        if rep_data is None:
            return

        sim_types = {reg_name: 'ptr'}
        new_expr = trace_expr.replace(sub_data, rep_data, rep_info=sim_types)
        new_expr.expr.trace_dir = trace_dir
        new_expr.index = code_location.stmt_idx
        # print("oooo->binop-put-use %s" % (new_expr))
        return new_expr

    # Kai code!
    def _find_put_use_v1(self, reg_name, put_data, code_location, trace_expr, trace_dir):

        ast = BVV(put_data)
        # print(trace_expr, trace_expr.expr.sims)
        new_expr = trace_expr.replace(ast, reg_name, sub_type='ptr')
        new_expr.expr.trace_dir = trace_dir
        new_expr.index = code_location.stmt_idx
        # print(new_expr, new_expr.expr.sims)

        new_expr.expr.sims[reg_name].index = code_location.stmt_idx

        return new_expr

    def _find_put_use_v2(self, reg_name, put_data, code_location, trace_expr, trace_dir):

        base_ptr = trace_expr.expr.base_ptr
        ast = BVV(base_ptr)
        rep_data = BVS(reg_name) + (base_ptr - put_data)
        rep_info = {reg_name: 'ptr'}
        new_expr = trace_expr.replace(ast, rep_data, sub_type='ptr', rep_info=rep_info)
        new_expr.expr.trace_dir = trace_dir
        new_expr.index = code_location.stmt_idx
        new_expr.expr.sims[reg_name].index = code_location.stmt_idx

        return new_expr

    # Kai code!
    def _find_put_stack_pointer(self, reg_name, stack_ptr, code_location, trace_expr, trace_dir):

        new_expr = None
        base_ptr = trace_expr.expr.base_ptr
        offset = base_ptr - stack_ptr
        if 0 < offset <= 20 and self.config.do_offset_update():
            ast = BVV(base_ptr)
            rep_data = BVS(reg_name) + BVV(offset)
            rep_info = {reg_name: 'ptr'}
            new_expr = trace_expr.replace(ast, rep_data, sub_type='ptr', rep_info=rep_info)
            new_expr.expr.trace_dir = trace_dir
            new_expr.index = code_location.stmt_idx
            new_expr.expr.sims[reg_name].index = code_location.stmt_idx

        return new_expr

    # Kai code!
    def _find_wrtmp_use2(self, wr_tmp, wr_data, var_type, code_location, trace_expr):

        # if type(wr_data) is int:
        #     wr_data = BVV(wr_data)
        new_expr = trace_expr.replace(wr_data, wr_tmp, rep_type=var_type)
        new_expr.expr.trace_dir = 'F'
        new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx

        return [new_expr]

    # Kai code!
    def _find_load_alias(self, ld_addr, code_location, trace_expr):
        """
        Check if the trace_expr contain a load alias?
        e.g. Load(Load(rax + 0x8) + 0x20) with load lias 't4 = LDle(rax + 0x8)'
        """
        sim_actions = trace_expr.expr.sim_actions
        if len(sim_actions) == 0:
            return []

        # l_offset = self._get_vex_ls_offset(ld_addrs)
        # print("l_offset: %s %s" % (code_location, l_offset))

        if type(ld_addr) is tuple:
            addr_tmp = ld_addr[0]
            addr_info = ld_addr[1]
        else:
            addr_tmp = ld_addr
            addr_info = None

        load_ptrs = []
        for index, sim_action in sim_actions.items():
            name = sim_action.name
            action_data = sim_action.action_data

            if name and name[0] and action_data.op == 'Load':
                binop = sim_action.binop
                def_locs = sim_action.def_locs

                if ((addr_info and addr_info[0] == binop and addr_info[1] == name or
                        name[1] == 0 and name[0] == addr_tmp) and code_location not in def_locs):
                    load_ptrs.append(action_data)

        return load_ptrs

    # Kai code!
    def _find_register_load_use2(self, wr_tmp, ld_addr, code_location, trace_expr):

        sim_actions = trace_expr.expr.sim_actions
        # print("f_find_load: %s %s" % (trace_expr, sim_actions))

        if len(sim_actions) == 0:
            return []

        # for index, sim_action in sim_actions.items():
        #     print("%d %s" % (index, sim_action))

        # l_offset = self._get_vex_ls_offset(ld_addrs)
        # print("l_offset: %s %s" % (code_location, l_offset))

        if type(ld_addr) is tuple:
            ld_addr_tmp = ld_addr[0]
            ld_addr_info = ld_addr[1]

        else:
            ld_addr_tmp = ld_addr
            ld_addr_info = None

        load_ptrs = []
        for index, sim_action in sim_actions.items():
            name = sim_action.name
            action_data = sim_action.action_data

            if name:
                binop = sim_action.binop
                def_locs = sim_action.def_locs

                if code_location in def_locs:
                    continue
                # print("binop %s name %s" % (binop, name))
                # print("ld_addr %s" % (str(ld_addr_info)))

                if name[1] == 0 and name[0] == ld_addr_tmp:
                    load_ptrs.append(action_data)

                elif ld_addr_info and binop == ld_addr_info[0] and name == ld_addr_info[1]:
                    load_ptrs.append(action_data)

        # print("load-ptrs: %s" % (load_ptrs))
        if len(load_ptrs) == 0:
            return []

        elif len(load_ptrs) > 1:
            logger.info("There are two load expr could be update in %s %s" % (code_location, trace_expr))

        load_ptr = load_ptrs[0]

        new_expr = trace_expr.replace(load_ptr, wr_tmp)
        new_expr.expr.location = code_location
        new_expr.expr.trace_dir = 'F'
        new_expr.index = code_location.stmt_idx
        # print("f-load-new %s" % (new_expr))

        return [new_expr]

    # Kai code!
    def _find_load_use_v1(self, action, addr_value, code_location, trace_expr):

        # print("load-use-v1: %s" % (trace_expr))
        sim_actions = trace_expr.expr.sim_actions
        if len(sim_actions) == 0:
            return []

        ls_actions = []
        for index, sim_action in sim_actions.items():
            if sim_action.load_use(addr_value, 0, code_location):
                ls_actions.append(sim_action)

        # print("load-ptrs: %s" % (ls_actions))
        if len(ls_actions) == 0:
            return []

        elif len(ls_actions) > 1:
            logger.info("There are two load expr could be update in %s %s" % (code_location, trace_expr))
            return []
            # raise Exception

        ls_action = ls_actions[0]
        new_expr = trace_expr.replace(ls_action.action_data, action.dst, sub_type=ls_action.var_type)
        # new_expr.expr.location = code_location
        new_expr.expr.trace_dir = 'F'
        new_expr.index = code_location.stmt_idx
        # print("f-load-new %s" % (new_expr))

        return [new_expr]

    # Kai code!
    def _find_load_use_v2(self):
        return []

    # Kai code!
    def _find_load_use_v3(self, wr_tmp, opnd_info, var_type, code_location, trace_expr, block=None):

        # print("@_find_load_use_v3: %s" % (str(opnd_info)))
        sim_actions = trace_expr.expr.sim_actions
        if len(sim_actions) == 0:
            return []

        op, opnds = opnd_info[0], opnd_info[1]

        ls_actions = []
        for index, sim_action in sim_actions.items():
            # print("%d %s %s" % (index, sim_action, sim_action.name))
            if sim_action.load_use(opnds[0], opnds[1], code_location, binop=op, var_type=var_type):
                ls_actions.append(sim_action)

        # print(ls_actions)
        if len(ls_actions) == 0:
            self._match_array_load_index(op, opnds, sim_actions, code_location, block, ls_actions)
            if (len(ls_actions) == 0):
                return []

        elif len(ls_actions) > 1:
            logger.info("There are two load expr could be update in %s %s" % (code_location, trace_expr))
            return []
            # raise Exception

        ls_action = ls_actions[0]
        var_type = ls_action.var_type if ls_action.var_type else var_type

        new_expr = trace_expr.replace(ls_action.action_data, wr_tmp, rep_type=var_type)
        new_expr.expr.location = code_location
        new_expr.expr.trace_dir = 'F'
        new_expr.index = code_location.stmt_idx

        return [new_expr]

    def _match_array_load_index(self, op, opnds, sim_actions, code_location, block, choose_actions):
        """
        Match the symbolic array index in Load stmt.
        E.g., s[a].f1 ==> 'shl     rax, 4; add     rax, rbp; sub     rax, 30h; mov     rdx, [rax]'
        ==> rdx = load(rbp + rax << 4 - 0x30)
        ('-', ('t8', 48), (64, 64), ('ptr', 'int'))
        """
        if (not (isinstance(opnds[0], str) and 't' in opnds[0])):
            return
        for sim_action in sim_actions.values():
            if ( not (isinstance(opnds[1], int) and sim_action.match_concrete_offset(op, opnds[1],
                                                                               code_location)) ):
                continue
            flag, array_base = self._check_array_index_pattern(opnds[0], block)
            if (flag and sim_action.match_array_index_base(array_base)):
                choose_actions.append(sim_action)
                return

    def _check_array_index_pattern(self, tmp, block):
        """
        Backward tarck the tmp variable in the block and
        check if it matches the 'reg + tmp << stride' pattern
        't8':
        <
         Action (<0x4009c4 id=0x4009bb[11]> - 64 - wo)
         dst: t8
         src: ('+', ('t4', 't33'), (64, 64), ('long', 'ptr'))
         dst_alias: None
         src_alias: ('+', ('r56', 't4'), (64, 64), ('ptr', 'long'))
         addr_type: None, src_type: None, var_type: ptr
        >
        't4':
        <
         Action (<0x4009c0 id=0x4009bb[9]> - 64 - wo)
         dst: t4
         src: ('Iop_Shl64', ('t36', 4), (64, 8), ('long', 'int'))
         dst_alias: None
         src_alias: ('Iop_Shl64', ('t35', 4), (64, 8), ('long', 'int'))
         addr_type: None, src_type: None, var_type: long
        >
        """
        if (tmp not in block.live_defs):
            return False, None
        # print(1)
        tmp_action = block.live_defs[tmp]
        src_alias = tmp_action.src_alias
        if (src_alias[0] != '+'):
            return False, None
        # print(2)
        opnd_1, opnd_2 = src_alias[1]
        # print(opnd_1, opnd_2)
        if (not (isinstance(opnd_1, str)
                 and isinstance(opnd_2, str) and 't' in opnd_2)):
            return False, None
        # print(3)
        if (opnd_2 not in block.live_defs):
            return False, None
        # print(4)
        index_action = block.live_defs[opnd_2]
        index_src = index_action.src
        index_op = index_src[0]
        index_offset = index_src[1][1]
        if ('Iop_Shl' in index_op and isinstance(index_offset, int)
                and index_offset <= 16):
            return True, opnd_1

        return False, None

    # Kai code!
    def _find_load_use_v4(self, action, addr_sym, var_type, code_location, trace_expr):
        sim_actions = trace_expr.expr.sim_actions
        # print("find_load_use_v4: %s" % (sim_actions))

        if len(sim_actions) == 0:
            return []

        ls_actions = []
        for index, sim_action in sim_actions.items():
            if sim_action.load_use(addr_sym, 0, code_location, var_type=var_type):
                ls_actions.append(sim_action)

        if len(ls_actions) == 0:
            return []

        elif len(ls_actions) > 1:
            logger.info("There are two load expr could be update in %s %s" % (code_location, trace_expr))
            return []
            # raise Exception

        ls_action = ls_actions[0]
        load_ptr = ls_action.action_data
        var_type = var_type if var_type else ls_action.var_type
        new_expr = trace_expr.replace(load_ptr, action.dst, rep_type=var_type)
        new_expr.expr.location = code_location
        new_expr.expr.trace_dir = 'F'
        new_expr.index = code_location.stmt_idx

        return [new_expr]

    def _find_load_value_v1(self, wr_tmp, addr_value, var_type, var_size, code_location, trace_expr):
        """
        Find load(ptr) when the load's addr is global pointer,
        then forward trake the loaded pointer.
        E.g., LDR R0, [0x4432e0]
        """
        # print("Find-load-value-v1: %s %s" % (code_location, trace_expr))
        new_exprs = []
        value = trace_expr.expr.value
        if value is None:
            return []

        trace_ast = trace_expr.expr.ast
        trace_sims = trace_expr.expr.sims
        if trace_ast.op != 'BVV':
            return []
        elif trace_ast.args[0] != addr_value:
            return []

        load_ast = self._generate_ast_by_load(addr_value, var_size)
        old_value = trace_expr.expr.value
        if old_value.size() != trace_ast.size():
            return []

        new_value = load_ast.replace(trace_ast, old_value)

        if sim_action_len(new_value) > APTR_MAX_LS:
            return []

        new_expr = trace_expr.replace(trace_ast, wr_tmp, rep_type=var_type)
        new_expr.expr.trace_dir = 'F'
        new_expr.index = code_location.stmt_idx
        new_expr.expr.value = new_value
        new_exprs.append(new_expr)

        return new_exprs

    def _find_load_value_v2(self):
        return []

    # Kai code!
    def _find_load_value_v3(self, wr_tmp, addr_alias, var_type, var_size, code_location, trace_expr):
        """
        In forward, find the load(ptr), the trace_ast.op is BVS
        """
        # print("@@->_find_load_value_v3: %s %s %s %s" % (code_location, wr_tmp, addr_alias, trace_expr))
        new_exprs = []
        value = trace_expr.expr.value
        if value is None:
            return new_exprs

        trace_ast = trace_expr.expr.ast
        trace_sims = trace_expr.expr.sims
        if trace_ast.op != 'BVS':
            return []

        if type(addr_alias) is tuple:
            op, opnds = addr_alias[0], addr_alias[1]
            base, offset = opnds
        else:
            op, base, offset = '+', addr_alias, 0

        if base not in trace_sims:
            return []

        base_type = trace_sims[base].var_type
        if base_type is None or base_type == 'ptr':

            load_ast = self._generate_ast_by_load(addr_alias, var_size)
            old_value = trace_expr.expr.value
            if old_value.size() != trace_ast.size():
                return []

            new_value = load_ast.replace(trace_ast, old_value)

            if sim_action_len(new_value) > APTR_MAX_LS:
                return []

            new_expr = trace_expr.replace(trace_ast, wr_tmp, rep_type=var_type)
            new_expr.expr.trace_dir = 'F'
            new_expr.index = code_location.stmt_idx
            new_expr.expr.value = new_value
            new_exprs.append(new_expr)

        return new_exprs

    # Kai code!
    def _find_load_value2(self, wr_tmp, ld_addr, ld_size, code_location, trace_expr):

        ld_addr_value = trace_expr.expr.value

        if ld_size == self.arch_bits:
            new_value = claripy.Load(ld_addr_value, ld_size)

        else:
            # Now, we not trace the pure data wthich is not pointer.
            return []

        trace_ast = claripy.BVS(wr_tmp, ld_size, explicit_name=True)

        new_expr = trace_expr.deep_copy()
        new_expr.expr.ast = trace_ast
        new_expr.expr.value = new_value
        new_expr.expr.trace_dir = 'F'
        new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx
        new_expr.expr.initial_sims()

        return [new_expr]

    # Kai code!
    def _find_constant_load_use(self):
        # TODO
        pass

    # Kai code!
    def _find_wrtmp_use_with_binop(self, wr_tmp, opnd, value, code_location, trace_expr):

        new_expr = trace_expr.replace(opnd, wr_tmp)
        new_expr.expr.trace_dir = 'F'
        new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx
        new_expr.expr.value = value

        return [new_expr]

    # Kai code!
    def _find_store_alias_v1(self):
        pass

    # Kai code!
    def _find_store_alias_v2(self, st_addr_info, st_data_alias, code_location, trace_expr):
        """
        For the b-expr, case "STle(t2)=rax+0x20", find whether b-expr contain alias "rax+0x20"
        """

        new_expr = None

        def check_binop_alias(op, op_data, op_offset, sim_actions):

            for sim_action in sim_actions.values():
                if (sim_action.name and
                        sim_action.action_data.op == 'Load' and
                        sim_action.name[0] == op_data and
                        sim_action.name[1] == op_offset and
                        sim_action.binop == op):
                    return True, sim_action.action_data.args[0]

            return False, None

        op, op_data, op_offset = st_data_alias[0], st_data_alias[1][0], st_data_alias[1][1]
        sim_actions = trace_expr.expr.sim_actions
        is_alias, alias_data = check_binop_alias(op, op_data, op_offset, sim_actions)

        if not is_alias:
            return None

        # st_data = self._calculate_simple_binop_v1(st_data_alias)
        # print("find-store-ptr-alias-true: %s" % (code_location))
        if type(st_addr_info) is tuple:
            st_addr = self._calculate_simple_binop_v1(st_addr_info[1])
        elif type(st_addr_info) is str:
            st_addr = BVS(st_addr_info)
        else:
            return None

        # print("addr %s, save %s" % (v_addr, st_data))
        st_ast = claripy.Store(st_addr, self.arch_bits)
        sim_action = self.create_sim_action(st_ast, code_location)
        re_sim_actions = {0: sim_action}
        new_expr = trace_expr.replace(alias_data, st_ast, re_sim_actions)
        new_expr.expr.trace_dir = 'F'
        new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx
        new_expr.expr.bw_loc = code_location
        new_expr.expr.flag |= 0x40
        # print("trace alias-v2: %s" % (new_expr))

        return new_expr

    # Kai code!
    def _find_store_ptr_alias_in_backward(self, st_addr, st_data_info, code_location, trace_expr):

        new_expr = None

        def check_binop_alias(op, op_data, op_offset, sim_actions):

            for sim_action in sim_actions.values():
                if (sim_action.name and
                        sim_action.action_data.op == 'Load' and
                        sim_action.name[0] == op_data and
                        sim_action.name[1] == op_offset and
                        sim_action.binop == op):
                    return True

            return False

        op, op_data, op_offset = st_data_info[0], st_data_info[1][0], st_data_info[1][1]
        sim_actions = trace_expr.expr.sim_actions
        is_alias = check_binop_alias(op, op_data, op_offset, sim_actions)

        if not is_alias:
            return None

        v_addr = None
        st_data = self._calculate_simple_binop_v1(st_data_info)
        # print("find-store-ptr-alias-true: %s" % (code_location))
        if type(st_addr) is tuple:
            st_addr_tmp = st_addr[0]
            st_addr_info = st_addr[1]
            v_addr = self._calculate_simple_binop_v1(st_addr_info)

        if v_addr is None:
            return None

        # print("addr %s, save %s" % (v_addr, st_data))
        st_ast = claripy.Store(v_addr, self.arch_bits)
        new_expr = self.create_new_trace_expr(st_ast, value=st_data, pattern='SBF', data_type='sDef', trace_dir='F', code_location=code_location)
        sim_action = self.create_sim_action(st_ast, code_location)
        new_expr.expr.sim_actions[0] = sim_action
        # print("trace alias: %s" % (new_expr))

        return new_expr

    # Kai code!
    def _find_binop_alias_in_backward(self, op, wr_tmp, op_data, op_offset, code_location, trace_expr):

        new_expr = None

        def check_binop_alias(op_data, op_offset, sim_actions):

            for sim_action in sim_actions.values():
                if (sim_action.action_data.op == 'Load' and sim_action.name[0] == op_data and sim_action.name[1] == op_offset):
                    if sim_action.binop == '+' and 'Add' in op:
                        return True

                    elif sim_action.binop == '-' and 'Sub' in op:
                        return True

            return False

        # print("binop_alias: %s %s" % (wr_tmp, opnds))

        sim_actions = trace_expr.expr.sim_actions
        binop_alias = check_binop_alias(op_data, op_offset, sim_actions)

        # if binop_alias:
        #     print("find-binop-alias-true: %s" % (code_location))

        return new_expr

    # Kai code!
    def _find_wrtmp_with_binop_alias(self, wr_tmp, opnd_info, var_type, code_location, trace_expr):

        new_expr = None

        def check_binop_alias(op, opnds, sim_actions):
            binop_alias = None

            for sim_action in sim_actions.values():
                action_data = sim_action.action_data
                if action_data.op == 'Store' and sim_action.binop == op:
                    if sim_action.name == opnds:
                        binop_alias = action_data.args[0]

                    elif sim_action.name:
                        if (sim_action.name[0] == opnds[0] and
                                sim_action.name[1] == 'o'):
                            binop_alias = opnds[0]

            return binop_alias

        op, opnds = opnd_info[0], opnd_info[1]
        sim_actions = trace_expr.expr.sim_actions
        # for i, sim_action in sim_actions.items():
        #     print(i, sim_action.name, sim_action.action_data)

        binop_alias = check_binop_alias(op, opnds, sim_actions)
        var_type = 'ptr' if var_type is None else var_type

        if binop_alias is not None:
            # print("find binop_alias: %s" % (str(binop_alias)))
            new_expr = trace_expr.replace(binop_alias, wr_tmp, rep_type=var_type)
            new_expr.expr.trace_dir = 'F'
            new_expr.expr.location = code_location
            new_expr.index = code_location.stmt_idx

        return new_expr

    def _find_binop_alias(self, wr_tmp, opnd_info, code_location, block, trace_expr):
        """
        Find accurate binop 't1 = r2 + 0x20' alias when 'r2 + 0x20' in trace_expr.
        """
        # print('Find-binop-alias: %s' % (trace_expr))
        new_exprs = []
        trace_sims = trace_expr.expr.sims
        op, opnds, opnds_type = opnd_info[0], opnd_info[1], opnd_info[3]
        opnd0_type = opnds_type[0] if opnds_type[0] else trace_sims[opnds[0]].var_type
        if opnd0_type != 'ptr':
            return new_exprs
        # print(opnds)
        trace_ast = trace_expr.expr.ast
        if 'add' not in trace_ast.op:
            return new_exprs

        # Check the array indexing
        if trace_expr.is_contain_array_index(trace_ast):
            base, index = trace_expr.get_array_base_index(trace_ast)
            # print(base, index)
            if base is None or index is None:
                return []

            flag, array_base = self._check_array_index_pattern(wr_tmp, block)
            # print(flag, array_base)

            if not flag or base.args[0] != array_base:
                return []

            new_expr = trace_expr.replace(base+index, wr_tmp, rep_type='ptr')
            new_expr.index = code_location.stmt_idx
            new_expr.expr.trace_dir = 'F'
            new_exprs.append(new_expr)
            return new_exprs

        base, offset_info = get_base_offset_v2(trace_ast, trace_sims)
        if base is None:
            return new_exprs
        base_var = base.args[0]
        offset = offset_info[1]
        if offset is None or offset.op != 'BVV':
            return new_exprs
        # print(base, offset)
        if base_var != opnds[0] or offset.args[0] != opnds[1]:
            return new_exprs

        new_expr = trace_expr.replace(trace_ast, wr_tmp, rep_type='ptr')
        new_expr.index = code_location.stmt_idx
        new_expr.expr.trace_dir = 'F'
        new_exprs.append(new_expr)
        return new_exprs

    def _find_sim_action_with_binop(self, opnd_info, trace_expr):
        sim_actions = trace_expr.expr.sim_actions
        op, opnds = opnd_info[0], opnd_info[1]

        for i, sim_action in sim_actions.items():
            sim_action_data = sim_action.action_data
            # print(" %s %s" % (sim_action, str(sim_action.name)))

            if sim_action.var_type == 'ptr' and sim_action_data.args[0].op in offset_ops:
                find_data = find_ptr_taint_v4(opnd_info, sim_action_data.args[0])
                if find_data is not None:
                    return find_data

    def _find_binop_taint_v3(self, reg_name, opnd_info, code_location, trace_expr):
        """
        In forward, find the taint transfer in binop, e.g. (Add r3, r3, 5)
        """
        new_exprs = []
        sim_actions = trace_expr.expr.sim_actions
        trace_sims = trace_expr.expr.sims
        opnds, opnds_type = opnd_info[1], opnd_info[3]

        opnd0_type = opnds_type[0] if opnds_type[0] else trace_sims[opnds[0]].var_type
        # print("find-binop-taint-v3, %s %s" % (opnds[0], opnd0_type))
        if opnd0_type != 'ptr':
            return new_exprs

        find_data = self._find_sim_action_with_binop(opnd_info, trace_expr)

        if find_data is None:
            return new_exprs

        # print("xx-find: %s" % (find_data))
        new_expr = trace_expr.replace(find_data, reg_name, rep_type=opnd0_type)
        new_expr.index = code_location.stmt_idx
        new_expr.expr.trace_dir = 'F'
        new_exprs.append(new_expr)

        return new_exprs

    def _find_binop_taint_v4(self, reg_name, opnd_info, code_location, trace_expr):
        """
        In forward, find the taint transfer in binop, e.g. (Add r3, r3, 5)
        """
        new_exprs = []
        sim_actions = trace_expr.expr.sim_actions
        trace_sims = trace_expr.expr.sims
        op, opnds, opnds_type = opnd_info[0], opnd_info[1], opnd_info[3]

        opnd0_type = opnds_type[0] if opnds_type[0] else trace_sims[opnds[0]].var_type
        # print("find-binop-taint-v4, %s %s" % (opnds[0], opnd0_type))
        if opnd0_type != 'ptr':
            return new_exprs

        binop_alias, offset = None, None
        for i, sim_action in sim_actions.items():
            binop_alias, offset = sim_action.get_binop_alias(op, opnds[0], opnds[1])
            if binop_alias is not None:
                break

        if binop_alias is None:
            return new_exprs

        replacement = BVS(reg_name) + BVV(offset)
        rep_info = {reg_name: opnd0_type}
        new_expr = trace_expr.replace(binop_alias, replacement, rep_type=opnd0_type, rep_info=rep_info)
        new_expr.index = code_location.stmt_idx
        new_expr.expr.trace_dir = 'F'
        new_exprs.append(new_expr)

        return new_exprs

    def _find_loop_length_taint(self, wr_tmp, wr_info, opnd0_type, code_location, action, trace_expr):
        new_exprs = []
        binop = wr_info[0]
        trace_ast = trace_expr.expr.ast
        if (binop == '-' and isinstance(trace_expr, RecursiveExpr) and
                trace_expr.base is not None and
                trace_expr.base.op == 'BVS'):
            var_type = basic_types['default']
            new_expr = trace_expr.replace_v2(trace_ast, wr_tmp, rep_type=var_type)
            new_expr.index = code_location.stmt_idx
            new_expr.expr.var_type = var_type
            new_expr.expr.trace_dir = 'F'
            new_expr.expr.cons_type = 5
            # print("tttt-> length taint: %s %s" % (code_location, new_expr))
            new_exprs.append(new_expr)

        return new_exprs

    def _find_binop_taint(self, wr_tmp, opnd_info, opnd0_type, code_location, action, trace_expr):
        """
        In forward, find the taint transfer in binop, e.g. (Add r3, r3, 5)
        """
        new_exprs = []
        trace_ast = trace_expr.expr.ast
        trace_sims = trace_expr.expr.sims

        # print("find_binop_taint in %s" % (code_location))
        if find_ptr_taint_v2(opnd_info, trace_ast, trace_sims):
            # print("Lucky, find tiant transfer %s to %s" % (trace_expr, wr_tmp))
            # print("inc_flag: %s %s" % (action.inc_flag, action.inc_offset))
            if trace_ast.op == 'BVS' and action.inc_flag and action.inc_offset and type(action.inc_offset[1]) is int:
                # print("oooo0-> %s %s" % (trace_expr, trace_expr.cons_ids))
                inc_offset_value = action.inc_offset[1]
                base_ast = BVS(wr_tmp, trace_ast.size())
                offset_ast = BVV(inc_offset_value, trace_ast.size())
                rep_data = base_ast + BVS('i', trace_ast.size()) * offset_ast
                n_expr = trace_expr.replace(trace_ast, rep_data, rep_type='ptr')
                # print("oooo1-> %s %s" % (n_expr, n_expr.cons_ids))
                new_expr = self.create_recursive_expr(n_expr, base_ast, offset_ast)
                # print("oooo2-> %s %s" % (new_expr, new_expr.cons_ids))
            elif isinstance(trace_expr, RecursiveExpr):
                base_ast = trace_expr.base
                new_expr = trace_expr.replace(base_ast, wr_tmp, rep_type='ptr')
            else:
                new_expr = trace_expr.replace(trace_ast, wr_tmp, rep_type='ptr')
            new_expr.index = code_location.stmt_idx
            new_expr.expr.trace_dir = 'F'
            new_exprs.append(new_expr)
        return new_exprs

    def _find_binop_taint_v2(self, wr_tmp, opnd_info, var_size, var_type, code_location, block, trace_expr):

        new_exprs = []

        trace_ast = trace_expr.expr.ast
        trace_sym = trace_ast.args[0]
        cons_type = trace_expr.expr.cons_type
        sim = trace_expr.expr.sims[trace_sym]

        op, opnds = opnd_info[0], opnd_info[1]

        # print("xx-> %s %s" % (trace_expr, str(opnd_info)))
        # if cons_type == 5 and op != '+' and trace_sym == opnds[0] and (type(opnds[1]) is str or opnds[1] > 4):
        #     return new_exprs

        if (cons_type == 5 or cons_type == 6) and var_type != 'ptr':
            if sim.live and trace_sym in opnd_info[1]:
                rep_type = basic_types[var_size]
                new_expr = trace_expr.replace(trace_ast, wr_tmp, rep_type=rep_type)
                new_expr.index = code_location.stmt_idx
                new_expr.expr.var_type = rep_type
                new_expr.expr.trace_dir = 'F'

                if cons_type == 5 and op != '+' and (type(opnds[1]) is str or opnds[1] > 4):
                    new_expr.expr.ptr_id = block.addr

                new_exprs.append(new_expr)
                block.taint_tmps.add(wr_tmp)
                # print(" -->ppp %s %s" % (code_location, new_expr))

        return new_exprs

    def _find_load_taint_v2(self, wr_tmp, addr_info, var_type, var_size, code_location, trace_expr):

        new_exprs = []
        trace_sims = trace_expr.expr.sims
        trace_ast = trace_expr.expr.ast

        if (find_ptr_taint_v2(addr_info, trace_ast, trace_sims) or
                (trace_ast.op == 'BVS' and trace_ast.args[0] in addr_info[1])):
            rep_type = basic_types[var_size]
            if isinstance(trace_expr, RecursiveExpr):
                new_expr = trace_expr.replace_v2(trace_ast, wr_tmp, rep_type=rep_type)
            else:
                new_expr = trace_expr.replace(trace_ast, wr_tmp, rep_type=rep_type)
            new_expr.index = code_location.stmt_idx
            new_expr.expr.var_type = rep_type
            new_expr.expr.cons_type = 6
            new_expr.expr.trace_dir = 'F'
            new_exprs.append(new_expr)
            print("Lucky-v2-> %s %s" % (code_location, new_expr))

        return new_exprs

    def _find_load_taint_v3(self, wr_tmp, addr_value, var_type, var_size, code_location, trace_expr):

        new_exprs = []
        trace_sims = trace_expr.expr.sims
        trace_ast = trace_expr.expr.ast

        if find_ptr_taint_v3(addr_value, trace_ast, trace_sims):
            # print("Lucky-v3!!!")
            rep_type = basic_types[var_size]
            if isinstance(trace_expr, RecursiveExpr):
                new_expr = trace_expr.replace_v2(trace_ast, wr_tmp, rep_type=rep_type)
            else:
                new_expr = trace_expr.replace(trace_ast, wr_tmp, rep_type=rep_type)
            new_expr.index = code_location.stmt_idx
            new_expr.expr.var_type = rep_type
            new_expr.expr.cons_type = 6
            new_expr.expr.trace_dir = 'F'
            new_exprs.append(new_expr)

        return new_exprs

    def _find_load_taint_v4(self):
        pass

    def _find_load_taint_v1(self, wr_tmp, addr_var, var_type, var_size, code_location, trace_expr):
        """
        Find a load tainted data from a taint pointer.
        The taint pointer may be 'r1' or 'r1 + o' or 'r1 + i * offset'
        """

        # print("find-load-taint-v1: %s" % (trace_expr))
        new_exprs = []

        trace_sims = trace_expr.expr.sims
        trace_ast = trace_expr.expr.ast

        if find_ptr_taint_v1(addr_var, trace_ast, trace_sims):
            rep_type = basic_types[var_size]
            if isinstance(trace_expr, RecursiveExpr):
                new_expr = trace_expr.replace_v2(trace_ast, wr_tmp, rep_type=rep_type)
            else:
                new_expr = trace_expr.replace(trace_ast, wr_tmp, rep_type=rep_type)
            new_expr.index = code_location.stmt_idx
            new_expr.expr.var_type = rep_type
            new_expr.expr.cons_type = 6
            new_expr.expr.trace_dir = 'F'
            new_exprs.append(new_expr)
            print("Lucky-v1-> %s %s" % (code_location, new_expr))

        return new_exprs

    def _find_binop_pointer_v1(self, wr_tmp, wr_info, var_type, code_location, action, trace_expr):
        """
        The trace_expr is pointer and ast.op is BVS and value.op is BVV.
        In forward trace, propagate data with binop.
        """
        op, opnds, opnds_size, opnds_type = wr_info[0], wr_info[1], wr_info[2], wr_info[3]
        # if type(opnds[1]) is not int:
        #     return []

        new_exprs = []
        trace_sims = trace_expr.expr.sims
        trace_ast = trace_expr.expr.ast
        var_type = var_type if var_type else trace_sims[opnds[0]].var_type

        if type(opnds[1]) is int:
            if action.inc_flag and action.inc_offset:
                offset = action.inc_offset[1]
                offset_ast = BVV(offset) if type(offset) is int else BVS(offset)
                value = trace_expr.expr.value + BVS('i') * offset_ast
            else:
                value = trace_expr.expr.value + opnds[1]
            new_expr = trace_expr.replace(trace_ast, wr_tmp, rep_type=var_type)
            new_expr.expr.value = value
            new_expr.index = code_location.stmt_idx
            new_expr.expr.trace_dir = 'F'
            new_exprs.append(new_expr)

        else: # TODO add it or delete it ?
            new_expr = trace_expr.replace(trace_ast, wr_tmp, rep_type=var_type)
            value = trace_expr.expr.value + BVS(opnds[1], opnds_size[1])
            new_expr.expr.value = value
            new_expr.index = code_location.stmt_idx
            new_expr.expr.trace_dir = 'F'
            new_exprs.append(new_expr)
            print("xpp-> %s" % (new_expr))
        return new_exprs

    def _find_binop_pointer_v2(self, wr_tmp, wr_info, code_location, trace_expr):
        """
        In forward, for the 't2 = t1 + 0x8', if the t1 is a pointer,
        then replace t1 with 't2 - 0x8'.
        The add offset should be in [-32, 32]
        """
        op, opnds, opnds_size, opnds_type = wr_info[0], wr_info[1], wr_info[2], wr_info[3]
        base_var, add_offset = opnds
        if type(add_offset) is not int:
            return []
        elif add_offset > 32 or add_offset < -32:
            return []

        new_exprs = []
        trace_sims = trace_expr.expr.sims
        trace_ast = trace_expr.expr.ast
        rep_data = BVS(wr_tmp) + BVV(-add_offset)
        sim_types = {wr_tmp: 'ptr'}
        new_expr = trace_expr.replace(base_var, rep_data, rep_type='ptr', rep_info=sim_types)
        new_expr.index = code_location.stmt_idx
        new_expr.expr.trace_dir = 'F'
        new_exprs.append(new_expr)

        return new_exprs

    # Kai code!
    def _kill_register_define(self, reg_name, code_location, trace_expr):

        sims = trace_expr.expr.sims
        live_count = [1 for sim in sims.values() if sim and sim.live]
        if len(live_count) <= 1:
            return None

        new_sim = Sim(live=False, def_loc=code_location)
        new_expr = trace_expr.deep_copy()
        new_sims = new_expr.expr.sims

        new_sims[reg_name] = new_sim

        return new_expr

    # Kai code!
    def kill_expr_by_reg_redefine(self, reg_name, code_location, trace_expr):
        """
        In forward, the put will kill the register live, maybe the trace expr will be killed and should be removed.
        If the trace expr has other load/store expr is live, will generate a new expr.
        """
        sims = trace_expr.expr.sims
        live_count = [1 for sim in sims.values() if sim and sim.live]
        if len(live_count) <= 1:
            return None

        var_type = sims[reg_name].var_type
        if var_type == 'ptr':
            return None

        new_sim = Sim(live=False, def_loc=code_location, var_type=var_type)
        new_expr = trace_expr.deep_copy()
        new_sims = new_expr.expr.sims
        new_sims[reg_name] = new_sim

        # Check the sim_actions whether should changed to false live.
        copy_actions = {}
        sim_actions = new_expr.expr.sim_actions
        for index, sim_action in sim_actions.items():
            if reg_name in sim_action.action_data.variables:
                new_action = sim_action.copy()
                new_action.live = False
                copy_actions[index] = new_action

        for index, new_action in copy_actions.items():
            sim_actions[index] = new_action

        return new_expr

    # Kai code!
    def _forward_store_stmt(self, block, action, code_location, forward_exprs):
        """
        In forward, the vex 'STle(t4) = t5'.
        """
        # print("F-psu-debug:(store) %s" % (action))

        new_forward_exprs = []
        addr_alias = action.dst_alias if action.dst_alias else action.dst
        addr_value = action.addr_value
        addr_type, src_type, = action.addr_type, action.src_type
        var_size = action.var_size

        st_data_alias = action.src_alias
        st_data = st_data_alias if type(st_data_alias) is str else action.src
        st_value = action.value
        var_type = action.var_type

        killed_exprs = []
        current_idx = code_location.stmt_idx

        for trace_expr in forward_exprs:
            trace_expr.expr.active_store_action_by_loc(code_location)
            if trace_expr.index >= current_idx:
                continue

            pattern = trace_expr.expr.pattern
            data_type = trace_expr.expr.data_type
            cons_type = trace_expr.expr.cons_type
            trace_ast = trace_expr.expr.ast
            trace_sims = trace_expr.expr.sims
            base = trace_expr.expr.base_ptr
            # print("oooo3-> %s %s %s %s" % (trace_expr, pattern, data_type, trace_sims))

            if st_data in trace_sims and trace_sims[st_data].var_type == 'ptr':
                if st_value is None and var_type and var_type != 'ptr':
                    continue
                else:
                    action.var_type = 'ptr'
                    var_type = 'ptr'

            # For the f-expr to find alise expr by STle(txx) = alias_ptr.
            if 'BF' in pattern and (var_type is None or var_type == 'ptr'):
                if type(st_value) is int:
                    if st_value in trace_sims:
                        new_alias = self._find_store_use_v4(action, addr_alias, st_value, trace_expr, block.live_defs)
                        new_forward_exprs.extend(new_alias)
                    elif (type(base) is int and 0 <= base - st_value <= 0x20 and
                            self.config.do_offset_update()):
                        new_alias = self._find_store_use_v5(action, addr_alias, st_value, trace_expr, block.live_defs)
                        new_forward_exprs.extend(new_alias)

                if st_data in trace_sims:
                    new_alias = self._find_store_use_v1(action, st_data, trace_expr)
                    new_forward_exprs.extend(new_alias)
                    if trace_ast.op == 'BVS' and data_type in ['Vptr', 'Dptr'] and len(new_alias):
                        new_exprs = self._generate_tmp_expr(block, code_location, new_alias)
                        new_forward_exprs.extend(new_exprs)

                if type(st_data_alias) is tuple and st_data_alias[1][0] in trace_sims:
                    new_alias = self._find_store_use_v3(block, action, st_data_alias, trace_expr)
                    new_forward_exprs.extend(new_alias)

                # Find argument ptrs definition.
                if data_type == 'Aptr' and trace_ast.op == 'BVS' and trace_expr.expr.value.op in ['BVS', 'Load']:
                    if type(addr_alias) is tuple and addr_alias[0] in ['+', '-']:
                        new_exprs = self._find_argument_ptr_def_v2(addr_alias, st_data, var_type, var_size, code_location, trace_expr)
                        new_forward_exprs.extend(new_exprs)

                    elif type(addr_alias) is str and addr_alias in trace_sims:
                        new_exprs = self._find_argument_ptr_def_v1(addr_alias, st_data, var_type, var_size, code_location, trace_expr)
                        new_forward_exprs.extend(new_exprs)

                elif data_type == 'Aptr' and type(addr_value) is int and trace_ast.op == 'BVV':
                    new_exprs = self._find_global_ptr_def_v1(addr_value, st_data, var_type, var_size, code_location, trace_expr)
                    new_forward_exprs.extend(new_exprs)

            elif data_type == 'Tdata' and (var_type == 'char' and trace_expr.expr.var_type != 'ptr' or trace_expr.expr.var_type == 'char'):
                if trace_ast.op == 'BVS' and st_data in trace_sims:
                    # print("Find store char!")
                    new_exprs = self._find_char_store(block, action, st_data, code_location, trace_expr)
                    # print("xx %s" % (new_exprs))
                    new_forward_exprs.extend(new_exprs)

            elif data_type == 'Cons' and cons_type in [1, 2] and trace_ast.op == 'BVS' and addr_type == 'S':
                if st_data in trace_sims:
                    new_alias = self._find_store_use_v1(action, st_data, trace_expr)
                    new_forward_exprs.extend(new_alias)

            if len(trace_expr.expr.sim_actions):
                # In forware trace, do not kill expr while the load expr find
                # store define.
                new_exprs = self._do_store_define(block, action, trace_expr, forward_exprs, trace_dir='F')
                if new_exprs:
                    new_forward_exprs.extend(new_exprs)
                #     killed_exprs.append(trace_expr)

                self._do_store_redefine(block, action, trace_expr, killed_exprs)

        self._kill_exprs(block.forward_exprs, forward_exprs, killed_exprs)

        return new_forward_exprs

    def _check_strong_store_update(self, index, trace_expr, code_location, block, tracing_exprs):
        """
        """
        print("@@:2275-->_check_strong_store_update in %s\n  --> %s\n" % (code_location, trace_expr))
        first_locs = set()
        trace_alias_id = trace_expr.expr.alias_id
        for tmp_expr in block.forward_exprs:
            if tmp_expr.expr.alias_id != trace_alias_id:
                continue
            if index not in tmp_expr.store_locs:
                continue
            first_loc = tmp_expr.store_locs[index]
            first_locs.add(first_loc)

        if len(first_locs) == 0:
            return
        killed_locs = set()
        for first_loc in first_locs:
            killed = self.is_store_updated_backward(block, first_loc, code_location)
            print("@@:2280--> %s is killed by %s %s" % (first_loc, code_location, killed))
            if killed:
                killed_locs.add(first_loc)

        if len(killed_locs) == 0:
            return
        killed_exprs = []
        for tmp_expr in block.forward_exprs:
            if tmp_expr.expr.alias_id != trace_alias_id:
                continue
            if index in tmp_expr.store_locs and tmp_expr.store_locs[index] in killed_locs:
                killed_exprs.append(tmp_expr)

        for tmp_expr in tracing_exprs:
            if tmp_expr.expr.alias_id != trace_alias_id:
                continue
            if index in tmp_expr.store_locs and tmp_expr.store_locs[index] in killed_locs:
                tmp_expr.index = MAX_VALUE

        print("@@:2292--> killed:")
        for kill_expr in killed_exprs:
            print("   --> %s" % (kill_expr))
        print("")
        self._kill_exprs(block.forward_exprs, [], killed_exprs)

        # for tmp_expr in block.forward_exprs:
        #     print("After-kill has: %s" % (tmp_expr))
        # for tmp_expr in tracing_exprs:
        #     print("After-kill has: %s" % (tmp_expr))

    def _do_store_redefine(self, block, action, trace_expr, killed_exprs):
        """
        Find store re-define and kill the trace expr.
        """
        result = False
        trace_sims = trace_expr.expr.sims
        code_location = action.code_location
        st_addr = action.dst_alias if action.dst_alias else action.dst
        addr_value = action.addr_value

        if type(addr_value) is int:
            result = self._find_store_redefine_v1(addr_value, code_location, trace_expr)

        elif type(st_addr) is str and st_addr in trace_sims:
            result = self._find_store_redefine_v3(st_addr, code_location, trace_expr)

        elif type(st_addr) is tuple and st_addr[0] in ['+', '-']:
            if st_addr[1][0] in trace_sims:
                result = self._find_store_redefine_v4(st_addr, code_location, trace_expr)

            if action.dst in trace_sims:
                result = self._find_store_redefine_v3(action.dst, code_location, trace_expr)

        if result:
            killed_exprs.append(trace_expr)

    def _do_store_define(self, block, action, trace_expr, tracing_exprs, trace_dir=None):
        """
        Find store define.
        """
        st_addr = action.dst_alias if action.dst_alias else action.dst
        addr_value = action.addr_value
        if type(addr_value) is int:
            new_exprs = self._find_concrete_addr_store_def_v1(block, action, trace_expr,
                                                              tracing_exprs, trace_dir)

        elif type(st_addr) is str:
            new_exprs = self._find_register_store_def_v1(block, action, st_addr, trace_expr,
                                                         tracing_exprs, trace_dir)

        elif type(st_addr) is tuple:
            new_exprs = self._find_register_store_def_v2(block, action, st_addr, trace_expr,
                                                         tracing_exprs, trace_dir)

        else:
            logger.info("not support the type of %s" % (str(action)))
            new_exprs = []

        if new_exprs and 'F' not in trace_expr.expr.pattern and trace_dir == 'F':
            for new_expr in new_exprs:
                new_expr.expr.trace_dir = 'B'

        return new_exprs

    def _forward_loadg_stmt(self, block, action, code_location, forward_exprs):
        """
        Process LoadG stmt ('t9 = if (t32) ILGop_Ident32(LDle(t19)) else t2').
        """
        # print("psu-debug-f %s" % (action))
        new_forward_exprs = []
        execute_stmt_flag = False

        wr_tmp, wr_size = action.dst, action.var_size
        wr_data = action.src_alias if action.src_alias else action.src
        ld_addr, ld_size = wr_data[0][1], wr_data[1][1]
        alt_data, alt_size = wr_data[0][2], wr_data[1][2]
        var_type = action.var_type

        guard = wr_data[0][0]
        guard_ast = self.calculate_binop_stmt_v2(guard)
        true_guard = guard_ast != 0
        false_guard = guard_ast == 0
        # print('LoadG %s %s %s' % (guard_ast, true_guard, false_guard))

        b_var1 = self.find_equal_zero_guard(true_guard)
        b_var2 = self.find_equal_zero_guard(false_guard)
        # print("Has equal zero: %s %s" % (b_var1, b_var2))

        current_idx = code_location.stmt_idx

        for trace_expr in forward_exprs:
            if trace_expr.index >= current_idx or trace_expr.expr.cons_type in [1, 2]:
                continue

            curr_guard = trace_expr.guard
            true_satisfiable, false_satisfiable = True, True
            if curr_guard is not None:
                constraints = [true_guard, curr_guard]
                true_satisfiable = self.judge_constraints_satisfiable(constraints)

                constraints = [false_guard, curr_guard]
                false_satisfiable = self.judge_constraints_satisfiable(constraints)

            trace_sims = trace_expr.expr.sims
            trace_ast = trace_expr.expr.ast
            pattern = trace_expr.expr.pattern

            if false_satisfiable and alt_data != b_var2:
                new_exprs = None
                if type(alt_data) is str and alt_data in trace_sims:
                    sim = trace_sims[alt_data]
                    var_type = sim.var_type if sim.var_type else action.var_type
                    new_exprs = self._find_wrtmp_use2(wr_tmp, alt_data, var_type, code_location, trace_expr)

                elif type(alt_data) is tuple:
                    pass

                if new_exprs:
                    for new_expr in new_exprs:
                        new_expr.guard = false_guard
                        new_forward_exprs.append(new_expr)

            if true_satisfiable:
                new_exprs = None
                if action.addr_value is int and action.src_type != 'A':
                    addr_value = action.addr_value
                    if type(addr_value) is int:
                        if (trace_ast.op == 'BVV' and addr_value == trace_ast.args[0]
                                and pattern in ['LBF', 'SLBF', 'SBF']):
                            # new_exprs = self._find_load_value_v1(wr_tmp, addr_value, var_type, var_size, code_location, trace_expr)
                            new_exprs = []

                        else:
                            new_exprs = self._find_load_use_v1(action, addr_value, code_location, trace_expr)

                    elif type(addr_value) is list:
                        if (trace_ast.op == 'BVV' and trace_ast.args[0] in addr_value
                                and pattern in ['LBF', 'SLBF', 'SBF']):
                            new_exprs = self._find_load_value_v2()

                        else:
                            new_exprs = self._find_load_use_v2()

                else:
                    addr_alias = ld_addr
                    if type(addr_alias) is tuple and addr_alias[0] in ['+', '-']:
                        new_exprs = self._find_load_use_v3(wr_tmp, addr_alias, var_type, code_location, trace_expr)

                    elif type(addr_alias) is str:
                        if (trace_ast.op == 'BVS' and addr_alias in trace_expr.expr.sims
                                and pattern in ['LBF', 'SLBF', 'SBF']):
                            new_exprs = self._find_load_value_v3(wr_tmp, addr_alias, var_type, wr_size, code_location, trace_expr)

                        elif ld_size == self.arch_bits and addr_alias in trace_sims:
                            var_type = action.var_type if action.var_type else trace_sims[addr_alias].var_type
                            if 's' in addr_alias:
                                new_exprs = self._find_wrtmp_use2(wr_tmp, addr_alias, var_type, code_location, trace_expr)

                            else:
                                new_exprs = self._find_load_use_v4(action, addr_alias, var_type, code_location, trace_expr)

                if new_exprs:
                    for new_expr in new_exprs:
                        new_expr.guard = true_guard
                        # print("expr- %s has guard %s" % (new_expr, true_guard))
                        new_forward_exprs.append(new_expr)

        return new_forward_exprs

    # Kai code!
    def _forward_put_stmt(self, block, action, code_location, forward_exprs):

        # print("psu-debug: %s" % (action))

        new_forward_exprs = []
        killed_exprs = []

        reg_name, put_data, put_size = action.dst, action.src, action.var_size
        put_alias = action.src_alias
        put_value = action.value
        var_type = action.var_type
        current_idx = code_location.stmt_idx

        for trace_expr in forward_exprs:
            if trace_expr.index >= current_idx:
                continue

            data_type = trace_expr.expr.data_type
            trace_sims = trace_expr.expr.sims
            trace_ast = trace_expr.expr.ast
            sim_actions = trace_expr.expr.sim_actions
            base_ptr = trace_expr.expr.base_ptr

            if type(put_value) is int and put_value in trace_sims:
                new_expr = self._find_put_use_v1(reg_name, put_value, code_location, trace_expr, 'F')
                new_forward_exprs.append(new_expr)

            elif (var_type == 'ptr' and type(put_value) is int and
                    type(base_ptr) is int and
                    0 < (base_ptr - put_value) <= 8 and
                    self.config.do_offset_update()):
                new_expr = self._find_put_use_v2(reg_name, put_value, code_location, trace_expr, 'F')
                new_forward_exprs.append(new_expr)

            elif (block.has_callsite and action.src_type == 'S' and
                    type(action.value) is int and type(base_ptr) is int and
                    get_mem_permission(base_ptr) == 'stack' and
                    len(sim_actions)):
                new_expr = self._find_put_stack_pointer(reg_name, action.value, code_location, trace_expr, 'F')
                if new_expr is not None:
                    new_forward_exprs.append(new_expr)
                    # print("Calliste-update-stack %x %s" % (block.addr, new_expr))

            elif type(action.value) is list and action.value[0] in trace_sims:
                new_expr = self._find_put_use_v1(reg_name, action.value[0], code_location, trace_expr, 'F')
                new_forward_exprs.append(new_expr)

            elif data_type == 'Tdata' and type(put_alias) is tuple and len(sim_actions):
                op, opnds = put_alias[0], put_alias[1]
                if op in ['+', '-'] and opnds[0] in trace_sims:
                    if type(opnds[1]) is str and has_sym_o(trace_ast):
                        new_exprs = self._find_binop_taint_v3(reg_name, put_alias, code_location, trace_expr)
                        new_forward_exprs.extend(new_exprs)

                    elif type(opnds[1]) is int:
                        new_exprs = self._find_binop_taint_v4(reg_name, put_alias, code_location, trace_expr)
                        new_forward_exprs.extend(new_exprs)

            # In forward trace, the reg will be redefined.
            if reg_name in trace_sims and trace_sims[reg_name].live:
                killed_exprs.append(trace_expr)
                # new_expr = self.kill_expr_by_reg_redefine(reg_name, code_location, trace_expr)
                # # print("psu-debug: kill reg %s\n new_expr: %s" % (reg_name, new_expr))

                # if new_expr is not None:
                #     new_forward_exprs.append(new_expr)
                # else:
                trace_expr.expr.flag |= 0x20

        # In the Ijk_Ret block, if the stack reg is redefined, clear the forward_exprs.
        if reg_name == self.sp_name and block.irsb:
            jumpkind = block.irsb.jumpkind

            if jumpkind == 'Ijk_Ret' and list(block.predecessors):
                forward_exprs.clear()

        # Check future, if there will be errors (TODO)
        # self._kill_exprs(block.forward_exprs, forward_exprs, killed_exprs)
        self._kill_exprs_v2(block.forward_exprs, killed_exprs)

        return new_forward_exprs

    # Kai code!
    def _forward_wrtmp_stmt(self, block, action, code_location, forward_exprs):
        """
        In forward, IR " t4 = Get(rdi) " could trace from rdi to tmp t4.
        """
        # print("psu-debug: %s" % (action))
        new_forward_exprs = []
        wr_tmp = action.dst
        wr_data = action.src_alias if action.src_alias else action.src
        var_type = action.var_type

        if wr_data == 'r%d' % (self.sp_offset):
            return []

        current_idx = code_location.stmt_idx
        for trace_expr in forward_exprs:
            if (trace_expr.index >= current_idx or
                    trace_expr.expr.cons_type == 0 or
                    (var_type and var_type == 'ptr')):
                continue

            trace_sims = trace_expr.expr.sims
            trace_ast = trace_expr.expr.ast
            # print("oooooooooo")

            if trace_ast.op == 'BVS' and wr_data in trace_sims:
                # print("ooo-> %s %s" % (code_location, trace_expr))
                var_type = var_type if var_type else trace_expr.expr.var_type
                new_exprs = self._find_wrtmp_use2(wr_tmp, wr_data, var_type, code_location, trace_expr)
                new_forward_exprs.extend(new_exprs)

        return new_forward_exprs

    # Kai code
    def _forward_wrtmp_load_stmt(self, block, action, code_location, forward_exprs):

        # print("psu-debug(load): %s" % (action))
        wr_tmp, var_type = action.dst, action.var_type
        addr_alias = action.src_alias if action.src_alias else action.src
        var_size = action.var_size
        addr_value = action.addr_value

        new_forward_exprs = []
        current_idx = code_location.stmt_idx

        for trace_expr in forward_exprs:
            if trace_expr.index >= current_idx:
                continue

            sim_actions = trace_expr.expr.sim_actions
            for sim_action in sim_actions.values():
                if code_location in sim_action.def_locs:
                    sim_action.live = False

            new_exprs = []
            pattern = trace_expr.expr.pattern
            trace_ast = trace_expr.expr.ast
            trace_sims = trace_expr.expr.sims
            data_type = trace_expr.expr.data_type
            # print("@@xx-> %s %s %s" % (trace_expr, sim_actions, pattern))

            if type(addr_alias) is str and 's' in addr_alias and addr_alias in trace_sims:
                # Trace the stack arguments.
                var_type = var_type if var_type else trace_sims[addr_alias].var_type
                new_exprs = self._find_wrtmp_use2(action.dst, addr_alias, var_type, code_location, trace_expr)
                new_forward_exprs.extend(new_exprs)

            elif len(sim_actions) == 0 and pattern in ['LBF', 'SLBF'] and (trace_ast.op in ['BVV', 'BVS'] or trace_ast.op in offset_ops):
                # print("@@xx-> 1")
                # The trace_expr not contain load or store operators.
                if type(addr_value) is int:
                    if data_type == 'Tdata':
                        new_exprs = self._find_load_taint_v3(wr_tmp, addr_value, var_type, var_size, code_location, trace_expr)
                        new_forward_exprs.extend(new_exprs)

                    else:
                        new_exprs = self._find_load_value_v1(wr_tmp, addr_value, var_type, var_size, code_location, trace_expr)
                        new_forward_exprs.extend(new_exprs)

                if data_type == 'Tdata':
                    if type(addr_alias) is tuple and addr_alias[0] in ['+', '-']:
                        new_exprs = self._find_load_taint_v2(wr_tmp, addr_alias, var_type, var_size, code_location, trace_expr)
                        new_forward_exprs.extend(new_exprs)

                    elif type(addr_alias) is str and addr_alias in trace_sims:
                        new_exprs = self._find_load_taint_v1(wr_tmp, addr_alias, var_type, var_size, code_location, trace_expr)
                        new_forward_exprs.extend(new_exprs)

                else:
                    new_exprs = self._find_load_value_v3(wr_tmp, addr_alias, var_type, var_size, code_location, trace_expr)
                    new_forward_exprs.extend(new_exprs)

            elif len(sim_actions):
                if addr_value:
                    if type(addr_value) is int:
                        new_exprs = self._find_load_use_v1(action, addr_value, code_location, trace_expr)
                        new_forward_exprs.extend(new_exprs)

                    elif type(addr_value) is list:
                        new_exprs = self._find_load_use_v2()

                elif type(addr_alias) is tuple and addr_alias[0] in ['+', '-']:
                    new_exprs = self._find_load_use_v3(wr_tmp, addr_alias, var_type, code_location,
                                                       trace_expr, block)
                    new_forward_exprs.extend(new_exprs)

                elif type(addr_alias) is str and addr_alias in trace_sims:
                    new_exprs = self._find_load_use_v4(action, addr_alias, var_type, code_location, trace_expr)
                    new_forward_exprs.extend(new_exprs)

            # if new_exprs:
            #     new_forward_exprs.extend(new_exprs)

        return new_forward_exprs

    # Kai code!
    def _forward_wrtmp_binop_stmt(self, block, action, code_location, forward_exprs):
        """
        In forward, IR "t4 = Add(t5, 0x20)" could trace into tmp t4.
        """

        # print("f-wrtmp_binop: %s" % (action))
        new_forward_exprs = []

        wr_tmp = action.dst
        wr_info = action.src_alias if action.src_alias else action.src
        op, opnds, opnds_type = wr_info[0], wr_info[1], wr_info[3]
        var_type, var_size = action.var_type, action.var_size
        current_idx = code_location.stmt_idx

        for trace_expr in forward_exprs:
            if trace_expr.index >= current_idx:
                continue

            trace_sims = trace_expr.expr.sims
            trace_ast = trace_expr.expr.ast
            trace_value = trace_expr.expr.value
            pattern = trace_expr.expr.pattern
            data_type = trace_expr.expr.data_type

            if data_type == 'Tdata':
                if trace_ast.op == 'BVS' and trace_expr.expr.var_type != 'ptr':
                    if 'Cmp' in op:
                        cons_expr = self._find_taint_constraint(block, wr_info, code_location, trace_expr)
                        # if cons_expr is not None:
                        #     new_forward_exprs.append(cons_expr)

                    elif wr_tmp not in block.taint_tmps:
                        new_exprs = self._find_binop_taint_v2(wr_tmp, wr_info, var_size, var_type, code_location, block, trace_expr)
                        new_forward_exprs.extend(new_exprs)

                elif op in ['+'] and opnds[0] in trace_sims and len(trace_expr.expr.sim_actions) == 0:
                    # The trace_expr is taint and not contain load or store.
                    opnd0_sim = trace_sims[opnds[0]]
                    opnd0_type = opnd0_sim.var_type if opnd0_sim.var_type else opnds_type[0]
                    if (self.taint_check and not self.alias_check) and (opnd0_type is None or opnd0_type == 'ptr'):
                        new_exprs = self._find_binop_taint(wr_tmp, wr_info, opnd0_type, code_location, action, trace_expr)
                        new_forward_exprs.extend(new_exprs)
                    elif self.alias_check and opnd0_type == 'ptr':
                        new_exprs = self._find_binop_alias(wr_tmp, wr_info, code_location, block, trace_expr)
                        new_forward_exprs.extend(new_exprs)

                elif op in ['-'] and opnds[0] in trace_sims and len(trace_expr.expr.sim_actions) == 0:
                    opnd0_sim = trace_sims[opnds[0]]
                    opnd0_type = opnd0_sim.var_type if opnd0_sim.var_type else opnds_type[0]
                    opnd1_type = opnds_type[1]
                    if (opnd0_type is None or opnd0_type == 'ptr') and opnd1_type == 'ptr':
                        new_exprs = self._find_loop_length_taint(wr_tmp, wr_info, opnd0_type, code_location, action, trace_expr)
                        new_forward_exprs.extend(new_exprs)
                # """
                # .text:0000000000000A51 mov     [rbp+var_10], rax
                # .text:0000000000000A55 mov     rax, [rbp+var_10]
                # .text:0000000000000A59 add     rax, 40h ; '@'
                # .text:0000000000000A5D mov     [rbp+var_8], rax
                # .text:0000000000000A61 mov     rax, [rbp+var_8]
                # .text:0000000000000A65 mov     rdi, rax
                # .text:0000000000000A68 call    ringqFlush
                # .text:0000000000000A6D mov     rax, [rbp+var_8]
                # .text:0000000000000A71 mov     rdx, [rax+8]
                # .text:0000000000000A75 mov     rax, [rbp+var_10]
                # .text:0000000000000A79 mov     rax, [rax+50h]
                # .text:0000000000000A7D mov     rsi, rdx
                # .text:0000000000000A80 mov     rdi, rax
                # .text:0000000000000A83 call    MUSTALIAS
                # """
                elif op in ['+'] and opnds[0] in trace_sims and len(trace_expr.expr.sim_actions) >= 1:
                    opnd0_sim = trace_sims[opnds[0]]
                    opnd0_type = opnd0_sim.var_type if opnd0_sim.var_type else opnds_type[0]
                    if opnd0_type == 'ptr':
                        new_expr = self._find_put_use2(wr_tmp, wr_info, code_location, trace_expr, trace_dir='F')
                        if new_expr is not None:
                            new_forward_exprs.append(new_expr)

                if trace_ast.op == 'BVS' and trace_expr.expr.var_type == 'ptr':
                    self._find_taint_constraint(block, wr_info, code_location, trace_expr)

            elif data_type in ['Vptr', 'Dptr']:
                if trace_ast.op == 'BVS' and (trace_value is not None and trace_value.op == 'BVV') and opnds[0] in trace_sims:
                    new_exprs = self._find_binop_pointer_v1(wr_tmp, wr_info, var_type, code_location, action, trace_expr)
                    new_forward_exprs.extend(new_exprs)
                    # print("Find-binop-ptr: %s" % (new_exprs))
                    if len(new_exprs):
                        tmp_exprs = self._generate_tmp_expr(block, code_location, new_exprs)
                        new_forward_exprs.extend(tmp_exprs)

            elif data_type == 'Cons':
                cons_type = trace_expr.expr.cons_type
                if trace_ast.op == 'BVS' and cons_type in [1, 2] and 'Cmp' in op:
                    self._find_taint_constraint(block, wr_info, code_location, trace_expr)
                    # if 't' in trace_ast.args[0]:
                    #     self._find_taint_constraint(block, action.src, code_location, trace_expr)

            # TODO
            # elif data_type == 'Aptr':
            #     if op == '+' and opnds[0] in trace_sims and trace_sims[opnds[0]].var_type == 'ptr':
            #         new_exprs = self._find_binop_pointer_v2(wr_tmp, wr_info, code_location, trace_expr)
            #         new_forward_exprs.extend(new_exprs)

        return new_forward_exprs

    def _forward_wrtmp_ite_stmt(self, block, action, code_location, forward_exprs):
        """
        In forward, process ITE stmtament ('t54 = ITE(t53,t6,t23)').
        """
        # print("psu-debug-f: %s" % (action))
        new_forward_exprs = []

        wr_tmp, wr_size = action.dst, action.var_size
        guard, data1_alias, data2_alias = action.src_alias
        data1 = action.src[1] if type(data1_alias) is tuple else data1_alias
        data2 = action.src[2] if type(data2_alias) is tuple else data2_alias

        if type(guard) is str:
            guard_ast = BVS(guard)
        else:
            guard_ast = self.calculate_binop_stmt_v2(guard)
        true_guard = guard_ast == 0
        false_guard = guard_ast != 0
        # print(guard_ast, true_guard, false_guard)

        current_idx = code_location.stmt_idx

        for trace_expr in forward_exprs:
            if trace_expr.index > current_idx:
                continue

            curr_guard = trace_expr.guard
            trace_sims = trace_expr.expr.sims
            # print("WI: %s with %s" % (trace_expr, curr_guard))

            true_satisfiable, false_satisfiable = True, True

            if curr_guard is not None:
                constraints = [true_guard, curr_guard]
                true_satisfiable = self.judge_constraints_satisfiable(constraints)

                constraints = [false_guard, curr_guard]
                false_satisfiable = self.judge_constraints_satisfiable(constraints)

            # print("true: %s %s" % (true_satisfiable, data1))
            if true_satisfiable and data1 in trace_sims:
                sim = trace_sims[data1]
                var_type = sim.var_type if sim.var_type else action.var_type
                # print("Ite-ture: %s %s" % (sim.live, var_type))
                if sim.live and (var_type == 'ptr' or var_type is None):
                    new_exprs = self._find_wrtmp_use2(wr_tmp, data1, var_type, code_location, trace_expr)

                    for new_expr in new_exprs:
                        new_expr.guard = true_guard
                        new_forward_exprs.append(new_expr)

            # print("false: %s %s" % (false_satisfiable, data2))
            if false_satisfiable and data2 in trace_sims:
                sim = trace_sims[data2]
                var_type = sim.var_type if sim.var_type else action.var_type
                if sim.live and (var_type == 'ptr' or var_type is None):
                    new_exprs = self._find_wrtmp_use2(wr_tmp, data2, var_type, code_location, trace_expr)

                    for new_expr in new_exprs:
                        new_expr.guard = false_guard
                        new_forward_exprs.append(new_expr)

        return new_forward_exprs

    # Kai code!
    def update_put_alias_in_forward(self, block, trace_expr, update_type=None):
        """
        We update trace expr's tmp or reg with its alias reg while the trace_expr is forward.
        """
        tmp_alias, f_reg_alias = block.tmp_alias, block.f_reg_alias

        # print("update-put-alias(F) : %s" % (f_reg_alias))
        if len(tmp_alias) and (update_type is None or update_type == 'tmp'):
            new_exprs = self._forward_update_tmp_alias(trace_expr, tmp_alias)
            if len(new_exprs):
                block.forward_exprs.extend(new_exprs)
                block.is_tainted = 1
                for new_expr in new_exprs:
                    print("psu-debug: get new expr (1) %s, cons-ids: %s %s" % (new_expr, new_expr.cons_ids, new_expr.guard))

        if len(f_reg_alias) and (update_type is None or update_type == 'reg'):
            new_exprs = self._forward_update_reg_alias(trace_expr, f_reg_alias)
            if len(new_exprs):
                block.forward_exprs.extend(new_exprs)
                block.is_tainted = 1
                for new_expr in new_exprs:
                    print("psu-debug: get new expr (2) %s, cons-ids: %s" % (new_expr, new_expr.cons_ids))

    # Kai code!
    def update_put_alias_in_backward(self, block, trace_expr):
        """
        We update trace expr's reg with its alias reg and generate forward expr.
        """
        new_forward_exprs = []
        old_exprs = [trace_expr]

        live_defs = block.live_defs
        trace_sims = trace_expr.expr.sims

        # print("YYYY: %s %s" % (trace_expr, trace_expr.expr.data_type))

        if trace_expr.expr.data_type != 'Ret':
            for reg, sim in trace_sims.items():
                # print("reg %s sim %s" % (reg, sim))
                if type(reg) is str and reg in live_defs:
                    value = None
                    d_at = live_defs[reg]
                    if type(d_at.value) is int:
                        value = d_at.value

                    elif type(d_at.src) is int and d_at.code_location.block_addr == block.addr:
                        value = d_at.src

                    if value is not None:
                        new_forward_exprs.clear()
                        for t_expr in old_exprs:
                            new_expr = t_expr.replace(reg, value)
                            new_expr.expr.trace_dir = 'F'
                            new_forward_exprs.append(new_expr)
                        old_exprs = new_forward_exprs[:]

            if len(new_forward_exprs):
                block.forward_exprs.extend(new_forward_exprs)
                for new_expr in new_forward_exprs:
                    print("Add new forward (B1): %s" % (new_expr))
                new_forward_exprs.clear()

        b_reg_alias = block.b_reg_alias
        # print("b_alias: %s" % (b_reg_alias))
        if len(b_reg_alias) == 0:
            return

        special_alias_regs = []
        old_exprs = [trace_expr]
        re_regs = [reg for reg in b_reg_alias if reg in trace_sims and (trace_sims[reg].var_type == 'ptr' or trace_sims[reg].var_type is None)]

        while re_regs:
            r_reg = re_regs.pop()
            rep_type = trace_sims[r_reg].var_type
            new_forward_exprs.clear()
            for alias_reg in b_reg_alias[r_reg]:
                if alias_reg in re_regs:
                    special_alias_regs.append((r_reg, alias_reg))
                    continue

                if rep_type is None:
                    rep_type = block.live_defs[alias_reg].var_type

                for t_expr in old_exprs:
                    new_expr = t_expr.replace(r_reg, alias_reg, rep_type=rep_type)
                    new_expr.expr.trace_dir = 'F'
                    new_forward_exprs.append(new_expr)

            if len(new_forward_exprs):
                old_exprs = new_forward_exprs[:]

        for new_expr in new_forward_exprs:
            if new_expr.expr.data_type == 'Ret':
                trace_syms = new_expr.get_trace_symbols()
                if len(trace_syms):
                    block.forward_exprs.append(new_expr)

            else:
                block.forward_exprs.append(new_expr)
                print("Add new forward (B2): %s ptr-id: %x" % (new_expr, new_expr.expr.ptr_id))
                # new_expr.print_sims()

    # Kai code!
    def _forward_execute_stmt(self, block, action, code_location, forward_exprs):
        action_type = action.action_type
        # print("f- %s %s" % (code_location, forward_exprs))

        if action_type == 's':
            new_forward_exprs = self._forward_store_stmt(block, action, code_location, forward_exprs)

        elif action_type == 'p':
            new_forward_exprs = self._forward_put_stmt(block, action, code_location, forward_exprs)

        # elif action_type == 'w':
        #     new_forward_exprs = self._forward_wrtmp_stmt(block, action, code_location, forward_exprs)

        elif action_type == 'wo':
            new_forward_exprs = self._forward_wrtmp_binop_stmt(block, action, code_location, forward_exprs)

        elif action_type == 'wl':
            new_forward_exprs = self._forward_wrtmp_load_stmt(block, action, code_location, forward_exprs)

        elif action_type == 'wi':
            new_forward_exprs = self._forward_wrtmp_ite_stmt(block, action, code_location, forward_exprs)

        elif action_type == 'sg':
            new_forward_exprs = self._forward_storeg_stmt(block, action, code_location, forward_exprs)

        elif action_type == 'lg':
            new_forward_exprs = self._forward_loadg_stmt(block, action, code_location, forward_exprs)

        elif action_type in ['wu', 'w']:
            new_forward_exprs  =[]

        else:
            logger.debug("This action type %s is not support!" % (action_type))
            new_forward_exprs  =[]

        if len(new_forward_exprs):
            print("\nForward: %s" % (code_location))
            for new_expr in new_forward_exprs:
                print("new expr %s %s org-%s" % (new_expr, new_expr.expr.sims,
                                                 new_expr.expr.invariant_loc))
                print("  with store-locs: %s" % (new_expr.store_locs))

                # for i, sim_action in new_expr.expr.sim_actions.items():
                #     print("sim action: %d %s" % (i, sim_action))
                print("")

        return new_forward_exprs

    # Kai code!
    def forward_data_trace2(self, block, forward_exprs):
        """
        param: irsb:
        param: forward_exprs: a list of forward trace variable expressions.
        """
        irsb = block.irsb

        self.state.scratch.tyenv = irsb.tyenv
        self.state.scratch.temps = {}

        code_locations = block.code_locations
        actions = block.actions

        # DEBUG
        print("Forward trace: %s" % (block))
        for fe in forward_exprs:
            print("  %s 0x%x with-cons- %s ptr-id- %x org- %s alias_id- %s-%s" %
                  (fe, fe.expr.flag, fe.constraints, fe.expr.ptr_id, fe.expr.invariant_loc, fe.expr.data_type, fe.expr.alias_id))
            print("      --> cons-ids: %s, taint-src: %x" % (fe.cons_ids, fe.expr.taint_source))
            # print("      --> inter-funcs: %s" % (fe.inter_funcs))
            # for action in fe.expr.sim_actions.values():
            #     print("     -> %s %s" % (action, action.def_locs))
            # for var, sim in fe.expr.sims.items():
            #     print("  %s %s" % (var, sim))
            # fe.print_path()

            # DEBUG
            # if len(str(fe.expr.ast)) > max_ast_lenght:
            #     print("DEBUG: fun- %s, %s" % (block.func_addr, block))
            #     debug

        # if len(forward_exprs) > max_trace_exprs:
        #     print("DEBUG (exprs_len_max): fun- %s, %s" % (block.func_addr, block))
        #     debug
        # print("")

        for trace_expr in forward_exprs:
            self.update_put_alias_in_forward(block, trace_expr)

        alive_exprs = []
        for code_location in code_locations:
            # print("location: %s" % (code_location))

            action = actions[code_location]

            new_forward_exprs = self._forward_execute_stmt(block, action, code_location, forward_exprs)

            if len(new_forward_exprs) == 0:
                continue

            block.is_tainted = 1

            for new_expr in new_forward_exprs:

                self.simplify_expr_v2(new_expr)
                self._judge_trace_dir(new_expr)
                trace_dir = new_expr.expr.trace_dir

                if trace_dir == 'B':
                    if action.action_type == 's':
                        new_expr.expr.kill_store_action_by_loc(code_location)
                    block.backward_exprs.append(new_expr)
                    alive_exprs.append(new_expr)

                elif trace_dir == 'F':
                    forward_exprs.append(new_expr)
                    block.forward_exprs.append(new_expr)
                    self.update_put_alias_in_forward(block, new_expr)

                else:
                    new_expr.expr.trace_dir = 'F'
                    forward_exprs.append(new_expr)
                    block.forward_exprs.append(new_expr)
                    self.update_put_alias_in_forward(block, new_expr)

                    copy_expr = new_expr.make_backward_copy()
                    if action.action_type == 's':
                        copy_expr.expr.kill_store_action_by_loc(code_location)
                    block.backward_exprs.append(copy_expr)
                    alive_exprs.append(copy_expr)
                    # print("copy expr %s" % (copy_expr))

        # for trace_expr in forward_exprs:
        #     self.update_put_alias_in_forward(block, trace_expr)

        return alive_exprs

    # Kai code!
    def backward_data_trace2(self, block, backward_exprs):
        """
        Trace expr by travel a block's isrb from last stmt to first stmt.
        """

        alive_exprs = []
        self.state.scratch.tyenv = block.irsb.tyenv
        self.state.scratch.temps = {}

        code_locations = block.code_locations
        actions = block.actions
        live_defs = block.live_defs
        reg_defs = block.reg_defs
        ins_len = len(code_locations)

        self._backward_update_put_def(block, live_defs, backward_exprs, reg_defs, alive_exprs)

        # Debug
        print("Backward trace: %s" % (block))
        for b_expr in backward_exprs:
            print("  %s 0x%x with-cons- %s ptr-id- %x org- %s alias_id- %s-%s"
                  % (b_expr, b_expr.expr.flag, b_expr.constraints, b_expr.expr.ptr_id, b_expr.expr.invariant_loc, b_expr.expr.data_type, b_expr.expr.alias_id))
            print("      --> cons-ids: %s" % (b_expr.cons_ids))
            # print("      --> inter-funcs: %s" % (b_expr.inter_funcs))
            # for action in b_expr.expr.sim_actions.values():
            #     print("     -> %s %s" % (action, action.def_locs))
            # for var, sim in b_expr.expr.sims.items():
            #     print("  %s %s" % (var, sim))
            # b_expr.print_path()

            # DEBUG
            # if len(str(b_expr.expr.ast)) > max_ast_lenght:
            #     print("DEBUG (ast_len_max): fun- %s, %s" % (block.func_addr, block))
            #     debug

        # if len(backward_exprs) > max_trace_exprs:
        #     print("DEBUG (exprs_len_max): fun- %s, %s" % (block.func_addr, block))
        #     debug
        # print("")

        for i in range(ins_len-1, -1, -1):

            code_location = code_locations[i]
            action = actions[code_location]
            new_backward_exprs = self._backward_execute_stmt2(block, action, code_location, backward_exprs)

            if len(new_backward_exprs) == 0:
                continue

            block.is_tainted = 1

            for new_expr in new_backward_exprs:
                # if (new_expr.expr.data_type == 'Aptr' and is_filter_v3(new_expr.expr.ast)):
                #     continue
                if block.is_loop:
                    if code_location not in new_expr.cycle_locs:
                        new_expr.cycle_locs.append(code_location)
                else:
                    self.simplify_expr(new_expr)

                self._judge_trace_dir(new_expr)
                if new_expr.expr.trace_dir == 'F':
                    self._check_sim_action(action, new_expr)
                    new_expr.copy_sim_and_action()
                    block.forward_exprs.append(new_expr)
                    alive_exprs.append(new_expr)

                elif new_expr.expr.trace_dir == 'B':
                    self._check_sim_action(action, new_expr)
                    backward_exprs.append(new_expr)
                    block.backward_exprs.append(new_expr)

                else:
                    new_expr.expr.trace_dir = 'B'
                    self._check_sim_action(action, new_expr)
                    backward_exprs.append(new_expr)
                    block.backward_exprs.append(new_expr)

                    if 'BF' in new_expr.expr.pattern:
                        copy_expr = new_expr.make_forward_copy()
                        self._check_sim_action(action, copy_expr)
                        block.forward_exprs.append(copy_expr)
                        alive_exprs.append(copy_expr)
                        # print("copy expr %s" % (copy_expr))

        return alive_exprs

    # Kai code!
    def _backward_execute_stmt2(self, block, action, code_location, backward_exprs):
        action_type = action.action_type

        if action_type == 's':
            new_backward_exprs = self._backward_store_stmt(block, action, code_location, backward_exprs)

        elif action_type == 'p':
            new_backward_exprs = self._backward_put_stmt(block, action, code_location, backward_exprs)

        # elif action_type == 'w':
        #     new_backward_exprs = self._backward_wrtmp_stmt(block, action, code_location, backward_exprs)

        elif action_type == 'wo':
            new_backward_exprs = self._backward_wrtmp_binop_stmt(block, action, code_location, backward_exprs)

        elif action_type == 'wl':
            new_backward_exprs = self._backward_wrtmp_load_stmt(block, action, code_location, backward_exprs)

        # elif action_type == 'wu':
        #     new_backward_exprs = self._backward_wrtmp_unop_stmt(block, action, code_location, backward_exprs)

        elif action_type == 'lg':
            new_backward_exprs = self._backward_loadg_stmt(block, action, code_location, backward_exprs)

        elif action_type == 'wi':
            new_backward_exprs = self._backward_wrtmp_ite_stmt(block, action, code_location, backward_exprs)

        elif action_type in ['w', 'wu']:
            return []

        else:
            logger.debug("This action type %s is not support!\n %s" % (action_type, action))
            new_backward_exprs = []

        if len(new_backward_exprs):
            print("\nBackward: %s" % (code_location))
            for new_expr in new_backward_exprs:
                print("new expr %s, flag: %x" % (new_expr, new_expr.expr.flag))
                print("  with store-locs: %s" % (new_expr.store_locs))
                # print(new_expr.expr.sims)

                # for index, sim_action in new_expr.expr.sim_actions.items():
                #     print("sim_action: %d %s" % (index, sim_action))
                print("")

        return new_backward_exprs

    # Kai code!
    def _calculate_simple_binop_v1(self, binop_opnds):
        datas = []
        op, opnds = binop_opnds[0], binop_opnds[1]
        # print("NOW-%s %s" % (op, str(opnds)))
        for opnd in opnds:
            data = BVV(opnd) if type(opnd) is int else BVS(opnd)
            datas.append(data)

        if op == '+':
            result = datas[0] + datas[1]
        elif op == '-':
            result = datas[0] -  datas[1]

        return result

    # Kai code!
    def _calculate_simple_binop_v2(self, binop_opnds, data_size):
        datas = []
        op, opnds = binop_opnds[0], binop_opnds[1]
        for opnd in opnds:
            data = BVV(opnd, data_size) if type(opnd) is int else BVS(opnd, data_size)
            datas.append(data)

        if op == '+':
            result = datas[0] + datas[1]
        elif op == '-':
            result = datas[0] -  datas[1]

        return result

    # Kai code!
    def _calculate_simple_binop_v3(self, binop_opnds):
        datas = []
        op, opnds, opnds_size = binop_opnds[0], binop_opnds[1], binop_opnds[2]
        for opnd, size in zip(opnds, opnds_size):
            data = BVV(opnd, size) if type(opnd) is int else BVS(opnd, size)
            datas.append(data)

        if op == '+':
            result = datas[0] + datas[1]
        elif op == '-':
            result = datas[0] - datas[1]

        return result

    # Kai code!
    def _update_register_bak(self, block, def_regs, reg_defs, live_defs, trace_expr):

        # print("psu-debug: %s\nupdate_register %s %s %s" % (code_location, def_regs, reg_defs, live_defs))

        last_index = trace_expr.index
        new_expr = trace_expr
        live_regs = def_regs[:]
        while def_regs:
            reg, reg_type = def_regs.pop(0)
            use_at = live_defs[reg]

            loc, u_var = reg_defs[reg]
            index = loc.stmt_idx

            if (type(use_at.value) is int and not block.is_loop):
                u_var = use_at.value

            elif type(use_at.src) is int:
                u_var = use_at.src

            elif use_at.action_type in ['w', 'wu', 'p']:
                u_alias = use_at.src_alias if use_at.src_alias else use_at.src
                if type(u_alias) is str:
                    u_var = u_alias
                    index = use_at.src_locs

            if u_var in live_regs:
                def_regs.append((reg, reg_type))
                continue

            new_expr = self._update_register_in_expr(reg, u_var, reg_type, last_index, index, new_expr)

        return new_expr

    def _get_reg_ast(self, action, is_loop):

        if type(action.value) is int and action.src_type == 'S':
            data = BVV(action.value, action.var_size)

        if action.action_type == 'wl':
            if (action.var_type and action.var_type != 'ptr' and
                    type(action.value) is int):
                data = BVV(action.value, action.var_size)
            else:
                data = BVS(action.dst, action.var_size)

        elif action.action_type in ['wi', 'lg']:
            data = BVS(action.dst, action.var_size)

        elif type(action.src) is int:
            data = BVV(action.src, action.var_size)

        elif action.action_type in ['w', 'wu', 'p']:
            reg_alias = action.src_alias if type(action.src_alias) is str else action.src
            data = BVS(reg_alias, action.var_size)

        else:
            data = BVS(action.dst, action.var_size)

        return data

    # Kai code!
    def _update_register(self, block, update_regs, reg_defs, live_defs, trace_expr):

        def contain_repeat_reg(data, update_regs):
            for var in data.variables:
                for reg, reg_type in update_regs:
                    if var == reg:
                        return True
            return False

        is_should_forward = False
        trace_flag = trace_expr.expr.flag
        data_type = trace_expr.expr.data_type
        trace_ast = trace_expr.expr.ast
        new_expr = trace_expr
        live_regs = update_regs[:]
        # block.irsb.pp()
        # print("update-regs: %s" % (update_regs))

        update_count = 0
        while update_regs:
            reg, reg_type = update_regs.pop(0)
            use_at = live_defs[reg]
            base_ast, offset_ast, sim_types = None, None, None
            update_count += 1
            # print("xxxx-- %s %s %s" % (reg, use_at, use_at.inc_flag))

            # if use_at.action_type == 'wl':
            #     if (use_at.var_type and use_at.var_type != 'ptr' and
            #             type(use_at.value) is int):
            #         data = BVV(use_at.value, use_at.var_size)
            #     else:
            #         data = BVS(use_at.dst, use_at.var_size)

            # elif use_at.action_type in ['wi', 'lg']:
            #     data = BVS(use_at.dst, use_at.var_size)

            if trace_expr.expr.data_type == 'Cons' and type(use_at.value) is int:
                data = BVV(use_at.value, use_at.var_size)

            elif type(use_at.src) is int:
                data = BVV(use_at.src, use_at.var_size)

            elif type(use_at.value) is int and use_at.src_type == 'S':
                data = BVV(use_at.value, use_at.var_size)

            else:
                use_at = live_defs[use_at.src]
                if use_at.action_type == 'wo':
                    data, base_ast, offset_ast = self._get_binop_action_ast(use_at, reg_type, data_type, trace_flag=trace_flag)
                    if data is None:
                        return None
                    opnds_info = use_at.src_alias if use_at.src_alias else use_at.src
                    sim_types = get_opnds_type(block, opnds_info, reg_type)

                else:
                    data = self._get_reg_ast(use_at, block.is_loop)

            if update_count > 10:
                use_at = live_defs[reg]
                put_src = use_at.src
                data = BVS(put_src, use_at.var_size) if type(put_src) is str else BVV(put_src, use_at.var_size)

            elif contain_repeat_reg(data, update_regs):
                update_regs.append((reg, reg_type))
                continue

            if (data_type == 'Cons' and
                    (trace_expr.contain_special_symbol('o') or len(trace_expr.expr.sim_actions) > 1)):
                return None

            # print("up-with: %s" % (data))
            # whether_meet_replace(data, update_regs)

            find_loop_copy_flag = False
            if use_at.inc_flag:
                if isinstance(new_expr, RecursiveExpr):
                    # print("Kai-Rec: %s %s\n base-offset: %s %s" % (trace_expr, trace_expr.base, base_ast, offset_ast))

                    if use_at.code_location in new_expr.inc_records or (trace_expr.expr.data_type in ['Cons', 'Tdata']):
                        return None

                    elif base_ast is not None:
                        if new_expr.is_update_base(reg) and self.taint_check:
                            new_expr = new_expr.replace(reg, base_ast, rep_type=reg_type)

                        elif new_expr.with_same_inc_info(base_ast, offset_ast):
                            new_expr = new_expr.replace(reg, base_ast, rep_type=reg_type)

                        else:
                            new_expr = new_expr.replace(reg, data, rep_type=reg_type, rep_info=sim_types)

                    else:
                        new_expr = new_expr.replace(reg, data, rep_type=reg_type, rep_info=sim_types)

                else:
                    if trace_flag & 0x200:
                        if reg_type and reg_type != 'ptr':
                            base_ptr = new_expr.expr.base_ptr
                            base_ast = BVS(base_ptr) if type(base_ptr) is str else BVV(base_ptr) if type(base_ptr) is int else base_ast
                            offset_ast = BVV(1)
                            binop_data = BVV(0)
                            n_expr = new_expr.replace(reg, binop_data, rep_type=reg_type)

                        elif reg_type == 'ptr':
                            n_expr = new_expr.replace(reg, base_ast, rep_type=reg_type)

                        else:
                            n_expr = new_expr.replace(reg, data, rep_info=sim_types)
                        n_expr.expr.flag &= 0xfffffdff
                        find_loop_copy_flag = True
                        # print("uuuu-> %s" % (n_expr))

                    else:
                        n_expr = new_expr.replace(reg, data, rep_info=sim_types)
                    new_expr = self.create_recursive_expr(n_expr, base_ast, offset_ast)
                    new_expr.inc_records.append(use_at.code_location)

            else:
                new_expr = new_expr.replace(reg, data, rep_type=reg_type, rep_info=sim_types)
                base_ptr = new_expr.expr.base_ptr
                if (data_type == 'Tdata' and type(base_ptr) is str and data.op == '__add__' and data.args[0].op == 'BVS' and
                        data.args[1].op == 'BVV' and data.args[0].args[0] == base_ptr and base_ptr not in reg_defs):
                    is_should_forward = True
                    # print("Expr-should-forward: %s" % (new_expr))
                # print("xxxx-> %s %s %s %s" % (new_expr, data, reg_type, sim_types))

            for var, sim in new_expr.expr.sims.items():
                if var in data.variables and 'r' in var:
                    sim.index = 0

        new_expr.expr.trace_dir = 'B' if not is_should_forward else None
        new_expr.index = trace_expr.index

        return new_expr

    # Kai code!
    def _update_register_in_expr(self, d_reg, u_var, var_type, last_index, index, trace_expr):
        """
        update the register name 'rxx' in expr with reg's use var.
        :param u_var: maybe is rxx, txx or 0xabcd.
        """
        new_expr = trace_expr.replace(d_reg, u_var, rep_type=var_type)
        new_expr.expr.trace_dir = 'B'
        if u_var in new_expr.expr.sims and new_expr.expr.sims[u_var]:
            new_expr.expr.sims[u_var].index = index
            new_expr.expr.sims[u_var].var_type = trace_expr.expr.sims[d_reg].var_type
        new_expr.index = last_index

        return new_expr

    # Kai code!
    def _backward_update_put_def(self, block, live_defs, backward_exprs, reg_defs, alive_exprs):
        """
        update the register put def in backward.
        """
        new_exprs = []
        killed_exprs = []
        new_forward_exprs = []
        ins_len = len(block.irsb.statements)
        # update_info = []

        for trace_expr in backward_exprs:
            # print("oooo-> %s" % (trace_expr))
            trace_sims = trace_expr.expr.sims
            index = trace_expr.index
            if index != ins_len:
                continue

            def_regs = []
            for name, sim in trace_sims.items():
                if type(name) is str and 'r' in name and sim.live and name in reg_defs:
                    if sim.index is None or sim.index > live_defs[name].code_location.stmt_idx:
                        reg_type = sim.var_type if sim.var_type else live_defs[name].var_type
                        def_regs.append((name, reg_type))

            if len(def_regs):
                new_expr = self._update_register(block, def_regs, reg_defs, live_defs, trace_expr)
                # update_info.append((trace_expr, new_expr))
                killed_exprs.append(trace_expr)

                if new_expr is None:
                    continue
                print("b-put-newexpr:\n  old %s %s\n  new %s %s" % (trace_expr, trace_expr.inter_funcs, new_expr, new_expr.inter_funcs))

                block.is_tainted = 1
                new_exprs.append(new_expr)

                if trace_expr.expr.flag & 0x200 and (not new_expr.expr.flag & 0x200):
                    new_forward_exprs.append(new_expr)
                    new_expr.loop_num += 1
                    new_expr.expr.flag |= 0x10000000
                    new_expr.expr.taint_loc = block.func_addr
                    print("Found loop copy %s" % (new_expr))

        for new_expr in new_exprs:
            # if new_expr.expr.data_type == 'Aptr' and is_filter_v3(new_expr.expr.ast):
            #     continue
            if new_expr.expr.trace_dir is None:
                copy_expr = new_expr.make_forward_copy()
                block.forward_exprs.append(copy_expr)
                alive_exprs.append(copy_expr)

            new_expr.expr.trace_dir = 'B'
            backward_exprs.append(new_expr)
            block.backward_exprs.append(new_expr)


        for new_expr in new_forward_exprs:
            copy_expr = new_expr.make_forward_copy()
            # self._check_sim_action(action, copy_expr)
            block.forward_exprs.append(copy_expr)
            alive_exprs.append(copy_expr)
            # print("new-forward: %s" % (copy_expr))

        for kill_expr in killed_exprs:
            backward_exprs.remove(kill_expr)
            block.backward_exprs.remove(kill_expr)

    # Kai code!
    def _forward_update_tmp_alias(self, trace_expr, tmp_alias):
        new_exprs = []
        trace_sims = trace_expr.expr.sims
        tmps = [tmp for tmp in tmp_alias if tmp in trace_sims]

        if len(tmps):
            new_exprs.append(trace_expr)

        while tmps:
            tmp = tmps.pop()
            tmp_exprs = []
            for alias_reg in tmp_alias[tmp]:
                for t_expr in new_exprs:
                    new_expr = t_expr.replace(tmp, alias_reg)
                    new_expr.expr.trace_dir = 'F'
                    tmp_exprs.append(new_expr)
            new_exprs = tmp_exprs

        # print("tmp-alias: %s" % (new_exprs))
        return new_exprs

    # Kai code!
    def _forward_update_reg_alias(self, trace_expr, reg_alias):
        """
        In forward analysis, we should update the reg with its alias register.
        For example, in a block, 'Put(r3) = r5', should update r5 with r3.
        """
        re_regs = []
        new_forward_exprs = []
        special_alias_regs = []
        trace_sims = trace_expr.expr.sims
        expr_var_type = trace_expr.expr.var_type
        for name, sim in trace_sims.items():
            if expr_var_type == 'ptr' and sim.var_type == 'ptr' or expr_var_type != 'ptr':
                if name in reg_alias:
                    re_regs.append((name, sim.index))

        old_exprs = [trace_expr]
        # print("forward_update_reg:\n  %s %s\n  with: %s" % (trace_expr, re_regs, reg_alias))
        while re_regs:
            r_reg, index = re_regs.pop()
            for alias_reg, loc_i in reg_alias[r_reg]:
                if index and index >= loc_i:
                    continue

                if alias_reg in re_regs:
                    special_alias_regs.append((r_reg, alias_reg))
                    continue

                for t_expr in old_exprs:
                    new_expr = t_expr.replace(r_reg, alias_reg)
                    new_expr.expr.trace_dir = 'F'
                    new_forward_exprs.append(new_expr)
            old_exprs = new_forward_exprs[:]

        return new_forward_exprs

    # Kai code!
    def _check_and_update_remaining_exprs(self, block, code_location, redef_exprs, backward_exprs):
        """
        Check and update the remaining exprs which re-backward trace to find store definition.
        """
        new_backward_exprs = []
        killed_exprs = []
        for trace_expr in backward_exprs:
            flag = trace_expr.expr.flag
            # print("test-path: %s %s" % (block.addr, trace_expr.backward_path))
            if flag & 2 != 2:
                continue
            # TODO (loop addr not in backward_path ???)
            # if flag & 2 != 2 or block.addr not in trace_expr.backward_path:
            #     continue

            alias_id, bw_loc = trace_expr.expr.alias_id, trace_expr.expr.bw_loc
            for redef_expr in redef_exprs:
                if alias_id == redef_expr.expr.alias_id and bw_loc == redef_expr.expr.bw_loc:
                    new_backward_exprs.append(redef_expr)
                    killed_exprs.append(trace_expr)

        # print("www-re-backward: %s" % (new_backward_exprs))
        # print("kill-expr: %s" % (killed_exprs))
        for kill_expr in killed_exprs:
            if kill_expr in backward_exprs:
                backward_exprs.remove(kill_expr)
            if kill_expr in block.backward_exprs:
                block.backward_exprs.remove(kill_expr)

        return new_backward_exprs

    # Kai code!
    def _backward_check_store_def(self, block, store_defs, code_location, backward_exprs):
        """
        Check the complex struct field store definition.
        """
        new_backward_exprs = []
        killed_exprs = []
        remove_sources = set()
        store_ids = {}

        # claculate the store ast's struct id.
        for s_expr in store_defs:
            value = s_expr.expr.value
            if value is not None and value.op == 'Store':
                struct_id = calculate_ast_struct_id(value)
                store_ids[struct_id] = s_expr

        # print("store-struct: %s" % (store_ids))

        current_idx = code_location.stmt_idx
        for trace_expr in backward_exprs:
            if trace_expr.index <= current_idx and trace_expr.expr.flag & 2 != 2:
                continue

            if block.addr not in trace_expr.backward_path:
                continue

            sim_actions = trace_expr.expr.sim_actions
            # print("back-trace: %s %s %x" % (trace_expr.expr.source, trace_expr, trace_expr.expr.flag))
            # print("backward-path: %s" % (trace_expr.backward_path))

            for sim_action in sim_actions.values():
                action_data = sim_action.action_data
                if action_data is not None and action_data.op == 'Load':
                    struct_id = calculate_ast_struct_id(action_data)
                    # print("xdx: %s %s" % (struct_id, action_data))

                    if struct_id in store_ids:
                        s_expr = store_ids[struct_id]
                        store_value = s_expr.expr.ast
                        new_expr = trace_expr.replace(action_data, store_value)
                        new_expr.expr.location = code_location
                        new_expr.index = code_location.stmt_idx
                        new_expr.expr.trace_dir = 'B'
                        new_expr.expr.flag = (new_expr.expr.flag & 0xfd) | 0x80

                        new_backward_exprs.append(new_expr)
                        remove_sources.add(trace_expr.expr.source)
                        # killed_exprs.append(trace_expr)
                        break

        for trace_expr in backward_exprs[:]:
            s = trace_expr.expr.source
            if s in remove_sources:
                # print("remove-expr: %s %s" % (s, trace_expr))
                backward_exprs.remove(trace_expr)
                block.backward_exprs.remove(trace_expr)

        # for kill_expr in killed_exprs:
        #     backward_exprs.remove(kill_expr)
        #     try:
        #         block.backward_exprs.remove(kill_expr)
        #     except:
        #         l.debug("The expr %s has been removed from block.backward_exprs" % (kill_expr))

        return new_backward_exprs

    # Kai code!
    def _backward_store_stmt(self, block, action, code_location, backward_exprs):
        """
        How to process 'store' action in backward? Any store may change the variable.
        """
        # print("psu-debug(B-store): %s" % (action))
        new_backward_exprs = []
        addr_type = action.addr_type
        var_size = action.var_size
        st_addr = action.dst_alias if action.dst_alias else action.dst

        st_data_alias = action.src_alias
        st_data = st_data_alias if type(st_data_alias) is str else action.src
        st_value = action.value
        var_type = action.var_type

        killed_exprs = []
        current_idx = code_location.stmt_idx

        for trace_expr in backward_exprs:

            do_store_use = True
            if (trace_expr.index <= current_idx or trace_expr.expr.flag & 2 == 2):
                continue

            if (block.is_loop and code_location in trace_expr.cycle_locs):
                # print(code_location, trace_expr.cycle_locs)
                do_store_use = False

            pattern = trace_expr.expr.pattern
            data_type = trace_expr.expr.data_type
            trace_ast = trace_expr.expr.ast
            trace_sims = trace_expr.expr.sims

            if data_type == 'Aptr' and trace_expr.expr.value.op == 'Store' and trace_ast.op not in ['BVS']:
                pass

            # In backward, save a ptr to mem could create a alias for f-expr.
            elif (do_store_use and 'BF' in pattern and addr_type != 'S' and var_size == self.arch_bits and trace_expr.do_store_alias()):

                if type(st_value) is int:
                    if st_value in trace_sims:
                        new_alias = self._find_store_use_v4(action, st_addr, st_value, trace_expr, block.live_defs)
                        new_backward_exprs.extend(new_alias)

                else:
                    if st_data in trace_sims:
                        new_alias = self._find_store_use_v1(action, st_data, trace_expr)
                        new_backward_exprs.extend(new_alias)

                    # if type(st_data_alias) is tuple and st_data_alias[1][0] in trace_sims:
                    #     new_alias = self._find_store_use_v3(action, st_addr, st_data_alias, var_type, trace_expr, block.live_defs)
                    #     new_backward_exprs.extend(new_alias)

            elif (do_store_use and 'BF' in pattern and addr_type == 'S' and var_type == 'ptr'):
                if type(st_value) is int:
                    base_ptr = trace_expr.expr.base_ptr
                    if st_value in trace_sims:
                        new_alias = self._find_store_use_v4(action, st_addr, st_value, trace_expr, block.live_defs)
                        new_backward_exprs.extend(new_alias)
                    elif (type(base_ptr) is int and
                            0 < (base_ptr - st_value) <= 0x20 and
                            self.config.do_offset_update()):
                        new_alias = self._find_store_use_v5(action, st_addr, st_value, trace_expr, block.live_defs)
                        new_backward_exprs.extend(new_alias)

            # In backward, for the case: STle(rbx + 0x20) = t3
            if len(trace_expr.expr.sim_actions):
                new_exprs = self._do_store_define(block, action, trace_expr, backward_exprs, trace_dir='B')
                new_backward_exprs.extend(new_exprs)

                # Cannot kill expr in backward while encountering store def.
                # See cs_tests/cs17.c
                if len(new_exprs) and addr_type == 'S' and self.config.do_strong_backward_update():
                    killed_exprs.append(trace_expr)

                # if len(new_exprs):
                #     print("@@:3725--> %s in %s" % (trace_expr, code_location))
                #     for sim_action in trace_expr.expr.sim_actions.values():
                #         print("  --> action: %s %s" % (sim_action, sim_action.store_update_loc))
                #     print("")

        self._kill_exprs(block.backward_exprs, backward_exprs, killed_exprs)

        # print("xxx-%s" % (new_backward_exprs))
        return new_backward_exprs

    # Kai code!
    def _backward_put_stmt(self, block, action, code_location, backward_exprs):
        """
        In backward, IR "Put(rdi) = t4 + offset" could trace from 't4+offset' to reg rdi in taint analysis.
        """
        new_backward_exprs = []
        put_data = action.src_alias if action.src_alias else action.src
        put_reg = action.dst
        current_idx = code_location.stmt_idx

        for trace_expr in backward_exprs:
            data_type = trace_expr.expr.data_type
            if trace_expr.index <= current_idx or data_type != 'Tdata':
                continue

            trace_sims = trace_expr.expr.sims
            if type(put_data) is tuple and put_data[1][0] in trace_sims and put_data[0] == '+' and trace_expr.expr.var_type == 'ptr':
                new_expr = self._find_put_use2(put_reg, put_data, code_location, trace_expr, trace_dir='F')
                if new_expr is not None:
                    new_backward_exprs.append(new_expr)

        return new_backward_exprs

    # Kai code!
    def _backward_wrtmp_stmt(self, block, action, code_location, backward_exprs):
        """
        In backward, IR "t4 = Get(rdi) or t4 = t5"
        """

        new_backward_exprs = []

        wr_tmp, wr_data, wr_size = action[1], action[2], action[3]

        killed_exprs = []
        current_idx = code_location.stmt_idx

        for trace_expr in backward_exprs:
            if trace_expr.index <= current_idx or trace_expr.expr.flag & 2 == 2:
                continue

            pattern = trace_expr.expr.pattern
            if (pattern != 'OB' and wr_data != self.sp_name and wr_data in trace_expr.expr.sims):
                new_alias = self._find_wrtmp_use2(wr_tmp, wr_data, code_location, trace_expr)

                new_backward_exprs.extend(new_alias)

            if wr_tmp in trace_expr.expr.sims:

                new_exprs = self._find_wrtmp_def2(wr_tmp, wr_data, wr_size, code_location, trace_expr)

                if len(new_exprs):
                    killed_exprs.append(trace_expr)
                    new_backward_exprs.extend(new_exprs)

                    try:
                        block.backward_exprs.remove(trace_expr)
                    except:
                        pass

        for kill_expr in killed_exprs:
            backward_exprs.remove(kill_expr)

        return new_backward_exprs

    # Kai code!
    def _backward_wrtmp_binop_stmt(self, block, action, code_location, backward_exprs):

        # print("psu-debug(B-binop): %s" % (action))
        new_backward_exprs = []
        execute_stmt_flag = False
        find_increment_flag = False

        wr_tmp, wr_size = action.dst, action.var_size
        wr_data = action.src_alias if action.src_alias else action.src
        binop = wr_data[0]
        opnd0, opnd1 = wr_data[1]
        var_type = action.var_type
        value = action.value

        killed_exprs = []
        current_idx = code_location.stmt_idx

        for trace_expr in backward_exprs:
            # print("  -->xx-B %s %s" % (trace_expr, trace_expr.expr.sims))
            if (trace_expr.index <= current_idx or
                    trace_expr.expr.flag & 2 == 2 or
                    block.is_loop and code_location in trace_expr.cycle_locs):
                continue

            trace_sims = trace_expr.expr.sims
            data_type = trace_expr.expr.data_type
            flag = trace_expr.expr.flag
            if wr_tmp in trace_sims:

                tmp_type = trace_sims[wr_tmp].var_type
                if tmp_type and var_type is None:
                    action.var_type = tmp_type
                    infer_variable_type(None, block, wr_data, tmp_type)

                # print("@@D->%s %s" % (tmp_type, var_type))

                new_exprs = self._find_wrtmp_binop_def(block, action, wr_data, tmp_type, trace_expr, killed_exprs)

                for new_expr in new_exprs:
                    if tmp_type and tmp_type != 'ptr' or ((new_expr.expr.flag >> 9) & 0x1 == 1):
                        new_expr.expr.trace_dir = 'B'

                if len(new_exprs):
                    new_backward_exprs.extend(new_exprs)
                killed_exprs.append(trace_expr)

            # This is find binop alias 'alias = value (opnd + offset)'
            # So, should not kill the backward expr.
            elif isinstance(value, int) and value == trace_expr.expr.base_ptr:
                new_expr = self._find_binop_use(wr_tmp, value, code_location, trace_expr)
                new_backward_exprs.append(new_expr)
                # print("@@--> %s" % (new_expr))

            elif ('Cmp' in binop and block.is_loop and flag & 0x200):
                if (opnd0 in trace_sims or opnd1 in trace_sims):
                    # print("Find-loop-guard:")
                    cons_expr = self._find_loop_constraint(block, wr_data, code_location, trace_expr)
                    if cons_expr is not None:
                        new_backward_exprs.append(cons_expr)
                elif opnd1 in block.live_defs and block.live_defs[opnd1].src_type =='A':
                    # print("Find-loop-guard-with-argument: %s %s" % (block, trace_expr))
                    cons_expr = self._find_loop_constraint_v2(block, wr_data, code_location, trace_expr)
                    if cons_expr is not None:
                        new_backward_exprs.append(cons_expr)

            # elif ('Cmp' in binop and (opnd0 == wr_tmp or opnd1 == wr_tmp)):
            #     self._collect_constraints(block, wr_data, code_location, trace_expr)

            # TODO binop alias?

        self._kill_exprs(block.backward_exprs, backward_exprs, killed_exprs)

        return new_backward_exprs

    # Kai code!
    def _backward_wrtmp_load_stmt(self, block, action, code_location, backward_exprs):

        print("psu-debug(B-load): %s" % action)
        new_backward_exprs = []

        wr_tmp = action.dst
        ld_addr = action.src_alias if action.src_alias else action.src
        addr_value = action.addr_value
        var_type = action.var_type

        killed_exprs = []
        may_recursive_exprs = []
        current_idx = code_location.stmt_idx

        for trace_expr in backward_exprs:
            if (trace_expr.index <= current_idx or trace_expr.expr.flag & 2 == 2):
                continue
            if (block.is_loop and code_location in trace_expr.cycle_locs):
                if self._is_check_recursive(wr_tmp, trace_expr):
                    may_recursive_exprs.append(trace_expr)
                continue

            pattern = trace_expr.expr.pattern
            data_type = trace_expr.expr.data_type
            trace_ast = trace_expr.expr.ast
            trace_sims = trace_expr.expr.sims

            if wr_tmp in trace_sims:

                if data_type == 'Iptr' and block.is_loop and contain_mul(trace_ast, wr_tmp):
                    new_exprs = self._find_wrtmp_load_def_v3(block, action, trace_expr)
                else:
                    new_exprs = self._find_wrtmp_load_def_v1(block, action, trace_expr)
                killed_exprs.append(trace_expr)
                if len(new_exprs):
                    new_backward_exprs.extend(new_exprs)

            elif data_type == 'Aptr' and sim_action_len(trace_ast) > APTR_MAX_LS:
                pass

            # Find load use in backward.
            elif 'BF' in pattern and trace_expr.do_load_alias():
                # if type(ld_addr) is tuple and ld_addr[0] in ['+', '-'] and ld_addr[1][0] in trace_sims:
                if type(ld_addr) is tuple and ld_addr[0] in ['+', '-']:
                    new_exprs = self._find_load_use_v3(wr_tmp, ld_addr, var_type, code_location,
                                                       trace_expr, block)
                    new_backward_exprs.extend(new_exprs)

                if type(ld_addr) is str and ld_addr in trace_sims:
                    new_exprs = self._find_load_use_v4(action, ld_addr, var_type, code_location, trace_expr)
                    new_backward_exprs.extend(new_exprs)

                if type(addr_value) is int and trace_expr.do_load_alias():
                    # print("Do-load-alias-backward (concret_addr).")
                    new_exprs = self._find_load_use_v1(action, addr_value, code_location, trace_expr)
                    new_backward_exprs.extend(new_exprs)
                    # print("Found: %s" % (new_exprs))

        new_exprs = self._check_recursive_structure_pattern(wr_tmp,
                                                ld_addr,
                                                action,
                                                code_location,
                                                may_recursive_exprs,
                                                backward_exprs,
                                                killed_exprs,
                                                block)
        new_backward_exprs.extend(new_exprs)

        self._kill_exprs(block.backward_exprs, backward_exprs, killed_exprs)

        # if is_match_recursive:
        #     print(new_backward_exprs)
        #     debug
        # print("@@->input exprs: %s" % (block.input_exprs))

        return new_backward_exprs

    def _is_check_recursive(self, wr_tmp, trace_expr):
        """
        Whether check this trace_expr to recursive
        """
        base_ptr = trace_expr.expr.base_ptr
        return base_ptr is not None and base_ptr == wr_tmp

    def _check_recursive_structure_pattern(self, wr_tmp,
                                           ld_addr,
                                           action,
                                           code_location,
                                           may_recursive_exprs,
                                           trace_exprs,
                                           killed_exprs,
                                           block):
        """
        Check whether the trace_expr is a recursive structure.
        :return: generated a list of new RecursiveExpr
        """
        if len(may_recursive_exprs) == 0:
            return []
        if type(ld_addr) is tuple and ld_addr[0] == '+':
            ld_offset = ld_addr[1][1]
        elif type(ld_addr) is str:
            ld_offset = 0
        else:
            return []
        is_recursive = False
        recursive_base = None
        for trace_expr in may_recursive_exprs:
            print("@->_check_recursive_structure_pattern: %s" % (trace_expr))
            is_recursive, recursive_base = trace_expr.is_recursive_structure(wr_tmp, ld_offset)
            if (is_recursive):
                print("Find-Recursive base-offset: (%s : %s)" % (recursive_base, ld_offset))
                break

        if (not is_recursive):
            return []

        recursive_alias_ids = set()
        generated_recursive_exprs = []
        for trace_expr in may_recursive_exprs:
            new_expr = trace_expr.copy_to_recursive(recursive_base, ld_offset, flag=0,
                                                    recursive_type="Chain")
            new_expr.expr.trace_dir = None
            print("@->New-recursive: %s" % (new_expr))
            # generated_recursive_exprs.append(new_expr)

            new_exprs = self._find_wrtmp_load_def_v1(block, action, new_expr)
            for new_recur_expr in new_exprs:
                new_recur_expr.cycle_locs.clear()
                new_recur_expr.cycle_locs.append(code_location)
            print("@->New-update-recursive: %s" % (new_exprs))
            generated_recursive_exprs.extend(new_exprs)

            recursive_alias_ids.add(trace_expr.expr.alias_id)
            for alias_id in trace_expr.expr.alias_ids:
                recursive_alias_ids.add(alias_id)
        print("recursive_alias_ids: ", recursive_alias_ids)
        killed_exprs.extend(may_recursive_exprs)

        recursive_bases = set()
        candidate_exprs = []
        for trace_expr in block.input_exprs:
            print("@@->trace_expr: %s" % (trace_expr))
            if trace_expr.expr.alias_id not in recursive_alias_ids:
                continue
            if trace_expr in may_recursive_exprs:
                continue
            print("@-> Should change to RecursiveExpr: %s" % (trace_expr))
            candidate_exprs.append(trace_expr)
            is_recursive, recursive_base = trace_expr.infer_recursive_base_info(ld_offset)
            print("Get-recursive-info: %s %s" % (is_recursive, recursive_base))
            if (not is_recursive):
                continue
            recursive_bases.add(recursive_base)
        print("recursive-base: %s" % recursive_bases)
        # if len(recursive_bases) == 0:
        #     return []

        # Change trace exprs to RecursiveExpr
        for trace_expr in candidate_exprs:
            for recursive_base in recursive_bases:
                if trace_expr.is_contain_recursive_base(recursive_base):
                    new_expr = trace_expr.copy_to_recursive(recursive_base, ld_offset, flag=0,
                                                            recursive_type='Chain')
                    new_expr.expr.trace_dir = None
                    generated_recursive_exprs.append(new_expr)
                    print("@(2)->New-recursive: %s" % (new_expr))
                    killed_exprs.append(trace_expr)

        return generated_recursive_exprs

    # Kai code!
    def _backward_loadg_stmt(self, block, action, code_location, backward_exprs):
        """
        Process the pyvex.stmt.LoadG statement
        """
        # print("LoadG stmt action: %s" % (action))
        new_backward_exprs = []
        execute_stmt_flag = False

        wr_tmp, wr_size = action.dst, action.var_size
        wr_data = action.src_alias if action.src_alias else action.src
        ld_addr, ld_size = wr_data[0][1], wr_data[1][1]
        alt_data, alt_size = wr_data[0][2], wr_data[1][2]

        guard = wr_data[0][0]
        guard_ast = self.calculate_binop_stmt_v2(guard)
        true_guard = guard_ast != 0
        false_guard = guard_ast == 0
        # print('LoadG %s %s' % (true_guard, false_guard))

        killed_exprs = []
        current_idx = code_location.stmt_idx

        for trace_expr in backward_exprs:

            if (trace_expr.index <= current_idx or
                    trace_expr.expr.flag & 2 == 2 or
                    block.is_loop and code_location in trace_expr.cycle_locs):
                continue

            # print("trace_expr: %s, has guard: %s" % (trace_expr, trace_expr.guard))
            curr_guard = trace_expr.guard
            trace_sims = trace_expr.expr.sims

            if wr_tmp in trace_sims:
                tmp_type = trace_sims[wr_tmp].var_type
                true_satisfiable, false_satisfiable = True, True

                if curr_guard is not None:
                    constraints = [true_guard, curr_guard]
                    true_satisfiable = self.judge_constraints_satisfiable(constraints)

                    constraints = [false_guard, curr_guard]
                    false_satisfiable = self.judge_constraints_satisfiable(constraints)

                if true_satisfiable:
                    new_exprs_1 = self._find_wrtmp_load_def_v2(block, action, trace_expr)

                    for new_expr in new_exprs_1:
                        if tmp_type and tmp_type != 'ptr':
                            new_expr.expr.trace_dir = 'B'
                        new_expr.guard = true_guard
                        new_backward_exprs.append(new_expr)

                if false_satisfiable:
                    if type(alt_data) is tuple:
                        if tmp_type:
                            self.infer_variable_type(block.live_defs, alt_data, tmp_type)
                        sim_types = self._get_sim_type_v1(alt_data, block.live_defs)
                        new_exprs_2 = self._find_wrtmp_def_v2(wr_tmp, alt_data, tmp_type, code_location, sim_types, trace_expr)
                    else:
                        new_exprs_2 = self._find_wrtmp_def_v1(wr_tmp, alt_data, wr_size, code_location, tmp_type, trace_expr)

                    for new_expr in new_exprs_2:
                        if tmp_type and tmp_type != 'ptr':
                            new_expr.expr.trace_dir = 'B'
                        new_expr.guard = false_guard
                        new_backward_exprs.append(new_expr)

                killed_exprs.append(trace_expr)

        self._kill_exprs(block.backward_exprs, backward_exprs, killed_exprs)

        return new_backward_exprs

    def _find_binop_use(self, wr_tmp, wr_value, code_location, trace_expr):
        """
        lea     rax, [rbp+var_1B0]      # rax = 0x7ffffe47
        Backward: <T-Expr <BV64 0x7ffffe47 + o + 0x8> (2147483207) (ptr) (None-19)>
        """
        ast = BVV(wr_value)
        new_expr = trace_expr.replace(ast, wr_tmp, sub_type='ptr')
        new_expr.expr.trace_dir = 'F'
        new_expr.index = code_location.stmt_idx

        new_expr.expr.sims[wr_tmp].index = code_location.stmt_idx

        return new_expr


    # Kai code!
    def _backward_wrtmp_ite_stmt(self, block, action, code_location, backward_exprs):
        """
        Process t3 = ITE(guard, t1, t2)
        """
        # print("psu-debug: %s" % (action))
        new_backward_exprs = []

        wr_tmp, wr_size = action.dst, action.var_size
        guard, data1, data2 = action.src_alias

        if type(guard) is str:
            guard_ast = BVS(guard)
        else:
            guard_ast = self.calculate_binop_stmt_v2(guard)
        true_guard = guard_ast == 0
        false_guard = guard_ast != 0
        # print("ITE guard: %s %s" % (true_guard, false_guard))

        killed_exprs = []
        current_idx = code_location.stmt_idx

        for trace_expr in backward_exprs:

            if (trace_expr.index <= current_idx or
                    trace_expr.expr.flag & 2 == 2 or
                    block.is_loop and code_location in trace_expr.cycle_locs):
                continue

            # print("trace_expr: %s, has guard: %s" % (trace_expr, trace_expr.guard))
            curr_guard = trace_expr.guard
            trace_sims = trace_expr.expr.sims

            # if trace_expr.guard is not None:
            #     constraints = [true_guard, trace_expr.guard]
            #     satisfiable = self.judge_constraints_satisfiable(constraints)

            if wr_tmp in trace_sims:
                tmp_type = trace_sims[wr_tmp].var_type
                tmp_type = tmp_type if tmp_type else action.var_type

                true_satisfiable, false_satisfiable = True, True
                if curr_guard is not None:
                    constraints = [true_guard, curr_guard]
                    true_satisfiable = self.judge_constraints_satisfiable(constraints)

                    constraints = [false_guard, curr_guard]
                    false_satisfiable = self.judge_constraints_satisfiable(constraints)

                if true_satisfiable:
                    if type(data1) is tuple:
                        if tmp_type:
                            self.infer_variable_type(block.live_defs, data1, tmp_type)
                        sim_types = self._get_sim_type_v1(data1, block.live_defs)
                        new_exprs_1 = self._find_wrtmp_def_v2(wr_tmp, data1, tmp_type, code_location, sim_types, trace_expr)
                    else:
                        new_exprs_1 = self._find_wrtmp_def_v1(wr_tmp, data1, wr_size, code_location, tmp_type, trace_expr)

                    for new_expr in new_exprs_1:
                        if tmp_type and tmp_type != 'ptr':
                            new_expr.expr.trace_dir = 'B'
                        new_expr.guard = true_guard
                        new_backward_exprs.append(new_expr)

                if false_satisfiable:
                    if type(data2) is tuple:
                        if tmp_type:
                            self.infer_variable_type(block.live_defs, data2, tmp_type)
                        sim_types = self._get_sim_type_v1(data2, block.live_defs)
                        new_exprs_2 = self._find_wrtmp_def_v2(wr_tmp, data2, tmp_type, code_location, sim_types, trace_expr)
                    else:
                        new_exprs_2 = self._find_wrtmp_def_v1(wr_tmp, data2, wr_size, code_location, tmp_type, trace_expr)

                    for new_expr in new_exprs_2:
                        if tmp_type and tmp_type != 'ptr':
                            new_expr.expr.trace_dir = 'B'
                        new_expr.guard = false_guard
                        new_backward_exprs.append(new_expr)

                killed_exprs.append(trace_expr)

        for kill_expr in killed_exprs:
            backward_exprs.remove(kill_expr)
            block.backward_exprs.remove(kill_expr)

        return new_backward_exprs

    def _forward_storeg_stmt(self, block, action, code_location, forward_exprs):
        """
        Process storeg stmt ('if (t58) STle(t10) = t54').
        """
        # print("psu-debug-f: %s" % (action))

        new_forward_exprs = []

        st_data_alias = action.src_alias[1]
        st_data = st_data_alias if type(st_data_alias) is str else action.src[1]
        st_value = action.value

        guard = action.src_alias[0]
        addr_alias = action.dst_alias if action.dst_alias else action.dst
        addr_type, src_type, var_type = action.addr_type, action.src_type, action.var_type

        guard_ast = self.calculate_binop_stmt_v2(guard)
        true_guard = guard_ast == 1
        # false_guard = guard_ast != 1
        # print(guard_ast, true_guard, false_guard)
        # return []

        killed_exprs = []
        current_idx = code_location.stmt_idx

        for trace_expr in forward_exprs:
            if trace_expr.index >= current_idx or trace_expr.expr.cons_type in [1, 2]:
                continue

            curr_guard = trace_expr.guard
            satisfiable = True

            # print('kai', curr_guard, true_guard)
            if curr_guard is not None:
                constraints = [true_guard, curr_guard]
                satisfiable = self.judge_constraints_satisfiable(constraints)

            if not satisfiable:
                continue

            trace_sims = trace_expr.expr.sims
            data_type = trace_expr.expr.data_type
            trace_ast = trace_expr.expr.ast
            pattern = trace_expr.expr.pattern

            # For the f-expr to find alise expr by STle(txx) = alias_ptr.
            if 'BF' in pattern and (var_type is None or var_type == 'ptr'):
                if type(st_value) is int:
                    if st_value in trace_sims:
                        new_alias = self._find_store_use_v4(action, addr_alias, st_value, trace_expr, block.live_defs)
                        new_forward_exprs.extend(new_alias)

                else:
                    if st_data in trace_sims:
                        new_alias = self._find_store_use_v1(action, st_data, trace_expr)
                        new_forward_exprs.extend(new_alias)

                    # if type(st_data_alias) is tuple and st_data_alias[1][0] in trace_sims:
                    #     new_alias = self._find_store_use_v3(action, st_addr, st_data_alias, var_type, trace_expr, block.live_defs)
                    #     new_forward_exprs.extend(new_alias)

            elif data_type == 'Tdata' and (var_type == 'char' and trace_expr.expr.var_type != 'ptr' or trace_expr.expr.var_type == 'char'):
                if trace_ast.op == 'BVS' and st_data in trace_sims:
                    # print("Find storeg char!")
                    new_exprs = self._find_char_store(block, action, st_data, code_location, trace_expr)
                    # print("xx %s" % (new_exprs))
                    new_forward_exprs.extend(new_exprs)


        self._kill_exprs(block.forward_exprs, forward_exprs, killed_exprs)

        return new_forward_exprs

    # Kai code!
    def _backward_wrtmp_unop_stmt(self, block, action, code_location, backward_exprs):

        new_backward_exprs = []

        wr_tmp, wr_data = action[1], action[2]
        opnds = wr_data[1]

        if len(opnds) != 1:
            logger.info("Not support the action: %s" % (action))
            return []

        wr_opnd = opnds[0]
        if type(wr_opnd) is int or 't' not in wr_opnd:
            return []

        killed_exprs = []
        current_idx = code_location.stmt_idx
        for trace_expr in backward_exprs:
            if trace_expr.index <= current_idx or trace_expr.expr.flag & 2 == 2:
                continue

            if wr_tmp in trace_expr.expr.sims:

                new_exprs = self._find_wrtmp_unop_def(wr_tmp, wr_opnd, code_location, trace_expr)

                if len(new_exprs):
                    killed_exprs.append(trace_expr)
                    new_backward_exprs.extend(new_exprs)

                    try:
                        block.backward_exprs.remove(trace_expr)
                    except:
                        pass

        for kill_expr in killed_exprs:
            backward_exprs.remove(kill_expr)

        return new_backward_exprs

    # Kai code!
    def _find_register_store_def_v1(self, block, action, st_addr, trace_expr, tracing_exprs,
                                    trace_dir):
        """
        The st_addr is str, e.g. ('txx' or 'rxx')
        """

        code_location = action.code_location
        sim_actions = trace_expr.expr.sim_actions
        if len(sim_actions) == 0:
            return []

        var_type = action.var_type
        st_data = action.src_alias if type(action.src_alias) is str else action.src
        st_value, st_size = action.value, action.var_size

        copy_actions = {}
        load_actions = []
        for index, sim_action in sim_actions.items():
            name = sim_action.name
            if name is None:
                continue

            binop = sim_action.binop
            action_data = sim_action.action_data
            if name[1] == 0 and name[0] == st_addr and action_data.op == 'Load' and sim_action.live:
                if (self.config.is_strong_update() and sim_action.store_update_loc):
                    print("@@:4361--> %s %s %s" % (trace_expr, code_location,
                                                   sim_action.store_update_loc))
                    if (self.is_store_updated_backward(block, code_location, sim_action.store_update_loc)):
                        continue
                sim_action.store_update_loc = code_location
                load_actions.append(sim_action)
                copy_actions[index] = sim_action.copy()

                if trace_dir == 'F':
                    self._check_strong_store_update(index, trace_expr, code_location, block,
                                                tracing_exprs)

        # for index, copy_action in copy_actions.items():
        #     print("kkk- %s %s %s" % (code_location, index, copy_action))
        #     sim_actions.pop(index)
        #     copy_action.live = False
        #     sim_actions[index] = copy_action

        if len(load_actions) == 0:
            return []

        load_ptr = load_actions[0].action_data
        if var_type is None:
            var_type = load_actions[0].var_type

        if type(action.src) is int:
            data_ast = BVV(action.src)

        elif not block.is_loop and type(st_value) is int:
            data_ast = BVV(st_value, st_size)

        elif type(st_data) is str:
            if var_type is None:
                var_type = get_sim_type(block, st_data)
            data_ast = BVS(st_data, st_size)

        else:
            return []

        new_expr = trace_expr.replace(load_ptr, data_ast, rep_type=var_type)
        new_expr.index = code_location.stmt_idx

        if new_expr.expr.pattern == 'OB':
            new_expr.expr.trace_dir = 'B'

        return [new_expr]

    # Kai code!
    def _find_register_store_def_v2(self, block, action, addr_info, trace_expr, tracing_exprs,
                                    trace_dir):

        code_location = action.code_location
        sim_actions = trace_expr.expr.sim_actions
        if len(sim_actions) == 0:
            return []

        var_type = action.var_type
        st_value, st_size = action.value, action.var_size
        st_data = action.src_alias if type(action.src_alias) is str else action.src
        op, opnds = addr_info[0], addr_info[1]

        copy_actions = {}
        load_actions = []
        for index, sim_action in sim_actions.items():
            name = sim_action.name
            if name is None:
                continue

            binop = sim_action.binop
            action_data = sim_action.action_data
            if action_data.op == 'Load' and sim_action.live and op == binop and name == opnds:
                if (self.config.is_strong_update() and sim_action.store_update_loc):
                    print("@@:4426--> %s %s %s" % (trace_expr, code_location,
                                                   sim_action.store_update_loc))

                    if (self.is_store_updated_backward(block, code_location, sim_action.store_update_loc)):
                        continue
                sim_action.store_update_loc = code_location
                load_actions.append(sim_action)
                copy_actions[index] = sim_action.copy()

                if trace_dir == 'F':
                    self._check_strong_store_update(index, trace_expr, code_location, block,
                                                tracing_exprs)

        # for index, copy_action in copy_actions.items():
        #     print("kkk- %s %s %s" % (code_location, index, copy_action))
        #     sim_actions.pop(index)
        #     copy_action.live = False
        #     sim_actions[index] = copy_action

        if len(load_actions) == 0:
            return []

        elif len(load_actions) > 1:
            logger.info("There are two load ptr should be update!")

        load_ptr = load_actions[0].action_data
        if var_type is None:
            var_type = load_actions[0].var_type

        if type(action.src) is int:
            data_ast = BVV(action.src)

        elif not block.is_loop and type(st_value) is int:
            data_ast = BVV(st_value, st_size)

        elif type(st_data) is str:
            if var_type is None:
                var_type = get_sim_type(block, st_data)
            data_ast = BVS(st_data, st_size)

        else:
            return []

        new_expr = trace_expr.replace(load_ptr, data_ast, rep_type=var_type)
        new_expr.index = code_location.stmt_idx

        if new_expr.expr.pattern == 'OB':
            new_expr.expr.trace_dir = 'B'

        return [new_expr]

    # Kai code!
    def _find_concrete_addr_store_def_v1(self, block, action, trace_expr, tracing_exprs, trace_dir):
        """
        The store addr is concrete.
        """
        # print("-->Find-concrete-store-def: %s %s" % (block, trace_expr))
        code_location = action.code_location
        sim_actions = trace_expr.expr.sim_actions
        if len(sim_actions) == 0:
            return []

        var_type = action.var_type
        st_value, st_size = action.value, action.var_size
        st_data = action.src_alias if type(action.src_alias) is str else action.src
        addr_value = action.addr_value

        if trace_expr.expr.data_type == 'Cons' and st_value == 0:
            return []

        copy_actions = {}
        load_actions = []
        store_loc_info = {}
        for index, sim_action in sim_actions.items():
            name = sim_action.name
            # print("sim_action: %s %s" % (sim_action, name))
            if name is None:
                continue

            binop = sim_action.binop
            action_data = sim_action.action_data
            flag = False
            if name[1] == 0 and name[0] == addr_value and action_data.op == 'Load' and sim_action.live:
                if (self.config.is_strong_update() and sim_action.store_update_loc):
                    print("@@:4501--> %s %s %s" % (trace_expr, code_location,
                                                   sim_action.store_update_loc))
                    if (self.is_store_updated_backward(block, code_location, sim_action.store_update_loc)):
                        continue
                sim_action.store_update_loc = code_location
                load_actions.append(sim_action)
                copy_actions[index] = sim_action.copy()
                flag = True
            elif (self.config.do_array_symbolic_index() and name[1] == 'o'
                    and isinstance(name[0], int) and 0<= addr_value-name[0] <= 64):
                if (self.config.is_strong_update() and sim_action.store_update_loc):
                    print("@@:4512--> %s %s %s" % (trace_expr, code_location,
                                                   sim_action.store_update_loc))
                    if (self.is_store_updated_backward(block, code_location, sim_action.store_update_loc)):
                        continue
                sim_action.store_update_loc = code_location
                load_actions.append(sim_action)
                flag = True
            if flag:
                if trace_dir == 'F':
                    self._check_strong_store_update(index, trace_expr, code_location, block,
                                                tracing_exprs)
                store_loc_info[index] = code_location

        # for index, copy_action in copy_actions.items():
        #     print("kkk- %s %s %s" % (code_location, index, copy_action))
        #     sim_actions.pop(index)
        #     copy_action.live = False
        #     sim_actions[index] = copy_action

        if len(load_actions) == 0:
            return []

        load_ptr = load_actions[0].action_data
        if var_type is None:
            var_type = load_actions[0].var_type

        if type(action.src) is int:
            data_ast = BVV(action.src)

        elif not block.is_loop and type(st_value) is int:
            data_ast = BVV(st_value, st_size)

        elif type(st_data) is str:
            if var_type is None:
                var_type = get_sim_type(block, st_data)
            data_ast = BVS(st_data, st_size)

        else:
            return []

        new_expr = trace_expr.replace(load_ptr, data_ast, rep_type=var_type)
        new_expr.index = code_location.stmt_idx

        if new_expr.expr.pattern == 'OB' or (var_type and var_type != 'ptr'):
            new_expr.expr.trace_dir = 'B'

        new_expr.update_store_locs(store_loc_info)
        # trace_expr.update_store_locs(store_loc_info)
        print("@@:4559-->F-store-v1 gen-new: %s\n  -->with store_loc: %s" % (new_expr,
                                                                           new_expr.store_locs))
        return [new_expr]

    def is_store_updated_backward(self, block, current_loc, store_loc):
        """
        :param current_loc: the code_location in current store ins.
        :param store_loc: the code_location in backward store ins, shown the trace expr has been
        store update in the flowing procedural.
        """
        if current_loc.block_addr == store_loc.block_addr:
            return store_loc.stmt_idx > current_loc.stmt_idx

        function = self.call_graph.get_function_by_addr(block.func_addr)
        graph_parser = function.graph_parser

        current_block = function.cfg.get_node_by_addr(current_loc.block_addr)
        store_block = function.cfg.get_node_by_addr(store_loc.block_addr)

        killed = graph_parser.judge_post_dome(current_block, store_block)
        print("@@:4562--> %s is killed %s %s" % (current_block, store_block, killed))

        return killed

    # Kai code!
    def _find_register_store_def(self, st_addr, st_data, st_size, code_location, trace_expr):
        # if st_addr not in trace_expr.expr.sims:
        #     return []

        store_label = False

        # print("b_find_store: %s" % (trace_expr))
        sim_actions = trace_expr.expr.sim_actions
        if len(sim_actions) == 0:
            return []

        load_ptrs = []
        for index, sim_action in sim_actions.items():
            name = sim_action.name
            binop = sim_action.binop
            action_data = sim_action.action_data
            if name is None:
                continue

            if name[1] == 0 and name[0] == st_addr and action_data.op == 'Load':
                load_ptrs.append(action_data)
            elif name[1] == 0:
                store_label = True

        # record the store maybe alias ptr store action
        if len(load_ptrs) == 0:
            if store_label:
                self.backward_store_records.add(code_location)
                trace_expr.expr.flag |= 4
            return []

        if type(st_data) is int:
            if st_data == 0:
                logger.info("The store data is zero, maybe the callee redefined it. do it future!")

            st_data = claripy.BVV(st_data, st_size)

        elif type(st_data) is str:
            st_data = claripy.BVS(st_data, st_size, explicit_name=True)

        elif type(st_data) is tuple:
            st_data = self._calculate_simple_binop_v1(st_data[1])

        load_ptr = load_ptrs[0]
        new_expr = trace_expr.replace(load_ptr, st_data)
        new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx

        if new_expr.expr.pattern == 'OB':
            new_expr.expr.trace_dir = 'B'

        return [new_expr]

    # Kai code!
    def _find_register_store_def2(self, st_addr, st_data, st_size, code_location, trace_expr):

        store_label = False

        # print("b_find_store: %s" % (trace_expr))
        sim_actions = trace_expr.expr.sim_actions
        if len(sim_actions) == 0:
            return []

        # for index, sim_action in sim_actions.items():
        #     print("%d %s" % (index, sim_action.action_data))
        #     print(sim_action.name)

        ls_addr_tmp = st_addr[0]
        ls_addr, ls_offset = st_addr[1][1][0], st_addr[1][1][1]
        _op = st_addr[1][0]
        load_ptrs = []
        for index, sim_action in sim_actions.items():
            name = sim_action.name
            binop = sim_action.binop
            action_data = sim_action.action_data

            if name and action_data.op == 'Load':
                if name[1] == ls_offset:
                    if _op == binop and name[0] == ls_addr:
                        load_ptrs.append(action_data)

                    else:
                        store_label = True
                elif name[1] == 0 and name[0] == ls_addr_tmp:
                    load_ptrs.append(action_data)

        if store_label:
            self.backward_store_records.add(code_location)
            trace_expr.expr.flag |= 4

        if len(load_ptrs) == 0:
            return []

        elif len(load_ptrs) > 1:
            logger.info("There are two load ptr should be update!")

        # print("backward-find-store: %s" % (load_ptrs))

        if type(st_data) is int:
            if st_data == 0:
                logger.info("The store data is zero, maybe the callee redefined it. do it future!")

            st_data = claripy.BVV(st_data, st_size)

        elif type(st_data) is str:
            st_data = claripy.BVS(st_data, st_size, explicit_name=True)

        elif type(st_data) is tuple:
            st_data = self._calculate_simple_binop_v1(st_data[1])

        load_ptr = load_ptrs[0]
        new_expr = trace_expr.replace(load_ptr, st_data)
        new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx

        if new_expr.expr.pattern == 'OB':
            new_expr.expr.trace_dir = 'B'

        return [new_expr]

    # Kai code!
    def _find_put_def2(self, reg_name, put_data, put_size, code_location, trace_expr):

        trace_dir = None
        if type(put_data) is int:
            put_data = claripy.BVV(put_data, put_size)
            trace_dir = 'B'

        # print("put_def: %s %s %s" % (trace_expr, reg_name, put_data))
        new_expr = trace_expr.replace(reg_name, put_data)
        new_expr.expr.location = code_location
        new_expr.expr.trace_dir = trace_dir
        new_expr.index = code_location.stmt_idx

        return [new_expr]

    # Kai code!
    def _find_wrtmp_def_v1(self, wr_tmp, wr_data, wr_size, code_location, var_type, trace_expr):

        if type(wr_data) is int:
            wr_data = BVV(wr_data, wr_size)
        else:
            wr_data = BVS(wr_data, wr_size)

        new_expr = trace_expr.replace(wr_tmp, wr_data, rep_type=var_type)
        new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx

        # if type(wr_data) is str and 'r' in wr_data:
        #     wr_reg_sim = new_expr.expr.sims[wr_data]
        #     wr_reg_sim.def_loc = code_location

        return [new_expr]

    # Kai code
    def _find_wrtmp_def_v2(self, wr_tmp, data_info, var_type, code_location, sim_types, trace_expr):
        """
        The data_info's type is Tuple, '(op, (opnd1, opnd2), (opnd1_size, opnd2_size))'
        """
        if var_type and var_type != 'ptr':
            wr_data = BVS("o%d" % (next(symbolic_count)))
            # print("unsym-data(2): %s %s" % (code_location, wr_data))
        else:
            wr_data = self.calculate_binop_stmt_v2(data_info)

        new_expr = trace_expr.replace(wr_tmp, wr_data, rep_info=sim_types)
        new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx

        return [new_expr]

    # Kai code!
    def _find_wrtmp_def2(self, wr_tmp, wr_data, wr_size, code_location, trace_expr):

        if type(wr_data) is int:
            wr_data = claripy.BVV(wr_data, wr_size)

        new_expr = trace_expr.replace(wr_tmp, wr_data)
        new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx

        if type(wr_data) is str and 'r' in wr_data:
            wr_reg_sim = new_expr.expr.sims[wr_data]
            wr_reg_sim.def_loc = code_location

        return [new_expr]

    # Kai code!
    def _find_wrtmp_binop_def(self, block, action, opnds_info, var_type, trace_expr, killed_exprs):
        """
        In backward, find a binop statement, e.g., 't1 = binop(t2, t3)'.
        While 't1' in trace_expr, replace 't1' with 'binop(t2, t3)'.
        """
        new_exprs = []
        wr_tmp = action.dst
        op, opnds = opnds_info[0], opnds_info[1]
        code_location = action.code_location
        data_type = trace_expr.expr.data_type
        sim_types = get_opnds_type(block, opnds_info, var_type)

        if action.inc_flag:
            binop_data, base_ast, offset_ast = self._get_increment_ast(action)
            # if isinstance(trace_expr, RecursiveExpr):
            #     print("Kai-Rec: %s %s\n base-offset: %s %s" % (trace_expr, trace_expr.base, base_ast, offset_ast))

            if isinstance(trace_expr, RecursiveExpr):

                if data_type == 'Cons' or data_type == 'Tdata':
                    killed_exprs.append(trace_expr)
                    return new_exprs

                if code_location in trace_expr.inc_records:
                    killed_exprs.append(trace_expr)
                    return new_exprs

                elif base_ast is not None:
                    if trace_expr.is_update_base(wr_tmp) and self.taint_check:
                        new_expr = trace_expr.replace(wr_tmp, base_ast, rep_type=var_type)
                        # print("x1-> %s" % (new_expr))

                    elif trace_expr.with_same_inc_info(base_ast, offset_ast):
                        new_expr = trace_expr.replace(wr_tmp, base_ast, rep_type=var_type)
                        # print("x2-> %s" % (new_expr))

                    else:
                        new_expr = trace_expr.replace(wr_tmp, binop_data, rep_info=sim_types)
                        # print("x3-> %s" % (new_expr))

                else:
                    new_expr = trace_expr.replace(wr_tmp, binop_data, rep_info=sim_types)
                    # print("x4-> %s" % (new_expr))

            else:
                n_expr = trace_expr.replace(wr_tmp, binop_data, rep_info=sim_types)
                new_expr = self.create_recursive_expr(n_expr, base_ast, offset_ast)
                # print("x5-> %s" % (new_expr))

            new_expr.inc_records.append(code_location)
            new_expr.index = code_location.stmt_idx
            new_exprs.append(new_expr)

        else:
            base_ptr = trace_expr.expr.base_ptr
            if (data_type not in ['Cons'] and self.taint_check and var_type and var_type != 'ptr'):
                binop_data = self.get_binop_symbol(code_location)
                # print("1 %s" % (binop_data))

            elif (data_type == 'Tdata' and trace_expr.expr.flag & 0x200 == 0 and
                    (type(opnds[1]) is int and
                    (opnds[1] >= 0x8000 or opnds[1]%2 != 0))):
                killed_exprs.append(trace_expr)
                return new_exprs

            elif action.src_type != 'S':
                binop_data = self._get_binop_ast(action, data_type)
                # print("2 %s" % (binop_data))

            elif type(action.value) is int:
                binop_data = BVV(action.value, action.var_size)
                # print("3 %s" % (binop_data))

            else:
                binop_data = self._get_binop_ast(action, data_type)
                # print("4 %s" % (binop_data))

            new_expr = trace_expr.replace(wr_tmp, binop_data, rep_type=var_type, rep_info=sim_types)

            new_expr.set_tag(binop_data)

            if data_type == 'Iptr' and 'Shl' in op and opnds[1] == 16 and len(new_expr.expr.sim_actions) == 0:
                new_expr = self._simplify_arm_ldrh_instruction(new_expr)
            if new_expr.expr.ast.op == 'BVV' and new_expr.expr.flag & 0x200:
                pass
            else:
                new_expr.index = code_location.stmt_idx
                new_exprs.append(new_expr)


        return new_exprs

    # Kai code!
    def _find_wrtmp_unop_def(self, wr_tmp, wr_data, code_location, trace_expr):

        new_expr = trace_expr.replace(wr_tmp, wr_data)
        # new_expr.get_trace_variable(trace_expr.expr.killed_vars)
        new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx

        return [new_expr]

    # Kai code!
    def _find_wrtmp_load_def_v1(self, block, action, trace_expr, is_recursive=False):

        # print("wrtmp-load: %s" % (action))
        new_exprs = []
        link_base = None
        wr_tmp = action.dst
        value = action.value
        code_location = action.code_location
        data_type = trace_expr.expr.data_type
        trace_ast = trace_expr.expr.ast
        sim_types = {}

        # print(code_location, trace_expr.expr.store_location)
        # if (not is_recursive and (code_location in trace_expr.expr.store_location or
        if ((data_type == 'Aptr' and sim_action_len(trace_ast) > APTR_MAX_Load)):
            # print("Skip: %s" % (trace_expr))
            return new_exprs

        var_type = trace_expr.expr.sims[wr_tmp].var_type
        if var_type:
            action.var_type = var_type
        else:
            var_type = get_sim_type(block, wr_tmp)
        var_tag = trace_expr.expr.sims[wr_tmp].tag

        # if (data_type == 'Aptr' and var_type and var_type != 'ptr' and
        #         type(action.addr_value) is not int and type(action.value) is not int):
        #     print("OMG--> %s %s" % (trace_expr, wr_tmp))
        #     return new_exprs
        # elif data_type == 'Aptr' and var_type is None:
        #     print("OMG(U)--> %s %s" % (trace_expr, wr_tmp))

        if self.taint_check and type(value) is int and get_scope(value) == 'global':
            ld_data = BVV(value, action.var_size)

        elif (var_type and var_type != 'ptr' and data_type == 'Tdata'):
            ld_data = BVS('o', action.var_size)

        elif var_tag == 0x1:
            ld_data = BVS('i', action.var_size)

        # We will not trace the non-pointer variable while encounter 't1 =LDle(addr)'
        elif var_type and var_type != 'ptr':
            ld_data = BVS('s', action.var_size)

        elif action.link_flag:
            ld_data, link_base, link_offset = self._get_link_action_ast(action, sim_types)

        elif is_recursive:
            ld_data, link_base, link_offset = self._get_chain_action_ast(action, sim_types)
            # print(ld_data, link_base, link_offset)

        else:
            ld_data = self._get_load_action_ast(action, block, sim_types, trace_ast, is_loop=block.is_loop, data_type=data_type)

        if ld_data.op == 'Load':
            sim_action = trace_expr.create_sim_action(ld_data, def_loc=code_location, var_type=var_type, live=True)
            sim_action.var_type = var_type
            re_sim_actions = {0: sim_action}
        else:
            re_sim_actions = {}

        if action.link_flag and link_base is not None:
            if isinstance(trace_expr, RecursiveExpr):
                base = trace_expr.base
                if code_location in trace_expr.inc_records:
                    return new_exprs
                elif base is not None and base.__hash__() == link_base.__hash__():
                    return new_exprs

                new_expr = trace_expr.replace(wr_tmp, ld_data, re_sim_actions, rep_info=sim_types)
                new_expr.base = link_base
                new_expr.offset = link_offset

            else:
                n_expr = trace_expr.replace(wr_tmp, ld_data, re_sim_actions, rep_info=sim_types)
                new_expr = self.create_recursive_expr(n_expr, link_base, link_offset)
            new_expr.expr.base_ptr = link_base.args[0]
            new_expr.inc_records.append(code_location)
            print('pppp-> %s %s %s %s' % (ld_data, link_base, link_offset, sim_types))

        elif is_recursive:
            if isinstance(trace_expr, RecursiveExpr) and code_location in trace_expr.inc_records:
                return new_exprs

            new_expr = trace_expr.replace(wr_tmp, ld_data, re_sim_actions, rep_info=sim_types)
            new_expr = new_expr.copy_to_recursive(link_base, link_offset, flag=0,
                                                    recursive_type="Chain")
            print("oooo-> %s" % (new_expr))

        else:
            new_expr = trace_expr.replace(wr_tmp, ld_data, re_sim_actions, rep_info=sim_types)
            print("xxxx-> %s" % (new_expr))

        new_expr.index = code_location.stmt_idx
        if code_location not in new_expr.expr.store_location:
            new_expr.expr.store_location.append(code_location)
        if var_type and var_type != 'ptr' or trace_expr.expr.flag & 0x200:
            new_expr.expr.trace_dir = 'B'
        # if trace_expr.expr.data_type == 'Aptr':
        #     print("OMG-> is_link %s old %s\n   -> new %s\n" % (action.link_flag, trace_expr, new_expr))
        new_exprs.append(new_expr)
        return new_exprs

    # Kai code!
    def _find_wrtmp_load_def_v2(self, block, action, trace_expr):

        wr_tmp = action.dst
        code_location = action.code_location
        sim_types = {}
        ld_data = self._get_loadg_action_ast(action, sim_types)

        var_type = trace_expr.expr.sims[wr_tmp].var_type
        if var_type:
            action.var_type = var_type
        else:
            var_type = get_sim_type(block, wr_tmp)

        if ld_data.op == 'Load':
            sim_action = self.create_sim_action(ld_data, code_location)
            sim_action.var_type = var_type
            re_sim_actions = {0: sim_action}
        else:
            re_sim_actions = {}
        new_expr = trace_expr.replace(wr_tmp, ld_data, re_sim_actions, rep_info=sim_types)
        # new_expr.expr.location = code_location
        new_expr.index = code_location.stmt_idx

        if var_type and var_type != 'ptr':
            new_expr.expr.trace_dir = 'B'

        return [new_expr]

    # Kai code!
    def _find_wrtmp_load_def_v3(self, block, action, trace_expr):
        """
        In backward, if trace_expr have 'var * 4' or 'var *8',
        and the block in a loop. Then replace var with i.
        """
        # print("wrtmp-load: %s" % (action))
        new_exprs = []
        wr_tmp = action.dst
        code_location = action.code_location
        new_expr = trace_expr.replace(wr_tmp, 'i')
        new_expr.index = code_location.stmt_idx
        new_expr.expr.trace_dir = 'B'
        new_exprs.append(new_expr)
        return new_exprs

    def _judge_trace_dir(self, trace_expr):
        data_type = trace_expr.expr.data_type
        if (data_type == 'Aptr' and
                trace_expr.expr.value.op == 'Store' and
                trace_expr.expr.ast.op not in ['BVS', 'BVV', 'Load']):
            trace_expr.expr.trace_dir = 'B'
        elif (data_type == 'Ret' and len(trace_expr.expr.sim_actions)):
            trace_expr.expr.trace_dir = 'B'

    # Kai code!
    def _find_constant_store_def(self):

        return []

    # Kai code!
    def _label_and_create_reforward_exprs(self, alias_ptr, code_location, trace_exprs):
        """
        In backward, some load expr should re-forward to find store def.
        """
        alias_ptr = alias_ptr[1] if type(alias_ptr) is tuple else alias_ptr
        new_exprs = []
        for trace_expr in trace_exprs:
            if trace_expr.expr.is_contain_load_ptr(alias_ptr):
                new_expr = trace_expr.make_forward_copy()
                new_expr.expr.bw_loc = code_location
                new_expr.forward_path = trace_expr.forward_path
                new_expr.backward_path = trace_expr.backward_path
                new_expr.expr.flag |= 0x40
                # print("re-forward: %s %s 0x%x" % (new_expr, new_expr.expr.pattern, new_expr.expr.flag))
                new_exprs.append(new_expr)

        return new_exprs

    # Kai code!
    def _create_increment_data(self, wr_data_info, wr_size):
        binop = wr_data_info[0]
        opnds = wr_data_info[1]
        # print("psu-debug: %s %s" % (binop, opnds))
        inc_sym, inc_offset = None, None
        inc_data = None

        if binop == '+':
            for opnd in opnds:
                if type(opnd) is int:
                    inc_offset = opnd
                elif type(opnd) is str:
                    inc_sym = opnd

            if inc_sym and inc_offset:
                sym_ast = claripy.BVS(inc_sym, wr_size, explicit_name=True)
                i = claripy.BVS('i', wr_size, explicit_name=True)
                inc_data = sym_ast + i * inc_offset

        elif binop == '-':
            for opnd in opnds:
                if type(opnd) is int:
                    inc_offset = opnd
                elif type(opnd) is str:
                    inc_sym = opnd

            if inc_sym and inc_offset:
                sym_ast = claripy.BVS(inc_sym, wr_size, explicit_name=True)
                i = claripy.BVS('i', wr_size, explicit_name=True)
                inc_data = sym_ast - i * inc_offset

        return inc_data

    def parse_bool_condition(self, bool_con):
        cc_deps = []
        if len(bool_con.args) == 2:
            cc_dep1 = bool_con.args[0]
            cc_dep2 = bool_con.args[1]
            cc_deps.append((cc_dep1, cc_dep2))

        else:
            logger.info("The bool expr %s have not two args, do it future!" % (bool_con))

        return cc_deps

    def trace_constraint_dep(self, block, con_exprs, sp_tmp):
        bb = block.shallow_copy()
        self.backward_data_trace(bb, con_exprs, sp_tmp)

    def simplify_expr_v2(self, trace_expr):
        ast = trace_expr.expr.ast
        if ('add' in ast.op or 'sub' in ast.op) and len(ast.args) == 2:
            opnd0, opnd1 = ast.args
            if opnd1.op == 'BVV' and (opnd1.args[0] == 0):
                trace_expr.expr.ast = opnd0
            elif (trace_expr.expr.data_type == 'Tdata' and
                  trace_expr.expr.var_type == 'ptr' and
                  opnd0.op == 'BVS' and opnd1.op == 'BVS' and 'o' in opnd1.args[0]):
                trace_expr.expr.ast = opnd0

    # TODO
    def simplify_expr(self, expr):
        """
        Simplify a claripy ast
        """
        return
        simply_asts = []
        for child_ast in expr.expr.ast.recursive_children_asts:
            # print(child_ast)
            simplify_flag = False
            if child_ast.op in self.simplify_ops:
                if len(child_ast.args) >= 3:
                    simplify_flag = True

                elif len(child_ast.args) == 2:
                    if child_ast.args[0].op in self.simplify_ops:
                        simplify_flag = True
                    elif child_ast.args[1].op in self.simplify_ops:
                        simplify_flag = True

                if simplify_flag:
                    simple_ast = self.state.simplify(child_ast)
                    if simple_ast.__hash__() != child_ast.__hash__():
                        simply_asts.append((child_ast, simple_ast))
                        break

        # print("simplify:\n %s" % (simply_asts))
        if len(simply_asts):
            # print("simpily before %s" % (expr))
            new_ast = expr.expr.ast
            for child_ast, simple_ast in simply_asts:
                new_ast = new_ast.replace(child_ast, simple_ast)
            expr.expr.ast = new_ast
            expr.get_trace_variable(expr.expr.killed_vars)
            # print("The simplify expr %s" % (expr))

    # Kai code!
    def convert_shift_operators(self, data ,data_type=None):
        if len(data.args) != 2:
            logger.info("The data %s has complex operators" % (data))
            return data

        new_data = data
        arg_1 = data.args[0]
        arg_2 = data.args[1]
        if arg_2.concrete:
            shift_count = arg_2.args[0]
            if shift_count <= 6:
                value = 2**shift_count
                value_ast = claripy.BVV(value, arg_1.size())
                if self.icall_check and data_type in ['Ret', 'Aptr']:
                    new_data = BVS('o') * value_ast
                else:
                    new_data = arg_1 * value_ast
                return new_data
            elif data_type in ['Ret', 'Aptr']:
                return BVS('o', data.size())
            else:
                return data
        return BVS('o', data.size())

            # if shift_count <= 15:
            #     value = 2**shift_count
            #     value_ast = claripy.BVV(value, arg_1.size())
            #     # if self.icall_check and data_type in ['Iptr', 'Ret', 'Aptr']:
            #     if self.icall_check and data_type in ['Ret', 'Aptr']:
            #         new_data = BVS('o') * value_ast
            #     else:
            #         new_data = arg_1 * value_ast
            # else:
            #     l.info("The shift count > 15, we igonre %s!" % (data))
        # else:
            # l.info("The shift is symbolc, simplify %s future!" % (data))
        # return new_data

    def get_user_trace_data(self, block, user_location):
        """
        :param block: a cfg block
        :param user_location: a CodeLocation, which is defined by user for data tracing.
        """
        irsb = block.irsb
        statements = irsb.statements
        stmt = statements[user_location.stmt_idx]
        if hasattr(stmt, 'data') and isinstance(stmt.data, pyvex.expr.RdTmp):
            tmp = stmt.data.tmp
            trace_data = claripy.BVS('t%d' % (tmp), self.arch_bits, explicit_name=True)
            return trace_data

    # Kai code!
    def create_sim_action(self, action_data, def_loc, var_type=None):
        all_deref_info = get_all_deref_info(action_data)
        deref_info = all_deref_info[0]

        binop, name, data = deref_info[0], deref_info[1], deref_info[2]
        new_sim_action = SimAction(name, binop, data)
        new_sim_action.def_locs.add(def_loc)
        if var_type:
            new_sim_action.var_type = var_type

        return new_sim_action

    # Kai code!
    def create_sim_actions(self, action_data, def_loc, var_type=None):
        # print("create_sim_actions: %s %s" % (action_data, def_loc))
        new_sim_actions = {}
        all_deref_info = get_all_deref_info(action_data)
        for i, deref_info in all_deref_info.items():
            binop, name, data = deref_info[0], deref_info[1], deref_info[2]
            new_sim_action = SimAction(name, binop, data)
            new_sim_action.def_locs.add(def_loc)
            if var_type:
                new_sim_action.var_type = var_type

            new_sim_actions[i] = new_sim_action

        return new_sim_actions

    def _get_vex_ls_offset(self, addr_info):
        _len = len(addr_info)
        if _len == 1:
            offset = 0
        elif _len > 1:
            offset = addr_info[1][1][1]
        # print("get offset: %s" % (offset))
        return offset

    def create_new_trace_expr(self, ast, value=None, pattern=None, data_type=None, trace_dir=None, code_location=None):
        var_expr = VarExpr(ast, value=value, pattern=pattern, data_type=data_type, trace_dir=trace_dir)
        var_expr.location = code_location
        var_expr.alias_id = code_location.__hash__()
        var_expr.source = code_location
        var_expr.initial_sims()

        trace_expr = TraceExpr(var_expr, index=code_location.stmt_idx)
        return trace_expr

    def _generate_ast_by_binop(self, opnd_info, data_size, code_location, block):
        op = opnd_info[0]
        if op in self.ignore_binops:
            ast = self.insignificant_symbol
        else:
            ast = self.calculate_binop_stmt_v2(opnd_info)

        # if op in ['+', '-']:
        #     ast = self._calculate_simple_binop_v2(opnd_info, data_size)
        # elif op in self.ignore_binops:
        #     ast = self.insignificant_symbol
        # else:
        #     ast = self.calculate_binop_stmt_v2(opnd_info)
        return ast

    def _generate_ast_by_load(self, ld_addr, data_size):
        if type(ld_addr) is tuple:
            # addr = self._calculate_simple_binop_v3(s_addr)
            addr = self.calculate_binop_stmt_v2(ld_addr)
            ast = claripy.Load(addr, data_size)
        else:
            addr = BVS(ld_addr) if type(ld_addr) is str else BVV(ld_addr)
            ast = claripy.Load(addr, data_size)
        return ast

    def _generate_ast_by_store(self, s_addr, data_size):
        if type(s_addr) is tuple:
            # addr = self._calculate_simple_binop_v3(s_addr)
            addr = self.calculate_binop_stmt_v2(s_addr)
            ast = claripy.Store(addr, data_size)
        else:
            addr = BVS(s_addr) if type(s_addr) is str else BVV(s_addr)
            ast = claripy.Store(addr, data_size)
        return ast

    def _generate_ast(self, data, data_size=None):
        if type(data) is tuple:
            data_ast = self.calculate_binop_stmt_v2(data)
        else:
            data_size = self.arch_bits if data_size is None else data_size
            data_ast = BVS(data, data_size) if type(data) is str else BVV(data, data_size)
        return data_ast

    def _generate_ast_by_tmp(self, block, tmp):
        """
        Generate the tmp's alias expr by the live_defs.
        """
        live_defs = block.live_defs

        use_info = live_defs[tmp]
        stmt_type, code_location, use_data, data_size = use_info[0], use_info[1], use_info[2], use_info[3]
        # print("psu-debug: %s %s" % (tmp, str(use_info)))

        asts = []
        if stmt_type == 'l':
            ast = self._generate_ast_by_load(use_data, data_size)
            asts.append(ast)
            # print("%s = %s" % (tmp, ast))
            block.tmp_info[tmp] = ast

        elif stmt_type == 'o':
            ast = self._generate_ast_by_binop(use_data, data_size, code_location, block)
            asts.append(ast)
            # print("%s = %s" % (tmp, ast))
            block.tmp_info[tmp] = ast

        elif stmt_type == 'w':
            ast = BVV(use_data, data_size) if type(use_data) is int else BVS(use_data, data_size)
            asts.append(ast)
            # print("%s = %s" % (tmp, ast))
            block.tmp_info[tmp] = ast

        elif stmt_type == 'i':
            pass

        new_tmps = set()
        for tmp in map(lambda ast: [sym for sym in ast.variables if 't' in sym], asts):
            new_tmps |= set(tmp)

        for t in new_tmps:
            self._generate_ast_by_tmp(block, t)

    def generate_expr_by_ud_chain(self, block, tmp, trace_dir='B'):
        """
        For the given tmp txx, generate it's ast expr in backward.
        """
        tmp_ast = BVS(tmp)
        code_location = block.live_defs[tmp][1]
        tmp_expr = self.create_new_trace_expr(tmp_ast, code_location=code_location)
        tmp_exprs = [tmp_expr]
        new_exprs = self._update_expr_by_ud_chain(block, tmp_exprs, trace_dir=trace_dir)
        # print("tmp: %s, new-exprs: %s" % (tmp_expr, new_exprs))

        return new_exprs

    def _update_expr_with_asts(self, use, u_def, code_location, trace_expr):

        new_exprs = []
        u_defs = []
        u_defs = u_def if type(u_def) is list else [u_def]
        for d in u_defs:
            re_sim_actions = {}
            if d.op == 'Load':
                sim_action = self.create_sim_action(d, code_location)
                re_sim_actions = {0: sim_action}
            new_expr = trace_expr.replace(use, d, re_sim_actions)
            new_expr.expr.location = code_location
            new_expr.index = code_location.stmt_idx
            new_exprs.append(new_expr)

        return new_exprs

    def _update_expr_by_ud_chain(self, block, trace_exprs, trace_dir='B'):
        results = []
        block_tmp_info = block.tmp_info

        for trace_expr in trace_exprs:
            new_exprs = []
            trace_sims = trace_expr.expr.sims
            uses = [u for u, sim in trace_sims.items() if 't' in u]
            if len(uses):
                use = uses[0]
                if use not in block_tmp_info:
                    self._generate_ast_by_tmp(block, use)

                use_d = block_tmp_info[use]
                if trace_dir == 'F':
                    if self._judge_reg_live_in_forward(block, use_d):
                        code_location = block.live_defs[use][1]
                        new_exprs = self._update_expr_with_asts(use, use_d, code_location, trace_expr)
                    # else:
                    new_exprs_two = self._update_forward_expr_with_register(block, use, trace_expr)
                    if len(new_exprs_two):
                        new_exprs.extend(new_exprs_two)
                else:
                    code_location = block.live_defs[use][1]
                    new_exprs = self._update_expr_with_asts(use, use_d, code_location, trace_expr)
            if len(new_exprs) == 0:
                results.append(trace_expr)
            else:
                new_exprs = self._update_expr_by_ud_chain(block, new_exprs, trace_dir)
                results.extend(new_exprs)
        return results

    def _judge_reg_live_in_forward(self, block, ast_data):
        """
        Judge the reg (rxx) in ast_data is live to block exit in forward.
        """
        reg_defs = block.reg_defs
        return not any([reg for reg in ast_data.variables if reg in reg_defs])

    def _update_forward_expr_with_register(self, block, u_tmp, trace_expr):
        new_exprs = []
        reg_defs = block.reg_defs
        alias_regs = [reg for reg, tmp in reg_defs.items() if tmp == u_tmp]
        for alias_reg in alias_regs:
            new_expr = trace_expr.replace(u_tmp, alias_reg)
            new_expr.expr.trace_dir = 'F'
            new_expr.index = len(block.irsb.statements)
            new_exprs.append(new_expr)
        return new_exprs

    def _generate_forward_exprs_update_tmp(self, block, u_tmp, code_location, trace_exprs):
        """
        Generate forward exprs by updating the tmp in trace exprs with tmp's alias.
        """
        if type(u_tmp) is not str or 't' not in u_tmp:
            return []

        new_exprs = []
        tmp_aliases = self.generate_expr_by_ud_chain(block, u_tmp, trace_dir='F')
        for trace_expr in trace_exprs:
            for tmp_alias in tmp_aliases:
                new_expr = trace_expr.replace(u_tmp, tmp_alias.expr.ast, tmp_alias.expr.sim_actions)
                new_expr.expr.trace_dir = 'F'
                new_expr.expr.location = code_location
                new_expr.index = code_location.stmt_idx
                new_exprs.append(new_expr)

        return new_exprs

    def _clear_alias_redef_exprs(self, block, forward_exprs, killed_exprs):
        """
        Remove the alias exprs which would be re-define by store.
        """
        # if len(killed_exprs):
        #     print("clear_alise_redef_exprs: %s" % (killed_exprs))
        remove_exprs1, remove_exprs2 = [], []
        for kill_expr in killed_exprs:
            bw_loc = kill_expr.expr.bw_loc
            alias_id = kill_expr.expr.alias_id
            for f_expr in forward_exprs:
                if f_expr.expr.bw_loc == bw_loc and f_expr.expr.alias_id == alias_id:
                    remove_exprs1.append(f_expr)

            for f_expr in block.forward_exprs:
                if f_expr.expr.bw_loc == bw_loc and f_expr.expr.alias_id == alias_id:
                    remove_exprs2.append(f_expr)

            for r_expr in remove_exprs1:
                try:
                    forward_exprs.remove(r_expr)
                except ValueError:
                    pass
            for r_expr in remove_exprs2:
                try:
                    block.forward_exprs.remove(r_expr)
                except ValueError:
                    pass

    def _find_constant_ptr_xref(self, stmts, index, unsolve_ptrs):
        result = []
        for stmt_idx, stmt in enumerate(stmts[index:]):
            true_idx = stmt_idx + index
            if (isinstance(stmt, pyvex.stmt.Put) and
                    isinstance(stmt.data, pyvex.expr.Const)):
                value = stmt.data.con.value
                if value in unsolve_ptrs:
                    src_data = claripy.BVV(value, self.arch_bits)
                    var = 'r%d' % (stmt.offset)
                    dst_data = claripy.BVS(var, self.arch_bits, explicit_name=True)
                    t = (true_idx, src_data, dst_data)
                    result.append(t)

            elif (isinstance(stmt, pyvex.stmt.Store) and
                    isinstance(stmt.data, pyvex.expr.Const)):
                value = stmt.data.con.value
                if value in unsolve_ptrs:
                    src_data = claripy.BVV(value, self.arch_bits)
                    if isinstance(stmt.addr, pyvex.expr.RdTmp):
                        var = 't%d' % (stmt.addr.tmp)
                        sym_addr = claripy.BVS(var, self.arch_bits, explicit_name=True)
                        dst_data = claripy.Store(sym_addr, self.arch_bits)
                    elif isinstance(stmt.addr, pyvex.expr.Const):
                        value = stmt.addr.con.value
                        value_ast = claripy.BVV(value, self.arch_bits)
                        dst_data = claripy.Store(value_ast, self.arch_bits)
                    else:
                        logger.info("The stmt %s is special, do it future!" % (stmt))
                        continue

                    t = (true_idx, src_data, dst_data)
                    result.append(t)
        return result

    def get_ptr_xref_info(self, block, ptr_info, ptr_type=None):

        collect_info = []
        code_locations = block.code_locations
        actions = block.actions

        ptr_values = [t[1] for t in ptr_info]

        for code_location in code_locations:
            action = actions[code_location]
            action_type = action.action_type
            if action_type == 'p' or action_type == 'wl' or action_type == 'wo':
                value = action.value
                if value in ptr_values:
                    trace_ast = BVS(action.dst)
                    ptr_ast = BVV(value)
                    xref_info = (code_location.stmt_idx, ptr_ast, trace_ast)
                    collect_info.append(xref_info)
                elif type(action.src) is tuple and action.src[1][0] in ptr_values:
                    trace_ast = BVS(action.dst)
                    ptr_ast = self._calculate_simple_binop_v3(action.src)
                    xref_info = (code_location.stmt_idx, ptr_ast, trace_ast)
                    collect_info.append(xref_info)

            elif action_type == 's':
                value = action.value
                if value in ptr_values:
                    addr_ast = BVS(action.dst) if type(action.dst) is str else BVV(action.dst)
                    trace_ast = claripy.Store(addr_ast, self.arch_bits)
                    ptr_ast = BVV(value)
                    xref_info = (code_location.stmt_idx, ptr_ast, trace_ast)
                    collect_info.append(xref_info)

        return collect_info

    def get_icall_ptr(self, block):
        """
        Get the indirect callsite target's tmp backward ast data in VEX
            call qword ptr [rax+10]
            NEXT: PUT(rip) = t3; Ijk_Call
        """
        trace_tmp = None
        irsb = block.irsb
        self.state.scratch.tyenv = irsb.tyenv
        self.state.scratch.temps = {}
        # irsb.pp()
        live_defs = block.live_defs
        for stmt in irsb.statements:
            if type(irsb.next) is pyvex.expr.RdTmp:
                trace_tmp = 't%d' % irsb.next.tmp

        if trace_tmp is None:
            return None, None

        use_at = live_defs[trace_tmp]
        if use_at.action_type in ['w', 'p', 'wu']:
            use_var = use_at.src_alias if type(use_at.src_alias) is str else use_at.src
            use_loc = use_at.code_location
        else:
            use_var = use_at.dst
            use_loc = CodeLocation(use_at.code_location.block_addr, use_at.code_location.stmt_idx+1)
        use_data = BVS(use_var)
        # print("Icall target: %s %s" % (use_var, use_loc))
        return use_data, use_loc

    def _get_sim_type_v1(self, opnds_info, live_defs):
        sim_types = {}
        opnds, opnds_type = opnds_info[1], opnds_info[3]
        for opnd, opnd_type in zip(opnds, opnds_type):
            if opnd_type:
                sim_types[opnd] = opnd_type

            elif opnd in live_defs:
                vtype = live_defs[opnd].var_type
                if vtype:
                    sim_types[opnd] = vtype

        return sim_types

    def _get_offset(self, binop_data, sim_types):
        """
        Get the base and offset in binop_data based on var types.
        """
        for var in binop_data.args:
            if var.op == 'xx':
                pass

    def _simplify_arm_ldrh_instruction(self, trace_expr):
        """
        Simplify the LDRH instruction in arm.
            LDRH            R2, [R3,#0x12]
            LDRH            R3, [R3,#0x14]
            <BV32 t37 << 0x10 | t33>
        """
        new_expr = trace_expr
        trace_ast = trace_expr.expr.ast
        if len(trace_ast.args) == 2 and trace_ast.op == '__or__':
            opnd0, opnd1 = trace_ast.args
            if opnd0.op == '__lshift__' and opnd1.op == 'BVS':
                new_expr = trace_expr.replace(trace_ast, opnd1, rep_type='ptr')
        return new_expr

    def set_trace_expr_constraint_in_backward(self, src, dst, backward_exprs):
        """
        In backward, set trace expr's constraint.
        """
        # print("Set-constraint (B) in %s -> %s" % (src, dst))

        if src.addr not in dst.guard:
            return

        guard = dst.guard[src.addr]
        # print(guard)
        if guard.op == '__eq__':
            return

        var0, var1 = get_guard_args(src, guard)
        if var0 is None or var1 is None:
            return

        # print(var0, var1)
        if var0[1] == 0 or var1[1] == 0:
            return

        elif var0[0] is None and var1[0] is None:
            return

        for trace_expr in backward_exprs:
            v0, v1 = var0[0], var1[0]
            c0, c1 = var0[1], var1[1]
            trace_sims = trace_expr.expr.sims

            if c1 and v0 in trace_sims:
                # print("Hello-> %s %s %s" % (trace_expr, v0, c1))
                if c1 not in trace_expr.constraints:
                    trace_expr.constraints.append(c1)

            elif c0 and v1 in trace_sims:
                if c0 not in trace_expr.constraints:
                    trace_expr.constraints.append(c0)
