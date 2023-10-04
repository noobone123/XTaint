#!/usr/bin/env python

# import pyvex

from collections import defaultdict
from .variable_expression import construct_trace_expr
from .code_location import CodeLocation
from .parse_ast import get_all_deref_info, BVS

from global_config import default_arguments

import logging
l = logging.getLogger("data_process")
l.setLevel('INFO')


process_data_type = [
    'vPtr',
    'iCall',
    'funcPtr',
    'extPtr',
    'extData',
    'iJmp',
    'Data',
]

# Lable all data sources
ALIAS_SOURCES = {}
ALIAS_INFO = {}

ALL_SOURCES = {}
ICALL_SOURCES = {}

plugin_functions = {}


# def add_sim(trace_expr, var_type=None):

#     sims = trace_expr.expr.sims
#     symbols = trace_expr.get_trace_symbols()

#     for sym in symbols:
#         sim = Sim(live=True, var_type=var_type)
#         sims[sym] = sim

# def add_sim_action(binary_parser, trace_expr, action_type=None, live=True):

#     ast = trace_expr.expr.ast

#     deref_info = get_all_deref_info(ast)

#     if len(deref_info) == 0:
#         return

#     code_location = trace_expr.expr.location
#     sim_actions = trace_expr.expr.sim_actions

#     for index, deref in deref_info.items():

#         binop, base_offset, mem_data = deref
#         trace_expr.expr.add_sim_actions(index, name=base_offset, binop=binop, def_loc=code_location, action_data=mem_data)

# def construct_trace_expr(ast, block_addr, value=None, pattern=None, data_type=None, trace_dir=None, stmt_idx=None, index=None, var_type=None, code_location=None):
#     e = VarExpr(ast, value=value, pattern=pattern, trace_dir=trace_dir, data_type=data_type, var_type=var_type)
#     code_location = CodeLocation(block_addr, stmt_idx) if  code_location is None else code_location
#     e.location = code_location
#     e.alias_id = code_location.__hash__()
#     e.source = code_location
#     e.get_trace_variable()

#     ALL_SOURCES[e.alias_id] = code_location

#     trace_expr = TraceExpr(e, index=index)

#     return trace_expr


def plugin_process_vPtr(binary_parser, data_info):

    xref_locs = {}
    for block, info in data_info.items():
        print("DEBUG: block %s has vtalbe ptr" % (block))
        results = binary_parser.get_ptr_xref_info(block, info)
        for result in results:
            stmt_idx, src_data, dst_data = result
            value_id = src_data.__hash__()
            if value_id in xref_locs:
                code_location = xref_locs[value_id]
            else:
                code_location = CodeLocation(block.addr, stmt_idx)
                xref_locs[value_id] = code_location

            vptr_expr = construct_trace_expr(dst_data,
                                             value=src_data,
                                             pattern='LBF',
                                             data_type='Vptr',
                                             trace_dir='F',
                                             var_type='ptr',
                                             index=stmt_idx,
                                             code_location=code_location)

            if vptr_expr not in block.forward_exprs:
                for var, sim in vptr_expr.expr.sims.items():
                    if sim.var_type == 'ptr':
                        vptr_expr.expr.base_ptr = var
                print("@@@--> vtable: %s" % (vptr_expr))
                block.forward_exprs.append(vptr_expr)

                if vptr_expr.expr.ast.op == 'Store':
                    new_expr = vptr_expr.make_backward_copy()
                    block.backward_exprs.append(new_expr)


def plugin_process_iCall(binary_parser, data_info):
    for block, datas in data_info.items():
        # DEBUG
        # if block.addr not in [0x596ed9]:
        #     continue

        funcea = block.func_addr
        callsite_addr = datas[0][0]

        print("DEBUG: block %s has icall ptr" % (block))
        icall_target, location = binary_parser.get_icall_ptr(block)
        # print("%x %x" % (callsite_addr, location.block_addr))
        if icall_target is not None:
            icall_expr = construct_trace_expr(icall_target,
                                              pattern='OB',
                                              data_type='Iptr',
                                              trace_dir='B',
                                              var_type='ptr',
                                              index=location.stmt_idx,
                                              code_location=location)

            for var, sim in icall_expr.expr.sims.items():
                if sim.var_type == 'ptr':
                    icall_expr.expr.base_ptr = var

            icall_expr.expr.invariant_loc = location
            print("@@@--> icall: %s" % (icall_expr))
            block.backward_exprs.append(icall_expr)
            ICALL_SOURCES[icall_expr.expr.invariant_loc] = (funcea, callsite_addr)


def plugin_process_iJmp(parser, data_info):
    """
    Process switch jmp in block.
    """
    for block, datas in data_info.items():
        # continue
        # DEBUG
        # if block.addr not in [0x21140, ]:
        #     continue

        funcea = block.func_addr
        callsite_addr = datas[0][0]
        # block.irsb.pp()

        print("DEBUG: block %s has switch ptr" % (block))
        icall_target, location = parser.get_icall_ptr(block)
        if icall_target is not None:
            icall_expr = construct_trace_expr(icall_target,
                                              pattern='OB',
                                              data_type='Iptr',
                                              trace_dir='B',
                                              var_type='ptr',
                                              index=location.stmt_idx,
                                              code_location=location)


            for var, sim in icall_expr.expr.sims.items():
                if sim.var_type == 'ptr':
                    icall_expr.expr.base_ptr = var

            print("@@@--> switch-jmp: %s" % (icall_expr))
            block.backward_exprs.append(icall_expr)
            ICALL_SOURCES[icall_expr.expr.invariant_loc] = (funcea, block.addr)


def plugin_process_funcPtr(binary_parser, data_info):

    xref_locs = {}
    for block, info in data_info.items():
        print("DEBUG: block %s has function ptr" % (block))
        # if block.addr not in [0x485524]:
        #     continue
        results = binary_parser.get_ptr_xref_info(block, info)
        for result in results:
            stmt_idx, src_data, dst_data = result
            value_id = src_data.__hash__()
            if value_id in xref_locs:
                code_location = xref_locs[value_id]
            else:
                code_location = CodeLocation(block.addr, stmt_idx)
                xref_locs[value_id] = code_location

            fptr_expr = construct_trace_expr(dst_data,
                                             value=src_data,
                                             pattern='BF',
                                             data_type='Fptr',
                                             trace_dir='F',
                                             var_type='ptr',
                                             index=stmt_idx,
                                             code_location=code_location)

            if fptr_expr not in block.forward_exprs:
                for var, sim in fptr_expr.expr.sims.items():
                    if sim.var_type == 'ptr':
                        fptr_expr.expr.base_ptr = var

                print("@@@--> func ptr: %s" % (fptr_expr))
                block.forward_exprs.append(fptr_expr)

                if fptr_expr.expr.ast.op == 'Store':
                    new_expr = fptr_expr.make_backward_copy()
                    block.backward_exprs.append(new_expr)


def plugin_process_extPtr(binary_parser, data_info):
    pass


def plugin_process_extData(binary_parser, data_info):
    pass


def plugin_process_Data(parser, data_info):

    xref_locs = {}
    for block, info in data_info.items():
        # if block.addr not in [0x442204]:
        #     continue

        print("DEBUG: block %s has data xref" % (block))
        # print("xref-info: %s" % (info))
        results = parser.get_ptr_xref_info(block, info)
        for result in results:
            stmt_idx, src_data, dst_data = result
            value_id = src_data.__hash__()
            if value_id in xref_locs:
                code_location = xref_locs[value_id]
            else:
                code_location = CodeLocation(block.addr, stmt_idx)
                xref_locs[value_id] = code_location

            dptr_expr = construct_trace_expr(dst_data,
                                             value=src_data,
                                             pattern='LBF',
                                             data_type='Vptr',
                                             trace_dir='F',
                                             var_type='ptr',
                                             index=stmt_idx,
                                             code_location=code_location)

            if dptr_expr not in block.forward_exprs:
                for var, sim in dptr_expr.expr.sims.items():
                    if sim.var_type == 'ptr':
                        dptr_expr.expr.base_ptr = var

                print("@@@--> data ptr: %s" % (dptr_expr))
                block.forward_exprs.append(dptr_expr)

                if dptr_expr.expr.ast.op == 'Store':
                    new_expr = dptr_expr.make_backward_copy()
                    block.backward_exprs.append(new_expr)


class DataParser(object):

    def __init__(self, binary_parser):

        self._binary_parser = binary_parser

        self._register_default()

    def _analyze(self):
        self._register_default()

        self.pre_process_data_info()

    def pre_process_function_data(self, function_block_info):
        for data_type, data_info in function_block_info.items():
            new_block_info = defaultdict(list)
            for ida_block, info in data_info.items():
                nodes = ida_block.contain_blocks
                if len(nodes) == 0:
                    l.info("The node %s cleanup in IDA Pro!" % (ida_block))
                    continue

                for t in info:
                    xref_addr = t[0]
                    # print("xref addr: %x" % (xref_addr))
                    irsb_block = [n for n in nodes if n.addr <= xref_addr < n.end][0]
                    new_block_info[irsb_block].append(t)

            plugin_func = self._get_plugin(data_type)
            if plugin_func is None:
                l.info("No plugin to process the data type %s!" % (data_type))
                continue

            plugin_func(self._binary_parser, new_block_info)

    def pre_process_data_info(self):
        for data_type, data_info in self._block_datas.items():
            # print("xx - %s %s" % (data_type, data_info))
            plugin_func = self._get_plugin(data_type)
            if plugin_func is None:
                l.info("No plugin to process the data type %s!" % (data_type))
                continue

            plugin_func(self._binary_parser, data_info)

    def _register_default(self):
        for proc_type in process_data_type:
            func = globals().get('plugin_process_%s' % (proc_type))
            plugin_functions[proc_type] = func

    def _get_plugin(self, name):
        func = plugin_functions.get(name)
        return func

    def inital_user_search(self, block, user_location):

        trace_data = self._binary_parser.get_user_trace_data(block, user_location)
        # print("user trace: %s" % (trace_data))

        if trace_data is None:
            return

        stmt_idx = user_location.stmt_idx
        if trace_data.op == 'Store':
            pattern = 'BF'
            trace_dir = 'B'
        else:
            pattern = 'OB'
            trace_dir = 'B'

        # print("trace_data: %s %s" % (user_location, trace_data))
        trace_expr = construct_trace_expr(trace_data, block.addr,
                                            value=None,
                                            pattern=pattern,
                                            data_type='data',
                                            trace_dir=trace_dir,
                                            stmt_idx=stmt_idx,
                                            index=stmt_idx)

        add_sim(trace_expr)
        trace_expr.expr.initialize_sim_actions(user_location)
        print("@@@--> user: %s" % (trace_expr))
        block.backward_exprs.append(trace_expr)

        if trace_data.op == 'Store':
            fw_expr = trace_expr.make_forward_copy()
            block.forward_exprs.append(fw_expr)

    def inital_alias_check_variables(self, block, alias_func):

        print("@@->inital_alias_check: %s" % (block))
        # if (block.addr not in [0x40009cc, 0x40009b9, 0x4009a6]):
        #     return

        pattern = 'BF'
        trace_dir = 'B'

        arg0 = 'r%d' % (default_arguments[0])
        # arg1 = 'r%d' % (default_arguments[1])

        # arg0_ast = BVS(arg0)
        # arg1_ast = BVS(arg1)

        data_ast = BVS(arg0)
        trace_expr = construct_trace_expr(data_ast,
                                            value=None,
                                            pattern='BF',
                                            data_type='Tdata',
                                            trace_dir='B',
                                            block_addr=block.addr,
                                            stmt_idx=0,
                                            index=0,
                                            var_type='ptr',
                                            base_ptr=arg0)

        # trace_expr1 = construct_trace_expr(arg0_ast, block.addr,
        #                                     value=None,
        #                                     pattern=pattern,
        #                                     data_type='uData',
        #                                     trace_dir=trace_dir,
        #                                     stmt_idx=0,
        #                                     index=0)

        trace_expr.expr.taint_source = block.addr
        trace_expr.expr.taint_sources.add(block.addr)
        trace_expr.expr.ptr_id = block.addr
        trace_expr.inter_funcs.append('%x' % (block.func_addr))
        block.backward_exprs.append(trace_expr)
        ALIAS_SOURCES[block.addr] = 0
        ALIAS_INFO[block.addr] = alias_func
        # trace_expr2 = construct_trace_expr(arg1_ast, block.addr,
        #                                     value=None,
        #                                     pattern=pattern,
        #                                     data_type='uData',
        #                                     trace_dir=trace_dir,
        #                                     stmt_idx=1,
        #                                     index=0)

        # add_sim(trace_expr2)
        # block.backward_exprs.append(trace_expr2)


    def inital_user_sink_arguments(self, block, arg_num):

        pattern = 'OB'
        trace_dir = 'B'

        for i in range(arg_num):
            if i < len(default_arguments):
                arg_i = 'r%d' % (default_arguments[i])
            else:
                l.info("The argument numbers more than default argument nums, should think about the stack. do it future!")
                continue

            argi_ast = BVS(arg_i)
            # print("argument: %s" % (argi_ast))
            arg_trace_expr = construct_trace_expr(argi_ast, block.addr,
                                                value=None,
                                                pattern=pattern,
                                                data_type='Iptr',
                                                trace_dir=trace_dir,
                                                stmt_idx=0,
                                                index=0)
            add_sim(arg_trace_expr)
            block.backward_exprs.append(arg_trace_expr)


def inital_source_arguments(block, describe):
    """
    Initial source function's arguments.
    """
    trace_exprs = []
    constraint_expr = None

    for arg, arg_desc in describe.items():
        # if i < len(default_arguments):
        #     arg_i = 'r%d' % (default_arguments[i])
        # else:
        #     l.info("The argument numbers more than default argument nums, should think about the stack. do it future!")
        #     continue
        argi_ast = BVS(arg)

        if arg_desc == 'dst':
            arg_trace_expr = construct_trace_expr(argi_ast,
                                                value=None,
                                                pattern='LBF',
                                                data_type='Tdata',
                                                trace_dir='B',
                                                var_type='ptr',
                                                index=0,
                                                block_addr=block.addr,
                                                stmt_idx=0)
            # add_sim(arg_trace_expr, var_type='ptr')
            arg_trace_expr.expr.flag = 0x100
            arg_trace_expr.expr.base_ptr = arg
            arg_trace_expr.expr.ptr_id = block.addr
            trace_exprs.append(arg_trace_expr)

        elif arg_desc == 'length':
            arg_trace_expr = construct_trace_expr(argi_ast,
                                                value=None,
                                                pattern='OB',
                                                data_type='Cons',
                                                trace_dir='B',
                                                var_type='int',
                                                index=0,
                                                block_addr=block.addr,
                                                stmt_idx=0)
            # add_sim(arg_trace_expr, var_type='int')
            constraint_expr = arg_trace_expr

    for trace_expr in trace_exprs:
        # if constraint_expr is not None:
        #     trace_expr.expr.constraints.append(constraint_expr)
            # print("With constraint %s" % (constraint_expr))
        block.backward_exprs.append(trace_expr)

        # block.forward_exprs.append(trace_expr)
        # bk_expr = trace_expr.make_backward_copy()
        # block.backward_exprs.append(bk_expr)
