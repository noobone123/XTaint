import logging
import angr
import time

from typing import List, Dict, Tuple, Set

from utils.bin_factory import BinaryInfo, BinFactory, LoopFinder, FunctionObj
from dataflow.model import DataFlowCFG, CFGBase, DataflowBlock
from dataflow.core import FastDataFlow, AccurateDataFlow, CodeLocation, Action, EngineVEX
from dataflow.procedures import SIM_PROCEDURES

logger = logging.getLogger("DataflowSolver")
logger.setLevel("INFO")

class DataflowSolver():
    def __init__(self, proj: angr.Project,
                    bin_factory: BinFactory,
                    binary_info: BinaryInfo,
                    start_functions: List[FunctionObj] = [],
                    fast_dataflow: FastDataFlow = None,
                    accurate_dataflow: AccurateDataFlow = None,
                    do_recursive_call: bool = False):
        """
        * do_recursive_call: whether add the recursive call loop's first node into the start_func
        """
        self.proj = proj
        self.bin_factory = bin_factory
        self.binary_info = binary_info
        self.start_functions = start_functions

        self._fast_dataflow = fast_dataflow
        self._accurate_dataflow = accurate_dataflow

        self.loop_finder = LoopFinder()

        # initialize the solver config
        self.do_recursive_call = do_recursive_call

        # initialize the taint info
        self.ignore_lib_functions = ['syslog']
        self.taint_source = ['BIO_read', 'recv', 'recvfrom', 'SSL_read', 'fgets', 'fread', 'read', 'BIO_gets', 'getenv'] 

        # initialze the arch info
        self.sp_name = self.binary_info.sp_name
        self.bp_name = self.binary_info.bp_name
        self.ret_name = self.binary_info.ret_name
        self.arch_bits = self.binary_info.arch_bits
        self._call_graph = self.bin_factory.cg

        self._sim_procedures = {}
        self._initial_lib_procedures()

    def _initial_lib_procedures(self):
        for lib, procs in SIM_PROCEDURES.items():
            for name, proc in procs.items():
                self._sim_procedures[name] = proc()

    def solve(self):
        """
        Solve the dataflow of the binary.
        """
        logger.info("Start to solve the dataflow of the binary...")
        time_start = time.time()
        self._initial_lib_procedure()
        self._solve()
        time_end = time.time()
        logger.info("Solve the dataflow of the binary done, time cost: {}s".format(time_end - time_start))

    
    def _solve(self):
        """
        Solve the dataflow of the binary.
        """
        # get the start function
        if not self.start_functions:
            self.start_functions = self.bin_factory.cg.find_start_nodes()
        else:
            logger.info("Start function: {}".format(self.start_functions))

        # add the recursive call loop's first node into the start_func (if needed)
        if self.do_recursive_call:
            # get loops in the binary
            self.loop_finder.get_loops_from_call_graph(self.bin_factory.cg)
            for call_loop in self.bin_factory.cg.loops:
                if len(call_loop.start_nodes) == 0:
                    self.start_functions.add(call_loop.first_node)


        analyzed_function = set()

        for func in self.start_functions:
            logger.info("Solving function {} at 0x{:x}".format(func.procedural_name, func.addr))

            # initialize the worklist, add all the successors of the functions into the worklist
            # using wide-first search, first add all the 1-hop successors, then 2-hop, 3-hop, ...
            # IMPORTANT: worklist's update algorithm ...
            worklist: List[FunctionObj] = []
            tree_nodes = self.bin_factory.cg.get_all_nodes_by_root(func)
            self.bin_factory.cg.get_pre_sequence_call_graph(func, tree_nodes, worklist)

            # consume the worklist
            for i in range(len(worklist) - 1, -1, -1):
                cur_func = worklist[i]
                logger.info("Analyzing function {} at 0x{:x}".format(cur_func.procedural_name, cur_func.addr))

                if cur_func.addr in analyzed_function:
                    continue
                
                # IMPORTANT: how to judge whether the function has taint sources?
                has_taint_sources = self._has_taint_sources(cur_func)

                # get function's block info
                function_block_info = self.bin_factory.blocks_info.get(cur_func.addr, None)
                if function_block_info:
                    logger.info(f"Block info found in function {cur_func.procedural_name}")

                if has_taint_sources:
                    logger.info("Taint sources found in function {} at 0x{:x}".format(cur_func.procedural_name, cur_func.addr))
                    self._pre_process_function(cur_func)

                # IMPORTANT: On Demand Analysis, if function has no taint sources, then skip it
                elif cur_func.dataflow_cfg == None:
                    logger.warning("CFG not found in function {} at 0x{:x}".format(cur_func.procedural_name, cur_func.addr))
                    continue


    def _initial_lib_procedure(self):
        """
        Initial the library procedure.
        """
        pass

    def _has_taint_sources(self, function):
        """
        Check whether the function has taint sources.
        """
        succ_functions = self.bin_factory.cg.graph.successors(function)
        # print(succ_functions)
        for succ_func in succ_functions:
            callee_name = succ_func.procedural_name
            # print("Find-source: %s" % (lib_name))
            if callee_name and (callee_name in self.taint_source):
                return True
        return False
    
    def _pre_process_function(self, function: FunctionObj):
        """
        Not all functions need to run dataflow analysis, for functions 
        that needs to run dataflow analysis, we need to pre-process them.
        """        
        if function.preprocessed == True:
            logger.info("Function {} at 0x{:x} has been pre-processed".format(function.procedural_name, function.addr))
            return
        else:
            logger.info("Pre-processing function {} at 0x{:x}".format(function.procedural_name, function.addr))

        func_ea = function.addr
        
        start_blocks = self.bin_factory.func_cfg[func_ea].find_function_start_ida_block(func_ea, self.bin_factory.base_addr)

        if len(start_blocks) == 0:
            logger.warning("No start block found in function {} at 0x{:x}".format(function.procedural_name, function.addr))
            return
        
        # IMPORTANT: generate dataflow cfg, maybe we need to combine dataflow cfg and binary factory cfg
        dataflow_cfg = DataFlowCFG(func_ea, self.bin_factory, self.proj)
        dataflow_cfg.generate_function_cfg(function, start_blocks)

        function.dataflow_cfg = dataflow_cfg
        function.start_node = dataflow_cfg._nodes[func_ea]

        self.loop_finder.get_loops_from_dataflowCFG(function)

        if len(function.dataflow_cfg.pre_sequence_nodes) == 0:
            pre_sequence_nodes = self._get_pre_sequence_in_function(function)
            function.dataflow_cfg.pre_sequence_nodes = pre_sequence_nodes
            self._pre_process_function_vex(function)

        # dataflow_cfg.print_cfg_edges()
        # dataflow_cfg.print_cfg()


    def _get_pre_sequence_in_function(self, function: FunctionObj):
        """
        flatten the function's dataflow bb into a sequence.
        """
        pre_sequence_nodes = []

        def _should_add_loop(cfg, loop, pre_sequence_nodes):
            # print("add_loop %s" % (pre_sequence_nodes))
            for s_node in loop.start_nodes:
                in_nodes = cfg.graph.predecessors(s_node)
                # print(in_nodes)
                for in_node in in_nodes:
                    if in_node not in pre_sequence_nodes and in_node not in loop.body_nodes:
                        return False
            return True

        cfg = function.dataflow_cfg
        start_node = function.start_node
        pre_sequence_nodes.append(start_node)
        traversed_nodes = set()
        traversed_nodes.add(start_node)

        analyzed_loops = []
        worklist = [start_node]
        while worklist:
            block = worklist.pop()
            succ_blocks = cfg.graph.successors(block)
            for succ_block in succ_blocks:
                # print("psu-debug: %s has succ %s %s" % (block, succ_block, succ_block.is_loop))
                if succ_block.is_loop:
                    loop = function.determine_node_in_loop(succ_block)
                    if loop in analyzed_loops:
                        continue

                    # print("psu-debug: analyze loop %s" % (loop))
                    # analyzed_loops.append(loop)
                    choosed = _should_add_loop(cfg, loop, pre_sequence_nodes)
                    # print("loop %s %s, choosed %s" % (succ_block, loop, choosed))
                    if choosed:
                        analyzed_loops.append(loop)
                        for n in loop.start_nodes:
                            if n not in traversed_nodes:
                                pre_sequence_nodes.append(n)
                                traversed_nodes.add(n)
                        for n in loop.end_nodes:
                            if n not in traversed_nodes:
                                pre_sequence_nodes.append(n)
                                traversed_nodes.add(n)
                        # pre_sequence_nodes.extend(loop.start_nodes)
                        # pre_sequence_nodes.extend(loop.end_nodes)
                        worklist.extend(loop.end_nodes)

                else:
                    choosed = True
                    # pre_blocks = cfg.graph.predecessors(succ_block)
                    in_edges = cfg.graph.in_edges(succ_block)
                    if len(in_edges) >= 2:
                        for pre_block, _ in in_edges:
                            if pre_block not in pre_sequence_nodes:
                                choosed = False
                                break
                    if choosed:
                        # if succ_block.addr == 0x2bc5db:
                        #     print("add succ node %s" % (succ_block))
                        #     print("block %s, pre blocks %s" % (block, pre_blocks))
                        if succ_block not in traversed_nodes:
                            pre_sequence_nodes.append(succ_block)
                            worklist.append(succ_block)
                            # print("node %s has in sequence" % (succ_block))
                            traversed_nodes.add(succ_block)

        # print("Function: %s get sequences:\n %s" % (function, pre_sequence_nodes))
        return pre_sequence_nodes
    

    def _pre_process_function_vex(self, function: FunctionObj):

        function_reg_defs = {}
        function_stack_defs = {}
        analyzed_blocks = set()
        analyzed_loops = set()
        pre_sequence_nodes = function.dataflow_cfg.pre_sequence_nodes
        arguments = function.arguments

        # IMPORTANT: initialize the function register and stack definitions
        self._initial_stack_in_function_start(function)

        # iterating ...
        for block in pre_sequence_nodes:

            # if block already analyzed, then skip it
            if block in analyzed_blocks:
                continue
            
            # if block is not a loop
            if not block.is_loop:
                analyzed_blocks.add(block)

                # only callee dummy node dost not have irsb
                if block.irsb:
                    self._accurate_dataflow.execute_block_irsb(function, block, arguments)  # IMPORTANT: what did this function do

                else:
                    if block.node_type in ['Call', 'iCall', 'Extern']:
                        self._execute_callsite_node(function, block)
                        # self._execute_libc_callee_to_infer_type(function, block)

            #     backward_trace_variable_type(function, block)
            #     # function.sort_arguments()
            #     # self._transfer_live_definitions(block, function)
            #     self._accurate_dataflow.transfer_live_definitions(block)

            # # if block is in a loop
            # else:
            #     loop = function.determine_node_in_loop(block)
            #     for block in loop.body_nodes:
            #         if block in analyzed_blocks:
            #             continue

            #         analyzed_blocks.add(block)
            #         if block.irsb:
            #             self._accurate_dataflow.execute_block_irsb(function, block, function_reg_defs, function_stack_defs, arguments)

            #         else:
            #             if block.node_type in ['Call', 'iCall', 'Extern']:
            #                 self._execute_callsite_node(function, block)
            #                 # self._execute_libc_callee_to_infer_type(function, block)

            #         backward_trace_variable_type(function, block)
            #         # function.sort_arguments()
            #         # self._transfer_live_definitions(block, function)
            #         self._accurate_dataflow.transfer_live_definitions(block)

            #     if loop not in analyzed_loops:
            #         # print("Fast-analyze-loop: %s" % (loop))
            #         analyzed_loops.add(loop)
            #         ddg_graph = self._fast_dataflow.execute_loop(loop)
            #         self._fast_dataflow.label_loop_variables(function, ddg_graph)

        function.correct_arguments()

        # for block in function.cfg.graph.nodes():
        #     print("vex-text: %s" % (block))
        #     for var, at in block.live_defs.items():
        #         print("%s  %s" % (var, at))


    def _initial_stack_in_function_start(self, function: FunctionObj):
        """
        Initalize the function's stack and register when the function starts.
        """
        stack_reg = self._accurate_dataflow.sp_name
        arch_bits = self._accurate_dataflow.arch_bits
        start_block = function.start_node

        # IMPORTANT: what is CodeLocation and Action?
        loc = CodeLocation(start_block.addr, 0)
        initial_action = Action('w', loc, stack_reg, stack_reg, arch_bits)
        initial_action.value = 0x7fffffff
        initial_action.src_type = 'S'
        initial_action.var_type = 'ptr'

        # IMPORTANT: what is live_defs? 
        start_block.live_defs[stack_reg] = initial_action

        if self.proj.arch.name in ['MIPS64', 'MIPS32']:
            reg_offset = self.proj.arch.registers['t9'][0]
            value = function.addr
            self._initial_reg_value(start_block, reg_offset, value, 'ptr', 'G')


    def _initial_reg_value(self, block, reg_offset, value, var_type, src_type):
        """
        Initial register value for mips. because mips does not have bp?
        """
        reg_name = 'r%d' % (reg_offset)
        loc = CodeLocation(block.addr, 0)
        initial_action = Action('w', loc, reg_name, reg_name, self.arch_bits)
        initial_action.value = value
        initial_action.src_type = src_type
        initial_action.var_type = var_type
        block.live_defs[reg_name] = initial_action

    def _execute_callsite_node(self, function, callsite):
        """
        Process libc function and infer the arguments and ret type.
        """
        # if external lib functions
        if type(callsite.target) is str:
            lib_func_name = callsite.target
            if lib_func_name in self._sim_procedures:
                proc = self._sim_procedures[lib_func_name]
                proc.execute(callsite, self.proj, "infer_type", caller_function=function)

            else:
                at = Action('p', CodeLocation(callsite.addr, 0), self.ret_name, 'RET', self.arch_bits)
                callsite.live_defs[self.ret_name] = at

        else:
            funcea = callsite.target
            callee_function = self._call_graph._nodes.get(funcea)
            function_name = callee_function.procedural_name if callee_function else None
            if function_name in self._sim_procedures:
                proc = self._sim_procedures[function_name]
                proc.execute(callsite, self.proj, "infer_type", caller_function=function)

            else:
                at = Action('p', CodeLocation(callsite.addr, 0), self.ret_name, 'RET', self.arch_bits)
                callsite.live_defs[self.ret_name] = at