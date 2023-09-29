import logging
import angr
import time

from typing import List, Dict, Tuple, Set

from utils.bin_factory import BinaryInfo, BinFactory, LoopFinder, FunctionObj

logger = logging.getLogger("DataflowSolver")
logger.setLevel("INFO")

class DataflowSolver():
    def __init__(self, proj: angr.Project,
                    bin_factory: BinFactory,
                    binary_info: BinaryInfo,
                    start_functions: List[FunctionObj] = [],
                    do_recursive_call: bool = False):
        """
        * do_recursive_call: whether add the recursive call loop's first node into the start_func
        """
        self.proj = proj
        self.bin_factory = bin_factory
        self.binary_info = binary_info
        self.start_functions = start_functions
        self.loop_finder = LoopFinder()

        # initialize the solver config
        self.do_recursive_call = do_recursive_call

        # initialize the taint info
        self.ignore_lib_functions = ['syslog']
        self.taint_source = ['BIO_read', 'recv', 'recvfrom', 'SSL_read', 'fgets', 'fread', 'read', 'BIO_gets', 'getenv'] 

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
                elif cur_func.cfg == None:
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
    
    def _pre_process_function(self, function):
        pass