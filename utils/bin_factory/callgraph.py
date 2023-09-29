import logging
import networkx

from .graph_base import GraphBase
from .function_obj import FunctionObj
from .loop_finder import Loop

logger = logging.getLogger("CallGraph")
logger.setLevel("INFO")

class CallGraph(GraphBase):
    """
    A class for CallGraph.
    """
    def __init__(self):
        super(CallGraph, self).__init__()

        self._nodes = {}
        self.loops = []

        self._initialize_graph()

    def add_node(self, node, type: str = None, hash = None):
        """
        Add a node to the graph.

        * type: is an external function or an internal function.
        """
        if type == 'external':
            if hash not in self._nodes:
                self._nodes[hash] = node
                self.graph.add_node(node)
        else:
            if node.addr not in self._nodes:
                self._nodes[node.addr] = node
                self.graph.add_node(node)

    def get_node(self, addr) -> FunctionObj:
        """
        get a function node by addr
        """
        if addr in self._nodes:
            return self._nodes[addr]
        
    def add_edge(self, src, dst, **kwargs):
        """
        Add an edge to the graph.
        """
        self.graph.add_edge(src, dst, **kwargs)

    def find_start_nodes(self):
        """
        Get the start function node. (`main` function or function with no in degree)
        """
        start_nodes = set()
        # TODO: exclude start nodes ptr in .init_array and .fini_array
        excluded_nodes_name = ['.init', '_start']

        # TODO: this heuristic is not good, need to improve
        # because I found CFG generated from ida is not good
        for n in self.graph.nodes():
            if n.procedural_name == 'main' or (n.addr > 0 and self.graph.in_degree(n) == 0):
                if n.procedural_name not in excluded_nodes_name:
                    logger.info("Found start function node: {}".format(n))
                    start_nodes.add(n.procedural_name)

        if len(start_nodes) == 0:
            all_nodes = list(self.graph.nodes())
            if len(all_nodes):
                start_nodes.add(n.procedural_name)

        return start_nodes

    def get_all_nodes_by_root(self, root):
        """
        Get all nodes in the tree which root nood is given.
        """
        all_nodes = []
        traversed_nodes = set()

        all_nodes.append(root)
        traversed_nodes.add(root)

        stack = [root]
        while stack:
            node = stack.pop()
            succ_nodes = self.graph.successors(node)
            for succ_n in succ_nodes:
                if succ_n.addr and succ_n not in traversed_nodes:
                    all_nodes.append(succ_n)
                    traversed_nodes.add(succ_n)
                    stack.append(succ_n)

        return all_nodes


    def get_all_callsites_to_function(self, function):
        """
        Get all callsite which call the given function.
        """
        callsites = []
        funcea = function.addr
        pre_functions = self.graph.predecessors(function)

        for pre_function in pre_functions:
            caller_sites = pre_function.callees.get(funcea)
            if caller_sites is None:
                logger.info("The function %s didn't call function %s, check it future!" % (pre_function, function))
                continue

            for cs in caller_sites:
                callsites.append(cs)

        return callsites

    def travel_call_graph(self, node, worklist):
        changed = False
        worklist_set = set()
        stack = [node]
        worklist.append(node)
        worklist_set.add(node.addr)

        while stack:
            node = stack.pop()
            successor_nodes = self.graph.successors(node)
            caller_addr = node.addr
            for suc_node in successor_nodes:
                called_addr = suc_node.addr

                if suc_node.addr not in worklist_set \
                        and suc_node.addr not in self.analyses_done_set:
                    stack.append(suc_node)
                    worklist.append(suc_node)
                    worklist_set.add(suc_node.addr)
                    changed = True
        return changed

    def worklist_update(self, node, worklist):
        changed = False
        for n in self.graph.successors(node):
            if n.addr not in self.analyses_done_set:
                self.travel_call_graph(n, worklist)
                changed = True
        return changed

    def determine_node_in_loop(self, node):
        """
        If a node in a cycle, then return the cycle
        :param node: a node in the function cfg
        :return loop
        """
        for loop in self.loops:
            if node in loop.body_nodes:
                return loop
        return None

    def _get_loop_callees(self, loop):
        loop_callees = set()

        for node in loop.body_nodes:

            succ_nodes = self.graph.successors(node)
            for succ_node in succ_nodes:
                loop_callees.add(succ_node)
                # print("loop %s call %s" % (node, succ_node))

        return loop_callees

    def get_pre_sequence_call_graph(self, start_node, tree_nodes, pre_sequence_nodes):
        """
        Get the pre sequences nodes in a call graph by root node start_node.
        """
        def _should_add_loop(loop, tree_nodes, pre_sequence_nodes):
            for s_node in loop.start_nodes:
                in_nodes = self.graph.predecessors(s_node)
                for in_node in in_nodes:
                    if (in_node not in pre_sequence_nodes and
                            in_node not in loop.body_nodes and
                            in_node in tree_nodes):
                        return False
            return True

        pre_sequence_nodes.append(start_node)
        traversed_nodes = set()
        traversed_nodes.add(start_node)

        debug_set = set()

        analyzed_loops = []
        worklist = [start_node]
        while worklist:
            block = worklist.pop()

            # DEBUG
            succ_blocks = self.graph.successors(block)
            # print("\n%s has succs %s" % (block, list(succ_blocks)))

            succ_blocks = self.graph.successors(block)

            for succ_block in succ_blocks:
                if succ_block.addr == 0:
                    continue

                # print("debug succ block: %s, is loop: %s" % (succ_block, succ_block.is_loop))
                if succ_block.is_loop:
                    loop = self.determine_node_in_loop(succ_block)
                    # print("loop %s" % (loop))
                    if loop in analyzed_loops:
                        continue

                    choosed = _should_add_loop(loop, tree_nodes, pre_sequence_nodes)
                    # print("choosed: %s" % (choosed))
                    if choosed:
                        analyzed_loops.append(loop)

                        for n in loop.start_nodes:
                            if n not in traversed_nodes:
                                pre_sequence_nodes.append(n)
                                traversed_nodes.add(n)
                                # print("loop add %s" % (n))

                        for n in loop.end_nodes:
                            if n not in traversed_nodes:
                                pre_sequence_nodes.append(n)
                                traversed_nodes.add(n)
                                # print("loop add %s" % (n))

                        # worklist.extend(loop.end_nodes)

                        loop_callees = self._get_loop_callees(loop)
                        for callee_node in loop_callees:
                            if callee_node.addr == 0:
                                continue

                            pre_nodes = list(self.graph.predecessors(callee_node))

                            choosed = True
                            if len(pre_nodes) >= 2:
                                for pre_n in pre_nodes:
                                    if (pre_n.addr and
                                            not pre_n.is_loop and
                                            pre_n in tree_nodes and
                                            pre_n not in pre_sequence_nodes):

                                        choosed = False
                                        break

                            if choosed and callee_node not in traversed_nodes:
                                pre_sequence_nodes.append(callee_node)
                                worklist.append(callee_node)
                                traversed_nodes.add(callee_node)

                else:
                    choosed = True
                    in_edges = self.graph.in_edges(succ_block)
                    if len(in_edges) >= 2:
                        for pre_block, _ in in_edges:
                            # print("Deubug: %s has pre-block %s" % (succ_block, pre_block))
                            if pre_block.addr == 0 or pre_block.addr == block.addr:
                                continue

                            if pre_block not in pre_sequence_nodes and pre_block in tree_nodes:
                                choosed = False
                                debug_set.add(succ_block)
                                break
                                # print("%s has pre %s" % (succ_block, pre_block))

                    if choosed and succ_block not in traversed_nodes:
                        pre_sequence_nodes.append(succ_block)
                        worklist.append(succ_block)
                        traversed_nodes.add(succ_block)
                        # print("add %s" % (succ_block))

        # for n in debug_set:
        #     if n not in pre_sequence_nodes:
        #         print("not add %s" % (n))

    def push_global_info(self, function):
        """
        Push function's global addrs info to all caller function.
        """
        if function.special_flag & 0x2:
            return

        succ_flag = True
        for succ_function in self.graph.successors(function):
            if succ_function.special_flag & 0x2 == 0:
                succ_flag = False

        if succ_flag:
            function.special_flag |= 0x2

        if function.special_flag & 0x2:
            for pre_function in self.graph.predecessors(function):
                pre_function.global_addrs |= function.global_addrs

        elif function.is_loop and function.special_flag & 0x2 == 0:
            all_global_addrs = set()
            loop = self.determine_node_in_loop(function)
            choose_loop = True
            for end_node in loop.end_nodes:
                if end_node.special_flag & 0x2 == 0:
                    choose_loop = False
            if loop is not None and choose_loop:
                for loop_func in loop.body_nodes:
                    all_global_addrs |= loop_func.global_addrs
                    loop_func.special_flag |= 0x2

                for loop_func in loop.body_nodes:
                    loop_func.global_addrs |= all_global_addrs

                for start_node in loop.start_nodes:
                    start_node.global_addrs |= loop.body_nodes[0].global_addrs
