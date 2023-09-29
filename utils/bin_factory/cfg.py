import json
import logging

from collections import defaultdict
from .graph_base import GraphBase
from .callgraph import CallGraph
from .basicblock import BasicBlock


class CFG(GraphBase):
    """
    Generate a complete control flow graph (CFG) for the analyzed binary.
    """
    def __init__(self):

        super(CFG, self).__init__()

        self.addr_bb_map = {}

        self._initialize_graph()

    def add_node(self, bb):
        """
        Add a node to the CFG
        """
        if bb not in self.graph.nodes():
            self.graph.add_node(bb)
            self.addr_bb_map[bb.addr] = bb

    def get_node(self, addr) -> BasicBlock:
        """
        Get the node by the address
        """
        return self.addr_bb_map.get(addr)
    
    def add_edge(self, src, dst, kwargs):
        """
        Add an edge to the CFG
        """
        self.graph.add_edge(src, dst, **kwargs)

    def print_cfg_graph(self):
        for node in self.graph.nodes():
            print("CFG: %s" % (node))

    def find_function_start_ida_block(self, funcea, base_addr):
        """
        Get start ida blocks from the ida cfg.
        """
        start_blocks = []
        ida_funcea = funcea - base_addr
        s_block = self.addr_bb_map.get(ida_funcea)
        if s_block is None:
            return start_blocks

        start_blocks.append(s_block)

        # Resolve the switch jump, the start node has not in-edge.
        for node in self.graph.nodes():
            if node.funcea == funcea and self.graph.in_degree(node) == 0 and node.addr + base_addr != funcea:
                start_blocks.append(node)

        return start_blocks