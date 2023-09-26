import os
import json
import angr

from .callgraph import CallGraph
from .cfg import CFG
from .basicblock import BasicBlock

class BinFactory(object):
    """
    Generate CFG and CallGraph by the block and jump info extracting from 
    IDA Pro.
    """
    def __init__(self, angr_proj, 
                       ida_preprocess_dir,
                       base_addr = 0x0):
        
        self.angr_proj = angr_proj
        self.base_addr = base_addr

        callinfo_path = os.path.join(ida_preprocess_dir, 'callinfo.json')
        cfg_path = os.path.join(ida_preprocess_dir, 'cfg.json')
        switch_path = os.path.join(ida_preprocess_dir, 'switch.json')

        self.cfg_record = json.load(open(cfg_path, 'r'))
        self.callinfo_record = json.load(open(callinfo_path, 'r'))

        # in some cases, `self.functions` is not same as `self.cfg_record`
        self.functions = self.cfg_record

        # build the Factory!
        self._build()


    def _build(self):
        # initialize CFG and CallGraph
        self.cg = CallGraph()
        self.cfg = CFG()

        self.fast_build()


    def fast_build(self):
        """
        Fast build CFG and CallGraph by the block and jump info extracting from IDA Pro.
        """
        func_cnt = 0

        for func in self.functions:
            blocks = self.cfg_record[func]['block']
            edges = self.cfg_record[func]['control-flow']
            func_name = self.cfg_record[func]['name']

            func_ea = int(func, 16) + self.base_addr
            func_cnt += 1

            tail_calls = set()

            # build basic blocks
            for bb in blocks:
                nodes = []
                bb_start, bb_end = bb

                if bb_start == bb_end:
                    tail_calls.add(bb_start)
                    continue

                bb_obj = BasicBlock(bb_start, bb_end, func_ea)
                self.cfg.add_node(bb_obj)

            # build edges
            for edge in edges:
                src_addr, dst_addr = edge
                if dst_addr in tail_calls:
                    continue
                
                src_bb = self.cfg.get_node(src_addr)
                dst_bb = self.cfg.get_node(dst_addr)
                
                self.cfg.add_edge(src_bb, dst_bb, kwargs = {'jumpkind': 'Boring'})