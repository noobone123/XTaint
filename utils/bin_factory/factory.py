import os
import json
from typing import Any
import angr

from .callgraph import CallGraph
from .cfg import CFG
from .basicblock import BasicBlock
from .binaryinfo import BinaryInfo
from .function_obj import FunctionObj
from ..logger import get_logger

logger = get_logger("BinFactory")
logger.setLevel("INFO")

class BinFactory(object):
    """
    Generate CFG and CallGraph by the block and jump info extracting from 
    IDA Pro.
    """
    def __init__(self, angr_proj: angr.Project, 
                       ida_preprocess_dir,
                       binary_info: BinaryInfo,
                       base_addr = 0x0):
        
        self.angr_proj = angr_proj
        self.binary_info = binary_info
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

        self.rebase_binary()
        self.fast_build()

    def rebase_binary(self):
        """
        Rebase the PIE binary to the 0x400000
        """
        func_ea = 0
        for func_addr in self.cfg_record:
            func_ea = int(func_addr, 16)
            break
        min_addr, max_addr = self.binary_info.sections['.loader']
        if func_ea <= min_addr and min_addr & 0x400000 == 0x400000:
            logger.warning("Binary base address has been rebased to 0x400000")
            self.base_addr = 0x400000

    def fast_build(self):
        """
        Fast build CFG and CallGraph by the block and jump info extracting from IDA Pro.
        """
        func_cnt = 0

        for func in self.functions:
            # BUILD the CFG
            blocks = self.cfg_record[func]['block']
            edges = self.cfg_record[func]['control-flow']
            func_name = self.cfg_record[func]['name']

            func_ea = int(func) + self.base_addr
            func_cnt += 1

            tail_calls = set()

            # build basic blocks
            for bb in blocks:
                nodes = []
                bb_start, bb_end = bb[0] + self.base_addr, bb[1] + self.base_addr

                if bb_start == bb_end:
                    tail_calls.add(bb_start)
                    continue

                bb_obj = BasicBlock(bb_start, bb_end, func_ea)
                self.cfg.add_node(bb_obj)

                logger.debug("BasicBlock {} built".format(bb_obj))

            # build edges
            for edge in edges:
                src_addr, dst_addr = edge[0] + self.base_addr, edge[1] + self.base_addr
                if dst_addr in tail_calls:
                    continue
                
                src_bb = self.cfg.get_node(src_addr)
                dst_bb = self.cfg.get_node(dst_addr)
                
                self.cfg.add_edge(src_bb, dst_bb, kwargs = {'jumpkind': 'Boring'})

                logger.debug("CFG Edges: {} -> {}".format(src_bb, dst_bb))


            # BUILD the CallGraph
            calls = self.cfg_record[func]['call']
            if func_ea not in self.cg._nodes:
                caller_obj = FunctionObj(
                    func_ea,
                    procedural_name = func_name,
                )
                self.cg.add_node(caller_obj)
                pass
            else:
                caller_obj = self.cg.get_node(func_ea)
                if caller_obj.procedural_name == None:
                    caller_obj.procedural_name = func_name
            
            for call_info in calls:
                bb_start, callsite, target = call_info
                bb_start = bb_start + self.base_addr
                callsite = callsite + self.base_addr
                # if callee is an internal function, target is the function address
                # if callee if an external function, target is the function name
                if type(target) == int:
                    target = target + self.base_addr
                
                src_bb = self.cfg.get_node(bb_start)
                if src_bb is None:
                    logger.error("Cannot find src_bb {} when building callgraph".format(hex(bb_start)))
                src_bb.callsites[callsite] = target

                # if target is an internal function
                if type(target) == int:
                    if target in self.cg._nodes:
                        callee_obj = self.cg.get_node(target)
                    else:
                        callee_obj = FunctionObj(target)
                        self.cg.add_node(callee_obj)
                # if target is an external function
                else:
                    callee_name = target
                    callee_name_hash = hash(callee_name)
                    if callee_name_hash not in self.cg._nodes:
                        callee_obj = FunctionObj(0, procedural_name = callee_name)
                        self.cg.add_node(callee_obj, type = "external", hash = callee_name_hash)
                    else:
                        callee_obj = self.cg.get_node(callee_name_hash)
                
                kwargs = {'jumpkind': 'Call'}
                self.cg.add_edge(caller_obj, callee_obj, **kwargs)

                # update caller_obj's callee info (exclude external functions)
                if callee_obj.addr:
                    if callee_obj.addr not in caller_obj.callees:
                        caller_obj.callees[callee_obj.addr] = 0
                    caller_obj.callees[callee_obj.addr] += 1
                
                logger.debug("CallGraph: {} -> {}".format(caller_obj, callee_obj))
        
        logger.info("Function CFG and CG built successfully.")