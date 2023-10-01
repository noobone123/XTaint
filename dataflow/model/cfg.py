#!/usr/bin/env python
import angr
import json
from collections import defaultdict
from .cfg_node import DataflowBlock
from .cfg_base import CFGBase

from utils.bin_factory import CFG, CallGraph, BinFactory

import logging
logger = logging.getLogger("Dataflow_CFG")
logger.setLevel('INFO')


class DataFlowCFG(CFGBase):
    def __init__(self, addr, 
                bin_factory: BinFactory, 
                project: angr.Project):

        super(DataFlowCFG, self).__init__()

        self.addr = addr
        self.bin_factory = bin_factory
        self.proj = project

        self._nodes = {}
        self.callsites = {}
        self.pre_sequence_nodes = []
        self.callees = defaultdict(list)
        self.exit_blocks = set()

        self._initialize_graph()


    def get_node_by_addr(self, addr):
        return self._nodes[addr]

    def generate_function_cfg(self, function, start_ida_blocks):
        """
        :param function: the analyzed function
        :return graph: a cfg graph of the function
        """
        logger.info(f"Generating Dataflow CFG for function {function.procedural_name} at {hex(function.addr)}")
        resolved_icalls = {}
        funcea = function.addr
        func_cfg = self.bin_factory.func_cfg[funcea]
        arch_flag = False
        if 'MIPS' in self.proj.arch.name:
            arch_flag = True

        traversed_ida_blocks = set()
        for s_block in start_ida_blocks:
            traversed_ida_blocks.add(s_block)

        stack = start_ida_blocks[:]

        while stack:
            ida_block = stack.pop()

            self._translate_build_irsb(ida_block, funcea)

            jumpkind, exit_node = self._update_irsb_to_cfg(ida_block)

            # almost impossible
            if exit_node is None:
                logger.warning("Exit node is None!")
                continue

            self.graph.add_node(exit_node)
            logger.debug(f"Added node {exit_node} to Dataflow_CFG")

            # out edges of the current ida basic block
            out_edges = func_cfg.graph.out_edges(ida_block)

            jmp_block = None
            if arch_flag and len(out_edges) == 2:
                jmp_block, jmp_target = self._check_jump_block(exit_node)
                # print("Get- %s %s" % (jmp_block, jmp_target))

            # Current ida bb is the exit node of the function
            if len(out_edges) == 0:
                self.graph.add_node(exit_node)
                # if the exit node is a call node, we add a dummy node after it.
                # TODO: I think each function should have an entry node and an exit node.
                if exit_node.node_type in ['Call', 'iCall', 'Extern']:
                    dummy_exit_node = DataflowBlock(exit_node.addr + 1, self, func_addr = self.addr, node_type='Boring')
                    self._nodes[dummy_exit_node.addr] = dummy_exit_node
                    self.exit_blocks.add(dummy_exit_node)
                    kwargs = {'jumpkind': 'Ret'}
                    self.graph.add_edge(exit_node, dummy_exit_node, **kwargs)
                else:
                    self.exit_blocks.add(exit_node)
            
            # Current ida bb has a out edge into next ida bb
            elif len(out_edges) == 1:
                if exit_node.irsb and exit_node.irsb.jumpkind == 'Ijk_Ret':
                    self.exit_blocks.add(exit_node)

            # tail call of all the bb in the function, just continue, no more add
            if jumpkind == 'call' and len(out_edges) == 0:
                continue

            else:
                for _, succ_ida_block in out_edges:
                    # print("%s has succ ida block: %s" % (ida_block, succ_ida_block))
                    self._translate_build_irsb(succ_ida_block, funcea)

                    if succ_ida_block not in traversed_ida_blocks:
                        stack.append(succ_ida_block)
                        traversed_ida_blocks.add(succ_ida_block)

                if arch_flag and jmp_block:
                    self._process_special_node(exit_node, jmp_block, jmp_target, out_edges, jumpkind)

                else:
                    # add edge from cur_bb's exit irsb into next bb's start irsb
                    for _, succ_ida_block in out_edges:
                        # print(succ_ida_block)
                        if len(succ_ida_block.contain_blocks) == 0:
                            continue
                        start_node = succ_ida_block.contain_blocks[0]

                        if jumpkind == 'call':
                            kwargs = {'jumpkind': 'Ret'}
                            exit_node.jumpkind = 'Ret'
                            self.graph.add_edge(exit_node, start_node, **kwargs)
                            # print("Add-edge-4: %s -> %s" % (exit_node, start_node))

                        elif jumpkind == 'jmp':
                            kwargs = {'jumpkind': 'Boring'}
                            exit_node.jumpkind = 'Boring'
                            self.graph.add_edge(exit_node, start_node, **kwargs)
                            # print("Add-edge-5: %s -> %s" % (exit_node, start_node))

        if len(resolved_icalls):
            self._add_icall_target_node(resolved_icalls)
            # print("Found resolved icalls: %s" % (resolved_icalls))

    def _block_slicing(self, block_start, block_end):
        irsbs = []
        block_size = block_end - block_start
        if block_size == 0:
            return [self.state.block(block_start).vex]

        irsb_size = 0
        slicing_addr = block_start
        slicing_size = block_size

        while irsb_size < block_size:
            if slicing_size > 5000:
                slicing_size = 5000

            try:
                # IMPORTANT: Get the VEX bb from the slicing_addr.
                # I found that a irsb may have multiple instructions, so angr's irsb is different from ida's bb.
                # An ida's bb may have mulitple irsb.
                # size is the maximum size of the angr's irsb
                irsb = self.proj.factory.block(slicing_addr, size = slicing_size).vex

                if irsb.instructions == 0 and 'MIPS' in self.proj.arch.name:
                    slicing_size += 4
                    irsb = self.proj.factory.block(slicing_addr, size = slicing_size).vex

                if irsb.jumpkind == 'Ijk_NoDecode':
                    raise Exception("No decode!")

                irsbs.append(irsb)
                irsb_size += irsb.size
                slicing_addr = block_start + irsb_size
                slicing_size = block_size - irsb_size

            except:
                logger.info("We couldn't translate addr %x to vex!" % (slicing_addr))
                break
        
        return irsbs

    def _translate_build_irsb(self, ida_block, funcea):
        """
        Translate a block built from ida analyze result to one or more irsb block.
        what is IRSB, see
        https://docs.angr.io/en/latest/advanced-topics/ir.html
        """
        if ida_block.contain_blocks:
            return

        base_addr = self.bin_factory.base_addr
        bb_start, bb_end = ida_block.addr, ida_block.bb_end
        irsbs = self._block_slicing(bb_start, bb_end)

        if len(irsbs) == 0:
            logger.error("IDA block %s has no irsb, error." % (ida_block))
            # exit(0)

        for irsb in irsbs:
            irsb_addr = irsb.addr
            block_node = DataflowBlock(irsb_addr, self, node_type='Boring')
            block_node.irsb = irsb
            block_node.func_addr = funcea
            block_node.end = irsb_addr + irsb.size

            # DataFlowCFG's node is add here
            self._nodes[irsb_addr] = block_node
            ida_block.contain_blocks.append(block_node)
            
            # following is for debugging, change the funcea to see the debug log of the function you want
            if funcea == 0x15a34:
                logger.debug(f"Add irsb {irsb} in address {hex(irsb_addr)} with node type {block_node.node_type} in function {hex(funcea)}")

    def _update_irsb_to_cfg(self, ida_block):
        """
        Add edges into DataflowCFG.
        There is 3 jump kind, including Boring, Ijk_Call, Ijk_Ret.

        DataflowBlock create here is a dummy node which represents the callee's block (with no irsb)
        And there is an edge from the callsite's block to this dummy callee's block, and also an edge
        from this dummy callee's block to return block.
        """

        callsites = ida_block.callsites

        # the irsb in the ida's basic block
        # the number of irsb nodes in a ida's basic block
        nodes = ida_block.contain_blocks
        nodes_len = len(nodes)

        for i, irsb_node in enumerate(nodes):
            # if current irsb_node contains callsites
            callsite_addr, target = self._check_has_callsite(irsb_node, callsites)

            # if there is a call in the current irsb
            if callsite_addr:
                bb_with_callsite = irsb_node
                logger.debug("Callsite node is %s" % bb_with_callsite)
                # this is the callsite's return node
                ret_node = nodes[i+1] if i < nodes_len-1 else None

                # Special, the will be a block has only one instruction (call),
                # then we inc the callsite addr.
                if callsite_addr in self._nodes:
                    callsite_addr += 1

                # If callee is an internal function
                if isinstance(target, int):
                    callee_addr = target + self.bin_factory.base_addr
                    # IMPORTANT: This target node does not have irsb
                    target_node = DataflowBlock(callsite_addr, self, target = callee_addr, func_addr = self.addr, node_type = 'Call')
                    self.callees[callee_addr].append(target_node)
                    self.callsites[target_node.__hash__()] = target_node
                    logger.debug("Target node is %s" % (target_node))
                # If callee is an external function
                else:
                    target_name = str(target)
                    # IMPORTANT: This target node does not have irsb
                    target_node = DataflowBlock(callsite_addr, self, target = target_name, func_addr = self.addr, node_type = 'Extern')
                    self.callees[target_name].append(target_node)
                    logger.debug("Target node is %s" % (target_node))

                self._nodes[callsite_addr] = target_node

                kwargs = {'jumpkind': 'Ijk_Call'}
                bb_with_callsite.jumpkind = 'Ijk_Call'
                # IMPORTANT: look like add a edge to the call's target node
                self.graph.add_edge(bb_with_callsite, target_node, **kwargs)
                bb_with_callsite.has_callsite = 1
                # print("Add-edge-1: %s -> %s" % (callsite_node, target_node))

                if ret_node is None:
                    return ('call', bb_with_callsite)

                else:
                    kwargs = {'jumpkind': 'Ret'}
                    target_node.jumpkind = 'Ret'
                    # IMPORTANT: look like add a edge to the call's return node
                    self.graph.add_edge(target_node, ret_node, **kwargs)
                    # print("Add-edge-3: %s -> %s" % (target_node, ret_node))

            # if this is just a normal irsb node
            else:
                if i < nodes_len - 1:
                    kwargs = {'jumpkind': 'Boring'}
                    irsb_node.jumpkind = 'Boring'
                    self.graph.add_edge(irsb_node, nodes[i+1], **kwargs)

                else:
                    # last irsb in the ida's basic block
                    return ('jmp', irsb_node)
                
        return (None, None)

    def _add_icall_target_node(self, resolved_icalls):
        """
        In vex cfg, adding indirect call target.
        """
        # print("add-icall-target-node: %s" % (resolved_icalls))
        for icall_node, targets in resolved_icalls.items():
            callsite_addr = icall_node.addr
            pre_nodes = list(icall_node.predecessors)
            succ_nodes = list(icall_node.successors)

            if len(targets):
                icall_node.icall_flag = 1
            #     for pre_node in pre_nodes:
            #         self.graph.remove_edge(pre_node, icall_node)
            #     for succ_node in succ_nodes:
            #         self.graph.remove_edge(icall_node, succ_node)
            #     self.graph.add_node(icall_node)
            #     # self.graph.remove_node(icall_node)

            for target in targets:
                if type(target) is str:
                    target_name = str(target)
                    target_node = DataflowBlock(callsite_addr, self, target=target_name, func_addr=self.addr, node_type='iCall')
                    self.callees[target_name].append(target_node)
                    self.callsites[target_node.__hash__()] = target_node

                else:
                    rebase_target = target
                    target_node = DataflowBlock(callsite_addr, self, target=rebase_target, func_addr=self.addr, node_type='iCall')
                    self.callees[rebase_target].append(target_node)
                    self.callsites[target_node.__hash__()] = target_node

                for pre_node in pre_nodes:
                    kwargs = {'jumpkind': 'Ijk_Call'}
                    self.graph.add_edge(pre_node, target_node, **kwargs)
                    pre_node.has_callsite = 1
                    # print("Add-icll-target: %s" % (target_node))

                for succ_node in succ_nodes:
                    kwargs = {'jumpkind': 'Ret'}
                    self.graph.add_edge(target_node, succ_node, **kwargs)

    def _get_callsite_and_ret_node(self, call_addr, nodes):
        _len = len(nodes)
        callsite_node, ret_node = None, None
        for i, node in enumerate(nodes):
            if node.addr <= call_addr < node.end:
                callsite_node = node
                if i < _len - 1:
                    ret_node = nodes[i+1]

                else:
                    ret_node = None

                break

        return callsite_node, ret_node

    def _check_has_callsite(self, irsb_node, callsites):

        for addr, target in callsites.items():
            if irsb_node.addr <= addr < irsb_node.end:
                return addr, target

        return None, None

    def print_cfg(self):
        for node in self.graph.nodes():
            print("Debug: %s" % (node))

    def print_cfg_edges(self):
        for src, dst in self.graph.edges():
            print("%s ---%s---> %s" % (src, self.graph[src][dst]['jumpkind'], dst))

    def _add_edge(self, src, dst, jumpkind):
        """
        Add block to cfg_graph.
        """
        if jumpkind == 'call':
            kwargs = {'jumpkind': 'Ret'}
            src.jumpkind = 'Ret'
            self.graph.add_edge(src, dst, **kwargs)

        elif jumpkind == 'jmp':
            kwargs = {'jumpkind': 'Boring'}
            src.jumpkind = 'Boring'
            self.graph.add_edge(src, dst, **kwargs)

    def find_all_predecessors(self, addr):
        node = self._nodes[addr]

        traversed_nodes = set()
        traversed_nodes.add(node)

        stack = [node]
        while stack:
            node = stack.pop()
            pre_nodes = self.graph.predecessors(node)
            for pre_node in pre_nodes:
                if pre_node not in traversed_nodes:
                    stack.append(pre_node)
                    traversed_nodes.add(pre_node)

        for n in traversed_nodes:
            print("%s" % (n))

        return traversed_nodes

    def get_special_exit_block(self):
        """
        For the non-returned function, how to get its exit block.
        Especially for the loop exit, e.g. vsftpd 0x40d330.
        """
        last_block = self.pre_sequence_nodes[-1]
        if last_block.is_loop:
            pre_blocks = list(self.graph.predecessors(last_block))
            # print("psu-test: xxx %s" % (pre_blocks))
            if len(pre_blocks) == 1:
                return pre_blocks[0]
            for pre_block in pre_blocks:
                if pre_block.is_loop:
                    return pre_block

    def create_block(self, addr, bytes_len, funcea):
        """
        Create a cfg block with irsb.
        """
        insn_bytes = self.bin_factory.read_binary_bytes(addr, bytes_len)
        irsb = self.proj.factory.block(addr, size=bytes_len, insn_bytes=insn_bytes).vex
        # irsb.pp()

        block_node = DataflowBlock(addr+1, self, node_type='Boring')
        block_node.irsb = irsb
        block_node.func_addr = funcea
        block_node.end = addr + irsb.size
        self._nodes[addr+1] = block_node

        return block_node

    def _check_jump_block(self, block):
        # print("Mips-jump-block: %s" % (block))
        addr = block.addr
        irsb = block.irsb
        last_stmt = irsb.statements[-1]
        if last_stmt.tag is 'Ist_Exit':
            return None, None

        # irsb.pp()
        new_block, target = None, None
        bytes_len = 0
        stmts = irsb.statements
        for index, stmt in enumerate(stmts):
            if stmt.tag is 'Ist_IMark':
                bytes_len += stmt.len
            elif stmt.tag is 'Ist_Exit' and 'Ico' in stmt.dst.tag:
                target = stmt.dst.value
                # print("  -> %x" % (target))
                new_block = self.create_block(addr, bytes_len, block.func_addr)
        return new_block, target

    def _process_special_node(self, exit_block, jmp_block, jmp_target, out_edges, jumpkind):
        """
        In Mips, some block has jmp instruction in block's middle.
            85 IRSB {
            86    t0:Ity_I1 t1:Ity_I1 t2:Ity_I64 t3:Ity_I64 t4:Ity_I64 t5:Ity_I64
            87
            88    00 | ------ IMark(0x12005c5ac, 4, 0) ------
            89    01 | t2 = GET:I64(v0)
            90    02 | t1 = CmpNE64(t2,0x0000000000000000)
            91    03 | if (t1) { PUT(pc) = 0x12005c5b4; Ijk_Boring }
            92    04 | ------ IMark(0x12005c5b0, 4, 0) ------
            93    05 | t4 = GET:I64(sp)
            94    06 | t3 = Add64(t4,0x0000000000000138)
            95    07 | PUT(a0) = t3
            96    NEXT: PUT(pc) = 0x000000012005c5d0; Ijk_Boring
            97 }
        """
        funcea = exit_block.func_addr
        for pre_block, _, data in self.graph.in_edges(exit_block, data=True):
            # print("pre_block %s %s" % (pre_block, data))
            self.graph.add_edge(pre_block, jmp_block, **data)

        jmp_succ_bock = None
        succ_blocks = []
        for _, succ_ida_block in out_edges:
            start_node = succ_ida_block.contain_blocks[0]
            if start_node.addr == jmp_target:
                jmp_succ_bock = start_node

            else:
                succ_blocks.append(start_node)

        if jmp_succ_bock:
            # print("Add-edge: %s -> %s" % (jmp_block, jmp_succ_bock))
            self._add_edge(jmp_block, jmp_succ_bock, jumpkind)

        for succ_block in succ_blocks:
            self._add_edge(exit_block, succ_block, jumpkind)

    def get_start_nodes(self):
        """
        Get start nodes in cfg.
        """
        start_nodes = []
        for n in self.graph.nodes():
            if self.graph.in_degree(n) == 0 and n.addr != self.addr:
                start_nodes.append(n)

        s_node = self.get_node_by_addr(self.addr)
        start_nodes.append(s_node)

        return start_nodes
