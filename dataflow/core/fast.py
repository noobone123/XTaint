#!/usr/bin/ven python
import networkx
from .vex_process import EngineVEX
from .code_location import CodeLocation

import logging
l = logging.getLogger("fast_data_flow")
l.setLevel('INFO')


class LiveSims(object):

    def __init__(self, name, stype):

        self.name = name
        self.stype = stype

    def __eq__(self, other):
        return type(other) is LiveSims and self.name == other.name and self.stype == other.stype

    def __hash__(self):
        return hash(self.name) + hash(self.stype)

    def __repr__(self):
        return '<Live-Sim %s %s>' % (str(self.name), self.stype)

    def filter_tmp_sim(self):
        """
        If the name contains TEMP 'tx', the LiveSims should be filtered and not be merged to other block.
        """
        if type(self.name) is str and 't' in self.name:
            return True
        elif (type(self.name) is tuple and
                (type(self.name[0]) is str and 't' in self.name[0] or
                 type(self.name[1]) is str and 't' in self.name[1])):
            return True
        return False


class FastDataFlow(EngineVEX):

    def __init__(self, project,
                 loop_execute_times=1,
                 summary_loop=False,
                 find_special_loop_copy=False,
                 ):

        super(FastDataFlow, self).__init__(project)

        self._loop_execute_times = loop_execute_times
        self._summary_loop = summary_loop
        self._find_special_loop_copy = find_special_loop_copy

    @property
    def summary_loop(self):
        return self._summary_loop

    @summary_loop.setter
    def summary_loop(self, value):
        self._summary_loop = value

    @property
    def find_special_loop_copy(self):
        return self._find_special_loop_copy

    @find_special_loop_copy.setter
    def find_special_loop_copy(self, value):
        self._find_special_loop_copy = value

    def test(self):
        print("summary_loop: %s" % (self._summary_loop))
        print("find_special_loop_copy: %s" % (self._find_special_loop_copy))

    def _add_use(self, new_use, loc, live_uses):
        if new_use in live_uses:
            live_uses[new_use].add(loc)
        else:
            live_uses[new_use] = {loc}

    def _lookup_uses(self, search, live_uses):

        for use in live_uses:
            name = use.name
            if search == name:
                return use

            elif type(search) is str and type(name) is tuple and search == name[0]:
                return use

    def _backward_update(self, block, live_uses, live_uses_per_block, graph):

        pre_blocks = graph.predecessors(block)

        for pre_block in pre_blocks:
            # print("loop-pre: %s" % (pre_block))
            if pre_block.addr in live_uses_per_block:
                pre_live_uses = live_uses_per_block[pre_block.addr]

            else:
                pre_live_uses = {}
                live_uses_per_block[pre_block.addr] = pre_live_uses

            if len(pre_live_uses) == 0:
                for use, locs in live_uses.items():
                    if use.filter_tmp_sim():
                        continue
                    pre_live_uses[use] = locs
                    # print("add %s %s" % (use, locs))

            else:
                # print("merge-live-uses: %s %s" % (pre_block, block))
                self._merge_live_uses(pre_live_uses, live_uses)

    def _merge_live_uses(self, new_live_uses, old_live_uses):

        for old_use, locs in old_live_uses.items():
            # print("old-live-use: %s %s" % (old_use, locs))
            if old_use.filter_tmp_sim():
                continue
            if old_use in new_live_uses:
                new_live_uses[old_use] |= locs

            else:
                new_live_uses[old_use] = locs

    def _check_inc_operations(self, block, live_uses_per_block):
        pass

    def _check_is_pointer_argument(self, block, dst_alias):
        """
        Check whether the store address dst_alias contain pointer argument.
        :param block:
        :param dst_alias: a tuple, like ('+', ('r24', 'r28'), (32, 32), ('ptr', 'int'))
        """
        op0, op1 = dst_alias[1]
        # print(op0, op1)
        if op0 in block.live_defs:
            op0_at = block.live_defs[op0]
            # print(op0_at)
            if op0_at.src_type == 'A':
                return True

        if op1 in block.live_defs:
            op1_at = block.live_defs[op1]
            # print(op1_at)
            if op1_at.src_type == 'A':
                return True
        return False

    def process_block_in_forward(self, block):
        live_defs = block.live_defs
        actions = block.actions
        if len(actions) == 0:
            return

        code_locations = block.code_locations
        ins_len = len(code_locations)
        for code_location in code_locations:
            action = actions[code_location]
            # print(action)

    def process_block_in_backward(self, block, live_uses, ddg_graph, analyzed_special_addrs):
        """
        This method only track 'reg', 'stack', 'direct mem access' variable.
        if trace mem access data, the name must be (base, offset).
        :param live_uses: is a dict, e.g. {LiveSims: set(location)}
        """
        live_defs = block.live_defs
        actions = block.actions
        if len(actions) == 0:
            return

        code_locations = block.code_locations
        ins_len = len(code_locations)
        for i in range(ins_len-1, -1, -1):

            code_location = code_locations[i]
            action = actions[code_location]
            action_type = action.action_type
            # print(action)

            if action_type == 'p':
                put_reg = action.dst
                put_data = action.src
                put_data_alias = action.src_alias
                live_sim = self._lookup_uses(put_reg, live_uses)
                # print("look-uses: %s" % (live_sim))

                if type(put_data) is str:
                    put_data_at = live_defs[put_data]
                    if (put_data_at.action_type == 'wl' and
                            put_data_at.addr_value is None and
                            type(put_data_at.src_alias) is tuple and
                            type(put_data_at.src_alias[1][0]) is str and
                            'r' in put_data_at.src_alias[1][0]):
                        # print(10*"="+"%s" % (action))
                        # print(10*"="+"%s" % (put_data_at))
                        if self._summary_loop and code_location not in analyzed_special_addrs:
                            analyzed_special_addrs.add(code_location)
                            name = put_data_at.src_alias[1]
                            new_use = LiveSims(name, 'link')
                            self._add_use(new_use, code_location, live_uses)
                            # print("add-link: %s" % (new_use))

                if live_sim:
                    if live_sim.stype == 'link':
                        kwargs = {'stype': 'link', 'action': 'p', 'data': put_reg}
                    else:
                        kwargs = {'stype': 'reg', 'action': 'p', 'data': put_reg}
                    for target_loc in live_uses[live_sim]:
                        ddg_graph.add_edge(code_location, target_loc, **kwargs)
                        # print("ADD-g: %s %s" % (code_location, target_loc))

                    # pop use variable if we have found it's def.
                    live_uses.pop(live_sim)

                    if type(put_data) is not int:
                        stype = live_sim.stype
                        if stype == 'reg':
                            new_use = LiveSims(put_data, 'reg')

                        else:
                            name = (put_data, live_sim.name[1])
                            new_use = LiveSims(name, 'mem')
                        self._add_use(new_use, code_location, live_uses)
                        # print("add_use: %s" % (new_use))

                if (self._summary_loop and put_reg != self.sp_name and
                        type(put_data_alias) is tuple and
                        put_data_alias[0] in ['+', '-'] and
                        code_location not in analyzed_special_addrs):
                    analyzed_special_addrs.add(code_location)
                    add_use = LiveSims(put_data, 'reg')
                    if add_use in live_uses:
                        live_uses[add_use].add(code_location)

                    else:
                        live_uses[add_use] = {code_location}
                    # print("add-use: %s %s" % (add_use, code_location))

            elif action_type == 'w':
                wr_tmp = action.dst
                wr_data, wr_data_alias = action.src, action.src_alias
                live_sim = self._lookup_uses(wr_tmp, live_uses)

                if live_sim:
                    # kwargs = {'stype': live_sim.stype, 'action': 'w', 'data': wr_tmp}
                    kwargs = {'stype': 'reg', 'action': 'w', 'data': wr_tmp}
                    for target_loc in live_uses[live_sim]:
                        ddg_graph.add_edge(code_location, target_loc, **kwargs)

                    # pop use variable if we have found it's def.
                    live_uses.pop(live_sim)

                    if wr_data != self.gp_name:
                        stype = live_sim.stype
                        if stype == 'reg':
                            new_use = LiveSims(wr_data, 'reg')

                        else:
                            name = (wr_data, live_sim.name[1])
                            new_use = LiveSims(name, stype)

                        self._add_use(new_use, code_location, live_uses)
                        # print("update-use: %s %s" % (new_use, code_location))

            elif action_type == 'wo':
                # print("xx- %s" % (action))
                wr_tmp = action.dst
                wr_datas = action.src
                opnds = wr_datas[1]
                live_sim = self._lookup_uses(wr_tmp, live_uses)

                if live_sim:
                    # kwargs = {'stype': live_sim.stype, 'action': 'wo', 'data': wr_tmp}
                    kwargs = {'stype': 'reg', 'action': 'wo', 'data': wr_tmp}
                    for target_loc in live_uses[live_sim]:
                        ddg_graph.add_edge(code_location, target_loc, **kwargs)
                        # print("add-edge: %s -> %s %s" % (code_location, target_loc, kwargs))

                    # pop use variable if we have found it's def.
                    live_uses.pop(live_sim)

                    stype = live_sim.stype
                    # if stype == 'reg':
                    if type(opnds[0]) is str:
                        new_use = LiveSims(opnds[0], 'reg')
                        self._add_use(new_use, code_location, live_uses)
                        # print("update-use: %s %s" % (new_use, code_location))

                    if type(opnds[1]) is str:
                        new_use = LiveSims(opnds[1], 'reg')
                        self._add_use(new_use, code_location, live_uses)
                        # print("add-use(wo1): %s %s" % (new_use, code_location))

                    if stype == 'mem':
                        if live_sim.name[1] == 0:
                            new_use = LiveSims(opnds, stype)
                            self._add_use(new_use, code_location, live_uses)
                            # print("add-use(wo2): %s %s" % (new_use, code_location))
                        else:
                            l.debug("We ignore the mem data trace with add/sub operation!")

            elif action_type == 'wu':
                wr_tmp =action.dst
                wr_data = action.src
                live_sim = self._lookup_uses(wr_tmp, live_uses)

                if live_sim:
                    # kwargs = {'stype': live_sim.stype, 'action': 'wu', 'data': wr_tmp}
                    kwargs = {'stype': 'reg', 'action': 'wu', 'data': wr_tmp}
                    for target_loc in live_uses[live_sim]:
                        ddg_graph.add_edge(code_location, target_loc, **kwargs)

                    # pop use variable if we have found it's def.
                    live_uses.pop(live_sim)

                    stype = live_sim.stype
                    if stype == 'reg':
                        new_use = LiveSims(wr_data, 'reg')

                    else:
                        name = (wr_data, live_sim.name[1])
                        new_use = LiveSims(name, 'mem')
                    # live_uses[new_use] = {code_location}
                    self._add_use(new_use, code_location, live_uses)

            elif action_type == 'wl':
                wr_tmp = action.dst
                l_data = action.src_alias if action.src_alias else action.src
                live_sim = self._lookup_uses(wr_tmp, live_uses)
                # print(action)

                if live_sim:
                    # kwargs = {'stype': live_sim.stype, 'action': 'wl', 'data': wr_tmp}
                    kwargs = {'stype': 'mem', 'action': 'wl', 'data': wr_tmp}
                    for target_loc in live_uses[live_sim]:
                        ddg_graph.add_edge(code_location, target_loc, **kwargs)

                    # pop use variable if we have found it's def.
                    live_uses.pop(live_sim)
                    # print("Found live_sim: %s" % (live_sim))

                    # stype = live_sim.stype
                    # if stype == 'reg':
                    name = l_data[1] if type(l_data) is tuple else (l_data, 0)
                    if name[0] != self.gp_name:
                        new_use = LiveSims(name, 'mem')
                        self._add_use(new_use, code_location, live_uses)
                        # print("add_use(wl-1) %s" % (new_use))

                    if type(name[0]) is str and name[0] != self.sp_name:
                        new_use = LiveSims(name[0], 'reg')
                        self._add_use(new_use, code_location, live_uses)
                    if type(name[1]) is str and name[1] != self.sp_name:
                        new_use = LiveSims(name[1], 'reg')
                        self._add_use(new_use, code_location, live_uses)

                    # else:
                    #     l.debug("We ignore the indirect mem access.")

            elif action_type == 's':
                data_alias = action.src_alias
                data = data_alias if type(data_alias) is str else action.src
                s_addr = action.dst_alias if action.dst_alias else action.dst
                addr = s_addr[1] if type(s_addr) is tuple else (s_addr, 0)

                live_sim = self._lookup_uses(addr, live_uses)

                if live_sim:
                    # kwargs = {'stype': live_sim.stype, 'action': 's', 'data': action.src}
                    kwargs = {'stype': 'mem', 'action': 's', 'data': action.src}
                    for target_loc in live_uses[live_sim]:
                        ddg_graph.add_edge(code_location, target_loc, **kwargs)

                    # pop use variable if we have found it's def.
                    live_uses.pop(live_sim)

                    new_use = LiveSims(data, 'reg')
                    # live_uses[new_use] = {code_location}
                    self._add_use(new_use, code_location, live_uses)

                if (self._summary_loop and
                        type(data_alias) is tuple and
                        data_alias[0] in ['+', '-']):
                    add_use = LiveSims(data, 'reg')
                    if add_use in live_uses:
                        live_uses[add_use].add(code_location)

                    else:
                        live_uses[add_use] = {code_location}
                    # print("add-use: %s" % (add_use))

                elif (self._find_special_loop_copy and
                        type(action.dst_alias) is tuple and
                        action.dst_alias[0] == '+'):
                    if self._check_is_pointer_argument(block, action.dst_alias):
                        # print("Find define to arg-ptr: %s" % (action))
                        add_use = LiveSims(action.dst, 'reg')
                        if add_use in live_uses:
                            live_uses[add_use].add(code_location)

                        else:
                            live_uses[add_use] = {code_location}
                        # print("add-use: %s" % (add_use))

            elif action_type == 'lg':
                # print(action)
                wr_tmp = action.dst
                # wr_src = action.src_alias if action.src_alias else action.src
                wr_src = action.src
                l_data = wr_src[0][1]
                wr_data = wr_src[0][2]
                live_sim = self._lookup_uses(wr_tmp, live_uses)
                # print(live_sim)

                if live_sim:
                    kwargs = {'stype': 'mem', 'action': 'wl', 'data': wr_tmp}
                    for target_loc in live_uses[live_sim]:
                        ddg_graph.add_edge(code_location, target_loc, **kwargs)
                        # print("add_edge: %s -> %s" % (code_location, target_loc))

                    stype = live_sim.stype
                    if stype == 'reg':
                        name = (l_data, 0)
                        if name[0] != self.gp_name:
                            new_use = LiveSims(name, 'mem')
                            self._add_use(new_use, code_location, live_uses)

                    else:
                        l.debug("We ignore the indirect mem access.")

                    new_location = code_location.copy()
                    new_location.unique_id += 1
                    # new_location = CodeLocation(code_location.block_addr, code_location.stmt_idx)
                    kwargs = {'stype': 'reg', 'action': 'w', 'data': wr_tmp}
                    for target_loc in live_uses[live_sim]:
                        ddg_graph.add_edge(new_location, target_loc, **kwargs)
                        # print("add_edge: %s -> %s" % (new_location, target_loc))

                    if stype == 'reg' and wr_data != self.gp_name:
                        new_use = LiveSims(wr_data, 'reg')
                        self._add_use(new_use, new_location, live_uses)

                    # pop use variable if we have found it's def.
                    live_uses.pop(live_sim)

            else:
                l.debug("Ignore action.")

    def execute_loop(self, loop):
        loop_sequence = loop.body_nodes
        loop_graph = loop.graph
        loop_len = len(loop_sequence)

        live_uses_per_block = {}
        analyzed_special_addrs = set()
        ddg_graph = networkx.DiGraph()

        for j in range(self._loop_execute_times):
            for i in range(loop_len-1, -1, -1):
                block = loop_sequence[i]
                block_addr = block.addr
                if block_addr in live_uses_per_block:
                    live_uses = live_uses_per_block[block_addr]

                else:
                    live_uses = {}
                    live_uses_per_block[block_addr] = live_uses

                if block.node_type in ['Call', 'iCall', 'Extern']:
                    self._pop_ret_live_sim(live_uses, block, ddg_graph)

                # print("\nloop_block %s" % (block))
                # if block.irsb:
                #     block.irsb.pp()
                # for sim, locs in live_uses.items():
                #     print(sim, locs)

                self.process_block_in_backward(block, live_uses, ddg_graph, analyzed_special_addrs)

                live_uses_per_block[block_addr] = {}

                self._backward_update(block, live_uses, live_uses_per_block, loop_graph)

                # print("\nloop_block (A) %s" % (block))
                # for sim, locs in live_uses.items():
                #     print(sim, locs)

                # live_uses_per_block[block_addr] = {}

        # TEST
        # for node in ddg_graph.nodes():
        #     print("node: %s" % (node))

        # for src, dst, data in ddg_graph.edges(data=True):
        #     print(src, dst, data)

        return ddg_graph

    def _pop_ret_live_sim(self, live_uses, callsite, ddg_graph):
        pop_uses = []
        ret_loc = None
        for use in live_uses:
            use_name = use.name
            if (type(use_name) is str or type(use_name) is tuple) and self.ret_name in use_name:
                pop_uses.append(use)
                ret_loc = CodeLocation(callsite.addr, 0) if ret_loc is None else ret_loc
                kwargs = {'stype': 'ret', 'action': 'p', 'data': callsite.target}
                for target_loc in live_uses[use]:
                    ddg_graph.add_edge(ret_loc, target_loc, **kwargs)
                # print(ret_loc, kwargs)

        for u in pop_uses:
            # print("pop ret sim: %s" % (str(u.name)))
            live_uses.pop(u)

    def _get_loop_tmp(self, node, loop_graph):
        loop_tmps = set()
        for _, _, datas in loop_graph.in_edges(node, data=True):
            loop_tmps.add(datas['data'])

        return loop_tmps

    def _label_inc_in_action(self, function, inc_info):
        """
        Lable loop inc variable in block actions.
        """
        inc_blocks = {}
        loc_set = set()
        for loc in inc_info:
            block_addr = loc.block_addr
            block = function.get_block(block_addr)
            if block not in inc_blocks:
                inc_blocks[block] = []
            inc_blocks[block].append(loc)

        for block, inc_locs in inc_blocks.items():
            # print("Inc-block: %s" % (block))
            actions = block.actions
            live_defs = block.live_defs
            for loc in inc_locs:
                tmps = inc_info[loc]
                # print("inc-loc: %s" % (loc))
                action = actions[loc]
                if action.action_type == 'wo':
                    bases, offset = [], []
                    for opnd in action.src[1]:
                        if type(opnd) is str:
                            opnd_at = live_defs[opnd]
                            if opnd_at.action_type in ['w', 'p', 'wu']:
                                alias_opnd = live_defs[opnd].src
                            else:
                                alias_opnd = live_defs[opnd].dst

                            opnd_value = opnd_at.value
                            if type(opnd_value) is int and opnd_at.src_type in ['S', 'G']:
                                # print("Get stack or global addr inc: %x" % (opnd_value))
                                function.concrete_inc_addrs.add(opnd_value)

                        else:
                            alias_opnd = opnd

                        if opnd in tmps:
                            action.inc_flag += 1
                            bases.append((opnd, alias_opnd))
                        else:
                            offset.append((opnd, alias_opnd))

                    if len(bases) == 1 and len(offset) == 1:
                        action.inc_base = bases[0]
                        action.inc_offset = offset[0]
                        # print(action.inc_base, action.inc_offset)

                    elif len(bases) == 2:
                        action.inc_base = bases

    def _label_link_in_action(self, function, link_info):
        """
        Check whether have a link load instruction.
        """
        link_blocks = {}
        for loc in link_info:
            block_addr = loc.block_addr
            block = function.get_block(block_addr)
            if block not in link_blocks:
                link_blocks[block] = []
            link_blocks[block].append(loc)

        for block, link_locs in link_blocks.items():
            actions = block.actions
            live_defs = block.live_defs
            for loc in link_locs:
                at = actions[loc]
                if at.action_type != 'p':
                    continue
                put_src = at.src
                src_at = live_defs[put_src]
                if src_at.action_type == 'wl':
                    # print("Good, find link load %s" % (src_at))
                    src_at.link_flag = 1

    def label_loop_variables(self, function, graph):

        # print("label loop varialbes: %s" % (function))
        inc_info = {}
        link_info = set()
        for subg in (networkx.induced_subgraph(graph, nodes).copy() for nodes in networkx.strongly_connected_components(graph)):
            if len(subg.nodes()) == 1:
                if len(list(subg.successors(list(subg.nodes())[0]))) == 0:
                    continue

            loop_locs = []
            for src, dst, data in subg.edges(data=True):
                # print("inc-edge: %s ->  %s %s" % (src, dst, data))
                if data['stype'] == 'reg' and data['action'] == 'wo':
                    loop_tmps = self._get_loop_tmp(src, subg)
                    inc_info[src] = loop_tmps

                elif data['stype'] == 'link' and data['action'] == 'p':
                    link_info.add(dst)

        self._label_inc_in_action(function, inc_info)

        self._label_link_in_action(function, link_info)

    def _backward_trace_block(self, block, trace_graph, ddg_graph, live_uses_per_block, analyzed_special_addrs):
        """
        :param block:
        :param trace_graph:
        :param ddg_graph:
        :param live_uses_per_block:
        :param analyzed_special_addrs:
        """
        block_addr = block.addr
        if block_addr in live_uses_per_block:
            live_uses = live_uses_per_block[block_addr]

        else:
            live_uses = {}
            live_uses_per_block[block_addr] = live_uses

        if block.node_type in ['Call', 'iCall', 'Extern']:
            self._pop_ret_live_sim(live_uses, block, ddg_graph)

        # if block.irsb:
        #     block.irsb.pp()
        # for sim, locs in live_uses.items():
        #     print("-->(before): %s %s" % (sim, locs))

        self.process_block_in_backward(block, live_uses, ddg_graph, analyzed_special_addrs)

        # for sim, locs in live_uses.items():
        #     print("-->(after): %s %s" % (sim, locs))

        self._backward_update(block, live_uses, live_uses_per_block, trace_graph)

        live_uses_per_block[block_addr] = {}

    def backward_trace(self, function, initial_uses):
        """
        Analyze a function with backward trace.
        :param function:
        :param initial_uses: a dict which contian the initial LiveSims objects.
        :param loop_execute_times: the max iteration execution time of a loop.
        """
        live_uses_per_block = {}
        analyzed_special_addrs = set()
        ddg_graph = networkx.DiGraph()
        analyzed_blocks = set()
        func_cfg = function.cfg
        pre_sequence_nodes = func_cfg.pre_sequence_nodes

        for block_addr in initial_uses:
            live_uses_per_block[block_addr] = initial_uses[block_addr]

        for i in range(len(pre_sequence_nodes)-1, -1, -1):
            block = pre_sequence_nodes[i]

            if block in analyzed_blocks:
                continue

            # print("\n+++--> Backward analyze block %s" % (block))
            # print("backward expr %s\nforward expr %s" % (block.backward_exprs, block.forward_exprs))

            if block.is_loop:
                loop = function.determine_node_in_loop(block)
                loop_sequence = loop.body_nodes
                loop_graph = loop.graph
                loop_len = len(loop_sequence)
                for j in range(self._loop_execute_times):
                    for i in range(loop_len-1, -1, -1):
                        block = loop_sequence[i]
                        self._backward_trace_block(block, func_cfg.graph, ddg_graph, live_uses_per_block, analyzed_special_addrs)

            else:
                self._backward_trace_block(block, func_cfg.graph, ddg_graph, live_uses_per_block, analyzed_special_addrs)
                analyzed_blocks.add(block)
        # TEST
        # for node in ddg_graph.nodes():
        #     print("node: %s" % (node))

        # for src, dst, data in ddg_graph.edges(data=True):
        #     print(src, dst, data)
        return ddg_graph

    def backward_trace_return_value(self, function):
        """
        Trace return value of the function and fastly generate DDG graph.
        :param function:
        """
        initial_uses = {}
        for exit_block in function.cfg.exit_blocks:
            live_uses = {}
            new_use = LiveSims(self.ret_name, 'reg')
            # print("exit block %s" % (exit_block))
            stmt_idx = len(exit_block.irsb.statements) if exit_block.irsb else 0
            code_location = CodeLocation(exit_block.addr, stmt_idx, ins_addr=exit_block.addr)
            # print(code_location)
            self._add_use(new_use, code_location, live_uses)
            initial_uses[exit_block.addr] = live_uses
        # print(initial_uses)
        ddg_graph = self.backward_trace(function, initial_uses)
        return ddg_graph

    def initialize_uses(self, block, var, initial_uses):
        """
        Trace return value of the function and fastly generate DDG graph.
        :param block:
        :param var: The initial variable that should be backward tracked.
        """
        if block.addr in initial_uses:
            live_uses = initial_uses[block.addr]
        else:
            live_uses = {}
        new_use = LiveSims(var, 'reg')
        stmt_idx = len(block.irsb.statements) if block.irsb else 0
        code_location = CodeLocation(block.addr, stmt_idx, ins_addr=block.addr)
        self._add_use(new_use, code_location, live_uses)
        initial_uses[block.addr] = live_uses
