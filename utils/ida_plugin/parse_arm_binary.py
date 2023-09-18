import sys
from headless_ida import HeadlessIda

ida_engine_path = sys.argv[1]
idb_path = sys.argv[2]
preprocess_dir = sys.argv[3]

headlessida = HeadlessIda(ida_engine_path, idb_path)

import idautils
import ida_nalt
import idaapi
import idc
import ida_funcs
import ida_idaapi

import json
import os

def MakeFunction(start, end=ida_idaapi.BADADDR):
    return ida_funcs.add_func(start, end)

def in_code_section(addr):
    """
    Check if address is in `.text` section.
    """
    for s in sections.keys():
        if s == ".text":
            start, end, perm = sections[s]
            if addr >= start and addr <= end:
                return True
    return False

def get_switch_bb_info(blocks):
    switch_bb_info = {}
    for bb in blocks:
        bb_start, bb_end = bb.start_ea, bb.end_ea
        ea = bb_start
        ins_addrs = {ea}

        while ea != idc.BADADDR and ea < bb_end:
            mnem = idc.print_insn_mnem(ea)
            operand = idc.get_operand_value(ea, 0)
            if 'LDR' in mnem and operand in ['PC']:
                switch_bb_info[bb] = ea
                print("Found switch block at %s" % hex(ea))

            ea = idc.next_head(ea, bb_end)
            if ea in ins_addrs:
                continue
            else:
                ins_addrs.add(ea)

def get_sections_func():
    """
    Get all sections and functions.
    """
    sections = {}
    func = []
    
    for s in idautils.Segments():
        name = idc.get_segm_name(s)
        start = idc.get_segm_start(s)
        end = idc.get_segm_end(s)

        perm = idaapi.getseg(s).perm

        sections[name] = (start, end, perm)

        if not perm & idaapi.SEGPERM_EXEC:
            continue
        if name == ".plt":
            continue
        
        # TODO: what if has no `.text` section?
        print("Processing section: %s" % name)
        for _, func_ea in enumerate(idautils.Functions(start, end)):
            func.append(func_ea)
    
    print("Total %d functions" % len(func))

    return sections, func

def get_jumptable_xref_info(functions):
    """
    Read the data sections and find all function ptr reference in code section.
    """
    if arch_bits == 32:
        step = 4
    elif arch_bits == 64:
        raise NotImplementedError("Not support 64 bit arch yet.")
    
    xref_to_info_tmp = {}
    xref_to_info = {}

    # find all sections with perm r+w
    data_region = []
    for s in sections.keys():
        perm = sections[s][2]
        if perm == 6:   # r+w
            data_region.append(s)

    for section_name in data_region:
        start, end, perm = sections[section_name]
        cur = start
        while cur < end:
            if arch_bits == 32:
                data = idc.get_wide_dword(cur)
            elif arch_bits == 64:
                # TODO: add 64 bit support
                pass
            
            # for jump table, in most cases, only jump table header
            # can be referenced by code, which `data` is not in .text section.
            # for entries in jump table (func_ptr), it has no xref info.

            # FIXME: Need a more sound way to find jump table header 
            xrefs_to = [x for x in idautils.DataRefsTo(cur)]
            if xrefs_to:
                xref_to_info_tmp.clear()
                for ref_start in xrefs_to:
                    xref_to_info_tmp[ref_start] = cur

            # check if data is a address in .text section
            if in_code_section(data):
                # find all `.text`` address that reference(read/write) to this address
                if data in functions:
                    print(f"Found function ptr {hex(data)} in section {section_name} at {hex(cur)}")
                
                # Trick: if data in .text section, but not in functions, it may be a function ptr
                else:
                    print(f"Found a weird function ptr {hex(data)} in section {section_name} at {hex(cur)}")
                    func = idaapi.get_func(data)
                    if func is None:
                        MakeFunction(data)
                        func = idaapi.get_func(data)
                        funcs.append(data)
                        print(f"Make function at {hex(data)}")
                
                # collect all xref info, which means there maybe jump table reference in `xref_to_info`
                if xref_to_info_tmp:
                    for ref_start, ref_end in xref_to_info_tmp.items():
                        if not in_code_section(ref_start):
                            continue
                        if ref_start not in xref_to_info:
                            xref_to_info[ref_start] = ref_end
                            print(f"Collected xref info: {hex(ref_start)} -> {hex(ref_end)}")

            cur += step
    
    return xref_to_info

def get_funcptr_xref_from(ea):
    """
    Get all function ptr if an inst reference to a function ptr.
    """
    res = []

    got_start, got_end, _ = sections['.got']
    plt_start, plt_end, _ = sections['.plt']

    for ref_addr in idautils.DataRefsFrom(ea):
        if in_code_section(ref_addr):
            func_addr = idc.get_func_attr(ref_addr, idc.FUNCATTR_START)
            if func_addr == ref_addr:
                print(f"Found a function ptr {hex(ref_addr)} reference at {hex(ea)}")
                res.append((ea, ref_addr, 'func_ptr'))

        elif got_start <= ref_addr <= got_end:
            may_ptr = idc.get_qword(ref_addr) if arch_bits == 64 else idc.get_wide_dword(ref_addr)
            if may_ptr:
                if in_code_section(may_ptr):
                    func_addr = idc.get_func_attr(may_ptr, idc.FUNCATTR_START)
                    if func_addr == may_ptr:
                        print(f"Found a function ptr {hex(ref_addr)} reference at {hex(ea)}")
                        res.append((ea, may_ptr, 'func_ptr'))

    return res


def get_call_info(bb, func_info):
    """
    get call info in each basic block.
    """
    bb_start, bb_end = bb.start_ea, bb.end_ea
    code_start, code_end, _ = sections['.text']
    plt_start, plt_end, _ = sections['.plt']
    extern_start, extern_end, _ = sections['extern']
    call_info = [] 

    # traverse all insts and get all call instruction in this basic block
    for ea in idautils.Heads(bb_start, bb_end):
        mnem = idc.print_insn_mnem(ea)
        if mnem == 'BL':
            operand_1 = idc.get_operand_value(ea, 0)
            addr = idc.get_func_attr(operand_1, idc.FUNCATTR_START)
            attr = idc.get_func_attr(operand_1, idc.FUNCATTR_FLAGS)

            if addr != idc.BADADDR and addr == operand_1:
                if plt_start <= addr <= plt_end:
                    func_name = idc.get_func_name(addr)
                    func_info['call'].append((bb_start, ea, func_name))
                
                elif code_start <= addr <= code_end:
                    func_info['call'].append((bb_start, ea, addr))
                
                elif extern_start <= addr <= extern_end:
                    func_name = idc.get_func_name(addr)
                    func_info['call'].append((bb_start, ea, func_name))
                    print("Found extern function call %s" % func_name)
                    print(idc.GetDisasm(ea))
                
            elif addr == idc.BADADDR:
                op0 = idc.print_operand(ea, 0)
                if op0 not in ['LR']:
                    print("Found a indirect call at %s" % hex(ea))
                    print(idc.GetDisasm(ea))
                    call_info.append((ea, None, 'iCall'))

        # TODO: function called by B / BLX / BLE / ...
        elif mnem in ['B', 'BLX', 'BLE', 'BLT', 'BLS']:
            operand_type = idc.get_operand_type(ea, 0)
            operand_value = idc.get_operand_value(ea, 0)
            if operand_type == idc.o_reg:
                if operand_value not in ['LR']:
                    print("Found a indirect call at %s" % hex(ea))
                    print(idc.GetDisasm(ea))
                    call_info.append((ea, None, 'iCall'))

        # if PC is modified, it may be a indirect call
        elif mnem in ['MOV', 'LDR']:
            op0 = idc.print_operand(ea, 0)
            op1 = idc.print_operand(ea, 1)
            if op0 == 'PC':
                tmp_ea = idc.next_head(ea)
                if tmp_ea >= bb_end and 'SP' in op1:
                    print("It's a tail return call, ingore!!!")
                else:
                    call_info.append((ea, None, 'iCall'))
        
        # get all func_ptr (in .data) reference in current ea
        if ea in jumptable_xref_info:
            ref_to_addr = jumptable_xref_info[ea]
            call_info.append((ea, ref_to_addr, 'data'))

        # get all func_ptr if this ea reference
        func_ptr = get_funcptr_xref_from(ea)
        if func_ptr:
            call_info.extend(func_ptr)

    return call_info
    

def get_cfg_block_info():
    """
    Parse the binary and get each function's cfg and block info.
    """
    cfg_record, callinfo_record, switch_record = {}, {}, {}
    for ea in funcs:
        func_info = {
            'block': [],
            'control-flow': [],
            'call': []
        }

        function_name = idc.get_func_name(ea)

        print("Analyzing function %s" % function_name)

        func_info['name'] = function_name
        func_obj = idaapi.get_func(ea)
        func_end = func_obj.end_ea

        visited_bb = set()
        all_bb = set()
        maybe_switch_bb = []

        for bb in idaapi.FlowChart(func_obj):
            # record block info (block start, block end)
            func_info['block'].append((bb.start_ea, bb.end_ea))
            all_bb.add(bb.start_ea)

            # parse each block's instruction and get call info
            call_info = get_call_info(bb, func_info)
            if ea not in callinfo_record.keys():
                callinfo_record[ea] = {}
            callinfo_record[ea][bb.start_ea] = call_info

            # find all non-pre and non-succ block (exclude case when function has only 1 bb)
            if len(list(bb.preds())) == 0 and len(list(bb.succs())) == 0 and \
                bb.start_ea != func_obj.start_ea and bb.end_ea != func_obj.end_ea:
                continue

            # record basic block control flow info (intraprocedural control flow)
            succs_bbs = list(bb.succs())
            visited_bb.add(bb.start_ea)
            for succ in succs_bbs:
                func_info['control-flow'].append((bb.start_ea, succ.start_ea))
                visited_bb.add(succ.start_ea)

            # find exit block but not function end (exit in the middle of function)
            # maybe a switch case block ?
            if len(succs_bbs) == 0 and bb.end_ea != func_obj.end_ea:
                maybe_switch_bb.append(bb)

        # add switch info into switch_record
        if len(visited_bb) != len(all_bb):
            print("Maybe has switch blocks in function %s" % function_name)
            switch_bb_info = get_switch_bb_info(maybe_switch_bb)
            for sbb, switch_ea in switch_bb_info.items():
                sbb_start = sbb.start_ea
                if function_name not in switch_record:
                    switch_record[function_name] = []
                switch_record[function_name].append((sbb_start, switch_ea))
        
        # record cfg info
        cfg_record[function_name] = func_info


    return cfg_record, callinfo_record, switch_record

if __name__ == "__main__":
    file_name = ida_nalt.get_root_filename()
    file_path = ida_nalt.get_input_file_path()
    info = idaapi.get_inf_structure()

    # check arch
    if info.is_64bit():
        arch_bits = 64
    elif info.is_32bit():
        arch_bits = 32
    else:
        raise Exception("Only support 32 or 64 bit arch.")

    base = idaapi.get_imagebase()
    sections, funcs = get_sections_func()
    jumptable_xref_info = get_jumptable_xref_info(funcs)

    cfg_record, callinfo_record, switch_record = get_cfg_block_info()

    with open(os.path.join(preprocess_dir, f"{file_name}_cfg.json"), "w") as f:
        json.dump(cfg_record, f, indent=4)
    
    with open(os.path.join(preprocess_dir, f"{file_name}_callinfo.json"), "w") as f:
        json.dump(callinfo_record, f, indent=4)
    
    with open(os.path.join(preprocess_dir, f"{file_name}_switch.json"), "w") as f:
        json.dump(switch_record, f, indent=4)