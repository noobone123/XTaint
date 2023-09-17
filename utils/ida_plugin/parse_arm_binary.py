import sys
from headless_ida import HeadlessIda

ida_engine_path = sys.argv[1]
idb_path = sys.argv[2]
headlessida = HeadlessIda(ida_engine_path, idb_path)

import idautils
import ida_nalt
import idaapi
import idc
import ida_funcs
import ida_idaapi

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

def get_funcptr_xref_info(functions):
    """
    Read the data sections and find all function ptr reference in code section.
    """
    if arch_bits == 32:
        step = 4
    elif arch_bits == 64:
        raise NotImplementedError("Not support 64 bit arch yet.")
    
    funcptr_xref_info = {}

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
                        print(f"Make function at {hex(data)}")
                
                # if data at cur is a function ptr, find all reference(from code section) to cur
                # if a function has no xref (analyzed by ida), then we need to make it.
                for ref_addr in idautils.DataRefsTo(cur):
                    if in_code_section(ref_addr):
                        funcptr_xref_info[ref_addr] = cur
                        print(f"Found data reference to {hex(cur)} at {hex(ref_addr)} in code section")

            cur += step
    
    return funcptr_xref_info


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
    funcptr_xref_info = get_funcptr_xref_info(funcs)

    print(funcptr_xref_info)