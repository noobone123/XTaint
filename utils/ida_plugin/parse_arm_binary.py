import sys
from headless_ida import HeadlessIda

ida_engine_path = sys.argv[1]
idb_path = sys.argv[2]
headlessida = HeadlessIda(ida_engine_path, idb_path)

import idautils
import ida_name
import ida_nalt
import ida_idaapi
import idaapi
import ida_segment
import idc

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

def recover_func_fromdata(functions):
    """
    Read the data region and recovery functions.
    """
    if arch_bits == 32:
        pass
    elif arch_bits == 64:
        raise NotImplementedError("Not support 64 bit arch yet.")

    data_region = []
    for s in sections.keys():
        perm = sections[s][2]
        if perm == 6:   # r+w
            pass
            # TODO: Next


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
    sections, func = get_sections_func()
    recover_func_fromdata(func)