import sys
from headless_ida import HeadlessIda

ida_engine_path = sys.argv[1]
idb_path = sys.argv[2]
headlessida = HeadlessIda(ida_engine_path, idb_path)

import idautils
import ida_name

for func in idautils.Functions():
    print(f"{hex(func)} {ida_name.get_ea_name(func)}")