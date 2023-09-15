#!/usr/bin/env python3
import os
import configparser
import subprocess

def get_binary_arch(binary_path):
    """
    run file command to get binary arch
    """
    cmd = "file %s" % binary_path
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if p.returncode == 0:
        if "32-bit" in stdout.decode():
            bit = 32
        elif "64-bit" in stdout.decode():
            bit = 64
        else:
            raise Exception("Unknown binary arch: %s" % stdout.decode())
        
        if "ARM" in stdout.decode():
            arch = "arm"
        elif "MIPS" in stdout.decode():
            arch = "mips"
        elif "x86" in stdout.decode():
            arch = "x86"
        else:
            raise Exception("Unknown binary arch: %s" % stdout.decode())
        
        return (arch, bit)
    else:
        raise Exception("get binary arch failed: %s" % stderr)


def ida_preprocess(binary_path, ida_preprocess_dir, config):
    """
    Use IDA Pro to preprocess binary file, and save the result to ida_preprocess_dir
    """
    ida_home = config["ida_pro"]["ida_home"]
    idb_tmpdir = config["ida_pro"]["idb_tmpdir"]

    arch, bit = get_binary_arch(binary_path)
    if bit == 32:
        ida_engine = os.path.join(ida_home, "idat")
    elif bit == 64:
        ida_engine = os.path.join(ida_home, "idat64")
    else:
        raise Exception("Unknown binary arch")
    
    idb_path = os.path.join(idb_tmpdir, "ida_preprocess.idb")
    
    # TODO: add x86 and mips support
    if arch == "arm":
        ida_script_path = os.path.join(os.path.dirname(__file__), "parse_arm_binary.py")
        print(ida_script_path)
    else:
        raise NotImplementedError("Not support arch: %s" % arch)

    # # TODO: to be done...
    # print("start analyze binary using ida...")
    # if os.path.exists(ida_engine_path):
    #     os.system('%s %s %s %s' % (ida_start, ida_engine_path, binary_path, idb_save_path))
    #     os.system("TVHEADLESS=1 %s -A -S'%s %s ' %s > /dev/null" % (ida_engine_path, ida_get_cfg, ida_data_path, idb_save_path))
    #     # print("idb-path: %s" % (idb_save_path))
    #     # os.system("%s -S'%s %s ' %s" % (ida_engine_path, ida_get_cfg, ida_data_path, idb_save_path))
