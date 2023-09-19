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

def run_ida_headless(cmd):
    ret = os.system(cmd)
    if ret != 0:
        raise Exception("Run IDA headless failed: %s" % cmd)

def ida_preprocess(binary_path, ida_preprocess_dir, config):
    """
    Use IDA Pro to preprocess binary file, and save the result to ida_preprocess_dir
    """
    ida_home = config["ida_pro"]["ida_home"]
    binary_name = os.path.basename(binary_path)

    # TODO: add a config to decide whether put idb in /tmp or in ida_preprocess
    # idb_tmpdir = config["ida_pro"]["idb_tmpdir"]

    arch, bit = get_binary_arch(binary_path)
    if bit == 32:
        ida_engine = os.path.join(ida_home, "idat")
        idb_path = os.path.join(ida_preprocess_dir, f"{binary_name}.idb")
    elif bit == 64:
        ida_engine = os.path.join(ida_home, "idat64")
        idb_path = os.path.join(ida_preprocess_dir, f"{binary_name}.i64")
    else:
        raise Exception("Unknown binary arch")
    
    # TODO: add x86 and mips support
    if arch == "arm":
        ida_script_path = os.path.join(os.path.dirname(__file__), "parse_arm_binary.py")
    else:
        raise NotImplementedError("Not support arch: %s" % arch)
    
    # create idb first
    if not os.path.exists(idb_path):
        print("Creating idb file: %s" % idb_path)
        cmd = f"{ida_engine} -B -o{idb_path} {binary_path}"
        run_ida_headless(cmd)
        print("Created idb file: %s" % idb_path)
    
    # if ida preprocess already done, skip
    if os.path.exists(os.path.join(ida_preprocess_dir, "callinfo.json")) and \
        os.path.exists(os.path.join(ida_preprocess_dir, "cfg.json")) and \
        os.path.exists(os.path.join(ida_preprocess_dir, "switch.json")):
        print("IDA preprocess already done!")
        return

    # run ida script
    cmd = f"python3 {ida_script_path} {ida_engine} {idb_path} {ida_preprocess_dir}"
    print("Running command: %s" % cmd)
    run_ida_headless(cmd)
    print("IDA preprocess done!")
