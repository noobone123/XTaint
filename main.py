import sys
import argparse
import pathlib
import json
import os
import shutil
import angr

from utils.ida_plugin import ida_preprocess
from utils.bin_factory import BinFactory, BinaryInfo
from utils.logger import get_logger
from dataflow.solver import DataflowSolver
from dataflow.config import Config
from dataflow.core import FastDataFlow
from dataflow.core import AccurateDataFlow
import global_config

CONFIG = pathlib.Path(__file__).parent / "config.json"

logger = get_logger("Analyzer")
logger.setLevel("INFO")

class EmTaintAnalyzer():
    def __init__(self, firmware_name: str, 
                    binary_filepath: str):

        self.binary_filepath = os.path.abspath(binary_filepath)
        self.firmware_name = firmware_name
        self.binary_name = os.path.basename(self.binary_filepath)

        # Load configures
        try:
            with open(CONFIG, "r") as f:
                self.config = json.load(f)
                logger.info("^^^^^^^^^^^ Current Config ^^^^^^^^^^^")
                logger.info(json.dumps(self.config, indent=4))
                logger.info("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^")
        except Exception as e:
            logger.error("Error: {}".format(e))
            sys.exit()
        
        # init data storage folder used by analyzer
        self.data_home_dir = self.config["data"]["data_home"]
        # make following path as absolute path
        self.firmware_dir = os.path.abspath(os.path.join(self.data_home_dir, self.firmware_name))
        self.binary_dir = os.path.abspath(os.path.join(self.firmware_dir, self.binary_name))
        self.ida_preprocess_dir = os.path.abspath(os.path.join(self.binary_dir, "ida_preprocess"))
        self.result_dir = os.path.abspath(os.path.join(self.binary_dir, "result"))

        self.init_data_storage()


    def init_data_storage(self):
        if not os.path.exists(self.ida_preprocess_dir):
            os.makedirs(self.ida_preprocess_dir)
            logger.info("Create ida processed dir: {}".format(self.ida_preprocess_dir))
        
        # force to reanalyze, delete the old result
        if os.path.exists(self.result_dir):
            shutil.rmtree(self.result_dir)
            logger.info("Delete old analyze target result dir: {}".format(self.result_dir))
        os.makedirs(self.result_dir)


    def init_binary_sections(self):
        """
        Extract binary info from angr project and initialize global info.
        """
        main_obj = self.proj.loader.main_object

        code_region_names = ['.text']
        ro_region_names = ['.rodata', '.rdata', '.got', '.init_array', '.plt']
        rw_region_names = ['.data', '.data.rel.ro', '.data.rel.ro.local',]
        bss_region_names = ['.bss', '.sbss']
        choose_region_names = ro_region_names + rw_region_names + bss_region_names + code_region_names

        for section in main_obj.sections:
            region_name = section.name
            if region_name in choose_region_names:
                start = section.vaddr
                end = section.vaddr + section.memsize
                self.binary_info.sections[region_name] = (start, end)
                logger.info("Section: {}, start: {}, end: {}".format(region_name, hex(start), hex(end)))

        min_addr, max_addr = self.proj.loader.min_addr, self.proj.loader.max_addr
        self.binary_info.sections['.loader'] = (min_addr, max_addr)
        logger.info("Section: {}, start: {}, end: {}".format('.loader', hex(min_addr), hex(max_addr)))
        
        extern_obj = self.proj.loader.extern_object
        self.binary_info.sections['.extern'] = (extern_obj.min_addr, extern_obj.max_addr)
        logger.info("Section: {}, start: {}, end: {}".format('.extern', hex(extern_obj.min_addr), hex(extern_obj.max_addr)))


    def run(self):
        """
        Running the `EmTaintAnalyzer`
        """
        ida_preprocess(self.binary_filepath, self.ida_preprocess_dir, self.config)

        self.proj = angr.Project(self.binary_filepath)
        self.binary_info = BinaryInfo(self.proj)
        self.init_binary_sections()

        # initialize global config related to archinfo
        global_config.initialize_global_config(self.proj)
        
        bin_factory = BinFactory(self.proj, 
                                 self.ida_preprocess_dir,
                                 self.binary_info)
        
        # TODO: add start_func into args
        start_funcs_addr = [0x9858]
        start_functions = []
        for start_func_addr in start_funcs_addr:
            start_functions.append(bin_factory.cg.get_node(start_func_addr))

        
        # add config used in dataflow solver
        custom_config = Config()
        fast_dataflow = FastDataFlow(self.proj, loop_execute_times = 3, summary_loop = True)
        accurate_dataflow = AccurateDataFlow(
            self.proj, bin_factory.cg,
            config=custom_config
        )

        dataflow_solver = DataflowSolver(self.proj,
                                        bin_factory,
                                        self.binary_info,
                                        start_functions,
                                        fast_dataflow,
                                        accurate_dataflow)
        dataflow_solver.solve()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Firmware Binary Static Analysis Tool.")
    parser.add_argument("-f", "--firmware_name", help="the firmware name, used for binary info generated by Ida Pro")
    parser.add_argument("-b", "--binary_file", help="single binary file path in firmware")
    # parser.add_argument("-i", "--icall_check", default=False, help="icall check?", action="store_true")
    # parser.add_argument("-t", "--taint_check", default=False, help="taint check?", action="store_true")
    # parser.add_argument("-s", "--switch_check", default=False, help="check and resolve the switch jmp", action="store_true")
    
    # parser.add_argument("-v", "--firmware_version", help="the firmware version, used for different binary path")
    # parser.add_argument("--resolve_icall", default=1, type=int, help="If reolve indirect call while doing taint analysis")
    # parser.add_argument("-a", "--alias_check", default=False, help="find alias", action="store_true")
    # parser.add_argument("--infer_source", default=False, help="Infer taint sources to do taint analysis", action="store_true")
    # parser.add_argument("--debug", default=False, help="check and resolve the switch jmp", action="store_true")
    # parser.add_argument("--load_ida_bytes", default=False, help="whether load binary bytes from IDA Pro", action="store_true")
    args = parser.parse_args()

    if not args.binary_file or not args.firmware_name:
        parser.print_help()
        sys.exit()

    analyzer = EmTaintAnalyzer(args.firmware_name, args.binary_file)
    analyzer.run()
