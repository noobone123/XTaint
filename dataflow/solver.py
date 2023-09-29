import logging
import angr
import time

from typing import List, Dict, Tuple, Set

from utils.bin_factory import BinaryInfo, BinFactory

logger = logging.getLogger("DataflowSolver")
logger.setLevel("INFO")

class DataflowSolver():
    def __init__(self, proj: angr.Project,
                    bin_factory: BinFactory,
                    binary_info: BinaryInfo,
                    start_func: List = []):
        self.proj = proj
        self.bin_factory = bin_factory
        self.binary_info = binary_info
        self.start_func = start_func

    def solve(self):
        """
        Solve the dataflow of the binary.
        """
        logger.info("Start to solve the dataflow of the binary...")
        time_start = time.time()
        self._initial_lib_procedure()
        self._solve()
        time_end = time.time()
        logger.info("Solve the dataflow of the binary done, time cost: {}s".format(time_end - time_start))

    
    def _solve(self):
        """
        Solve the dataflow of the binary.
        """
        if not self.start_func:
            start_function = self.bin_factory.cg.get_start_nodes()
        else:
            logger.info("Start function: {}".format(self.start_func))

    def _initial_lib_procedure(self):
        """
        Initial the library procedure.
        """
        pass