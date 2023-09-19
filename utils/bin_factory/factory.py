import os
import json
import angr

class BinFactory(object):
    """
    Generate CFG and CallGraph by the block and jump info extracting from 
    IDA Pro.
    """
    def __init__(self, angr_proj, ida_preprocess_dir):
        
        self.angr_proj = angr_proj

        callinfo_path = os.path.join(ida_preprocess_dir, 'callinfo.json')
        cfg_path = os.path.join(ida_preprocess_dir, 'cfg.json')
        switch_path = os.path.join(ida_preprocess_dir, 'switch.json')

        self.cfg_record = json.load(open(cfg_path, 'r'))
        self.callinfo_record = json.load(open(callinfo_path, 'r'))

        # in some cases, `self.functions` is not same as `self.cfg_record`
        self.functions = self.cfg_record

        # build the Factory!
        self._build()


    def _build(self):
        self.fast_build()


    def fast_build(self):
        """
        Fast build CFG and CallGraph by the block and jump info extracting from IDA Pro.
        """
        func_cnt = 0

        for func in self.functions:
            blocks = self.cfg_record[func]['block']
            edges = self.cfg_record[func]['control-flow']
            func_name = self.cfg_record[func]['name']

            print(func)