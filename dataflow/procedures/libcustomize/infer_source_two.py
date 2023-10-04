
import dataflow

class infer_source_two(dataflow.SimProcedure):
    """
    This is a summary function that denotes the infer source.
    source(key, value, len).
    """

    def run(self, arg1, arg2, arg3, arg4):
        print("execute the infer source two %x" % (self.block.addr))
        print("taint info: %s" % (self.arguments_info['taint_info']))
        if self.block.exec_taint == 0 and self.purpose == 0:
            describe = {}
            args = [arg1, arg2, arg3, arg4]
            taint_info = self.arguments_info['taint_info']
            print("Inital taint source in %s with %s" % (self.block, args))
            if 'source' in taint_info:
                # src_arg = args[taint_info['source']-1]
                src_arg = taint_info['source']
                describe[src_arg] = 'src'
            if 'taint' in taint_info:
                # taint_arg = args[taint_info['taint']-1]
                taint_arg = taint_info['taint']
                describe[taint_arg] = 'dst'
            if 'len' in taint_info:
                # length_arg = args[taint_info['len']-1]
                length_arg = taint_info['len']
                describe[length_arg] = 'length'
            print("describe: %s" % describe)
            self.initial_arguments_taint_source(describe)
            self.block.exec_taint = 1

        return 1

    def infer_type(self, arg1, arg2, arg3, arg4):
        pass
        # self.label_variable_type(fd, 'N')
        # self.label_variable_type(buf, 'ptr')
        # self.label_variable_type(length, 'N')
        # self.label_variable_type(flags, 'N')
        # self.label_return_type('N')
