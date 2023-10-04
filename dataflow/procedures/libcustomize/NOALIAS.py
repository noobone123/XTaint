
import dataflow

class NOALIAS(dataflow.SimProcedure):
    """
    NOALIAS(p1, p2): pointer p1 and p2 are not alias.
    """

    def run(self, arg1, arg2):
        print("execute NOALIAS %x" % (self.block.addr))
        self.check_alias(arg1, arg2, 'not')
        return 1

    def infer_type(self, arg1, arg2):
        self.label_variable_type(arg1, 'ptr')
        self.label_variable_type(arg2, 'ptr')
        # self.label_variable_type(length, 'N')
        # self.label_variable_type(flags, 'N')
        # self.label_return_type('N')
