
import dataflow
from dataflow.core.data_process import inital_source_arguments

class BIO_gets(dataflow.SimProcedure):
    """
    BIO_read(BIO *bio, void *buf, int len)
    """

    def run(self, bio, buf, length):
        # print("Get source BIO_gets in %s" % (self.block))

        if self.block.exec_taint == 0 and self.purpose == 0:
            print("Inital taint source in %s" % (self.block))
            describe = {bio: 'src', buf: 'dst', length: 'length'}
            self.initial_arguments_taint_source(describe)
            self.block.exec_taint = 1

        else:
            pass
            # print("Has initial before in %s" % (self.block))

        return 1

    def infer_type(self, bio, buf, length):
        # print("infer type in BIO_gets")
        self.label_variable_type(bio, 'ptr')
        self.label_variable_type(buf, 'ptr')
        self.label_variable_type(length, 'N')
        self.label_return_type('N')
