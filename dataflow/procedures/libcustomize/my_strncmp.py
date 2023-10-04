import dataflow

class my_strncmp(dataflow.SimProcedure):
    """
    my_strncmp(const char *str1, const char *str2, size_t n)
    """
    def run(self, str1, str2, n):
        if self.flow_dir == 'F' and self.purpose == 0:
            self.add_special_constraint_v2(str1, str2, cons_type=2, name='strncmp', cmp_flag=2)
        return 1

    def infer_type(self, str1, str2, n):
        self.label_variable_type(str1, 'ptr')
        self.label_variable_type(str2, 'ptr')
        self.label_variable_type(n, 'N')
        self.label_return_type('N')
