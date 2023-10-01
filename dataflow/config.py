class Config:
    """
    """
    def __init__(self):
        self.array_symbolic_index = True

        self.merge_expr_level = False

        self.strong_backward_update = False

        self.strong_update = True

        self.update_load_alias = True

        """
        The offset calculation method between stack and heap should be distinguished
        e.g., the stack pointer offset:
            Trace-expr: Load(0x7fff2408), with ins: STR [rdx + 0x8], 0x7fff2400
        and the heap pointer offset:
            Trace-expr: Load(rdi), with ins: TODO
        """
        self.offset_update = True

        # Whether push the callee's aptr definitions to the caller's callsite?
        self.push_aptr_summary = True

    def do_array_symbolic_index(self):
        return self.array_symbolic_index

    def get_merge_expr_level(self):
        return self.merge_expr_level

    def do_strong_backward_update(self):
        return self.strong_backward_update

    def is_strong_update(self):
        return self.strong_update

    def is_update_load_alias(self):
        return self.update_load_alias

    def do_offset_update(self):
        return self.offset_update

    def do_push_aptr_summary(self):
        return self.push_aptr_summary