
class CodeLocation(object):
    """
    Stands for a specific program point by specifying basic block address 
    and statement ID (for IRSBs), or SimProcedure name (for SimProcedures).

    looks like that each stmt (excluding the IMark and IExit) of IRSB has an unique CodeLocation
    """
    
    def __init__(self, block_addr, stmt_idx, sim_procedure=None, ins_addr=None, unique_id=0, **kwargs):
        """
        Constructor.

        :param int block_addr:      Address of the block
        :param int stmt_idx:        Statement ID. None for SimProcedures
        :param class sim_procedure: The corresponding SimProcedure class.
        :param int ins_addr:        The instruction address. Optional.
        :param kwargs:              Optional arguments, will be stored, but not used in __eq__ or __hash__.
        """

        self.block_addr = block_addr
        self.stmt_idx = stmt_idx
        self.sim_procedure = sim_procedure
        self.ins_addr = ins_addr
        self.unique_id = unique_id

        self.info = { }

        self._store_kwargs(**kwargs)

    def copy(self):
        return CodeLocation(self.block_addr, self.stmt_idx, self.sim_procedure, self.ins_addr, self.unique_id)

    def __repr__(self):
        if self.block_addr is None:
            return '<%s>' % self.sim_procedure

        else:
            if self.stmt_idx is None:
                s = "<%s%#x(-)" % (
                    ("%#x " % self.ins_addr) if self.ins_addr else "",
                    self.block_addr
                )
            else:
                s = "<%s%#x[%d]" % (
                    ("%#x id=" % self.ins_addr) if self.ins_addr else "",
                    self.block_addr,
                    self.stmt_idx
                )

            # ss = [ ]
            # if self.info:
            #     for k, v in self.info.iteritems():
            #         ss.append("%s=%s" % (k, v))
            #     s += " with %s" % ", ".join(ss)
            s += ">"

            return s

    @property
    def short_repr(self):
        if self.ins_addr is not None:
            return "%#x" % self.ins_addr
        else:
            return repr(self)

    def __eq__(self, other):
        """
        Check if self is the same as other.
        """
        if other:
            return self.block_addr == other.block_addr and self.stmt_idx == other.stmt_idx and self.unique_id == other.unique_id
        return False

    def __hash__(self):
        """
        returns the hash value of self.
        """
        return hash((self.block_addr, self.stmt_idx, self.unique_id))

    def _store_kwargs(self, **kwargs):
        for k, v in kwargs.items():
            self.info[k] = v
