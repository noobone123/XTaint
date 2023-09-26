
class BasicBlock():
    def __init__(self, bb_start,
                 bb_end,
                 funcea,
                 ):
        self.bb_start = bb_start
        self.bb_end = bb_end
        self.funcea = funcea

        self.contain_blocks = []
        self.callsites = {}

    @property
    def addr(self):
        return self.bb_start

    def __repr__(self):
        return "<Block 0x%x (0x%x, 0x%x)>" % (self.funcea, self.addr, self.bb_end)

    def __eq__(self, other):
        if not isinstance(other, BasicBlock):
            return False
        return (self.addr == other.addr)

    def __hash__(self):
        return hash(self.addr)