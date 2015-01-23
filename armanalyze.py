import binanalyze


# We may have to split this into ARM and THUMB Analyzer classes :P

class ArmAnalyze(binanalyze.BinAnalyze):
    aa = "aa"
    _aa = '_aa'
    _cpuregs = []
    def __init__(self):
        print "ArmAnalyze: init called"
        self._cpuregs = ["r0", "r1", "r2", "r3", "r4", \
                         "r5", "r6", "r7", "r8", "r9", \
                         "r10", "r11", "r12", "sp", \
                         "lr", "pc", "cpsr"]
        # note there are no address of data specific registers for ARM
        # self._addr_regs = None
        # self._data_regs = None

        # __suffix_list is used for building a list of conditional instructions from the other instructions
        # this helps us find conditionals/branches/etc
        self._suffix_list = ["eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"] # note: cs/hs and cc/lo are actually the same, not sure if ida always represents them one way or the other
        self._suffix_signed = ["ge", "lt", "gt", "le"]
        self._suffix_unsigned = ["cs", "hs", "cc", "lo", "hi", "ls"]
        self._suffix_zero = ["eq"] # eq
        self._suffix_nz = ["ne"] # nz
        self._sign_extend_mnem = ['sxtb', 'sxtw']

        # build up exclusive or operations with all flags
        self._xor_mnem = ["eor"]
        self._temp = []

        #TODO: make a pretty wrapper to build up the suffixes for each instruction type


        for mnem in self._xor_mnem:
            for suffix in self._suffix_list:
                self._temp.append(mnem + suffix)
        for mnem in self._temp:
            self._xor_mnem.append(mnem)


        # for conditional instructions, too
        self._assign_mnem = ["ldr", "mov", "add", "sub"]
        self._mod_mnem = ["add", "sub", "mult", "div"]
        # Need to append the flag set suffix to all mnems that can have it...oye!
        self._flag_set_suffix = ["s"]

        self._cmp_mnem = ["cmp"]
        self._call_mnem = ["b"] # do we need to add conditional forms of instructions?
        self._temp = []
        for mnem in self._call_mnem:
            for suffix in self._suffix_list:
                self._temp.append(mnem + suffix)
        for mnem in self._temp:
            self._call_mnem.append(mnem)

        self._branch_mnem = ["b"] # a problem with ARM is that every mnem is conditional...do we call those 'branches'? :(.
        # let's call all those conditionals branches
        self._all_mnem = []
        for mnem in self._assign_mnem:
            self._all_mnem.append(mnem)
        for mnem in self._cmp_mnem:
            self._all_mnem.append(mnem)
        for mnem in self._call_mnem:
            self._all_mnem.append(mnem)

        # build a list of signed mnemonics.  We'll do this for unsigned, zero, etc too
        self._signed_mnem = []
        self._temp = []
        for m in self._all_mnem:
            for signedsuffix in self._suffix_signed:
                self._temp.append(m+signedsuffix)
        for mnem in self._temp:
            self._signed_mnem.append(mnem)
        self._unsigned_mnem = []
        self._temp = []
        for m in self._all_mnem:
            for unsignedsuffix in self._suffix_unsigned:
                self._temp.append(m+unsignedsuffix)
        for mnem in self._temp:
            self._unsigned_mnem.append(mnem)




    """
    This method will take an input mnemonic and return all of its conditional forms.
    It totally ignores whether the mnemonic is one that can't have conditional forms (ex: pld, blx, and others use the
    conditional bits, this will still return a list of conditional uses of those instructions, sorry).
    It will not return the original mnemonic as part of the list
    """
    def __getConditionals(self, mnem):
        resp = []
        for suffix in self._suffix_list:
            resp.append(mnem + "." + suffix)
        return



