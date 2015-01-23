import idaapi
from idaapi import Form, Choose2, plugin_t # for gui stuff
import idc
import idautils
import inspect
import struct
import binascii

"""Help with analyzing binary and bootrom libraries for various CPU architectures

This module wraps IDA Pro's IDAAPI, IDC, and IDAUTILS python libraries to
provide useful and (hopefully) easy-to-use search functions for a disassembly.

The base BinAnalyze class provides some very basic search and function
creation funcionality, while processor-specific analyzers are expected to
increase its usefulness.

Note: please import this module using:
idaapi.require()
Especially while testing and modifying it
(see http://www.hexblog.com/?p=749 for information on why)


"""

class BinAnalyze():
    def __init__(self):
        return

    """
    The 'get' mnemonics are meant to be implemented in a derived class.
    These methods are CPU-dependent.
    """
    def getCpuRegs(self):
        if hasattr(self, '_regs'):
            return self._regs
        else:
            raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def getAddressRegs(self):
        if hasattr(self, '_addr_regs'):
            return self._addr_regs
        else:
            raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def getDataRegs(self):
        if hasattr(self, '_data_regs'):
            return self._data_regs
        else:
            raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def getAssignMnems(self):
        if hasattr(self, '_assign_mnem'):
            return self._assign_mnem
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def getBranchMnems(self):
        if hasattr(self, '_branch_mnem'):
            return self._branch_mnem
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def getCallMnems(self):
        if hasattr(self, '_call_mnem'):
            return self._call_mnem
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def getCmpMnems(self):
        if hasattr(self, '_cmp_mnem'):
            return self._cmp_mnem
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def getSignedMnems(self):
        if hasattr(self, '_signed_mnem'):
            return self._signed_mnem
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def getSignExtendMnems(self):
        if hasattr(self, '_signed_extend_mnem'):
            return self._signed_extend_mnem
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def getUnsignedMnems(self):
        if hasattr(self, '_unsigned_mnem'):
            return self._unsigned_mnem
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def getZeroMnems(self):
        if hasattr(self, '_zero_mnem'):
            return self._zero_mnem
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def getNotZeroMnems(self):
        if hasattr(self, '_nonzero_mnem'):
            return self._nonzero_mnem
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def getModMnems(self):
        if hasattr(self, '_mod_mnem'):
            return self._mod_mnem
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")
    def getXorMnem(self):
        if hasattr(self, '_xor_mnem'):
            return self._xor_mnem
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")

    def findConstantUse(self, const):
        """
        This will attempt to find *all* constant load operations for your target architecture.
        @args: const: string value of data we're looking for.  Use struct.pack().  Assumes cpu-native endianness,
        you may want to pack in opposite endianess for thoroughness.
        """
        """
        Notes: 

        idc.GetOpType() returns operand type.  optype 2 is memory xref, and GetOperandValue() will hold the value.

        """
        # Step 1: Search for straight-up bytes in memory
        # first build a binary search string based on the input string
        searchstr = ""
        for b in const:
            searchstr += binascii.hexlify(b) + " "
        ea = 0
        while ea != BADADDR:
            ea = idc.FindBinary(ea, idc.SEARCH_DOWN, searchstr) # optional radix value?
            if ea != BADADDR:
                # let's look at data xrefs, places where this memory is loaded
                raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")


    def findXorOps(self):
        """
        This attempts to find all xor operations where the source and destination of the xor are different.
        """
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")



    def findConstantComparesFromStart(self, startea, value):
        """
        This will attempt to find constant load operations reachable from a particular start address.  It will
        then trace the data from the start location to the comparison operation.  If the comparison is a direct compare
        (for architectures which support it), it will also identify those.  

        Results will be an array of tuples of (loadea, cmpea).  If the architecture does not require a load instruction first,
        the tuple will contain (None, cmpea).

        For example if an instruction directly loads a value into a register, it should identify all eas.
        It should also identify all eas with an indirect memory access, for example loading data from an address
        where memory for that address is available, it should identify the ea of any such instruction too.
        This will be highly dependent upon architecture for implementation..."""
        # targetEas = self.findAccessibleEas(startea)
        # First look for direct comparisons (easiest method):
        # for ea in targetEas:
        #    if self.getAssignMnem(ea)
        raise NotImplementedError(inspect.stack()[0][3],": You need to implement a cpu-specific binary analyzer for this feature")



    """
    Now we get to the functions that should be the same for all architectures
    """
    # traceData will eventually offer psuedo-emulation:
    # from a start ea will trace a particular variable
    def traceData(self, ea):
        # actually not the way we want to do it. the instruction can be any instruction, 
        # so long as it is either nonmutable *OR* the target of the trace is only an input
        # parameter.
        # 
        if hasattr(self, '_nonmutable_mnem'):
            # very complicated code
            # Basically we want to trace a variable as it gets moved around registers,
            # for immutable comparisons
            # for example
            raise NotImplementedError(inspect.stack()[0][3], ": Not implemented yet")
        raise NotImplementedError(inspect.stack()[0][3], ": Not implemented yet")

    def searchIntOverflows(self, startea):
        """
        Search for integer overflows.  We define integer overflows as anywhere that a MATH operand (add, subtract, multiply, divide)
        changes the value of a target register or memory.  No compare may happen to that the memory or register before it is used in
        a call or an assignment.  Determining if it is used in an assignment is easy enough: see if the value is copied to another
        array or register.  Determining if it is used in a call operation will involve tracking the register/memory and seeing if it
        is used as a parameter.  Tackling that will take a little more thinking still...

        We really want to search for instruction that adds to a target (hone in on the target of the add, this will be arch-specific)
        then we want to find accessible eas from that spot.  Accessible eas will be both sides of any branch if the branch was not
        a compare to our target ea.

        """
        # You will need to implement a version of this for each architecture?
        # find all accessible eas first
        targetEas = BinAnalyze.findAccessibleEas(self, startea)
        # Now search those eas for add, subtract, whatever eas
        targetEas = BinAnalyze.filterEasbyMnems(targetEas, self.getModMnems())
        # Now that we have just the modification eas, look at each one...
        for ea in targetEas:
            # Need to implement this function: it will return idc argtype and argument text for the output of the modification
            argtype, arg = self._mod_mnem_target_arg(arg)
            # Then we will need to find any compare operands 
            continue
        return

    # useful functions:
    # idc.FirstSeg() gets the first ea of the first segment of disasembly

    @staticmethod
    def filterEasbyMnems(ealist, mnemlist):
        """ This method filters a list of eas in ealist.  If the mnemonic of the ea is in mnemlist, 
        it is added to the response.
        """
        resulteas = []
        for ea in ealist:
            if BinAnalyze.getInsn(ea) in mnemlist:
                resulteas.append(ea)
        return resulteas

    @staticmethod
    def displayInstructionList(ealist):
        return


    # Unlike the idc.GetMnem, this will return the on-screen instruction
    # mnemonic exactly as it is printed.
    # results are always in lowercase.
    @staticmethod
    def getInsn(ea):
        return idc.GetDisasm(ea).split()[0].lower() # idc.GetDisasm


    @staticmethod
    def findMnemsInList(ealist, mnemlist):
        result = []
        for ea in ealist:
            mnem = GetInsn(ea) # BinAnalyze.GetInsn()
            if mnem in mnemlist:
                result.append(ea)
        return result

    def makeFuncsFromPreamble(funcpreamble, startea=idc.FirstSeg(), endea = idaapi.BADADDR):
        """ This method makes functions everywhere that the sequence 'funpreamble' is found.
            NOTE: this method is generally unsafe, because it will attempt to make functions where
            there may be no function.  Use it with caution.
        """
        ea = startea
        i = 0
        while (ea != idaapi.BADADDR and ea < endea):
            ea = idc.FindBinary(ea, SEARCH_DOWN, funcpreamble)
            makeFunction(ea)
            idc.Wait()
            ea = ea + 1 # idc.FindBinary(ea) returns ea if ea matches, silly

    @staticmethod
    def _allFlows(ea):
        reachable = []
        r = idc.Rfirst(ea) # first code flow from ea
        while r != idaapi.BADADDR:
            if r not in reachable: # not sure if ida can do circular flows...
                reachable.append(r)
            r = idc.Rnext(ea, r) # continue appending
        r = idc.Rfirst0(ea) # the '0' flows are "non-ordinary" flows. I don't remember what this means,
        # I just remember that we have to check them!
        while r != idaapi.BADADDR:
            if r not in reachable:
                reachable.append(r)
            r = idc.Rnext0(ea, r)
        return reachable


    @staticmethod
    def _hex_print_array(array):
        print "[",
        for ea in array:
            print hex(ea), ",",
        print "]"

    """_findAccesibleEasHelper()
    This was originally meant to be a tail recursive method, but Python is dumb and does not support tail recursion collapse.
    So, instead we have to do this ugly thing where we build 'tail recursion as a while-True'

    """
    @staticmethod
    def _findAccessibleEasHelper(todolist, donelist):
        while True:
            newtodos = []
            #print "current todolist is", 
            #BinAnalyze._hex_print_array(todolist)
            for todo in todolist:
                if todo in donelist:
                    continue # already did it, continue for loop
                # determine if we have new things to do
                for flow in BinAnalyze._allFlows(todo):
                    if flow not in donelist and flow not in todolist and flow != idaapi.BADADDR:
                        newtodos.append(flow) # new flow has not been analyzed, and not scheduled
                        donelist.append(todo) # current todo is done, now
            if len(newtodos) == 0:
                return donelist # done, pop!
            else:
                #print "--> newtodos is",
                #BinAnalyze._hex_print_array(newtodos)
                todolist = newtodos
                continue

    @staticmethod
    def findAccessibleEas(startea):
        """ Use recursion to find accessible code.  For example if you find an interrupt handler,
            you can use this to find every instruction accessible from that interrupt handler
        """
        todolist = []
        todolist.append(startea)
        donelist = []
        return BinAnalyze._findAccessibleEasHelper(todolist, donelist)

    @staticmethod
    def findAccessibleCode(startea):
        """alias for findAccessibleEas()"""
        return findAccessibleEas(startea)

    @staticmethod
    def buildFuncEaDictionary(ealist):
        """return a diction of function address:[code addresses] from a list of eas
        This is useful for filtering interesting instructions by function."""
        myDict = {}
        for ea in ealist:


    @staticmethod
    def findInterestingData():
        """
        This method is kind of a catch-all for interesting signatures to search for.
        Recommendations include CRC algorithm lookup tables, crypto algorithm s-boxes, hashing algorithm lookup tables, etc

        You'll want to look for each of the interesting table entries as well as data xrefs to those entries
        You'll also want to look up assignment instructions which load those entries (maybe fixed value or maybe by memory reference).

        """
        return


    @staticmethod
    def getInt(ea, length, endianness = "little"):
        """
        returns the value of the value of ea as an unsigned int of 'length' bytes.
        'length' can be anything, from a single byte to many many bytes (up to maximum number size of Python)
        useful for cpus that have tribytes, or if code does 'stupid endian stuff'.
        """
        mybytes = idc.GetManyBytes(ea, length)
        retval = 0
        if "little" == endianness:
            counter = length # e.g. 4
            while counter > 0:
                retval += ord(mybytes[counter-1]) << ((counter-1) * 8)
                counter -= 1
        elif "big" == endianness:
            counter = 0
            while counter < length:
                retval += ord(mybytes[counter]) << ((length - 1 - counter) *8)
                counter += 1
        return retval
