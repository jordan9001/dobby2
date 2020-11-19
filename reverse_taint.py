# takes a trace from Dobby, and uses Binary Ninja or Ghidra to trace where the desired value comes from
# right now this is just a place for my notes and some scrap code

addr = current_address
func = bv.get_functions_containing(addr)[0]
fl = func.llil
i_start = fl.get_instruction_start(addr)

i_end = i_start + 1
while fl[i_end].address == addr:
    i_end += 1

fl[i_start].ssa_form
    #operation, and operands

# maybe it would be better to use PCode, binja's llil depends on the function it is in too much?
# hmm, I'll try it first

# If I use Ghidra I need to fix up Ghidra's PE loading issues for my target
# it might work better in this situation. PCode doesn't depend on the surrounding function
# or play with Triton's internal semantics?

# go through some ssa IR and build a tree out to find dependancies for the item
# keep going on the tree until some max depth, or get them all
# interesting values are leave nodes that are not constant values in the image
