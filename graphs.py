import pydasm


def function_flow_graph(bin):
  o = "digraph functions_%s {"%"".join([x for x in bin.filename if x.isalpha()])
  
  for x in bin.functions:
    o += "    func_%.8x [label=\"%s\"];\n" % (x.start_addr,hex(x.start_addr))
    for y in x.parents:
      o +=  "    func_%.8x -> func_%.8x;\n"%(x.start_addr, y)

  o += "}"
  open("digraph.dot",'w').write(o)


class block:
  #a block can fall through or branch elsewhere
  def __init__(self, start):
    self.start = start
    self.end = 0
    self.code = []
    self.branch1 = 0
    self.branch2 = 0
    
  def split(self, addr):
    print "splitting block @ %x from %x"%(self.start, addr)
    i = 0
    for instr in self.code:
      if hex(int(addr)) in instr:
        break
      i += 1
    
    for line in self.code:
      if hex(int(addr)) in line[:line.find(":")]:
        print line, '******* split'
      else:
        print line
    
    self.end = int(self.code[i-1].split(':')[0], 16)
    
    newblock = block(addr)
    newblock.code = self.code[i:]
    self.code = self.code[:i]
        
    if self.branch1:
      if self.branch1 < addr:
        self.branch2 = self.branch1
      else:
        newblock.branch2 = self.branch1
    
    self.branch1 = addr
    
    #check if second branch now belongs to newblock
    if self.branch2:
      newblock.branch1 = self.branch2
      self.branch2 = 0
    
    #print hex(self.branch1), hex(self.branch2)
    #print hex(newblock.branch1), hex(newblock.branch2)
    
    return newblock

def graph_function(bin, func):

  pc = func.start_addr
  blocks = {}
  curblock = hex(int(pc))
  blocks[curblock] = block(pc)
  while pc <= func.end_addr:
    instr = pydasm.get_instruction(bin.mem[pc:pc+15], pydasm.MODE_32)
    if not instr:
      break
    mnemonic = pydasm.get_instruction_string(instr, pydasm.FORMAT_ATT, pc)
    
    #add mnemon strings
    blocks[curblock].code.append("%s: %.30s"%(hex(int(pc)),mnemonic))
    
    if instr.type in [pydasm.INSTRUCTION_TYPE_JMP, pydasm.INSTRUCTION_TYPE_JMPC]:
      if instr.op1.immediate < 256:
        branchdest = pc + instr.op1.immediate + instr.length
        branchdest2 = pc + instr.length
        
        #add the branches to the current block
        blocks[curblock].branch1 = branchdest
        if instr.type == pydasm.INSTRUCTION_TYPE_JMPC:
          blocks[curblock].branch2 = branchdest2
        
        print "BLOCK @ %x"%branchdest2
        bname = hex(int(branchdest2))
        if bname not in blocks:
          blocks[bname]= block(branchdest2)
         
        print "BLOCK @ %x"%branchdest          
        bname = hex(int(branchdest))
        if bname not in blocks:
          blocks[bname]= block(branchdest)
        
        print "switching to block %x"%branchdest2
        blocks[curblock].end = pc
        curblock = hex(int(branchdest2))

    if curblock != hex(int(pc+instr.length)):
      if hex(int(pc+instr.length)) in blocks:
        print "picking up curblock %x"%(pc+instr.length)
        blocks[curblock].end = pc
        blocks[curblock].branch1 = pc+instr.length
        curblock = hex(int(pc+instr.length))

    pc += instr.length
  blocks[curblock].end = pc 

  for b in blocks:
    if blocks[b].branch1:
      for c in blocks:
        if blocks[c].start < blocks[b].branch1 and blocks[c].end >= blocks[b].branch1:
          print "split A"
          newblock = blocks[c].split(blocks[b].branch1)
          print "---------------"
          blocks[hex(int(newblock.start))] = newblock
    if blocks[b].branch2:
      for c in blocks:
        if blocks[c].start < blocks[b].branch2 and blocks[c].end >= blocks[b].branch2:
          print "split B"
          newblock = blocks[c].split(blocks[b].branch2)
          blocks[hex(int(newblock.start))] = newblock
          print blocks[c]
          for j in blocks[c].code:
            print j

  
  o = "digraph function_%x_%s {\n"%(func.start_addr, func.name)  
  for b in blocks:
    code = "\n".join(blocks[b].code)
    o += "    block_%s [shape=box align=left label=\"%r\"];\n"%(b, code)
    if blocks[b].branch1:
      o += "    block_%s -> block_0x%x;\n"%(b, blocks[b].branch1)
    if blocks[b].branch2:
      o += "    block_%s -> block_0x%x;\n"%(b, blocks[b].branch2)
  o += "}\n"
  
  open("graphsx/digraph%x-funcs.dot"%func.start_addr,'w').write(o)
    
def graph(bin):
  #function_flow_graph(bin)
  for func in bin.functions:
    graph_function(bin, func)
  #graph_function(bin, bin.find_func(0x804a100))
  #import x86
  #x86.x86_disas_func(bin, 0x804a100)

