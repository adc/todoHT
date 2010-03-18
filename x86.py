import sys
#sys.path.append("/cs/radoca/libs/")
from target import *
import struct
import pydasm
import colors

def get_ascii_string(target, addr, pid=0, length=100):
  ret = ""

  if target.running:
    ret = target.read(addr, length, pid=pid)
    ret = ret[:ret.find("\x00")]
    if ret.count("\xff") == len(ret):
      return ""
  else:
    try:
      byte = target.mem[addr]
    except IndexError:
      return ''
    while byte != "\x00" and length:
      ret += byte
      length -= 1
      addr += 1    
      try:
        byte = target.mem[addr]
      except IndexError:
        return ''

  return ret


def find_functions(target):
  addrs = target.entry_points
  
  for addr in addrs:
    if not target.has_func(addr):
      target.add_func(addr)  

  for segment in target.mem.segments:
    next = segment.start 
    while next < segment.end:
      next = linear_sweep(target, next) + 1
  print "[*] Found %d functions"%len(target.functions)  

#TODO: add intelligent parent-detection

def add_func(kip, pc):
  f = func(pc); f.module="target"
  kip.add_func(f)


def linear_sweep(kip, addr):
  pc = addr
  mnemonic = ""

  while 1:
    try:
      instr = pydasm.get_instruction(kip.mem[pc:pc+15], pydasm.MODE_32)
    except IndexError:
      break
    if not instr:
      pc += 1
      parent = None
      continue #invalid instruction
    
    #if push %ebp; mov %esp, %ebp  -> this is a function: add it
    if kip.mem[pc:pc+3]  == "\x55\x89\xe5":
      parent = pc
      if not kip.has_func(pc):
        #print "Found func %x with prologue"%pc
        add_func(kip,pc)
    elif instr.type == pydasm.INSTRUCTION_TYPE_CALL:
      if instr.op1.type == pydasm.OPERAND_TYPE_IMMEDIATE:
        dest = instr.op1.immediate+pc+instr.length
        if not kip.has_func(dest):
          #print "Found func %x with call"%pc
          add_func(kip,dest)

    pc += instr.length

  kip.functions.sort(func_cmp)

  #second pass, add parents and set up function endings
  pc = addr
  while 1:
    try:
      instr = pydasm.get_instruction(kip.mem[pc:pc+15], pydasm.MODE_32)
    except IndexError:
      break
    if not instr:
      pc += 1
      parent = None
      continue #invalid instruction
    
    #if push %ebp; mov %esp, %ebp  -> this is a function: add it
    if instr.type == pydasm.INSTRUCTION_TYPE_CALL:
      if instr.op1.type == pydasm.OPERAND_TYPE_IMMEDIATE:
        dest = instr.op1.immediate+pc+instr.length
        x = kip.find_func(dest)
        parent = kip.which_parent(pc)
        if parent:
          try:
            x.parents.append(parent.start_addr)
          except:
            print "missing func @ %x"%dest
        else:
          print "!!!@@@ unknown parent start addr",hex(pc)
    pc += instr.length
  
  #add the ends now
  
  prev = kip.functions[0]
  for x in kip.functions[1:]:
    prev.end_addr = x.start_addr - 1
    prev = x
    
  return pc

#def deref(bin, addr):
#  try:
#    x = bin.mem[addr:addr+4]
#    return struct.unpack("<L",x)[0]
#  except IndexError:
#    return "fail"

####################################################  
#display routines  
def x86_disas_func(bin, addr, stop=0, running=0):
  pc = addr
  mnemonic = ""
  while pc < stop or (stop == 0 and "hlt" not in mnemonic and "ret" not in mnemonic):
    try:
      if not running:
        instr = pydasm.get_instruction(bin.mem[pc:pc+15], pydasm.MODE_32)
      else:
        instr = pydasm.get_instruction(str(bin.read(pc,15)), pydasm.MODE_32)
    except IndexError: #bad memory address
      break
      
    if not instr: break

    mnemonic = pydasm.get_instruction_string(instr, pydasm.FORMAT_ATT, pc)

    head = mid = tail = reset = ""
    if colors.COLORS:
      reset = colors.RESET
    head += "0x%.8x:\t"%pc
    
    #print "0x%.8x:\t%s"%(pc,mnemonic),
    if int(instr.type) in [pydasm.INSTRUCTION_TYPE_CMP, pydasm.INSTRUCTION_TYPE_CMPS, pydasm.INSTRUCTION_TYPE_TEST]:
      if colors.COLORS:
        mid = colors.PURPLEfgB
    elif instr.type in [pydasm.INSTRUCTION_TYPE_PUSH, pydasm.INSTRUCTION_TYPE_POP]:
      if colors.COLORS:
        mid = colors.GREENfg
    elif instr.type in [pydasm.INSTRUCTION_TYPE_RET]:
      if colors.COLORS:
        mid = colors.YELLOWfgB
    elif instr.type in [pydasm.INSTRUCTION_TYPE_CALL, pydasm.INSTRUCTION_TYPE_JMPC, pydasm.INSTRUCTION_TYPE_JMP]:
      #hilite calls
      if colors.COLORS:
        mid = colors.YELLOWfgB
      #show function name/ annotations
      if instr.immbytes:
        dest = instr.op1.immediate + instr.length + pc
        
        f = bin.find_func( dest )
        if f and f.name:
          tail = "\t###\t%s()"%f.name
    elif instr.op1.reg == pydasm.REGISTER_ESP or instr.op2.reg == pydasm.REGISTER_ESP or instr.op3.reg ==  pydasm.REGISTER_ESP:
      if colors.COLORS:
        mid = colors.CYANfg

    if instr.immbytes:
      x = ""
      if instr.op2.immediate in bin.mem:
        x = instr.op2.immediate
      elif instr.op1.immediate in bin.mem:
        x = instr.op1.immediate 
      if x != "":
        if colors.COLORS:
          tail = "\t@@@\t%s%r%s"%(colors.REDfg, get_ascii_string(bin, x), reset)
        else:
          tail = "\t@@@\t%r%s"%(get_ascii_string(bin, x), reset)

    print head + mid + mnemonic +reset + tail
    pc += instr.length
  #print "--"
  return pc

  
def dump_code(bin):
  bin.functions.sort(func_cmp)

  prev = 0
  for func in bin.functions:
    #mode 32
    #print "go",hex(func.start_addr),func.name
    if func.end_addr == 0: continue
    x86_disas_func(bin, func.start_addr, stop=func.end_addr)
    print ""
  

