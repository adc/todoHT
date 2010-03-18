import os, sys
import struct
import pydasm
from breakpoints import Breakpoint as BP
from breakpoints import find_breakpoint
import colors
import x86
from utils import pretty_hex_print
import ptrace
PT = ptrace.Ptrace(os.uname()[0].lower())

bps = {}

SIGTRAP = 5
SIGSEGV = 11
SIGCHLD = 17
SIGSTOP = 19
EVENT_FORK = 1
EVENT_VFORK = 2
EVENT_CLONE = 3
EVENT_EXEC = 4
EVENT_EXIT = 6

def hit_trace(bin):
  if bin.start(args=sys.argv[2:]) == -1:
    print '[-] Failed to start process'
    return
  
  bps[bin.pid] = []
  for func in bin.functions:
    bps[bin.pid].append( BP(bin, bin.pid, func.start_addr,
                      precall=display_func_hit, persist=1) )

  trace_state_machine(bin)

def display_func_hit(bp, bin):
  print "hit %x"%bp.addr
  f = bin.find_func(bp.addr)
  print "-hit- ### %s @ %x"%(f.name,bp.addr),
  resolve_args_entry(bin, bp.pid, bp.addr)
  print ''

def display_post(bp,bin):
  #print "post hit", hex(bp.funcentry)
  f = bin.find_func(bp.funcentry)
  print "-post- ### %s @ %x"%(f.name,bp.addr),
  regs = bin.getregs()
  print " ret= %x"%regs["EAX"],
  print ''

def ltrace(bin):
  #pull out args
  if bin.start(args=sys.argv[2:]) == -1:
    print '[-] Failed to start process'
    return
  bps[bin.pid] = []

  for func in bin.functions:
    if func.name:
      bps[bin.pid].append( BP(bin, bin.pid, func.start_addr, 
                          precall=display_func_hit, persist=1) )

  trace_state_machine(bin)

def trace_state_machine(bin, tracefork=True):
  
  PIDS = [bin.pid]
  print "go"
  PT.cont(bin.pid)
  while True:
    if len(PIDS) == 0: break
    
    #print "> wait"
    try:
      pid, status = os.wait()
    except OSError:
      print "OS ERROR"
      if len(PIDS) == 0:
        break
      #todo make sure its OSError 10 -> no child process

    signal = (status & 0xff00) >> 8

    print pid,status,signal

    if os.WIFEXITED(status):
      print "[-] Process %d exited with status %d"%(pid, status)
      PIDS.remove(pid)
      continue
    elif status>>16 in [EVENT_FORK, EVENT_CLONE, EVENT_VFORK]:
      newpid = PT.get_eventmsg(pid)
      if tracefork:
        print "[+] Attached to new child %d\n"%newpid
        bps[newpid] = []
        #copy over bps
        for bp in bps[pid]:
          #print "adding bp to %d (%x)"%(newpid, bp.addr)
          bps[newpid].append( BP(bin, newpid, bp.addr, precall=bp.precall,
                                postcall=bp.postcall, persist=bp.persist))
        PIDS.append(newpid)
    elif status>>16 == EVENT_EXEC:
      #breakpoints need to be re-evaluated here
      print "> Exec happened on pid:%d"%pid
      #remove all bps for now
      bps[pid] = []
      
      #the cats have sent a signal    
    elif signal == SIGTRAP:
      #print ">sigtrap on %d"%pid
      pc = bin.getpc(pid) -1
      bp = find_breakpoint(bps, pc, pid)
      if bp:
        handle_breakpoint(bin, bp, pc, pid)
      else:
        print "@@@@@@@@ did not find bp @ %x"%pc
      
    elif signal == SIGSTOP:
      print ">sigstop on %d"%pid
    else:
      print "> unhandled signal on pid: %d status=%d signal=%d"%(pid,status,signal)
    
    PT.cont(pid)

def handle_breakpoint(bin, bp, pc, pid):
  #print ">>>BP:%d @ %x"%(pid,pc)
  bp.unset()
  bin.setpc(pc, pid=pid)

  if bp.precall:
    bp.precall(bp, bin)

  if bp.postret == pc: #temporary breakpoint for retd
    bp.postcall(bp, bin)
    bps[bp.pid].remove(bp)
  elif bp.postcall:
    #assume return address is at the top of the stack
    ESP = bin.getregs()["ESP"]
    retd = struct.unpack("<L", bin.read(ESP, 4))[0]
    newbp = BP(bin, pid, retd, postcall=bp.postcall, persist=0) 
    newbp.postret = retd
    newbp.funcentry = pc
    bps[pid].append( newbp )

  if bp.persist:
    #single step through, and replace
    bin.step(pid) #this generates another signal, see below
    
    #print "wait on %d"%pid
    tpid, status = os.waitpid(pid, 0)
    signal = ((status) & 0xff00) >> 8
    if signal != SIGTRAP:
       #raise Exception("single step signaled other than SIGTRAP :(: %d"%signal)
       print "...FIXME persistant breakpoint waitpid [XXXXX]"

    bp.set()

fprotos = {}
def readProto(funcname):
  if len(fprotos) == 0:
    f = open("ltrace.conf")
    for line in f:
      line = line.strip()
      if not line: continue
      if line[0] == ';': continue
      retval, f = line.split(' ',1)
      i = f.find('(')
      j = f.find(');')
      func_name = f[:i].strip()
      args = f[i+1:j].split(',')
      fprotos[func_name] = {'ret' : retval, 'args':  args }
  if funcname in fprotos:
    return fprotos[funcname]
  else:
    return None

def resolve_args_entry(bin, pid, addr): 
  #binary is @ addr, figure out stack arguments from code if possible.
  function = bin.find_func(addr)
  if not function:
    print "unknown function",hex(addr)
  else: 
    func_prototype = readProto(function.name)
    if func_prototype:
      cnt = len(func_prototype['args'])
      if cnt:
        d = bin.getregs(pid=pid)
        regs = bin.getregs(pid=pid)
        if regs["EBP"] == 0: return #Invalid ebp
        if cnt == 0: return
        print '(',
        data = bin.read(regs["ESP"]+4, 4*cnt, pid=pid)
        o = ""
        for i in range(0,cnt):
          addr = struct.unpack("<L", data[(i)*4:(i+1)*4])[0]
          if func_prototype['args'][i] == "string":
            #read the string @ addr until 0x00
            #print `bin.read(addr,15)`
            o += '"%s",'%x86.get_ascii_string(bin, addr, pid)
          elif func_prototype['args'][i] == "char":
            o += `chr(addr)`+','
          elif func_prototype['args'][i] in ["int","uint"]:
            o += `addr`+','
          elif func_prototype['args'][i] == "format":
            #read stack based on fmt
            pass
          else:
            o += hex(addr)+','
        print o[:-1],
        print ')',
