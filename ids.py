from trace import *
import os
import ptrace
PT = ptrace.Ptrace(os.uname()[0].lower())

targetPIDS = []
def recv_hook(bp, bin):
  pass
def send_hook(bp, bin):
  pass
def read_hook(bp, bin):
  pass
def write_hook(bp, bin):
  pass
def fork_hook(bp, bin):
  regs = bin.getregs()
  retval = regs["EAX"]
  print "FORK libc func called -> retval=%d\n"%retval

def exec_hook(bp, bin):
  print "exec being called"
  
  #TODO
    
def analyze_IO(bin):
  if bin.start(args=sys.argv[2:]) == -1:
    print '[-] Failed to start process'
    return

  f = bin.find_func("read")
  if not f: print "unable to hook read"
  else: bps.append( BP(bin, f.start_addr, postcall=read_hook, persist=1) )

  f = bin.find_func("recv")
  if not f: print "unable to hook recv"
  else: bps.append( BP(bin, f.start_addr, postcall=recv_hook, persist=1) )

  f = bin.find_func("write")
  if not f: print "unable to hook write"
  else: bps.append( BP(bin, f.start_addr, precall=write_hook, persist=1) )

  f = bin.find_func("send")
  if not f: print "unable to hook send"
  else: bps.append( BP(bin, f.start_addr, precall=send_hook, persist=1) )

  f = bin.find_func("execv")
  if not f: print "unable to hook send"
  else: bps.append( BP(bin, f.start_addr, precall=exec_hook, persist=1) )
  
  #f = bin.find_func("fork")
  #if not f: print "unable to hook fork"
  #bps.append( BP(bin, f.start_addr, postcall=fork_hook, persist=1) )

  targetPIDS.append(bin.pid)
  
  handle_child(bin, targetPIDS)