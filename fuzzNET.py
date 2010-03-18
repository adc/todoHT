from trace import *
#ssize_t recv(int s, void *buf, size_t len, int flags);
#ssize_t write(int fildes, const void *buf, size_t nbyte);
#ssize_t send(int s, const void *buf, size_t len, int flags);


def randstring(sz):
  return open("/dev/urandom",'r').read(sz)

#precall hooks
def send_hook(bp, bin):
  #sprinkle dev random into arg 2 
  regs = bin.getregs(pid=bp.pid)
  s,addr,sz = struct.unpack("<LLL", bin.read(regs["ESP"]+4, 4*3, pid=bp.pid))
  print " send to fuzz %x"%addr,s,sz
  pass
  
def write_hook(bp, bin):
  regs = bin.getregs(pid=bp.pid)
  s,addr,sz = struct.unpack("<LLL", bin.read(regs["ESP"]+4, 4*3, pid=bp.pid))
  if s <= 2:
    #XXX assuming stdio
    return 
  print " write to fuzz %x"%addr,s,sz
  bin.write( addr, randstring(sz), sz, pid=bp.pid)
  pass

def recv_hook(bp, bin):
  pass
def read_hook(bp, bin):
  pass

hooks  = {"send" : (send_hook, None),
          "write" : (write_hook, None),
          "recv" : (None, recv_hook),
          "read" : (None, read_hook)
         }
         
def fuzz(bin):
  #pull out args
  if bin.start(args=sys.argv[2:]) == -1:
    print '[-] Failed to start process'
    return
  bps[bin.pid] = []
  print "started proc"
  for func in bin.functions:
    if func.name in hooks:
      prehook = hooks[func.name][0]
      posthook = hooks[func.name][1]
      print "bp %x"%func.start_addr
      bps[bin.pid].append( BP(bin, bin.pid, func.start_addr, 
                          precall=prehook, postcall=posthook,
                          persist=1) )

  trace_state_machine(bin)
