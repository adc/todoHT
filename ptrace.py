"""
TODO test FreeBSD
"""
import ctypes
import ctypes.util
import struct
from os import uname

libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c'))
#libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
PTRACE = libc.ptrace


#x86-32 ptrace
class Ptrace:
  def __init__(self, OS):
    self.OS = OS.lower()
    OS = self.OS
    #shared by linux + freebsd
    self.TRACEME = 0
    self.PEEKTEXT = 1
    self.PEEKDATA = 2
    self.PEEKUSER = 3
    self.POKETEXT = 4
    self.POKEDATA = 5
    self.POKEUSER = 6
    self.CONT = 7
    self.KILL = 8
    self.SINGLESTEP = 9
    if OS == "freebsd":
      self.ATTACH = 10
      self.DETACH = 11
      self.GETREGS = 33
      self.SETREGS = 34
      self.GETFPREGS = 35
      self.SETFPREGS = 36  
      self.SYSCALL = 22
      self.FS = 0
      self.ES = 1
      self.DS = 2
      self.EDI = 3
      self.ESI = 4
      self.EBP = 5
      self.ISP = 6
      self.EBX = 7
      self.ECX = 8
      self.EDX = 9
      self.EAX = 10
      self.ORIG_EAX = 11 #TRAPNO
      self.ERR = 12
      self.EIP = 13
      self.CS = 14
      self.EFLAGS = 15
      self.ESP = 16
      self.SS = 17
      self.GS = 18      
    elif OS == "linux":  
      self.PTRACE_EVENT_FORK = 1
      self.SETOPTIONS = 0x4200
      self.GETEVENTMSG = 0x4201
      self.PTRACE_O_TRACEFORK = 2
      self.PTRACE_O_TRACEVFORK = 4
      self.ATTACH = 16
      self.DETACH = 17
      self.GETREGS = 12
      self.SETREGS = 13
      self.GETFPREGS = 14
      self.SETFPREGS = 15
      self.SYSCALL = 24
      self.EBX = 0
      self.ECX = 1
      self.EDX = 2
      self.ESI = 3
      self.EDI = 4
      self.EBP = 5
      self.EAX = 6
      self.DS = 7
      self.ES = 8
      self.FS = 9
      self.GS = 10
      self.ORIG_EAX = 11
      self.EIP = 12
      self.CS = 13
      self.EFLAGS = 14
      self.ESP = 15
      self.SS = 16

    
  def ptrace(self, request, pid=0, addr=0, data=0):
    #print request,pid,hex(addr)
    return PTRACE(request, pid, addr&0xffffffff, data) 
  
  def attach(self, pid):
    return self.ptrace(self.ATTACH, pid)

  def detach(self, pid):
    return self.ptrace(self.DETACH, pid)

  def step(self, pid, addr=1, signal=0):
    if self.OS == "linux":
        return self.ptrace(self.SINGLESTEP, pid, 0, signal) 
    elif self.OS == "freebsd":
        return self.ptrace(self.SINGLESTEP, pid, addr, signal) 
    else:
        raise Exception("dont know how to step for this OS");    

  def cont(self, pid, addr=1,signal=0):
    if self.OS == "freebsd":
      self.ptrace(self.CONT,pid,addr,signal)
    elif self.OS == "linux":
      self.ptrace(self.CONT,pid,0,signal)
    else:
        raise exception("dont know how to cont  for this OS");    

  def kill(self, pid):
    return self.ptrace(self.KILL, pid)    

  def read_word(self, pid, addr):
    ret = self.ptrace(self.PEEKDATA, pid, addr, 0)
    return ret

  def read(self, pid, addr, sz):
    i = 0
    out = ""
    while i < sz:
      val = self.read_word(pid, addr)
      out += struct.pack("<l", val)
      addr += 4
      i += 4

    return out[:sz]

  def write_word(self, pid, addr, data):
    #print "write_word",pid,hex(data)
    return self.ptrace(self.POKEDATA, pid, addr, data)
    
  def write_data(self, pid, addr, data):
    #TODO: error checking
    i = 0
    while i < len(data):
      chunk = data[i:i+4]

      if len(chunk) < 4:
        old = struct.unpack("<L", self.read(pid, addr, 4))[0]

        #XXX ptrace can fail/check errno instead of 0xffffffff
        # python 2.6 has better support for errno, what to do for < 2.6 ??
        while old == 0xffffffffL:
          #print "ERRCHECK"#, ctypes.get_errno()
          old = struct.unpack("<L", self.read(pid, addr, 4))[0]

        padded = chunk+"\x00"*(4-len(chunk)) #XXX clean me        

        towrite = struct.unpack("<L",padded)[0]

        if len(chunk) == 3:
          towrite = (old & 0xff000000) + towrite
        elif len(chunk) == 2:
          towrite = (old & 0xffff0000) + towrite
        elif len(chunk) == 1:
          towrite = (old & 0xffffff00) + towrite
        
        self.write_word(pid, addr, towrite)
      else:
        self.write_word(pid, addr, struct.unpack("<L", chunk)[0])

      i += 4
      addr += 4
    

  def get_eip(self, pid):
    return self.get_regs_raw(pid)[self.EIP]
  
  def set_eip(self, pid, val):
    regbuf = self.get_regs_raw(pid)
    regbuf[self.EIP] = val & 0xffffffff
    if self.OS == "freebsd":
      return self.ptrace(self.SETREGS, pid, struct.pack("<LLLLLLLLLLLLLLLLLLLL", *regbuf), 0)
    elif self.OS == "linux":
      return self.ptrace(self.SETREGS, pid, 0, struct.pack("<LLLLLLLLLLLLLLLLLLLL", *regbuf))

  def setregs(self, pid, regs):
    print "XXX todo setregs"
    #return ptrace(PTRACE_PEEKUSER, pid, 16, val & 0xffffffff)
    #regbuf = self.get_regs_raw(pid)
    #regbuf[self.EIP] = val & 0xfffffff
    #return ptrace(self.PTRACE_SETREGS, pid, 0, struct.pack("<LLLLLLLLLLLLLLLLLLLL", *regbuf))


  def getregs(self, pid):
    regs = self.get_regs_raw(pid)
    d = {}
    d["EAX"] = regs[self.EAX]
    d["ORIG_EAX"] = regs[self.ORIG_EAX]
    d["EBX"] = regs[self.EBX]
    d["ECX"] = regs[self.ECX]
    d["EDX"] = regs[self.EDX]
    d["ESI"] = regs[self.ESI]
    d["EDI"] = regs[self.EDI]
    d["ESP"] = regs[self.ESP]
    d["EBP"] = regs[self.EBP]
    d["EIP"] = regs[self.EIP]
    d["EFLAGS"] = regs[self.EFLAGS]
    d["CS"] = regs[self.CS]
    d["DS"] = regs[self.DS]
    d["ES"] = regs[self.ES]
    d["FS"] = regs[self.FS]
    d["GS"] = regs[self.GS]
    d["SS"] = regs[self.SS]

    return d
  
  def get_regs_raw(self, pid):
    buf = ctypes.create_string_buffer(0x1000)
    if self.OS == "linux":  
      self.ptrace(self.GETREGS, pid, 0, buf)
    elif self.OS == "freebsd":
      self.ptrace(self.GETREGS, pid, buf, 0)
  
    a = struct.unpack("<LLLLLLLLLLLLLLLLLLLL",buf.raw[:20*4])
    return list(a)

  def get_fpregs(self, pid):
    pass
  
  def get_eventmsg(self, pid):
    newpid = ctypes.create_string_buffer(0x1000)
    self.ptrace(self.GETEVENTMSG, pid, 0, newpid)
    return struct.unpack("<L",newpid.raw[:4])[0]
    
