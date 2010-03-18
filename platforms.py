import elf
import x86
import ptrace
import os
import macho

class _Posix:
  
  def __init__(self):
    pass
    
  def load_target(self, pathname):
    #TODO support for other file formats
    self.bin = elf.UnixElf(pathname)
    self.__prepare_arch__(self.bin)
    return self.bin

  def __prepare_arch__(self, bin):
    if bin.format.e_machine == elf.EM_386:
      bin.__find_functions__ = x86.find_functions
      bin.__dump_code__ = x86.dump_code
      
      bin.__start__ = self.ptrace_start
      bin.__end__ = self.ptrace_end
      bin.__stop__ = self.ptrace_stop
      bin.__cont__ = self.ptrace_cont
      bin.__step__ = self.ptrace_step
      bin.__attach__ = self.ptrace_attach
      bin.__detach__ = self.ptrace_detach
      bin.__read__ = self.ptrace_read
      bin.__write__ = self.ptrace_write 
      bin.__getregs__ = self.ptrace_getregs
      bin.__setregs__ = self.ptrace_setregs
      bin.__getpc__ = self.ptrace_getpc
      bin.__setpc__ = self.ptrace_setpc
      bin.__get_event__ = self.ptrace_get_event

    else:
      raise Exception("Unknown architecture")

  def ptrace_attach(self, pid):
    ret = self.ptrace.attach(pid)
    
    if ret == -1:
      print "Couldn't attach to pid %d"%pid
    else:
      p, status = os.wait()
      if p != pid:
        print "XXXXXX ptrace attach"
      else:
        print "[+] Attached to process %d"%pid          
        self.bin.pid = pid
        self.running = 1

    return pid
    
  def ptrace_detach(self, pid=-1):
    if pid == -1:
      self.running = 0
      return self.ptrace.detach(self.bin.pid)
    else:
      return self.ptrace.detach(pid)
    
  def ptrace_start(self,bin,args=[]):
    pid = os.fork()
    if pid == 0:
      self.ptrace.ptrace(self.ptrace.TRACEME)
      os.execv(bin.filename,args)
      raise Exception("Failed to execute %s"%bin.filename)
    else:
      if pid == -1:
        raise Exception("Couldn't fork")
      p, status = os.wait()
      if p != pid:
        print "XXXXXXX uhoh"
      self.ptrace.ptrace(self.ptrace.SETOPTIONS, pid, 0, 2|4|8|0x10|self.ptrace.PTRACE_O_TRACEFORK)
      print "[+]  Opened process %d"%pid  
      self.bin.pid = pid
      self.bin.running = 1
    print "********-=-=-=-=-="
  
    if bin.format.e_type == elf.ET_DYN:
      #XX ELF specific stuff here
      bin.MEMBASE = bin.getregs()["EIP"]-bin.format.e_entry
      for segment in bin.memory.segments:
        segment.base = bin.MEMBASE
      print 'hai'
      for func in bin.functions:
        print "adjusting start addr by %x"%bin.MEMBASE
        func.start_addr += bin.MEMBASE
    
    return pid

  def ptrace_end(self, pid=-1):
    if pid == -1:
      self.running = 0
      return self.ptrace.kill(self.bin.pid)
    else:
      return self.ptrace.kill(pid)      

  def ptrace_stop(self, pid=-1):
    #TODO FIX
    if pid == -1:
      return os.kill(self.bin.pid, 19)  #YY
    else:
      return os.kill(pid, 19)  #YY      

  def ptrace_cont(self, sig=0, pid=-1):
    if pid == -1:
      return self.ptrace.cont(self.bin.pid, signal=sig)
    else:
      return self.ptrace.cont(pid, signal=sig)

  def ptrace_read(self, addr, size, pid=-1):
    if pid == -1:
      return self.ptrace.read(self.bin.pid, addr, size)
    else:
      return self.ptrace.read(pid, addr, size)      
    
  def ptrace_write(self, addr, data, size, pid=-1):
    data = data[:size]
    if pid == -1:
      return self.ptrace.write_data(self.bin.pid, addr, data)
    else:
      return self.ptrace.write_data(pid, addr, data)

  def ptrace_getregs(self, pid=-1):
    if pid == -1:
      return self.ptrace.getregs(self.bin.pid)
    else:
      return self.ptrace.getregs(pid)
      

  def ptrace_setregs(self, regs, pid = -1):
    if pid == -1:
      return self.ptrace.setregs(self.bin.pid, regs)
    else:
      return self.ptrace.setregs(pid, regs)
    

  def ptrace_getpc(self, pid=-1):
    if pid == -1:
      return self.ptrace.get_eip(self.bin.pid)
    else:
      return self.ptrace.get_eip(pid)
      
  def ptrace_setpc(self, addr, pid=-1):
    if pid == -1:
      return self.ptrace.set_eip(self.bin.pid, addr)
    else:
      return self.ptrace.set_eip(pid, addr)
      
  def ptrace_step(self,pid=-1):
    if pid == -1:
      return self.ptrace.step(self.bin.pid)
    else:
      return self.ptrace.step(pid)
  
  def ptrace_get_event(self,pid=-1):
    if pid == -1:
      return self.ptrace.get_eventmsg(self.bin.pid)
    else:
      return self.ptrace.get_eventmsg(pid)

class _Linux(_Posix):
  def __init__(self):
    _Posix.__init__(self)
    self.ptrace = ptrace.Ptrace('linux')

class _BSD(_Posix):
  def __init__(self):
    _Posix.__init__(self)
    self.ptrace = ptrace.Ptrace('freebsd')

class _Darwin:
  def load_target(self, pathname):
    self.bin = macho.Macho(pathname)
    self.__prepare_arch__(self.bin)
    return self.bin

  def __prepare_arch__(self, bin):
    bin.__find_functions__ = x86.find_functions
    bin.__dump_code__ = x86.dump_code
    
    bin.__start__ = self.ptrace_start
    bin.__end__ = self.ptrace_end
    bin.__stop__ = self.ptrace_stop
    bin.__cont__ = self.ptrace_cont
    bin.__step__ = self.ptrace_step
    bin.__attach__ = self.ptrace_attach
    bin.__detach__ = self.ptrace_detach
    bin.__read__ = self.unhandled
    bin.__write__ = self.unhandled 
    bin.__getregs__ = self.ptrace_getregs
    bin.__setregs__ = self.unhandled
    bin.__getpc__ = self.ptrace_getpc
    bin.__setpc__ = self.unhandled
    bin.__get_event__ = self.unhandled

  def ptrace_attach(self, pid):
    ret = self.ptrace.attach(pid)

    if ret == -1:
      print "Couldn't attach to pid %d"%pid
    else:
      p, status = os.wait()
      if p != pid:
        print "XXXXXX ptrace attach"
      else:
        print "[+] Attached to process %d"%pid          
        self.bin.pid = pid
        self.running = 1

    return pid

  def ptrace_detach(self, pid=-1):
    if pid == -1:
      self.running = 0
      return self.ptrace.detach(self.bin.pid)
    else:
      return self.ptrace.detach(pid)

  def ptrace_start(self,bin,args=[]):
    pid = os.fork()
    if pid == 0:
      self.ptrace.ptrace(self.ptrace.TRACEME)
      os.execv(bin.filename,args)
      raise Exception("Failed to execute %s"%bin.filename)
    else:
      if pid == -1:
        raise Exception("Couldn't fork")
      p, status = os.wait()
      if p != pid:
        print "XXXXXXX uhoh"
      self.ptrace.ptrace(self.ptrace.SETOPTIONS, pid, 0, 2|4|8|0x10|self.ptrace.PTRACE_O_TRACEFORK)
      print "[+]  Opened process %d"%pid  
      self.bin.pid = pid
      self.bin.running = 1
    print "********-=-=-=-=-="

    if bin.format.e_type == elf.ET_DYN:
      #XX ELF specific stuff here
      bin.MEMBASE = bin.getregs()["EIP"]-bin.format.e_entry
      for segment in bin.memory.segments:
        segment.base = bin.MEMBASE
      print 'hai'
      for func in bin.functions:
        print "adjusting start addr by %x"%bin.MEMBASE
        func.start_addr += bin.MEMBASE

    return pid
  
  def unhandled(self, *args):
    print "DARWIN TODO:::: NOT HANDLED YET"

  def ptrace_end(self, pid=-1):
    if pid == -1:
      self.running = 0
      return self.ptrace.kill(self.bin.pid)
    else:
      return self.ptrace.kill(pid)      

  def ptrace_stop(self, pid=-1):
    #TODO FIX
    if pid == -1:
      return os.kill(self.bin.pid, 19)  #YY
    else:
      return os.kill(pid, 19)  #YY      

  def ptrace_cont(self, sig=0, pid=-1):
    if pid == -1:
      return self.ptrace.cont(self.bin.pid, signal=sig)
    else:
      return self.ptrace.cont(pid, signal=sig)

  def ptrace_read(self, addr, size, pid=-1):
    if pid == -1:
      return self.ptrace.read(self.bin.pid, addr, size)
    else:
      return self.ptrace.read(pid, addr, size)      

  def ptrace_write(self, addr, data, size, pid=-1):
    data = data[:size]
    if pid == -1:
      return self.ptrace.write_data(self.bin.pid, addr, data)
    else:
      return self.ptrace.write_data(pid, addr, data)

  def ptrace_getregs(self, pid=-1):
    if pid == -1:
      return self.ptrace.getregs(self.bin.pid)
    else:
      return self.ptrace.getregs(pid)


  def ptrace_setregs(self, regs, pid = -1):
    if pid == -1:
      return self.ptrace.setregs(self.bin.pid, regs)
    else:
      return self.ptrace.setregs(pid, regs)


  def ptrace_getpc(self, pid=-1):
    if pid == -1:
      return self.ptrace.get_eip(self.bin.pid)
    else:
      return self.ptrace.get_eip(pid)

  def ptrace_setpc(self, addr, pid=-1):
    if pid == -1:
      return self.ptrace.set_eip(self.bin.pid, addr)
    else:
      return self.ptrace.set_eip(pid, addr)

  def ptrace_step(self,pid=-1):
    if pid == -1:
      return self.ptrace.step(self.bin.pid)
    else:
      return self.ptrace.step(pid)

  def ptrace_get_event(self,pid=-1):
    if pid == -1:
      return self.ptrace.get_eventmsg(self.bin.pid)
    else:
      return self.ptrace.get_eventmsg(pid)

Linux = _Linux()
BSD = _BSD()
Darwin = _Darwin()
