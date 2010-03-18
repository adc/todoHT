import ptrace
import struct

#TODO
#   single stepping
#   hw breakpoints 
#   hooks
#     for exit | use saved return address
class Breakpoint:
  def __init__(self, bin, pid, addr, precall=None, postcall=None, setme=1, persist = 0):
    self.pid = pid
    self.addr = addr
    self.isset = 0
    self.hit = 0
    self.bin = bin
    self.save = ""
    self.persist = persist
    self.precall = precall
    self.postcall = postcall
    self.postret = 0
    self.funcentry = 0
    
    if setme:
      self.set()
    
  def write(self):
    #TODO impement write on architecture (platforms.py) instead of this file
    #print "setting bp @ ",hex(self.addr)
    if "posix_x86" == "posix_x86":
      self.save = self.bin.read(self.addr, 1, pid=self.pid)
      #print "read out!",`self.save`
      self.bin.write(self.addr, '\xcc', pid=self.pid)
    else:
      raise Exception("[-] dont know how to handle platform: %s"%self.platform)

  def set(self):
    if self.isset:
      self.unset()
    self.isset = 1
    self.write()
    
  def unset(self):
    if self.isset:
      #TODO ERROR CHECK
      #print "unsetting bp",`self.save`
      self.bin.write(self.addr, self.save, pid=self.pid)
      self.isset = 0

#todo: break point manager class ??
def find_breakpoint(bps, addr, pid):
  if pid in bps:
    for x in bps[pid]:
      if x.addr == addr:
        return x
  return None
