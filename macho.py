try:
  from macholib.MachO import MachO
  import macholib
except ImportError:
  macholib = None

import struct
from target import *

class Macho(Target):
  def __init__(self, pathname):
    self.load(pathname)
    Target.__init__(self,pathname)
    self.entry_points.append(self.get_entry())    

  def resolve_symbols(self):
    pass
  
  def load(self, pathname):
    self.mem = memory()

    if not macholib:
      import sys
      print >> sys.stderr, "MISSING MACHO"
      sys.exit(0)

    CPU_TYPE_X86 = 7
    READ = 1; WRITE = 2; EXEC = 4

    self.data = open(pathname,'rb').read()
    fat = MachO(pathname)

    macho_header = None
    for arch in fat.headers:
     if arch.header.cputype == CPU_TYPE_X86:
       macho_header = arch
       break
    if not macho_header:
     raise Exception("Couldn't find x86 header")

    #only 386 for now
    self.architecture = "386"
    for cmd in macho_header.commands:
      if type(cmd[1]) == macholib.mach_o.segment_command:
        fake_start = cmd[1].fileoff
      if fake_start == 0:
        fake_start = cmd[1].vmaddr          
        seg = segment(cmd[1].vmaddr, cmd[1].vmaddr+cmd[1].vmsize, 
             self.data[fake_start : fake_start + cmd[1].filesize], 
             cmd[1].initprot)
        if seg.prot & EXEC:
          seg.code = 1

      self.mem.segments.append( seg )

    self.format = macho_header
    self.format.name = "macho"

  def get_entry(self):
    eip = None
    for cmd in self.format.commands:
      if type(cmd[1]) == macholib.mach_o.thread_command:
        regs = struct.unpack("<LLLLLLLLLLLLLLLLLL",cmd[2])
        flavor, count = regs[:2]
        regs = regs[2:]

        eip = regs[10]
    return eip
