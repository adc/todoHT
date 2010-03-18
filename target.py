######################################
# target
class Target:
  """
  To implement a Target a class must load at least file data and memory segments.
  Next it should try to load entry points, functions, symbols, and strings
  """
  def __init__(self, path=""):
    self.data              # the original target
    self.mem
    self.filename = path        
    self.functions = []
    self.entry_points = []
    self.symbols = {}
    self.running = 0
    self.pid = -1
    self.getbase = False
    self.MEMBASE = 0

  def add_func(self, addr):
    if type(addr) == int:
      f = func(addr)
    else:
      f = addr
    f.reach = 1
    self.functions.append(f)
    
  def find_func(self,addr):
    if type(addr) == str:
      for f in self.functions:
        if f.name == addr:
          return f
    else:
      for f in self.functions:
        #todo, range-check.
        if f.start_addr == addr:
          return f
    return None

  def which_parent(self,addr):
    top = None
    for f in self.functions:
      if addr >= f.start_addr:
        top = f
      elif addr <= f.start_addr:
        if not top: return None
        return top
    return None


  def has_func(self, addr):
    return self.find_func(addr) != None
    
  def find_functions(self):
    self.__find_functions__(self) ##TODO fix unbound functions

  def dump_code(self):
    self.__dump_code__(self) ##TODO fix unbound functions

########### Active process functions    
  def attach(self, pid):
    self.__attach__(self,pid)
  
  def detach(self, pid=-1):
    self.__detach__()

  def start(self,args=[]):
    self.__start__(self,args=args)
  
  def stop(self, pid=-1):
    self.__stop__(pid)
    
  def step(self, pid=-1):
    self.__step__(pid)

  def cont(self, pid=-1, sig=0):
    self.__cont__(sig, pid)
  
  def end(self,pid=-1):
    self.__end__(pid)

  def read(self, addr, size, pid=-1):
    return self.__read__(addr, size, pid)

  def write(self, addr, data, size=0, pid = -1):
    if size == 0:
      size = len(data)
    self.__write__(addr, data, size, pid)
    
  def getregs(self, pid = -1):
    return self.__getregs__(pid)
  
  def setregs(self, regs, pid=-1):
    self.__setregs__(self, regs, pid)

  def getpc(self, pid = -1):
    return self.__getpc__(pid)

  def setpc(self, pc, pid=-1):
    self.__setpc__(pc, pid)

  def get_event(self, pid=-1):
    return self.__get_event__(pid)

#######################################
#call graph structures
  
class func:
  def __init__(self,start_addr=0):
    self.parents = []       # which functions call this one?
    self.children = []      # which functions does this one call?
    self.module = ""        # is this part of the target? shared library? what
    self.name = ""

    self.start_addr = start_addr#where is it?
    self.end_addr = 0           #where is it?

    self.entry = 0          #is it an entry point?
    self.hit = 0            #has execution reached it?
    self.reach = 0          #does it appear to be reachable via simple code emul?
    self.args = []          #arguments?
    self.return_type = 0    #what does it seem to return (pointer, int (signed/unsigned?), double ?)

def func_cmp(a, b):
  #on some version of python a long is returned if the val is >= 32768
  try:
    return int(a.start_addr - b.start_addr)
  except:
    print a.start_addr.start_addr,b.start_addr
    from time import sleep
    sleep(100)
    return 0
  
######################################
#memory abstractions
class segment:
  data = ""
  permissons = 0
  def __init__(self,start,end,data="",prot=0,max_prot=0):
    self.base = 0
    self.start = start
    self.end = end
    self.data = data
    self.prot = prot
    self.max_prot = max_prot
    

    if len(data) > (end - start):
      self.data = data[:end - start]
    elif len(data) < (end - start):
      self.data += "\x00"*((end-start) - len(data)+1)

  def __contains__(self, addr):
    if addr > self.start+self.base and addr < self.end+self.base:
      return True
    return False

  def __getitem__(self, addr):
    if addr > self.end+self.base or addr < self.start+self.base:
      raise IndexError("memory address out of range: %x"%addr)
    return self.data[addr - self.start + self.base]

  def __getslice__(self, start, stop):
    if start > self.end+self.base or start < self.start + self.base \
     or stop > self.end+self.base or stop < self.start + self.base:
      raise IndexError("memory address out of range %x-%x"%(start,stop))
    return self.data[start-self.start: stop-self.start]

class memory:
  def __init__(self, segments=[]):
    self.segments = segments

  def add(self, segment):
    self.segments += [segment]

  def __contains__(self, addr):
    for x in self.segments:
      if addr in x:
        return True
    return False

  def __getitem__(self, addr):
    for x in self.segments:
      if addr in x:
        return x[addr]
    raise IndexError("memory address out of range: %x"%addr)

  def __len__(self):
    return 0

  def __getslice__(self, start, stop):
    start = start & 0xffffffff
    stop = stop & 0xffffffff
    for x in self.segments:
      if start in x:
        return x[start:stop]
    raise IndexError("f2 memory address out of range: %x"%start)
  
######################################
#process managment
class process:
  def __init__(self):
    self.mem = memory()

  def open(filename,args=[""], platform = "posix_x86"):
    if platform == "posix_x86":
      pid = os.fork()
      if pid == 0:
        ptrace.ptrace(ptrace.TRACEME)
        os.execv(filename,args)
      else:
        if pid == -1:
          raise Exception("Couldn't launch %s"%filename)
        p, status = os.wait()
        if p != pid:
          print "uhoh"
        print "[+] Opened process %d"%pid  
        return pid
    else:
      raise Exception("unknown platform %s?  for open_process"%platform)

  def handle_crash(pid):
    print "I KRASHED"

    #try to determine the cause of the crash

    #print out registers
    #print out    

    def show_state(bin, pid, bp):
      #1) get ALL registers
      #2) get current instruction

      #display all registers, attempt dereferencing pointers and check for asciiz

      regs = ptrace.getregs(pid)
      kr = regs.keys()
      kr.sort()
      for reg in kr:
        o = ""

        if colors.COLORS:
          if reg == "EIP":
            o += colors.REDfgB
          elif reg == "ESP":
            o += colors.GREENfgB
          elif reg == "EBP":
            o += colors.CYANfgB


        o += "%s: %x"%(reg, regs[reg])
        if colors.COLORS:

          if reg == "EIP":
            o += colors.RESET
          elif reg == "ESP":
            o += colors.RESET
          elif reg == "EBP":
            o += colors.RESET

        def deref(pid, addr):
          return ptrace.read_word(pid, addr)

        x = regs[reg]
        xs = x86.get_ascii_string(bin, x)
        y = deref(pid, x)
        ys = ''
        if y != "fail":
          ys = x86.get_ascii_string(bin, y)

          if y != -1:
            o += " *(%x)"%(y & 0xffffffff)
          else:
            o += " *(%x)"%(y)

        if reg != "EIP":
          if xs:
            o += " str: %s"%`xs`

          if ys:
            o += " *str: %s"%`ys`
        print o 

      #detect if %ebp setup is being used, check instructions for arguments
      #would be better if previous func analysis already determined that
      #Then, fetch appropriate arguments from stack/registers
      addrs = resolve_args(bin, pid, bp.addr, regs["EBP"])

      args = [x for x in addrs if x >= 0]
      locls = [x for x in addrs if x < 0]
      args.sort()
      locls.sort()
      #TODO this formatting style SUCKS
      if args:
        if colors.COLORS:
          print colors.YELLOWfg,    
        print "Arguments from %ebp usage: "
        if colors.COLORS:
          print colors.RESET,    
        for x in args:
          o = ""
          o += "%d(%%ebp)  = %x"%(x, 0xffffffff & addrs[x])

          xs = x86.get_ascii_string(bin,y)

          y = deref(pid, addrs[x])
          ys = ""

          if y != "fail":
            ys = x86.get_ascii_string(bin,y)
          if xs:
            o += " str: %s"%`xs`

          if ys:
            o += " *str: %s"%`ys`

          print o

      if locls:
        if colors.COLORS:
          print colors.YELLOWfg,
        print "Addresses of future locals from %ebp usage: "
        if colors.COLORS:
          print colors.RESET,
        for x in locls:
          o = ""
          o += "%d(%%ebp)  = %x"%(x, 0xffffffff & addrs[x])

          xs = x86.get_ascii_string(bin,y)

          y = deref(pid, addrs[x])
          ys = ""

          if y != "fail":
            ys = x86.get_ascii_string(bin,y)
          if xs:
            o += " str: %s"%`xs`

          if ys:
            o += " *str: %s"%`ys`

          print o

      #dump stack -8 to +8 DWORDS
      if colors.COLORS:
        print colors.YELLOWfg,
      print "Dumping stack from -8 to +8 DWORDS"
      if colors.COLORS:
        print colors.RESET,

      data = dump_mem(pid, regs["ESP"], -8,8,4)
      pretty_hex_print(data, 16)

      if colors.COLORS:
        print colors.YELLOWfg,    
      print "DUMPING FUNCTION @ %x"%bp.addr
      if colors.COLORS:
        print colors.RESET,

      x86.x86_disas_func(bin, bp.addr)

      print "="*3

    def dump_mem(pid, esp, start, stop, step):
      data = ptrace.read(pid, esp-start*step, stop*step-start*step)
      return data      
