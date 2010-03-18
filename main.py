import platforms
import trace
import sys
import os
import ids
import fuzzNET
import graphs

if __name__ == "__main__":
  target_os = os.uname()[0].lower()
  target_os = "linux"
  filen = sys.argv[1]

  bin = None

  print "[+] Loading %r...."%filen

  if target_os == "linux":
    bin = platforms.Linux.load_target(filen)
  elif target_os == "freebsd":
    bin = platforms.BSD.load_target(filen)
  elif target_os == "darwin":
    bin = platforms.Darwin.load_target(filen)

  if not bin:
    print "Failed to load target :("
    import sys
    sys.exit(1)
  
  bin.resolve_symbols()
  print '[+] Resolved symbols!'
  bin.find_functions()
  #bin.dump_code()

  trace.hit_trace(bin)
  #trace.ltrace(
  #fuzzNET.fuzz(bin)

  #ids.analyze_IO(bin)
  #graphs.graph(bin)
  #graphs.graph_function(0x8049180,bin)
  
  #import x86
  #addr = (0x8049180)# + 0x1e + 0xffffffe6) &0xffffffff
  #x86.x86_disas_func(bin, 0x8048700)
  
  
  print '[+] Done'
     
