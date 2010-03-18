import string

def pretty_hex_print(data, per_line):
  for i in range(0, len(data), per_line):
    #raw bytes
    print " ".join("%.2x"%(ord(x)&0xff) for x in data[i:i+per_line]),
    #and pretty ascii print
    L = []
    for x in data[i:i+per_line]:
      if x in string.printable[:-5]:
        L += x
      else:
        L += '.'
        
    print "\t\t"+ " ".join("%c"%x for x in L)
