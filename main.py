

from ctypes import cdll
import numba.cuda

# To get system calls used
# strace -qcf python3 main.py 2>&1 >/dev/null | awk '{print $NF}'

lib = cdll.LoadLibrary("./clib/src/libtest.so")

class SeccompInterface(object):
  def __init__(self) -> None:
    self.si = lib.SeccompInterface_new()

  def init(self) -> None:
    lib.SeccompInterface_init(self.si)

def main():
  print("Main running")
  si = SeccompInterface()
  val = si.init()
  print("Main got val:")
  a = numba.cuda.device_array((5,))

  print("still good")
  #import os
  a[0] = 2.5
  print("Did set")
  open("test.txt", "w")
  print("End")


if __name__ == "__main__":
  main()


