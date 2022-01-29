

import numpy as np

import numba.cuda


import prctl
prctl.set_dumpable(True)
prctl.set_seccomp(True)




def main():
  print("Here!")
  a = np.random.rand(5)
  print("Created memory!", a)
  a[0] = 0.5
  b = a * np.random.rand(5)
  import os
  print("Modified a")
  pid = os.fork()
  return b



