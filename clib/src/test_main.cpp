

#include "seccomp_interface.h"

int main() {
  SeccompInterface* si = SeccompInterface_new();
  SeccompInterface_init(si);
  delete si;
}
