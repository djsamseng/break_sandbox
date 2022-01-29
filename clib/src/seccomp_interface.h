#ifndef SECCOMP_INTERFACE_INCLUDED
#define SECCOMP_INTERFACE_INCLUDED


class SeccompInterface {
  public:
    void init();
};


#ifdef __cplusplus
extern "C" {
#endif
  SeccompInterface* SeccompInterface_new();
  void SeccompInterface_init(SeccompInterface* si);

#ifdef __cplusplus
}
#endif


#endif