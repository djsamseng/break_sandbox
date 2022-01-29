

# C++ shared library with seccomp

Run python in a sandboxed environment by limiting system calls using seccomp

```bash
make -C clib/src/ all
python3 main.py
```

```bash
cd clib/src
LD_LIBRARY_PATH=./ ./code
```