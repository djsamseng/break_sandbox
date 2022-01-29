
clean:
	rm *.o
	rm *.so

all:
	g++ -Wall -fPIC seccomp_interface.cpp -c -o seccomp_interface.o
	g++ -shared -o libtest.so seccomp_interface.o -lseccomp
	g++ -L. -Wall -o code test_main.cpp -ltest
