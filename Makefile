all: ot_test

ot_test: test.cpp ot.cpp
	g++ -std=c++11 -g -o ot_test -I/opt/local/include test.cpp ot.cpp tcp.cpp -pthread -msse2 -msse4 -L/usr/local/lib -lssl -lcrypto

clean: 
	rm ot_test