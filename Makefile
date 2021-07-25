a.out: *.cpp
	g++ -g3 *.cpp -L/usr/lib -lssl -lcrypto -Wall
