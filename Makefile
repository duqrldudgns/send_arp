all : send_arp

send_arp: main.o
	g++ -o send_arp main.o -lpcap

main.o: main.c arp.h
	g++ -c -o main.o main.c

clean:
	rm -f send_arp
	rm -f *.o

