
task2.1: task2.1.c
	gcc -Wall -g -c task2.1.c
	gcc -Wall -g -o sniffer task2.1.o -lpcap

task2.2: task2.2.c
	gcc -Wall -g -c task2.2.c
	gcc -Wall -g -o spoofer task2.2.o

task2.3: task2.3.c
	gcc -Wall -g -c task2.3.c
	gcc -Wall -g -o sniffspoof task2.3.o -lpcap