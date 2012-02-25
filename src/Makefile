all : fastd

fastd : fastd.o method_null.o
	gcc -Wall -o $@ $^

fastd.o : fastd.c fastd.h packet.h
	gcc -Wall -c -o $@ $<

method_null.o : method_null.c fastd.h
	gcc -Wall -c -o $@ $<
